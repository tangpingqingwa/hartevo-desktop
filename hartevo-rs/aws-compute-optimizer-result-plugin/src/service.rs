//! Read/proposal/record/verify service for bounded Compute Optimizer evidence.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    AwsComputeOptimizerEvidence, AwsComputeOptimizerObservationReceipt,
    AwsComputeOptimizerProposal, AwsComputeOptimizerScope, AwsComputeOptimizerVerificationReport,
    ConsentScope, Digest, EvidenceState, FailureClass, FailureEvidence, MAX_RECOMMENDATIONS,
    MAX_RESULT_PAGES, ModelError, RecommendationStatus, RegistrationStatus, ResourceKind,
    SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsComputeOptimizerOperation, AwsComputeOptimizerProvider, AwsComputeOptimizerProviderError,
    AwsComputeOptimizerReadRequest, AwsComputeOptimizerTransport,
    AwsComputeOptimizerTransportError, GetAutoScalingGroupRecommendationsRequest,
    GetEC2InstanceRecommendationsRequest,
};
use crate::{
    CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsComputeOptimizerServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] AwsComputeOptimizerProviderError),
    #[error("AWS Compute Optimizer registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS Compute Optimizer registration is invalid or drifted")]
    InvalidRegistration,
    #[error("AWS Compute Optimizer scope does not match the proposal")]
    ScopeMismatch,
    #[error("the idempotency key is invalid")]
    InvalidIdempotencyKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsComputeOptimizerServiceDefinition {
    pub service_id: String,
    pub service_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub operations: Vec<AwsComputeOptimizerOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub preference_mutation: bool,
    pub resource_resize: bool,
    pub savings_guarantee: bool,
    pub connected: bool,
    pub native: bool,
}

impl AwsComputeOptimizerServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            service_version: "1.0.0".to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            operations: vec![
                AwsComputeOptimizerOperation::GetEc2InstanceRecommendations,
                AwsComputeOptimizerOperation::GetAutoScalingGroupRecommendations,
                AwsComputeOptimizerOperation::CompileResultProposal,
                AwsComputeOptimizerOperation::RecordObservationReceipt,
                AwsComputeOptimizerOperation::VerifyResultProposal,
                AwsComputeOptimizerOperation::RevokeRegistration,
                AwsComputeOptimizerOperation::RestoreRegistration,
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            preference_mutation: false,
            resource_resize: false,
            savings_guarantee: false,
            connected: false,
            native: false,
        }
    }

    pub fn validate(&self) -> Result<(), AwsComputeOptimizerServiceError> {
        if self.service_id != SERVICE_ID
            || self.service_version != "1.0.0"
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || !self.read_only
            || !self.proposal_only
            || self.external_writes
            || self.preference_mutation
            || self.resource_resize
            || self.savings_guarantee
            || self.connected
            || self.native
        {
            Err(AwsComputeOptimizerServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsComputeOptimizerServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsComputeOptimizerRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_api_revision: String,
    provider_digest: Digest,
    api_digest: Digest,
    scope: AwsComputeOptimizerScope,
    scope_digest: Digest,
    resource_allowlist_digest: Digest,
    recommendation_window_digest: Digest,
    project_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    permission_digest: Digest,
    consent: ConsentScope,
    evidence_policy_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsComputeOptimizerRegistration {
    pub fn new<T: AwsComputeOptimizerTransport>(
        scope: AwsComputeOptimizerScope,
        secret_reference: SecretReference,
        provider: &AwsComputeOptimizerProvider<T>,
        registration_revision: u64,
    ) -> Result<Self, AwsComputeOptimizerServiceError> {
        if registration_revision == 0 {
            return Err(AwsComputeOptimizerServiceError::InvalidRegistration);
        }
        provider.definition().validate()?;
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        let mut registration = Self {
            id: "aws-compute-optimizer-registration".to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.definition().provider_id.clone(),
            provider_revision: provider.definition().provider_revision,
            provider_release: provider.definition().provider_release.clone(),
            provider_api_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.definition().provider_digest.clone(),
            api_digest: provider.definition().api_digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            resource_allowlist_digest: scope.resource_allowlist_digest(),
            recommendation_window_digest: scope.recommendation_window().window_digest.clone(),
            project_digest: scope.project().digest(),
            mission_digest: scope.mission().digest(),
            work_product_digest: scope.work_product().digest(),
            permission_digest: scope.permission_snapshot().permission_digest().clone(),
            consent: scope.consent().clone(),
            evidence_policy_digest: Digest::from_fields(
                "aws-compute-optimizer-evidence-policy/v1",
                &[
                    CONTRACT_VERSION.to_owned(),
                    MAX_RECOMMENDATIONS.to_string(),
                    MAX_RESULT_PAGES.to_string(),
                    "raw-utilization-series-excluded".to_owned(),
                ],
            ),
            secret_reference,
            scope,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-compute-optimizer-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }
    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }
    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    #[must_use]
    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }
    #[must_use]
    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
    }
    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }
    #[must_use]
    pub fn scope(&self) -> &AwsComputeOptimizerScope {
        &self.scope
    }
    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    #[must_use]
    pub fn resource_allowlist_digest(&self) -> &Digest {
        &self.resource_allowlist_digest
    }
    #[must_use]
    pub fn recommendation_window_digest(&self) -> &Digest {
        &self.recommendation_window_digest
    }
    #[must_use]
    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }
    #[must_use]
    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }
    #[must_use]
    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }
    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }
    #[must_use]
    pub fn evidence_policy_digest(&self) -> &Digest {
        &self.evidence_policy_digest
    }
    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }
    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }
    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }
    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<(), AwsComputeOptimizerServiceError> {
        let expected_evidence_policy = Digest::from_fields(
            "aws-compute-optimizer-evidence-policy/v1",
            &[
                CONTRACT_VERSION.to_owned(),
                MAX_RECOMMENDATIONS.to_string(),
                MAX_RESULT_PAGES.to_string(),
                "raw-utilization-series-excluded".to_owned(),
            ],
        );
        if self.id != "aws-compute-optimizer-registration"
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_api_revision != PROVIDER_API_REVISION
            || self.registration_revision == 0
            || self.scope_digest != *self.scope.scope_digest()
            || self.resource_allowlist_digest != self.scope.resource_allowlist_digest()
            || self.recommendation_window_digest != self.scope.recommendation_window().window_digest
            || self.project_digest != self.scope.project().digest()
            || self.mission_digest != self.scope.mission().digest()
            || self.work_product_digest != self.scope.work_product().digest()
            || self.permission_digest != *self.scope.permission_snapshot().permission_digest()
            || self.consent != *self.scope.consent()
            || self.evidence_policy_digest != expected_evidence_policy
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsComputeOptimizerServiceError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        Ok(())
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsComputeOptimizerServiceError::RegistrationRevoked);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(crate::RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsComputeOptimizerServiceError::RegistrationRevoked);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(crate::RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsComputeOptimizerServiceError::RegistrationRevoked);
        }
        let previous = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(crate::RegistrationTransitionEvidence::new(
            previous,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-compute-optimizer-registration/v1",
            &[
                self.id.clone(),
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.provider_id.clone(),
                self.provider_revision.to_string(),
                self.provider_release.clone(),
                self.provider_api_revision.clone(),
                self.provider_digest.as_str().to_owned(),
                self.api_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.resource_allowlist_digest.as_str().to_owned(),
                self.recommendation_window_digest.as_str().to_owned(),
                self.project_digest.as_str().to_owned(),
                self.mission_digest.as_str().to_owned(),
                self.work_product_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
                self.evidence_policy_digest.as_str().to_owned(),
                self.secret_reference.reference_digest().as_str().to_owned(),
                self.registration_revision.to_string(),
                format!("{:?}", self.status),
            ],
        )
    }
}

impl Serialize for AwsComputeOptimizerRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsComputeOptimizerRegistration", 24)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("resourceAllowlistDigest", &self.resource_allowlist_digest)?;
        state.serialize_field(
            "recommendationWindowDigest",
            &self.recommendation_window_digest,
        )?;
        state.serialize_field("projectDigest", &self.project_digest)?;
        state.serialize_field("missionDigest", &self.mission_digest)?;
        state.serialize_field("workProductDigest", &self.work_product_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent.digest())?;
        state.serialize_field("evidencePolicyDigest", &self.evidence_policy_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl fmt::Debug for AwsComputeOptimizerRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsComputeOptimizerRegistration")
            .field("id", &self.id)
            .field("provider_id", &self.provider_id)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("scope_digest", &self.scope_digest)
            .field("resource_allowlist_digest", &self.resource_allowlist_digest)
            .field(
                "recommendation_window_digest",
                &self.recommendation_window_digest,
            )
            .field("permission_digest", &self.permission_digest)
            .field("evidence_policy_digest", &self.evidence_policy_digest)
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

pub struct AwsComputeOptimizerService<T> {
    scope: AwsComputeOptimizerScope,
    secret_reference: SecretReference,
    provider: AwsComputeOptimizerProvider<T>,
    registration: AwsComputeOptimizerRegistration,
    definition: AwsComputeOptimizerServiceDefinition,
}

impl<T: AwsComputeOptimizerTransport> fmt::Debug for AwsComputeOptimizerService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsComputeOptimizerService")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsComputeOptimizerTransport> AwsComputeOptimizerService<T> {
    pub fn new(
        scope: AwsComputeOptimizerScope,
        secret_reference: SecretReference,
        provider: AwsComputeOptimizerProvider<T>,
    ) -> Result<Self, AwsComputeOptimizerServiceError> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        let definition = AwsComputeOptimizerServiceDefinition::new();
        definition.validate()?;
        let registration = AwsComputeOptimizerRegistration::new(
            scope.clone(),
            secret_reference.clone(),
            &provider,
            1,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            definition,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AwsComputeOptimizerScope {
        &self.scope
    }
    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }
    #[must_use]
    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }
    #[must_use]
    pub fn provider(&self) -> &AwsComputeOptimizerProvider<T> {
        &self.provider
    }
    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AwsComputeOptimizerProvider<T> {
        &mut self.provider
    }
    #[must_use]
    pub fn registration(&self) -> &AwsComputeOptimizerRegistration {
        &self.registration
    }
    #[must_use]
    pub fn definition(&self) -> &AwsComputeOptimizerServiceDefinition {
        &self.definition
    }

    pub fn read_ec2_instance_recommendations(
        &mut self,
        cursor: Option<crate::OpaquePageCursor>,
    ) -> Result<crate::AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerServiceError> {
        self.ensure_active()?;
        let request = GetEC2InstanceRecommendationsRequest::for_scope(&self.scope, cursor)?;
        Ok(self.provider.get_ec2_instance_recommendations(&request)?)
    }

    pub fn read_auto_scaling_group_recommendations(
        &mut self,
        cursor: Option<crate::OpaquePageCursor>,
    ) -> Result<crate::AwsComputeOptimizerRecommendationPage, AwsComputeOptimizerServiceError> {
        self.ensure_active()?;
        let request = GetAutoScalingGroupRecommendationsRequest::for_scope(&self.scope, cursor)?;
        Ok(self
            .provider
            .get_auto_scaling_group_recommendations(&request)?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        self.compile_proposal_at(Utc::now())
    }

    pub fn propose(
        &mut self,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        self.compile_proposal()
    }

    pub fn read(&mut self) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        self.compile_proposal()
    }

    pub fn read_bounded(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        self.compile_proposal_at(now)
    }

    pub fn compile_proposal_at(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        self.ensure_active()?;
        let provenance = self.provider.provenance();
        let mut recommendations = Vec::new();
        let mut recommendation_digests = BTreeSet::new();
        let mut pages_read = 0_u16;
        let kinds = [ResourceKind::Ec2Instance, ResourceKind::AutoScalingGroup];
        for kind in kinds {
            if !self
                .scope
                .resources()
                .iter()
                .any(|resource| resource.kind() == kind)
            {
                continue;
            }
            let mut cursor = None;
            let mut kind_pages = 0_u16;
            loop {
                let request =
                    AwsComputeOptimizerReadRequest::for_scope(&self.scope, kind, cursor.clone())?;
                let page = match self.provider.read(&request) {
                    Ok(page) => page,
                    Err(error) => return self.proposal_for_provider_error(error, pages_read),
                };
                kind_pages = kind_pages.saturating_add(1);
                pages_read = pages_read.saturating_add(1);
                for recommendation in &page.recommendations {
                    if !self.scope.contains_resource(&recommendation.resource) {
                        return self.failure_proposal(
                            EvidenceState::Tampered,
                            FailureClass::InvalidResponse,
                            None,
                            None,
                            "resource-not-allowlisted",
                            provenance,
                            pages_read,
                        );
                    }
                    if !recommendation_digests.insert(recommendation.digest().clone()) {
                        return self.failure_proposal(
                            EvidenceState::Tampered,
                            FailureClass::InvalidResponse,
                            None,
                            None,
                            "duplicate-recommendation",
                            provenance,
                            pages_read,
                        );
                    }
                    if !self
                        .scope
                        .recommendation_window()
                        .contains(recommendation.observed_at)
                    {
                        return self.failure_proposal(
                            EvidenceState::Stale,
                            FailureClass::Stale,
                            None,
                            None,
                            "recommendation-outside-window",
                            provenance,
                            pages_read,
                        );
                    }
                    let age = now.signed_duration_since(recommendation.observed_at);
                    if age < Duration::zero()
                        || age.num_seconds() > self.scope.max_recommendation_age_seconds()
                    {
                        return self.failure_proposal(
                            EvidenceState::Stale,
                            FailureClass::Stale,
                            None,
                            None,
                            "recommendation-freshness-fence",
                            provenance,
                            pages_read,
                        );
                    }
                    recommendations.push(recommendation.clone());
                    if recommendations.len() > MAX_RECOMMENDATIONS {
                        return self.failure_proposal(
                            EvidenceState::Partial,
                            FailureClass::Partial,
                            None,
                            None,
                            "recommendation-bound-exceeded",
                            provenance,
                            pages_read,
                        );
                    }
                }
                match page.next_page {
                    Some(_next) if kind_pages >= MAX_RESULT_PAGES => {
                        return self.failure_proposal(
                            EvidenceState::Partial,
                            FailureClass::Partial,
                            None,
                            None,
                            "pagination-bound-exceeded",
                            provenance,
                            pages_read,
                        );
                    }
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
        }
        let status = aggregate_status(&recommendations);
        let evidence = AwsComputeOptimizerEvidence::new(
            &self.scope,
            recommendations,
            pages_read,
            status,
            EvidenceState::Complete,
            provenance,
            None,
        )?;
        Ok(AwsComputeOptimizerProposal::new(
            &self.scope,
            self.registration.registration_digest().clone(),
            evidence,
            now,
        ))
    }

    pub fn record_observation_receipt(
        &self,
        proposal: &AwsComputeOptimizerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsComputeOptimizerObservationReceipt, AwsComputeOptimizerServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(AwsComputeOptimizerServiceError::ScopeMismatch);
        }
        if idempotency_key.as_ref().is_empty()
            || idempotency_key.as_ref().len() > crate::model::MAX_IDENTIFIER_BYTES
        {
            return Err(AwsComputeOptimizerServiceError::InvalidIdempotencyKey);
        }
        Ok(AwsComputeOptimizerObservationReceipt::new(
            Digest::from_text(idempotency_key.as_ref()),
            proposal.proposal_digest.clone(),
            proposal.scope_digest.clone(),
            self.registration.registration_digest().clone(),
            proposal.evidence.provenance,
            false,
        ))
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsComputeOptimizerProposal,
    ) -> Result<AwsComputeOptimizerVerificationReport, AwsComputeOptimizerServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(AwsComputeOptimizerServiceError::ScopeMismatch);
        }
        Ok(AwsComputeOptimizerVerificationReport::from_proposal(
            proposal,
        ))
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        self.registration.revoke()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        self.registration.restore()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<crate::RegistrationTransitionEvidence, AwsComputeOptimizerServiceError> {
        self.registration.reverse()
    }

    fn ensure_active(&self) -> Result<(), AwsComputeOptimizerServiceError> {
        if !self.registration.is_active() {
            return Err(AwsComputeOptimizerServiceError::RegistrationRevoked);
        }
        if self
            .secret_reference
            .validate_for_scope(&self.scope)
            .is_err()
        {
            return Err(AwsComputeOptimizerServiceError::RegistrationRevoked);
        }
        self.registration.validate()
    }

    fn proposal_for_provider_error(
        &self,
        error: AwsComputeOptimizerProviderError,
        pages_read: u16,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        let (state, class, status_code, retry_after) = match &error {
            AwsComputeOptimizerProviderError::Transport(transport_error) => {
                let class = match transport_error {
                    AwsComputeOptimizerTransportError::BadRequest => FailureClass::BadRequest,
                    AwsComputeOptimizerTransportError::Unauthorized => FailureClass::Unauthorized,
                    AwsComputeOptimizerTransportError::Forbidden => FailureClass::Forbidden,
                    AwsComputeOptimizerTransportError::NotFound => FailureClass::NotFound,
                    AwsComputeOptimizerTransportError::Conflict => FailureClass::Conflict,
                    AwsComputeOptimizerTransportError::RateLimited { .. } => {
                        FailureClass::Throttled
                    }
                    AwsComputeOptimizerTransportError::ServerError { .. } => {
                        FailureClass::ServerError
                    }
                    AwsComputeOptimizerTransportError::Timeout => FailureClass::Timeout,
                    AwsComputeOptimizerTransportError::AccessLost => FailureClass::AccessLost,
                    AwsComputeOptimizerTransportError::BlockedEnv => FailureClass::BlockedEnv,
                    AwsComputeOptimizerTransportError::InvalidResponse => {
                        FailureClass::InvalidResponse
                    }
                };
                let state = match class {
                    FailureClass::Unauthorized
                    | FailureClass::Forbidden
                    | FailureClass::AccessLost => EvidenceState::AccessLost,
                    FailureClass::NotFound => EvidenceState::ResourceNotFound,
                    FailureClass::Throttled => EvidenceState::Throttled,
                    FailureClass::InvalidResponse => EvidenceState::Tampered,
                    FailureClass::Partial => EvidenceState::Partial,
                    FailureClass::Stale => EvidenceState::Stale,
                    _ => EvidenceState::ProviderUnknown,
                };
                (
                    state,
                    class,
                    transport_error.status_code(),
                    transport_error.retry_after_seconds(),
                )
            }
            AwsComputeOptimizerProviderError::ProviderDrift => (
                EvidenceState::ProviderUnknown,
                FailureClass::Unknown,
                None,
                None,
            ),
            AwsComputeOptimizerProviderError::InvalidResponse
            | AwsComputeOptimizerProviderError::CursorBinding => (
                EvidenceState::Tampered,
                FailureClass::InvalidResponse,
                None,
                None,
            ),
        };
        self.failure_proposal(
            state,
            class,
            status_code,
            retry_after,
            format!("{error:?}"),
            self.provider.provenance(),
            pages_read,
        )
    }

    fn failure_proposal(
        &self,
        state: EvidenceState,
        class: FailureClass,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
        diagnostic: impl AsRef<[u8]>,
        provenance: TransportProvenance,
        pages_read: u16,
    ) -> Result<AwsComputeOptimizerProposal, AwsComputeOptimizerServiceError> {
        let blocked_env = class == FailureClass::BlockedEnv;
        let failure = FailureEvidence::new(
            class,
            status_code,
            retry_after_seconds,
            diagnostic,
            blocked_env,
        );
        let evidence = AwsComputeOptimizerEvidence::new(
            &self.scope,
            Vec::new(),
            pages_read,
            RecommendationStatus::Unknown,
            state,
            provenance,
            Some(failure),
        )?;
        Ok(AwsComputeOptimizerProposal::new(
            &self.scope,
            self.registration.registration_digest().clone(),
            evidence,
            Utc::now(),
        ))
    }
}

fn aggregate_status(
    recommendations: &[crate::ComputeOptimizerRecommendation],
) -> RecommendationStatus {
    if recommendations
        .iter()
        .any(|item| item.status == RecommendationStatus::Underprovisioned)
    {
        RecommendationStatus::Underprovisioned
    } else if recommendations
        .iter()
        .any(|item| item.status == RecommendationStatus::Overprovisioned)
    {
        RecommendationStatus::Overprovisioned
    } else if recommendations
        .iter()
        .any(|item| item.status == RecommendationStatus::NotOptimized)
    {
        RecommendationStatus::NotOptimized
    } else if recommendations
        .iter()
        .any(|item| item.status == RecommendationStatus::NotAvailable)
    {
        RecommendationStatus::NotAvailable
    } else if recommendations.is_empty() {
        RecommendationStatus::Unknown
    } else if recommendations
        .iter()
        .all(|item| item.status == RecommendationStatus::Optimized)
    {
        RecommendationStatus::Optimized
    } else {
        RecommendationStatus::Unknown
    }
}

pub type AwsComputeOptimizerResultProposal = AwsComputeOptimizerProposal;
pub type AwsComputeOptimizerReceipt = AwsComputeOptimizerObservationReceipt;
pub type AwsComputeOptimizerServiceErrorKind = AwsComputeOptimizerServiceError;
