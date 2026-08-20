//! Bounded AWS Service Quotas read, proposal, recording, and verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    AWS_SERVICE_QUOTA_CONTRACT_VERSION, AWS_SERVICE_QUOTA_PLUGIN_VERSION,
    AWS_SERVICE_QUOTA_PROVIDER_ID, AWS_SERVICE_QUOTA_PROVIDER_VERSION,
    AWS_SERVICE_QUOTA_SERVICE_ID, contract_digest,
    model::{
        AwsServiceQuotaOperation, AwsServiceQuotaReadRequest, AwsServiceQuotaScope, Digest,
        ModelError, PartialReason, PermissionAction, PermissionFence, ProviderErrorEvidence,
        ProviderId, ProviderRevision, QuotaEvidenceState, QuotaPostureDigest, Revision,
        SecretReference, TransportProvenance,
    },
    provider::{AwsServiceQuotaProvider, AwsServiceQuotaProviderError, AwsServiceQuotaTransport},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error("registration is already active")]
    AlreadyActive,
    #[error("registration is already revoked or reversed")]
    AlreadyRevoked,
    #[error("registration binding drifted: {0}")]
    Drift(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

impl RegistrationState {
    pub const fn active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsServiceQuotaServiceError {
    #[error("AWS Service Quotas model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Service Quotas provider error: {0}")]
    Provider(#[from] AwsServiceQuotaProviderError),
    #[error("AWS Service Quotas registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS Service Quotas registration binding drifted: {0}")]
    RegistrationDrift(String),
    #[error("AWS Service Quotas scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("AWS Service Quotas proposal is stale or tampered")]
    ProposalTampered,
    #[error("AWS Service Quotas record is stale or tampered")]
    RecordTampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaCapabilities {
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub operations: Vec<&'static str>,
    pub permissions: Vec<&'static str>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl AwsServiceQuotaCapabilities {
    pub fn layer_one() -> Self {
        Self {
            service_id: AWS_SERVICE_QUOTA_SERVICE_ID,
            provider_id: AWS_SERVICE_QUOTA_PROVIDER_ID,
            consumer_id: crate::AWS_SERVICE_QUOTA_CONSUMER_ID,
            operations: vec![
                "ListServiceQuotas",
                "GetServiceQuota",
                "GetAWSDefaultServiceQuota",
                "ListRequestedServiceQuotaChangeHistoryByQuota",
            ],
            permissions: vec![
                "servicequotas:ListServiceQuotas",
                "servicequotas:GetServiceQuota",
                "servicequotas:GetAWSDefaultServiceQuota",
                "servicequotas:ListRequestedServiceQuotaChangeHistoryByQuota",
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

/// The static part of a registration is digest-bound. Lifecycle status is
/// intentionally separate so revocation/reversal never rebinds old evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsServiceQuotaRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub provider_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub service_digest: Digest,
    pub quota_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AwsServiceQuotaRegistration {
    pub fn new<T>(
        scope: &AwsServiceQuotaScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsServiceQuotaProvider<T>,
    ) -> Result<Self, AwsServiceQuotaServiceError>
    where
        T: AwsServiceQuotaTransport,
    {
        scope.validate()?;
        let identity = provider.identity();
        let registration_revision = Revision::new(1)?;
        let evidence_digest = evidence_binding_digest(scope, permission, identity);
        let mut registration = Self {
            plugin_version: AWS_SERVICE_QUOTA_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_SERVICE_QUOTA_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: identity.provider_id.clone(),
            provider_version: identity.version.clone(),
            provider_revision: identity.api_revision.clone(),
            provider_digest: identity.provider_digest.clone(),
            api_digest: identity.api_digest.clone(),
            service_digest: service_digest(),
            quota_digest: scope.quota_digest(),
            scope_digest: scope.digest(),
            permission_digest: permission.digest(),
            evidence_digest,
            secret_reference_digest: secret_reference.digest().clone(),
            registration_revision,
            state: RegistrationState::Active,
            registration_digest: Digest::zero(),
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn is_active(&self) -> bool {
        self.state.active()
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-registration/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.provider_revision.as_str().to_owned(),
                self.provider_digest.to_string(),
                self.api_digest.to_string(),
                self.service_digest.to_string(),
                self.quota_digest.to_string(),
                self.scope_digest.to_string(),
                self.permission_digest.to_string(),
                self.evidence_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.registration_revision.get().to_string(),
            ],
        )
    }

    pub fn validate<T>(
        &self,
        scope: &AwsServiceQuotaScope,
        secret_reference: &SecretReference,
        permission: &PermissionFence,
        provider: &AwsServiceQuotaProvider<T>,
    ) -> Result<(), RegistrationError>
    where
        T: AwsServiceQuotaTransport,
    {
        let identity = provider.identity();
        let expected_evidence = evidence_binding_digest(scope, permission, identity);
        let valid = self.plugin_version == AWS_SERVICE_QUOTA_PLUGIN_VERSION
            && self.contract_version == AWS_SERVICE_QUOTA_CONTRACT_VERSION
            && self.contract_digest == contract_digest()
            && self.provider_id.as_str() == AWS_SERVICE_QUOTA_PROVIDER_ID
            && self.provider_version == AWS_SERVICE_QUOTA_PROVIDER_VERSION
            && self.provider_revision == identity.api_revision
            && self.provider_digest == identity.provider_digest
            && self.api_digest == identity.api_digest
            && self.service_digest == service_digest()
            && self.quota_digest == scope.quota_digest()
            && self.scope_digest == scope.digest()
            && self.permission_digest == permission.digest()
            && self.evidence_digest == expected_evidence
            && self.secret_reference_digest == *secret_reference.digest()
            && secret_reference.signing_region() == &scope.region
            && self.registration_digest == self.recomputed_digest();
        if valid {
            Ok(())
        } else {
            Err(RegistrationError::Drift(
                "version/provider/API/service/quota/scope/permission/evidence/secret binding"
                    .to_owned(),
            ))
        }
    }

    pub fn revoke(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<(), RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        self.state = RegistrationState::Reversed;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::AlreadyActive);
        }
        self.state = RegistrationState::Active;
        Ok(())
    }
}

impl Serialize for AwsServiceQuotaRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsServiceQuotaRegistration", 17)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("serviceDigest", &self.service_digest)?;
        state.serialize_field("quotaDigest", &self.quota_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub fn service_digest() -> Digest {
    Digest::from_parts(
        "hartevo-aws-service-quota-service/v1",
        &[
            AWS_SERVICE_QUOTA_SERVICE_ID.to_owned(),
            "read_bounded".to_owned(),
            "propose".to_owned(),
            "record".to_owned(),
            "verify".to_owned(),
        ],
    )
}

pub fn evidence_binding_digest(
    scope: &AwsServiceQuotaScope,
    permission: &PermissionFence,
    provider: &crate::AwsServiceQuotaProviderIdentity,
) -> Digest {
    Digest::from_parts(
        "hartevo-aws-service-quota-evidence-binding/v1",
        &[
            contract_digest().to_string(),
            service_digest().to_string(),
            scope.quota_digest().to_string(),
            scope.digest().to_string(),
            scope.usage_fence_digest().to_string(),
            permission.digest().to_string(),
            provider.provider_digest.to_string(),
            provider.api_digest.to_string(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaEvidence {
    pub state: QuotaEvidenceState,
    pub operation: AwsServiceQuotaOperation,
    pub scope_digest: Digest,
    pub service_digest: Digest,
    pub quota_digest: Digest,
    pub usage_fence_digest: Digest,
    pub permission_digest: Digest,
    pub registration_evidence_digest: Digest,
    pub filter_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub observations: Vec<QuotaPostureDigest>,
    pub quota_posture_digest: Digest,
    pub page_digests: Vec<Digest>,
    pub cursor_digests: Vec<Digest>,
    pub page_count: u16,
    pub request_count: u16,
    pub retry_count: u8,
    pub truncated: bool,
    pub partial_reason: Option<PartialReason>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub observed_at: DateTime<Utc>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub raw_quota_values_retained: bool,
    pub raw_usage_series_retained: bool,
    pub raw_requester_or_support_case_retained: bool,
    pub financial_guarantee: bool,
    pub infrastructure_guarantee: bool,
    pub evidence_digest: Digest,
}

impl AwsServiceQuotaEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        state: QuotaEvidenceState,
        request: &AwsServiceQuotaReadRequest,
        scope: &AwsServiceQuotaScope,
        registration_evidence_digest: Digest,
        provider_digest: Digest,
        api_digest: Digest,
        observations: Vec<QuotaPostureDigest>,
        page_digests: Vec<Digest>,
        cursor_digests: Vec<Digest>,
        page_count: u16,
        request_count: u16,
        retry_count: u8,
        truncated: bool,
        partial_reason: Option<PartialReason>,
        provider_errors: Vec<ProviderErrorEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let quota_posture_digest = posture_digest(&observations);
        let mut evidence = Self {
            state,
            operation: request.operation,
            scope_digest: scope.digest(),
            service_digest: service_digest(),
            quota_digest: scope.quota_digest(),
            usage_fence_digest: scope.usage_fence_digest(),
            permission_digest: scope.permission_digest.clone(),
            registration_evidence_digest,
            filter_digest: request.filter_digest.clone(),
            provider_digest,
            api_digest,
            contract_digest: contract_digest(),
            observations,
            quota_posture_digest,
            page_digests,
            cursor_digests,
            page_count,
            request_count,
            retry_count,
            truncated,
            partial_reason,
            provider_errors,
            provenance,
            observed_at: request.observed_at,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            raw_quota_values_retained: false,
            raw_usage_series_retained: false,
            raw_requester_or_support_case_retained: false,
            financial_guarantee: false,
            infrastructure_guarantee: false,
            evidence_digest: Digest::zero(),
        };
        evidence.evidence_digest = evidence.recomputed_digest();
        evidence
    }

    pub fn validate(&self) -> Result<(), AwsServiceQuotaServiceError> {
        if self.scope_digest.is_zero()
            || self.quota_digest.is_zero()
            || self.usage_fence_digest.is_zero()
            || self.permission_digest.is_zero()
            || self.registration_evidence_digest.is_zero()
            || self.filter_digest.is_zero()
            || self.provider_digest.is_zero()
            || self.api_digest.is_zero()
            || self.contract_digest != contract_digest()
            || self.service_digest != service_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.raw_quota_values_retained
            || self.raw_usage_series_retained
            || self.raw_requester_or_support_case_retained
            || self.financial_guarantee
            || self.infrastructure_guarantee
            || self.evidence_digest != self.recomputed_digest()
        {
            return Err(AwsServiceQuotaServiceError::ProposalTampered);
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        if self.quota_posture_digest != posture_digest(&self.observations) {
            return Err(AwsServiceQuotaServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-evidence/v1",
            &[
                format!("{:?}", self.state),
                self.operation.api_name().to_owned(),
                self.scope_digest.to_string(),
                self.service_digest.to_string(),
                self.quota_digest.to_string(),
                self.usage_fence_digest.to_string(),
                self.permission_digest.to_string(),
                self.registration_evidence_digest.to_string(),
                self.filter_digest.to_string(),
                self.provider_digest.to_string(),
                self.api_digest.to_string(),
                self.contract_digest.to_string(),
                self.quota_posture_digest.to_string(),
                self.page_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.cursor_digests
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.page_count.to_string(),
                self.request_count.to_string(),
                self.retry_count.to_string(),
                self.truncated.to_string(),
                format!("{:?}", self.partial_reason),
                self.provider_errors
                    .iter()
                    .map(|error| error.error_digest.to_string())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.provenance.as_str().to_owned(),
                self.observed_at.to_rfc3339(),
            ],
        )
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

fn posture_digest(observations: &[QuotaPostureDigest]) -> Digest {
    Digest::from_parts(
        "hartevo-aws-service-quota-posture-set/v1",
        &observations
            .iter()
            .map(|observation| observation.posture_digest.to_string())
            .collect::<Vec<_>>(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaReadResult {
    pub evidence: AwsServiceQuotaEvidence,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaProposal {
    pub operation: AwsServiceQuotaOperation,
    pub evidence: AwsServiceQuotaEvidence,
    pub proposed_at: DateTime<Utc>,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopted_outcome: bool,
    pub financial_guarantee: bool,
    pub infrastructure_guarantee: bool,
}

impl AwsServiceQuotaProposal {
    fn new(
        operation: AwsServiceQuotaOperation,
        evidence: AwsServiceQuotaEvidence,
        proposed_at: DateTime<Utc>,
        registration_digest: Digest,
    ) -> Self {
        let mut proposal = Self {
            operation,
            evidence,
            proposed_at,
            registration_digest,
            proposal_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopted_outcome: false,
            financial_guarantee: false,
            infrastructure_guarantee: false,
        };
        proposal.proposal_digest = proposal.recomputed_digest();
        proposal
    }

    pub fn validate(&self) -> Result<(), AwsServiceQuotaServiceError> {
        self.evidence.validate()?;
        if self.operation != self.evidence.operation
            || self.registration_digest.is_zero()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.adopted_outcome
            || self.financial_guarantee
            || self.infrastructure_guarantee
            || self.proposal_digest != self.recomputed_digest()
        {
            return Err(AwsServiceQuotaServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-proposal/v1",
            &[
                self.operation.api_name().to_owned(),
                self.evidence.evidence_digest.to_string(),
                self.proposed_at.to_rfc3339(),
                self.registration_digest.to_string(),
            ],
        )
    }

    pub fn is_review_only(&self) -> bool {
        true
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaRecordReceipt {
    pub recorded: bool,
    pub recorded_at: DateTime<Utc>,
    pub state: QuotaEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub quota_posture_digest: Digest,
    pub retained_observation_count: usize,
    pub raw_quota_values_retained: bool,
    pub raw_usage_series_retained: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub receipt_digest: Digest,
}

impl AwsServiceQuotaRecordReceipt {
    fn new(proposal: &AwsServiceQuotaProposal, recorded_at: DateTime<Utc>) -> Self {
        let mut receipt = Self {
            recorded: true,
            recorded_at,
            state: proposal.evidence.state,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            quota_posture_digest: proposal.evidence.quota_posture_digest.clone(),
            retained_observation_count: proposal.evidence.observations.len(),
            raw_quota_values_retained: false,
            raw_usage_series_retained: false,
            connected: false,
            native: false,
            durable_provider_receipt: false,
            receipt_digest: Digest::zero(),
        };
        receipt.receipt_digest = receipt.recomputed_digest();
        receipt
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "hartevo-aws-service-quota-record/v1",
            &[
                self.recorded.to_string(),
                self.recorded_at.to_rfc3339(),
                format!("{:?}", self.state),
                self.proposal_digest.to_string(),
                self.evidence_digest.to_string(),
                self.registration_digest.to_string(),
                self.scope_digest.to_string(),
                self.quota_posture_digest.to_string(),
                self.retained_observation_count.to_string(),
                self.raw_quota_values_retained.to_string(),
                self.raw_usage_series_retained.to_string(),
                self.connected.to_string(),
                self.native.to_string(),
                self.durable_provider_receipt.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceQuotaVerifiedRecord {
    pub verified: bool,
    pub state: QuotaEvidenceState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub quota_posture_digest: Digest,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
    pub financial_guarantee: bool,
    pub infrastructure_guarantee: bool,
}

#[derive(Clone)]
pub struct AwsServiceQuotaService<T>
where
    T: AwsServiceQuotaTransport,
{
    scope: AwsServiceQuotaScope,
    permission: PermissionFence,
    secret_reference: SecretReference,
    provider: AwsServiceQuotaProvider<T>,
    registration: AwsServiceQuotaRegistration,
}

impl<T> fmt::Debug for AwsServiceQuotaService<T>
where
    T: AwsServiceQuotaTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceQuotaService")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .finish()
    }
}

impl<T> AwsServiceQuotaService<T>
where
    T: AwsServiceQuotaTransport,
{
    pub fn register(
        scope: AwsServiceQuotaScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsServiceQuotaProvider<T>,
    ) -> Result<Self, AwsServiceQuotaServiceError> {
        Self::new(scope, secret_reference, permission, provider)
    }

    pub fn new(
        scope: AwsServiceQuotaScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: AwsServiceQuotaProvider<T>,
    ) -> Result<Self, AwsServiceQuotaServiceError> {
        scope.validate()?;
        if scope.permission_digest != permission.digest() {
            return Err(AwsServiceQuotaServiceError::ScopeMismatch(
                "permission digest".to_owned(),
            ));
        }
        for action in PermissionAction::ALL {
            if !permission.allows(&action) {
                return Err(AwsServiceQuotaServiceError::ScopeMismatch(
                    "all four Service Quotas read permissions are required".to_owned(),
                ));
            }
        }
        if secret_reference.signing_region() != &scope.region {
            return Err(AwsServiceQuotaServiceError::ScopeMismatch(
                "SigV4 secret reference region".to_owned(),
            ));
        }
        if provider.identity().provider_id.as_str() != AWS_SERVICE_QUOTA_PROVIDER_ID {
            return Err(AwsServiceQuotaServiceError::ScopeMismatch(
                "provider id".to_owned(),
            ));
        }
        let registration =
            AwsServiceQuotaRegistration::new(&scope, &secret_reference, &permission, &provider)?;
        Ok(Self {
            scope,
            permission,
            secret_reference,
            provider,
            registration,
        })
    }

    pub fn describe_capabilities() -> AwsServiceQuotaCapabilities {
        AwsServiceQuotaCapabilities::layer_one()
    }

    pub fn scope(&self) -> &AwsServiceQuotaScope {
        &self.scope
    }

    pub fn permission(&self) -> &PermissionFence {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &AwsServiceQuotaProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsServiceQuotaProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsServiceQuotaRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<(), AwsServiceQuotaServiceError> {
        self.registration
            .revoke()
            .map_err(|error| AwsServiceQuotaServiceError::RegistrationDrift(error.to_string()))
    }

    pub fn reverse_registration(&mut self) -> Result<(), AwsServiceQuotaServiceError> {
        self.registration
            .reverse()
            .map_err(|error| AwsServiceQuotaServiceError::RegistrationDrift(error.to_string()))
    }

    pub fn restore_registration(&mut self) -> Result<(), AwsServiceQuotaServiceError> {
        self.registration
            .restore()
            .map_err(|error| AwsServiceQuotaServiceError::RegistrationDrift(error.to_string()))
    }

    pub fn read(
        &mut self,
        request: AwsServiceQuotaReadRequest,
    ) -> Result<AwsServiceQuotaReadResult, AwsServiceQuotaServiceError> {
        self.ensure_active_and_bound()?;
        request.validate_against(&self.scope, &self.permission)?;
        let mut current_request = request.clone();
        let mut observations = BTreeMap::<Digest, QuotaPostureDigest>::new();
        let mut page_digests = Vec::new();
        let mut cursor_digests = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut page_count = 0_u16;
        let mut request_count = 0_u16;
        let mut retry_count = 0_u8;
        let mut consecutive_retries = 0_u8;
        let mut response_bytes = 0_usize;
        let mut partial_reason = None;
        let mut terminal_state = None;
        let mut truncated = false;

        loop {
            if request_count >= request.max_requests {
                partial_reason = Some(PartialReason::RequestBudget);
                truncated = true;
                break;
            }
            request_count = request_count.saturating_add(1);
            match self.provider.read(&current_request) {
                Ok(page) => {
                    if page.page_number != page_count.saturating_add(1) {
                        return Err(AwsServiceQuotaServiceError::Provider(
                            AwsServiceQuotaProviderError::PageBinding,
                        ));
                    }
                    response_bytes = response_bytes.saturating_add(page.response_bytes);
                    if response_bytes > request.max_response_bytes {
                        partial_reason = Some(PartialReason::ResponseTooLarge);
                        truncated = true;
                        break;
                    }
                    page_count = page_count.saturating_add(1);
                    page_digests.push(page.page_digest.clone());
                    for observation in page.observations {
                        let Some(binding) = self.scope.quotas.iter().find(|quota| {
                            quota.identity.digest() == observation.quota_identity_digest
                        }) else {
                            return Err(AwsServiceQuotaServiceError::ScopeMismatch(
                                "provider returned a quota outside the allowlist".to_owned(),
                            ));
                        };
                        if observation.usage_revision != binding.usage_revision {
                            partial_reason = Some(PartialReason::StaleUsage);
                            terminal_state = Some(QuotaEvidenceState::StaleUsage);
                            truncated = true;
                            break;
                        }
                        if let Some(existing) = observations.get(&observation.quota_identity_digest)
                            && existing.posture_digest != observation.posture_digest
                        {
                            partial_reason = Some(PartialReason::ObservationConflict);
                            terminal_state = Some(QuotaEvidenceState::Partial);
                            truncated = true;
                            break;
                        }
                        observations
                            .entry(observation.quota_identity_digest.clone())
                            .or_insert(observation);
                    }
                    if terminal_state.is_some() {
                        break;
                    }
                    consecutive_retries = 0;
                    let Some(cursor) = page.next_cursor else {
                        break;
                    };
                    cursor_digests.push(cursor.token_digest().clone());
                    if !seen_cursors.insert(cursor.token_digest().clone()) {
                        partial_reason = Some(PartialReason::CursorReplay);
                        terminal_state = Some(QuotaEvidenceState::PaginationIncomplete);
                        truncated = true;
                        break;
                    }
                    if page_count >= request.max_pages {
                        partial_reason = Some(PartialReason::PageBudget);
                        terminal_state = Some(QuotaEvidenceState::PaginationIncomplete);
                        truncated = true;
                        break;
                    }
                    current_request = current_request.with_cursor(Some(cursor))?;
                }
                Err(AwsServiceQuotaProviderError::Transport(error)) => {
                    provider_errors.push(error.evidence());
                    if error.retryable() && consecutive_retries < request.max_retries {
                        consecutive_retries = consecutive_retries.saturating_add(1);
                        retry_count = retry_count.saturating_add(1);
                        continue;
                    }
                    terminal_state = Some(if error.is_access_loss() {
                        QuotaEvidenceState::AccessLoss
                    } else {
                        QuotaEvidenceState::ProviderUnknown
                    });
                    break;
                }
                Err(error) => return Err(AwsServiceQuotaServiceError::Provider(error)),
            }
        }

        let expected = if let Some(quota) = &request.quota {
            vec![quota.digest()]
        } else {
            self.scope
                .quotas
                .iter()
                .map(|quota| quota.identity.digest())
                .collect::<Vec<_>>()
        };
        let state = terminal_state.unwrap_or_else(|| {
            if observations.is_empty() {
                QuotaEvidenceState::InsufficientData
            } else if partial_reason.is_some() {
                if matches!(
                    partial_reason,
                    Some(PartialReason::PageBudget | PartialReason::RequestBudget)
                ) {
                    QuotaEvidenceState::PaginationIncomplete
                } else {
                    QuotaEvidenceState::Partial
                }
            } else if expected
                .iter()
                .any(|digest| !observations.contains_key(digest))
            {
                QuotaEvidenceState::Partial
            } else {
                QuotaEvidenceState::Complete
            }
        });
        if matches!(state, QuotaEvidenceState::Partial) && partial_reason.is_none() {
            partial_reason = Some(PartialReason::MissingQuota);
            truncated = true;
        }
        let observations = observations.into_values().collect::<Vec<_>>();
        let evidence = AwsServiceQuotaEvidence::new(
            state,
            &request,
            &self.scope,
            self.registration.evidence_digest.clone(),
            self.provider.identity().provider_digest.clone(),
            self.provider.identity().api_digest.clone(),
            observations,
            page_digests.clone(),
            cursor_digests,
            page_count,
            request_count,
            retry_count,
            truncated,
            partial_reason,
            provider_errors,
            self.provider.identity().provenance,
        );
        Ok(AwsServiceQuotaReadResult {
            evidence,
            page_digests,
        })
    }

    pub fn propose(
        &mut self,
        request: AwsServiceQuotaReadRequest,
        proposed_at: DateTime<Utc>,
    ) -> Result<AwsServiceQuotaProposal, AwsServiceQuotaServiceError> {
        let operation = request.operation;
        let result = self.read(request)?;
        Ok(AwsServiceQuotaProposal::new(
            operation,
            result.evidence,
            proposed_at,
            self.registration.registration_digest.clone(),
        ))
    }

    pub fn record(
        &self,
        proposal: &AwsServiceQuotaProposal,
    ) -> Result<AwsServiceQuotaRecordReceipt, AwsServiceQuotaServiceError> {
        self.record_at(proposal, Utc::now())
    }

    pub fn record_at(
        &self,
        proposal: &AwsServiceQuotaProposal,
        recorded_at: DateTime<Utc>,
    ) -> Result<AwsServiceQuotaRecordReceipt, AwsServiceQuotaServiceError> {
        self.ensure_active_and_bound()?;
        self.verify_proposal(proposal)?;
        Ok(AwsServiceQuotaRecordReceipt::new(proposal, recorded_at))
    }

    pub fn verify(
        &self,
        receipt: &AwsServiceQuotaRecordReceipt,
    ) -> Result<AwsServiceQuotaVerifiedRecord, AwsServiceQuotaServiceError> {
        self.ensure_active_and_bound()?;
        if !receipt.recorded
            || receipt.registration_digest != self.registration.registration_digest
            || receipt.scope_digest != self.scope.digest()
            || receipt.receipt_digest != receipt.recomputed_digest()
            || receipt.raw_quota_values_retained
            || receipt.raw_usage_series_retained
            || receipt.connected
            || receipt.native
            || receipt.durable_provider_receipt
        {
            return Err(AwsServiceQuotaServiceError::RecordTampered);
        }
        let verification_digest = Digest::from_parts(
            "hartevo-aws-service-quota-verified-record/v1",
            &[
                receipt.receipt_digest.to_string(),
                self.registration.registration_digest.to_string(),
                self.scope.digest().to_string(),
                receipt.quota_posture_digest.to_string(),
            ],
        );
        Ok(AwsServiceQuotaVerifiedRecord {
            verified: true,
            state: receipt.state,
            proposal_digest: receipt.proposal_digest.clone(),
            evidence_digest: receipt.evidence_digest.clone(),
            registration_digest: receipt.registration_digest.clone(),
            scope_digest: receipt.scope_digest.clone(),
            quota_posture_digest: receipt.quota_posture_digest.clone(),
            verification_digest,
            connected: false,
            native: false,
            adopted_outcome: false,
            financial_guarantee: false,
            infrastructure_guarantee: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsServiceQuotaProposal,
    ) -> Result<(), AwsServiceQuotaServiceError> {
        self.ensure_active_and_bound()?;
        proposal.validate()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.quota_digest != self.scope.quota_digest()
            || proposal.evidence.usage_fence_digest != self.scope.usage_fence_digest()
            || proposal.evidence.permission_digest != self.permission.digest()
            || proposal.evidence.registration_evidence_digest != self.registration.evidence_digest
            || proposal.evidence.provider_digest != self.provider.identity().provider_digest
            || proposal.evidence.api_digest != self.provider.identity().api_digest
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.service_digest != service_digest()
            || proposal.evidence.filter_digest.is_zero()
        {
            return Err(AwsServiceQuotaServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn consumer(&self) -> Result<crate::MissionAwsServiceQuotaConsumer, crate::ConsumerError> {
        crate::MissionAwsServiceQuotaConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_active_and_bound(&self) -> Result<(), AwsServiceQuotaServiceError> {
        if !self.registration.is_active() {
            return Err(AwsServiceQuotaServiceError::RegistrationRevoked);
        }
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                &self.permission,
                &self.provider,
            )
            .map_err(|error| AwsServiceQuotaServiceError::RegistrationDrift(error.to_string()))
    }
}

pub type AwsServiceQuotaResultService<T> = AwsServiceQuotaService<T>;
pub type AwsServiceQuotaServiceResult<T> = AwsServiceQuotaService<T>;
pub type AwsServiceQuotaServiceErrorAlias = AwsServiceQuotaServiceError;
pub type AwsServiceQuotaRegistrationReceipt = AwsServiceQuotaRegistration;
pub type AwsServiceQuotaTransportProvenance = TransportProvenance;
