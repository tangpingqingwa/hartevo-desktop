use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    AwsTrustedAdvisorScope, CategorySummary, ConsentScope, Digest, FlaggedResourceDigest,
    MAX_FLAGGED_RESOURCES, MAX_RESULT_PAGES, ModelError, RecommendationStatus, RefreshState,
    SecretReference, TransportProvenance,
};
use crate::provider::{
    AwsTrustedAdvisorOperation, AwsTrustedAdvisorProvider, AwsTrustedAdvisorProviderError,
    AwsTrustedAdvisorTransport, AwsTrustedAdvisorTransportError,
    DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    DescribeTrustedAdvisorCheckRefreshStatusesResponse, DescribeTrustedAdvisorCheckResultRequest,
    DescribeTrustedAdvisorCheckResultResponse, DescribeTrustedAdvisorChecksRequest,
    DescribeTrustedAdvisorChecksResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsTrustedAdvisorServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] AwsTrustedAdvisorProviderError),
    #[error("AWS Trusted Advisor registration is revoked or reversed")]
    RegistrationRevoked,
    #[error("AWS Trusted Advisor registration is invalid or drifted")]
    InvalidRegistration,
    #[error("AWS Trusted Advisor scope does not match the proposal")]
    ScopeMismatch,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorServiceDefinition {
    pub service_id: String,
    pub service_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub operations: Vec<AwsTrustedAdvisorOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub external_writes: bool,
    pub refresh_mutation: bool,
    pub remediation: bool,
    pub connected: bool,
    pub native: bool,
}

impl AwsTrustedAdvisorServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            service_version: "1.0.0".to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            operations: vec![
                AwsTrustedAdvisorOperation::DescribeTrustedAdvisorChecks,
                AwsTrustedAdvisorOperation::DescribeTrustedAdvisorCheckRefreshStatuses,
                AwsTrustedAdvisorOperation::DescribeTrustedAdvisorCheckResult,
                AwsTrustedAdvisorOperation::CompileResultProposal,
                AwsTrustedAdvisorOperation::RecordObservationReceipt,
                AwsTrustedAdvisorOperation::VerifyResultProposal,
                AwsTrustedAdvisorOperation::RevokeRegistration,
                AwsTrustedAdvisorOperation::RestoreRegistration,
            ],
            read_only: true,
            proposal_only: true,
            external_writes: false,
            refresh_mutation: false,
            remediation: false,
            connected: false,
            native: false,
        }
    }

    pub fn validate(&self) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.service_id != SERVICE_ID
            || self.service_version != "1.0.0"
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || !self.read_only
            || !self.proposal_only
            || self.external_writes
            || self.refresh_mutation
            || self.remediation
            || self.connected
            || self.native
        {
            Err(AwsTrustedAdvisorServiceError::InvalidRegistration)
        } else {
            Ok(())
        }
    }
}

impl Default for AwsTrustedAdvisorServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_fields(
            "aws-trusted-advisor-registration-transition/v1",
            &[
                format!("{previous_status:?}"),
                format!("{new_status:?}"),
                registration_digest.as_str().to_owned(),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsTrustedAdvisorRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_api_revision: String,
    provider_digest: Digest,
    scope: AwsTrustedAdvisorScope,
    scope_digest: Digest,
    check_id_digest: Digest,
    category_digest: Digest,
    permission_digest: Digest,
    consent: ConsentScope,
    evidence_policy_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsTrustedAdvisorRegistration {
    pub fn new<T: AwsTrustedAdvisorTransport>(
        scope: AwsTrustedAdvisorScope,
        secret_reference: SecretReference,
        provider: &AwsTrustedAdvisorProvider<T>,
        registration_revision: u64,
    ) -> Result<Self, AwsTrustedAdvisorServiceError> {
        if registration_revision == 0 {
            return Err(AwsTrustedAdvisorServiceError::InvalidRegistration);
        }
        provider.definition().validate()?;
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        let mut registration = Self {
            id: "aws-trusted-advisor-registration".to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.definition().provider_id.clone(),
            provider_revision: provider.definition().provider_revision,
            provider_release: provider.definition().provider_release.clone(),
            provider_api_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.definition().provider_digest.clone(),
            scope_digest: scope.scope_digest().clone(),
            check_id_digest: scope.check_id().digest(),
            category_digest: Digest::from_fields(
                "aws-trusted-advisor-category-binding/v1",
                &[scope.category().as_str().to_owned()],
            ),
            permission_digest: scope.permission_snapshot().permission_digest().clone(),
            consent: scope.consent().clone(),
            evidence_policy_digest: Digest::from_fields(
                "aws-trusted-advisor-evidence-policy/v1",
                &[
                    CONTRACT_VERSION.to_owned(),
                    "bounded_digest_only_v1".to_owned(),
                ],
            ),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-trusted-advisor-registration"),
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
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn check_id_digest(&self) -> &Digest {
        &self.check_id_digest
    }

    #[must_use]
    pub fn category_digest(&self) -> &Digest {
        &self.category_digest
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

    pub fn validate(&self) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.id != "aws-trusted-advisor-registration"
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.provider_api_revision != crate::PROVIDER_API_REVISION
            || self.registration_revision == 0
            || self.scope_digest != *self.scope.scope_digest()
            || self.check_id_digest != self.scope.check_id().digest()
            || self.category_digest
                != Digest::from_fields(
                    "aws-trusted-advisor-category-binding/v1",
                    &[self.scope.category().as_str().to_owned()],
                )
            || self.permission_digest != *self.scope.permission_snapshot().permission_digest()
            || self.consent != *self.scope.consent()
            || self.evidence_policy_digest
                != Digest::from_fields(
                    "aws-trusted-advisor-evidence-policy/v1",
                    &[
                        CONTRACT_VERSION.to_owned(),
                        "bounded_digest_only_v1".to_owned(),
                    ],
                )
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorServiceError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        Ok(())
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsTrustedAdvisorServiceError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsTrustedAdvisorServiceError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsTrustedAdvisorServiceError::RegistrationRevoked);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_revision = self.registration_revision.saturating_add(1);
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-registration/v1",
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
                self.scope_digest.as_str().to_owned(),
                self.check_id_digest.as_str().to_owned(),
                self.category_digest.as_str().to_owned(),
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

impl Serialize for AwsTrustedAdvisorRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsTrustedAdvisorRegistration", 19)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("checkIdDigest", &self.check_id_digest)?;
        state.serialize_field("categoryDigest", &self.category_digest)?;
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

impl fmt::Debug for AwsTrustedAdvisorRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsTrustedAdvisorRegistration")
            .field("id", &self.id)
            .field("provider_id", &self.provider_id)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("scope_digest", &self.scope_digest)
            .field("check_id_digest", &self.check_id_digest)
            .field("category_digest", &self.category_digest)
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    UnsupportedSupportPlan,
    RefreshStale,
    RefreshInProgress,
    RefreshFailed,
    AccessLost,
    Throttled,
    CheckNotFound,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    UnsupportedSupportPlan,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    Timeout,
    AccessLost,
    BlockedEnv,
    InvalidResponse,
    ProviderDrift,
    StaleRefresh,
    PartialResult,
    RefreshInProgress,
    RefreshFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub class: FailureClass,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub diagnostic_digest: Digest,
    pub blocked_env: bool,
}

impl FailureEvidence {
    fn new(
        class: FailureClass,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
        diagnostic: impl AsRef<[u8]>,
        blocked_env: bool,
    ) -> Self {
        Self {
            class,
            status_code,
            retry_after_seconds,
            diagnostic_digest: Digest::from_text(diagnostic),
            blocked_env,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorEvidence {
    pub scope_digest: Digest,
    pub check_id: crate::CheckId,
    pub category: crate::TrustedAdvisorCategory,
    pub definition_digest: Option<Digest>,
    pub refresh_state: Option<RefreshState>,
    pub refresh_timestamp: Option<DateTime<Utc>>,
    pub result_timestamp: Option<DateTime<Utc>>,
    pub status: RecommendationStatus,
    pub summary: CategorySummary,
    pub flagged_resources: Vec<FlaggedResourceDigest>,
    pub pages_read: u16,
    pub result_response_digest: Option<Digest>,
    pub provenance: TransportProvenance,
    pub failure: Option<FailureEvidence>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsTrustedAdvisorEvidence {
    fn new(
        scope: &AwsTrustedAdvisorScope,
        definition_digest: Option<Digest>,
        refresh_state: Option<RefreshState>,
        refresh_timestamp: Option<DateTime<Utc>>,
        result_timestamp: Option<DateTime<Utc>>,
        status: RecommendationStatus,
        summary: CategorySummary,
        flagged_resources: Vec<FlaggedResourceDigest>,
        pages_read: u16,
        result_response_digest: Option<Digest>,
        provenance: TransportProvenance,
        failure: Option<FailureEvidence>,
    ) -> Result<Self, AwsTrustedAdvisorServiceError> {
        if flagged_resources.len() > MAX_FLAGGED_RESOURCES
            || !(0..=MAX_RESULT_PAGES).contains(&pages_read)
        {
            return Err(AwsTrustedAdvisorServiceError::Model(
                ModelError::BoundsExceeded,
            ));
        }
        let mut evidence = Self {
            scope_digest: scope.scope_digest().clone(),
            check_id: scope.check_id().clone(),
            category: scope.category(),
            definition_digest,
            refresh_state,
            refresh_timestamp,
            result_timestamp,
            status,
            summary,
            flagged_resources,
            pages_read,
            result_response_digest,
            provenance,
            failure,
            evidence_digest: Digest::from_text("unsealed-aws-trusted-advisor-evidence"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        evidence.evidence_digest = evidence.calculate_digest();
        Ok(evidence)
    }

    pub fn validate_integrity(
        &self,
        scope: &AwsTrustedAdvisorScope,
    ) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.scope_digest != *scope.scope_digest()
            || self.check_id != *scope.check_id()
            || self.category != scope.category()
            || self.flagged_resources.len() > MAX_FLAGGED_RESOURCES
            || self.pages_read > MAX_RESULT_PAGES
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorServiceError::Model(
                ModelError::DigestMismatch,
            ));
        }
        self.summary.validate()?;
        Ok(())
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        matches!(self.state(), EvidenceState::Complete)
    }

    #[must_use]
    pub fn state(&self) -> EvidenceState {
        self.failure.as_ref().map_or_else(
            || {
                if self.pages_read > 0 {
                    EvidenceState::Complete
                } else {
                    EvidenceState::Partial
                }
            },
            |failure| match failure.class {
                FailureClass::UnsupportedSupportPlan => EvidenceState::UnsupportedSupportPlan,
                FailureClass::StaleRefresh => EvidenceState::RefreshStale,
                FailureClass::RefreshInProgress => EvidenceState::RefreshInProgress,
                FailureClass::RefreshFailed => EvidenceState::RefreshFailed,
                FailureClass::PartialResult => EvidenceState::Partial,
                FailureClass::Unauthorized | FailureClass::Forbidden | FailureClass::AccessLost => {
                    EvidenceState::AccessLost
                }
                FailureClass::Throttled => EvidenceState::Throttled,
                FailureClass::NotFound => EvidenceState::CheckNotFound,
                FailureClass::InvalidResponse => EvidenceState::Tampered,
                FailureClass::BlockedEnv
                | FailureClass::BadRequest
                | FailureClass::Conflict
                | FailureClass::ServerError
                | FailureClass::Timeout
                | FailureClass::ProviderDrift => EvidenceState::ProviderUnknown,
            },
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-evidence/v1",
            &[
                self.scope_digest.as_str().to_owned(),
                self.check_id.digest().as_str().to_owned(),
                self.category.as_str().to_owned(),
                self.definition_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                self.refresh_state
                    .map_or_else(String::new, |state| format!("{state:?}")),
                self.refresh_timestamp
                    .map_or_else(String::new, |value| value.to_rfc3339()),
                self.result_timestamp
                    .map_or_else(String::new, |value| value.to_rfc3339()),
                format!("{:?}", self.status),
                self.summary.digest().as_str().to_owned(),
                self.flagged_resources
                    .iter()
                    .map(FlaggedResourceDigest::digest)
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
                self.pages_read.to_string(),
                self.result_response_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                self.provenance.as_str().to_owned(),
                self.failure.as_ref().map_or_else(String::new, |failure| {
                    failure.diagnostic_digest.as_str().to_owned()
                }),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::ProjectBinding,
    pub mission: crate::MissionBinding,
    pub work_product: crate::WorkProductBinding,
    pub evidence: AwsTrustedAdvisorEvidence,
    pub proposal_digest: Digest,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl AwsTrustedAdvisorProposal {
    fn new(
        scope: &AwsTrustedAdvisorScope,
        registration: &AwsTrustedAdvisorRegistration,
        evidence: AwsTrustedAdvisorEvidence,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.scope_digest().clone(),
            project: scope.project().clone(),
            mission: scope.mission().clone(),
            work_product: scope.work_product().clone(),
            evidence,
            proposal_digest: Digest::from_text("unsealed-aws-trusted-advisor-proposal"),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(
        &self,
        scope: &AwsTrustedAdvisorScope,
    ) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != *scope.scope_digest()
            || self.project.digest() != scope.project().digest()
            || self.mission.digest() != scope.mission().digest()
            || self.work_product.digest() != scope.work_product().digest()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.validate_integrity(scope).is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsTrustedAdvisorServiceError::ScopeMismatch);
        }
        Ok(())
    }

    #[must_use]
    pub fn state(&self) -> EvidenceState {
        self.evidence.state()
    }

    #[must_use]
    pub fn review_eligible(&self) -> bool {
        self.evidence.review_eligible()
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-proposal/v1",
            &[
                self.service_id.clone(),
                self.consumer_id.clone(),
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.evidence.evidence_digest.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorObservationReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub receipt_digest: Digest,
}

impl AwsTrustedAdvisorObservationReceipt {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsTrustedAdvisorProposal,
        replayed: bool,
    ) -> Self {
        let mut receipt = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            receipt_digest: Digest::from_text("unsealed-aws-trusted-advisor-receipt"),
        };
        receipt.receipt_digest = receipt.calculate_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.receipt_digest != self.calculate_digest()
        {
            Err(AwsTrustedAdvisorServiceError::Model(
                ModelError::DigestMismatch,
            ))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn as_replayed(&self) -> Self {
        let mut replayed = self.clone();
        replayed.replayed = true;
        replayed.receipt_digest = replayed.calculate_digest();
        replayed
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-trusted-advisor-observation-receipt/v1",
            &[
                self.idempotency_key_digest.as_str().to_owned(),
                self.proposal_digest.as_str().to_owned(),
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                format!("{:?}", self.state),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    NeedsMoreEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsTrustedAdvisorVerificationReport {
    pub proposal_digest: Digest,
    pub verification_state: VerificationState,
    pub valid: bool,
    pub evidence_state: EvidenceState,
    pub verification_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
}

impl AwsTrustedAdvisorVerificationReport {
    fn new(proposal: &AwsTrustedAdvisorProposal) -> Self {
        let verification_state = if proposal.review_eligible() {
            VerificationState::Verified
        } else {
            VerificationState::NeedsMoreEvidence
        };
        let valid = matches!(verification_state, VerificationState::Verified);
        let verification_digest = Digest::from_fields(
            "aws-trusted-advisor-verification/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                format!("{verification_state:?}"),
                format!("{valid}"),
            ],
        );
        Self {
            proposal_digest: proposal.proposal_digest.clone(),
            verification_state,
            valid,
            evidence_state: proposal.state(),
            verification_digest,
            connected: false,
            native: false,
            outcome_adopted: false,
        }
    }
}

pub struct AwsTrustedAdvisorService<T> {
    scope: AwsTrustedAdvisorScope,
    secret_reference: SecretReference,
    provider: AwsTrustedAdvisorProvider<T>,
    registration: AwsTrustedAdvisorRegistration,
    definition: AwsTrustedAdvisorServiceDefinition,
}

impl<T: AwsTrustedAdvisorTransport> fmt::Debug for AwsTrustedAdvisorService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsTrustedAdvisorService")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsTrustedAdvisorTransport> AwsTrustedAdvisorService<T> {
    pub fn new(
        scope: AwsTrustedAdvisorScope,
        secret_reference: SecretReference,
        provider: AwsTrustedAdvisorProvider<T>,
    ) -> Result<Self, AwsTrustedAdvisorServiceError> {
        scope.validate()?;
        secret_reference.validate_for_scope(&scope)?;
        let definition = AwsTrustedAdvisorServiceDefinition::new();
        definition.validate()?;
        let registration = AwsTrustedAdvisorRegistration::new(
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
    pub fn scope(&self) -> &AwsTrustedAdvisorScope {
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
    pub fn provider(&self) -> &AwsTrustedAdvisorProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AwsTrustedAdvisorProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &AwsTrustedAdvisorRegistration {
        &self.registration
    }

    #[must_use]
    pub fn definition(&self) -> &AwsTrustedAdvisorServiceDefinition {
        &self.definition
    }

    pub fn read_check_definitions(
        &mut self,
    ) -> Result<DescribeTrustedAdvisorChecksResponse, AwsTrustedAdvisorServiceError> {
        let request = DescribeTrustedAdvisorChecksRequest::for_scope(&self.scope)?;
        Ok(self.provider.describe_trusted_advisor_checks(&request)?)
    }

    pub fn read_refresh_status(
        &mut self,
    ) -> Result<DescribeTrustedAdvisorCheckRefreshStatusesResponse, AwsTrustedAdvisorServiceError>
    {
        let request = DescribeTrustedAdvisorCheckRefreshStatusesRequest::for_scope(&self.scope)?;
        Ok(self
            .provider
            .describe_trusted_advisor_check_refresh_statuses(&request)?)
    }

    pub fn read_result(
        &mut self,
        cursor: Option<crate::PageCursor>,
    ) -> Result<DescribeTrustedAdvisorCheckResultResponse, AwsTrustedAdvisorServiceError> {
        let request = DescribeTrustedAdvisorCheckResultRequest::for_scope(&self.scope, cursor)?;
        Ok(self
            .provider
            .describe_trusted_advisor_check_result(&request)?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AwsTrustedAdvisorProposal, AwsTrustedAdvisorServiceError> {
        self.compile_proposal_at(Utc::now())
    }

    pub fn propose(&mut self) -> Result<AwsTrustedAdvisorProposal, AwsTrustedAdvisorServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_at(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<AwsTrustedAdvisorProposal, AwsTrustedAdvisorServiceError> {
        self.ensure_active()?;
        self.secret_reference.validate_for_scope(&self.scope)?;
        let provenance = self.provider.provenance();
        if !self.scope.support_plan().is_eligible() {
            return self.failure_proposal(
                EvidenceState::UnsupportedSupportPlan,
                FailureClass::UnsupportedSupportPlan,
                None,
                None,
                "support-plan-not-eligible",
                provenance,
            );
        }

        let checks_request = DescribeTrustedAdvisorChecksRequest::for_scope(&self.scope)?;
        let checks = match self
            .provider
            .describe_trusted_advisor_checks(&checks_request)
        {
            Ok(response) => response,
            Err(error) => return self.proposal_for_provider_error(error),
        };
        let Some(definition) = checks
            .definitions
            .iter()
            .find(|definition| definition.check_id == *self.scope.check_id())
        else {
            return self.failure_proposal(
                EvidenceState::CheckNotFound,
                FailureClass::NotFound,
                Some(404),
                None,
                "check-id-not-found",
                provenance,
            );
        };
        if definition.category != self.scope.category() {
            return self.failure_proposal(
                EvidenceState::Tampered,
                FailureClass::InvalidResponse,
                None,
                None,
                "check-category-drift",
                provenance,
            );
        }

        let refresh_request =
            DescribeTrustedAdvisorCheckRefreshStatusesRequest::for_scope(&self.scope)?;
        let refresh = match self
            .provider
            .describe_trusted_advisor_check_refresh_statuses(&refresh_request)
        {
            Ok(response) => response,
            Err(error) => return self.proposal_for_provider_error(error),
        };
        let refresh_status = &refresh.refresh_status;
        if !matches!(refresh_status.state, RefreshState::Complete) {
            let (state, class) = match refresh_status.state {
                RefreshState::Enqueued | RefreshState::InProgress => (
                    EvidenceState::RefreshInProgress,
                    FailureClass::RefreshInProgress,
                ),
                RefreshState::Failed => (EvidenceState::RefreshFailed, FailureClass::RefreshFailed),
                RefreshState::NotRunning | RefreshState::Unknown => {
                    (EvidenceState::RefreshStale, FailureClass::StaleRefresh)
                }
                RefreshState::Complete => unreachable!(),
            };
            return self.failure_proposal(
                state,
                class,
                None,
                None,
                "refresh-not-complete",
                provenance,
            );
        }
        let Some(refresh_timestamp) = refresh_status.last_refresh_at else {
            return self.failure_proposal(
                EvidenceState::RefreshStale,
                FailureClass::StaleRefresh,
                None,
                None,
                "refresh-timestamp-missing",
                provenance,
            );
        };
        if !is_fresh(refresh_timestamp, now, self.scope.max_refresh_age_seconds()) {
            return self.failure_proposal(
                EvidenceState::RefreshStale,
                FailureClass::StaleRefresh,
                None,
                None,
                "refresh-stale",
                provenance,
            );
        }

        let mut cursor = None;
        let mut pages_read: u16 = 0;
        let mut flagged_resources = Vec::new();
        let mut summary = None;
        let mut status = RecommendationStatus::Unknown;
        let mut result_timestamp = None;
        let mut result_digests = Vec::new();
        loop {
            let result_request =
                DescribeTrustedAdvisorCheckResultRequest::for_scope(&self.scope, cursor.clone())?;
            let page = match self
                .provider
                .describe_trusted_advisor_check_result(&result_request)
            {
                Ok(response) => response,
                Err(error) => return self.proposal_for_provider_error(error),
            };
            pages_read = pages_read.saturating_add(1);
            let result = &page.result;
            if summary.is_none() {
                summary = Some(result.summary.clone());
                status = result.status;
                result_timestamp = Some(result.result_timestamp);
            } else if summary.as_ref() != Some(&result.summary)
                || status != result.status
                || result_timestamp != Some(result.result_timestamp)
            {
                return self.failure_proposal(
                    EvidenceState::Tampered,
                    FailureClass::InvalidResponse,
                    None,
                    None,
                    "result-page-transition-drift",
                    provenance,
                );
            }
            flagged_resources.extend(result.flagged_resources.iter().cloned());
            if flagged_resources.len() > MAX_FLAGGED_RESOURCES {
                return self.failure_proposal(
                    EvidenceState::Partial,
                    FailureClass::PartialResult,
                    None,
                    None,
                    "flagged-resource-bound-exceeded",
                    provenance,
                );
            }
            result_digests.push(page.response_digest.clone());
            match &result.next_page {
                Some(next_page) if pages_read >= MAX_RESULT_PAGES => {
                    return self.failure_proposal(
                        EvidenceState::Partial,
                        FailureClass::PartialResult,
                        None,
                        None,
                        "result-page-bound-exceeded",
                        provenance,
                    );
                }
                Some(next_page) => cursor = Some(next_page.clone()),
                None => break,
            }
        }
        let Some(result_timestamp) = result_timestamp else {
            return self.failure_proposal(
                EvidenceState::Partial,
                FailureClass::PartialResult,
                None,
                None,
                "result-timestamp-missing",
                provenance,
            );
        };
        if !is_fresh(result_timestamp, now, self.scope.max_refresh_age_seconds()) {
            return self.failure_proposal(
                EvidenceState::RefreshStale,
                FailureClass::StaleRefresh,
                None,
                None,
                "result-stale",
                provenance,
            );
        }
        let evidence = AwsTrustedAdvisorEvidence::new(
            &self.scope,
            Some(definition.definition_digest.clone()),
            Some(refresh_status.state),
            Some(refresh_timestamp),
            Some(result_timestamp),
            status,
            summary.unwrap_or_else(|| CategorySummary::empty(self.scope.category())),
            flagged_resources,
            pages_read,
            Some(Digest::from_fields(
                "aws-trusted-advisor-result-pages/v1",
                &result_digests
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>(),
            )),
            provenance,
            None,
        )?;
        Ok(AwsTrustedAdvisorProposal::new(
            &self.scope,
            &self.registration,
            evidence,
        ))
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        self.registration.revoke()
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        self.registration.restore()
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, AwsTrustedAdvisorServiceError> {
        self.registration.reverse()
    }

    pub fn record_observation_receipt(
        &self,
        proposal: &AwsTrustedAdvisorProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsTrustedAdvisorObservationReceipt, AwsTrustedAdvisorServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(AwsTrustedAdvisorServiceError::ScopeMismatch);
        }
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsTrustedAdvisorServiceError::InvalidIdempotencyKey);
        }
        Ok(AwsTrustedAdvisorObservationReceipt::new(
            Digest::from_text(idempotency_key),
            proposal,
            false,
        ))
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsTrustedAdvisorProposal,
    ) -> Result<AwsTrustedAdvisorVerificationReport, AwsTrustedAdvisorServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.registration_digest != *self.registration.registration_digest() {
            return Err(AwsTrustedAdvisorServiceError::ScopeMismatch);
        }
        Ok(AwsTrustedAdvisorVerificationReport::new(proposal))
    }

    fn ensure_active(&self) -> Result<(), AwsTrustedAdvisorServiceError> {
        if self.registration.is_active() {
            self.registration.validate()?;
            Ok(())
        } else {
            Err(AwsTrustedAdvisorServiceError::RegistrationRevoked)
        }
    }

    fn proposal_for_provider_error(
        &self,
        error: AwsTrustedAdvisorProviderError,
    ) -> Result<AwsTrustedAdvisorProposal, AwsTrustedAdvisorServiceError> {
        let (state, class, status_code, retry_after, blocked_env) = match &error {
            AwsTrustedAdvisorProviderError::Transport(transport_error) => {
                let class = match transport_error {
                    AwsTrustedAdvisorTransportError::BadRequest => FailureClass::BadRequest,
                    AwsTrustedAdvisorTransportError::Unauthorized => FailureClass::Unauthorized,
                    AwsTrustedAdvisorTransportError::Forbidden => FailureClass::Forbidden,
                    AwsTrustedAdvisorTransportError::NotFound => FailureClass::NotFound,
                    AwsTrustedAdvisorTransportError::Conflict => FailureClass::Conflict,
                    AwsTrustedAdvisorTransportError::RateLimited { .. } => FailureClass::Throttled,
                    AwsTrustedAdvisorTransportError::ServerError { .. } => {
                        FailureClass::ServerError
                    }
                    AwsTrustedAdvisorTransportError::Timeout => FailureClass::Timeout,
                    AwsTrustedAdvisorTransportError::AccessLost => FailureClass::AccessLost,
                    AwsTrustedAdvisorTransportError::BlockedEnv => FailureClass::BlockedEnv,
                    AwsTrustedAdvisorTransportError::InvalidResponse => {
                        FailureClass::InvalidResponse
                    }
                };
                let state = match class {
                    FailureClass::Unauthorized
                    | FailureClass::Forbidden
                    | FailureClass::AccessLost => EvidenceState::AccessLost,
                    FailureClass::NotFound => EvidenceState::CheckNotFound,
                    FailureClass::Throttled => EvidenceState::Throttled,
                    FailureClass::InvalidResponse => EvidenceState::Tampered,
                    _ => EvidenceState::ProviderUnknown,
                };
                (
                    state,
                    class,
                    transport_error.status_code(),
                    transport_error.retry_after_seconds(),
                    transport_error.is_blocked_env(),
                )
            }
            AwsTrustedAdvisorProviderError::ProviderDrift => (
                EvidenceState::ProviderUnknown,
                FailureClass::ProviderDrift,
                None,
                None,
                false,
            ),
            AwsTrustedAdvisorProviderError::InvalidResponse => (
                EvidenceState::Tampered,
                FailureClass::InvalidResponse,
                None,
                None,
                false,
            ),
        };
        self.failure_proposal(
            state,
            class,
            status_code,
            retry_after,
            format!("{error:?}").as_bytes(),
            self.provider.provenance(),
        )
        .map(|mut proposal| {
            if let Some(failure) = proposal.evidence.failure.as_mut() {
                failure.blocked_env = blocked_env;
                proposal.evidence.evidence_digest = proposal.evidence.calculate_digest();
                proposal.proposal_digest = proposal.calculate_digest();
            }
            proposal
        })
    }

    fn failure_proposal(
        &self,
        state: EvidenceState,
        class: FailureClass,
        status_code: Option<u16>,
        retry_after_seconds: Option<u64>,
        diagnostic: impl AsRef<[u8]>,
        provenance: TransportProvenance,
    ) -> Result<AwsTrustedAdvisorProposal, AwsTrustedAdvisorServiceError> {
        let summary = CategorySummary::empty(self.scope.category());
        let failure = FailureEvidence::new(
            class,
            status_code,
            retry_after_seconds,
            diagnostic,
            matches!(class, FailureClass::BlockedEnv),
        );
        let evidence = AwsTrustedAdvisorEvidence::new(
            &self.scope,
            None,
            None,
            None,
            None,
            RecommendationStatus::Unknown,
            summary,
            Vec::new(),
            0,
            None,
            provenance,
            Some(failure),
        )?;
        let mut proposal =
            AwsTrustedAdvisorProposal::new(&self.scope, &self.registration, evidence);
        if proposal.state() != state {
            let class = match state {
                EvidenceState::RefreshInProgress => FailureClass::RefreshInProgress,
                EvidenceState::RefreshFailed => FailureClass::RefreshFailed,
                EvidenceState::RefreshStale => FailureClass::StaleRefresh,
                EvidenceState::Partial => FailureClass::PartialResult,
                _ => class,
            };
            proposal.evidence.failure = Some(FailureEvidence::new(
                class,
                status_code,
                retry_after_seconds,
                "state-adjusted-failure",
                matches!(class, FailureClass::BlockedEnv),
            ));
            proposal.evidence.evidence_digest = proposal.evidence.calculate_digest();
            proposal.proposal_digest = proposal.calculate_digest();
        }
        Ok(proposal)
    }
}

fn is_fresh(timestamp: DateTime<Utc>, now: DateTime<Utc>, max_age_seconds: i64) -> bool {
    let age = now.signed_duration_since(timestamp);
    age >= Duration::zero() && age <= Duration::seconds(max_age_seconds)
}

pub type AwsTrustedAdvisorRegistrationStatus = RegistrationStatus;
pub type AwsTrustedAdvisorServiceErrorKind = AwsTrustedAdvisorServiceError;
pub type AwsTrustedAdvisorResultProposal = AwsTrustedAdvisorProposal;
pub type AwsTrustedAdvisorReceipt = AwsTrustedAdvisorObservationReceipt;
