//! Typed service, registration, proposal, and verification boundaries.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    CrowdStrikeDetectionEvidence, CrowdStrikeDetectionScope, DetectionEvidenceState, Digest,
    FailureReceipt, FalconDetectionStatus, FalconSeverity, ModelError, PermissionSnapshot,
    ProjectScope, SecretReference, TransportProvenance, WorkProductScope,
};
use crate::provider::{
    CROWDSTRIKE_API_REVISION, CrowdStrikeDetectionRead, CrowdStrikeFalconProviderDefinition,
    CrowdStrikeProviderError, FalconTransportError,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrowdStrikeServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider validation failed: {0}")]
    Provider(#[from] CrowdStrikeProviderError),
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration is not active")]
    RegistrationInactive,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("scope or revision fence does not match")]
    ScopeMismatch,
    #[error("evidence is stale")]
    StaleEvidence,
    #[error("evidence is tampered")]
    TamperedEvidence,
    #[error("recording idempotency key conflicts with an existing record")]
    RecordingConflict,
    #[error("registration transition is not permitted")]
    InvalidTransition,
}

pub type ServiceError = CrowdStrikeServiceError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionReceipt {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionReceipt {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        previous_registration_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        let transition_digest = crate::model::digest_serializable(&(
            previous_status,
            new_status,
            &previous_registration_digest,
            &registration_digest,
        ))?;
        Ok(Self {
            previous_status,
            new_status,
            previous_registration_digest,
            registration_digest,
            transition_digest,
        })
    }
}

/// A version/contract/provider/permission/scope/secret-bound registration.
///
/// The exact scope and secret reference are available only through typed
/// in-process accessors. The serialized registration contains digests rather
/// than host identifiers or any opaque credential handle.
#[derive(Clone, Eq, PartialEq)]
pub struct CrowdStrikeRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    api_revision: String,
    provider_revision: u64,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: CrowdStrikeDetectionScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for CrowdStrikeRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrowdStrikeRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("contract_digest", &self.contract_digest)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field(
                "secret_reference_digest",
                self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for CrowdStrikeRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CrowdStrikeRegistration", 16)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("region", self.secret_reference.region())?;
        state.serialize_field("cloud", &self.secret_reference.cloud())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl CrowdStrikeRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: CrowdStrikeDetectionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &CrowdStrikeFalconProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self, CrowdStrikeServiceError> {
        let id = id.into();
        validate_registration_id(&id)?;
        scope.validate()?;
        secret_reference.validate()?;
        permission_snapshot.validate()?;
        provider
            .validate()
            .map_err(CrowdStrikeServiceError::Provider)?;
        if registration_revision == 0 {
            return Err(CrowdStrikeServiceError::InvalidRegistration);
        }
        let mut value = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            provider_id: provider.provider_id.clone(),
            api_revision: provider.api_revision.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-crowdstrike-registration"),
        };
        value.registration_digest = value.calculate_digest()?;
        value.validate()?;
        Ok(value)
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
    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &CrowdStrikeDetectionScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
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
    pub fn evidence_binding_digest(&self, evidence_digest: &Digest) -> Digest {
        evidence_binding_digest(&self.registration_digest, evidence_digest)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<(), CrowdStrikeServiceError> {
        validate_registration_id(&self.id)?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        let definition = CrowdStrikeFalconProviderDefinition::new()?;
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.api_revision != CROWDSTRIKE_API_REVISION
            || self.provider_revision != definition.provider_revision
            || self.provider_digest != definition.provider_digest
            || self.scope_digest != self.scope.digest()
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_digest()?
        {
            return Err(CrowdStrikeServiceError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionReceipt, CrowdStrikeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(CrowdStrikeServiceError::RegistrationReversed);
        }
        if self.status == RegistrationStatus::Revoked {
            return Err(CrowdStrikeServiceError::InvalidTransition);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionReceipt, CrowdStrikeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(CrowdStrikeServiceError::RegistrationReversed);
        }
        if self.status != RegistrationStatus::Revoked {
            return Err(CrowdStrikeServiceError::InvalidTransition);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionReceipt, CrowdStrikeServiceError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(CrowdStrikeServiceError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(
        &mut self,
        new_status: RegistrationStatus,
    ) -> Result<RegistrationTransitionReceipt, CrowdStrikeServiceError> {
        let previous_status = self.status;
        let previous_digest = self.registration_digest.clone();
        self.status = new_status;
        self.registration_digest = self.calculate_digest()?;
        Ok(RegistrationTransitionReceipt::new(
            previous_status,
            new_status,
            previous_digest,
            self.registration_digest.clone(),
        )?)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&(
            &self.id,
            &self.plugin_version,
            &self.contract_version,
            &self.contract_digest,
            &self.provider_id,
            &self.api_revision,
            self.provider_revision,
            &self.provider_digest,
            &self.permission_snapshot,
            &self.scope_digest,
            self.secret_reference.reference_digest(),
            self.secret_reference.region(),
            self.secret_reference.cloud(),
            self.registration_revision,
            self.status,
        ))
    }
}

pub type CrowdStrikeDetectionRegistration = CrowdStrikeRegistration;

fn validate_registration_id(value: &str) -> Result<(), CrowdStrikeServiceError> {
    if value.is_empty() || value.len() > crate::model::MAX_IDENTIFIER_BYTES || value.trim() != value
    {
        return Err(CrowdStrikeServiceError::InvalidRegistration);
    }
    if value.chars().any(char::is_control) {
        return Err(CrowdStrikeServiceError::InvalidRegistration);
    }
    Ok(())
}

fn evidence_binding_digest(registration_digest: &Digest, evidence_digest: &Digest) -> Digest {
    crate::model::digest_serializable(&serde_json::json!({
        "registrationDigest": registration_digest,
        "evidenceDigest": evidence_digest,
        "binding": "crowdstrike-evidence-registration/v1",
    }))
    .expect("evidence binding is serializable")
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrowdStrikeDetectionResultService;

impl Default for CrowdStrikeDetectionResultService {
    fn default() -> Self {
        Self::new()
    }
}

impl CrowdStrikeDetectionResultService {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CrowdStrikeCapabilityDescription {
        CrowdStrikeCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            operations: vec![
                "QueryDetects".to_owned(),
                "GetDetectSummaries".to_owned(),
                "compile_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_evidence".to_owned(),
                "revoke_registration".to_owned(),
                "restore_registration".to_owned(),
                "reverse_registration".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn provider_definition(&self) -> Result<CrowdStrikeFalconProviderDefinition, ServiceError> {
        Ok(CrowdStrikeFalconProviderDefinition::new()?)
    }

    pub fn register(
        &self,
        id: impl Into<String>,
        scope: CrowdStrikeDetectionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        registration_revision: u64,
    ) -> Result<CrowdStrikeRegistration, ServiceError> {
        let provider = self.provider_definition()?;
        CrowdStrikeRegistration::new(
            id,
            scope,
            secret_reference,
            permission_snapshot,
            &provider,
            registration_revision,
        )
    }

    pub fn evidence_from_read(
        &self,
        registration: &CrowdStrikeRegistration,
        request: &crate::provider::CrowdStrikeDetectionReadRequest,
        read: CrowdStrikeDetectionRead,
    ) -> Result<CrowdStrikeDetectionEvidence, ServiceError> {
        registration.validate()?;
        if !registration.is_active()
            || request.scope_digest != *registration.scope_digest()
            || request.registration_digest != *registration.registration_digest()
            || request.permission_digest != registration.permission_digest()
            || request.provider_revision != registration.provider_revision()
        {
            return Err(CrowdStrikeServiceError::ScopeMismatch);
        }
        let complete = read.query_pages.last().is_some_and(|page| page.complete);
        let detections = read
            .query_pages
            .iter()
            .flat_map(|page| page.detections.iter())
            .collect::<Vec<_>>();
        let state = if !complete {
            DetectionEvidenceState::Partial
        } else if detections.is_empty() {
            DetectionEvidenceState::Empty
        } else {
            DetectionEvidenceState::Present
        };
        let provenance = read
            .query_pages
            .first()
            .map_or(TransportProvenance::BlockedEnv, |page| {
                page.receipt.provenance
            });
        Ok(CrowdStrikeDetectionEvidence::new(
            CONTRACT_VERSION,
            contract_digest(),
            PROVIDER_ID,
            crate::model::Revision::new(registration.provider_revision())?,
            registration.permission_digest(),
            registration.scope_digest().clone(),
            crate::model::Revision::new(request.project_revision)?,
            crate::model::Revision::new(request.mission_revision)?,
            crate::model::Revision::new(request.work_product_revision)?,
            crate::model::Revision::new(request.scope_revision)?,
            state,
            provenance,
            read.query_pages,
            Some(read.summary),
            read.observed_at,
        )?)
    }

    pub fn evidence_from_provider_error(
        &self,
        registration: &CrowdStrikeRegistration,
        _request: &crate::provider::CrowdStrikeDetectionReadRequest,
        provenance: TransportProvenance,
        error: &CrowdStrikeProviderError,
        observed_at: DateTime<Utc>,
    ) -> Result<CrowdStrikeDetectionEvidence, ServiceError> {
        let state = match error {
            CrowdStrikeProviderError::Transport(transport)
                if matches!(
                    transport.failure,
                    crate::provider::FalconTransportFailure::Unauthorized
                        | crate::provider::FalconTransportFailure::AccessDenied
                ) =>
            {
                DetectionEvidenceState::AccessLoss
            }
            CrowdStrikeProviderError::RegistrationInactive => DetectionEvidenceState::Revoked,
            CrowdStrikeProviderError::ScopeMismatch
            | CrowdStrikeProviderError::PermissionMismatch
            | CrowdStrikeProviderError::StaleRequest => DetectionEvidenceState::Stale,
            CrowdStrikeProviderError::TamperedResponse => DetectionEvidenceState::Tampered,
            _ => DetectionEvidenceState::ProviderUnknown,
        };
        let (provider_revision, permission_digest, scope_digest) = (
            crate::model::Revision::new(registration.provider_revision())?,
            registration.permission_digest(),
            registration.scope_digest().clone(),
        );
        Ok(CrowdStrikeDetectionEvidence::new_with_failure(
            CONTRACT_VERSION,
            contract_digest(),
            PROVIDER_ID,
            provider_revision,
            permission_digest,
            scope_digest,
            crate::model::Revision::new(registration.scope().project.revision.get())?,
            crate::model::Revision::new(registration.scope().mission.revision.get())?,
            crate::model::Revision::new(registration.scope().work_product.revision.get())?,
            crate::model::Revision::new(registration.scope().scope_revision.get())?,
            state,
            provenance,
            Vec::new(),
            None,
            observed_at,
            failure_receipt(error, provenance),
        )?)
    }

    pub fn compile_proposal(
        &self,
        registration: &CrowdStrikeRegistration,
        evidence: CrowdStrikeDetectionEvidence,
    ) -> Result<CrowdStrikeDetectionProposal, ServiceError> {
        registration.validate()?;
        evidence
            .validate_integrity()
            .map_err(|_| CrowdStrikeServiceError::TamperedEvidence)?;
        if !registration.is_active() {
            return Err(CrowdStrikeServiceError::RegistrationInactive);
        }
        if evidence.contract_version != CONTRACT_VERSION
            || evidence.contract_digest != contract_digest()
            || evidence.provider_id != PROVIDER_ID
            || evidence.provider_revision.get() != registration.provider_revision()
            || evidence.permission_digest != registration.permission_digest()
            || evidence.scope_digest != *registration.scope_digest()
            || evidence.project_revision != registration.scope().project.revision
            || evidence.mission_revision != registration.scope().mission.revision
            || evidence.work_product_revision != registration.scope().work_product.revision
        {
            return Err(CrowdStrikeServiceError::StaleEvidence);
        }
        CrowdStrikeDetectionProposal::new(registration, evidence)
    }

    pub fn verify_evidence(
        &self,
        registration: &CrowdStrikeRegistration,
        evidence: &CrowdStrikeDetectionEvidence,
    ) -> CrowdStrikeDetectionVerificationReport {
        let mut failures = Vec::new();
        if registration.validate().is_err() {
            failures.push("invalid_registration".to_owned());
        }
        if !registration.is_active() {
            failures.push("registration_revoked".to_owned());
        }
        if evidence.validate_integrity().is_err() {
            failures.push("evidence_tampered".to_owned());
        }
        if evidence.scope_digest != *registration.scope_digest()
            || evidence.provider_revision.get() != registration.provider_revision()
            || evidence.permission_digest != registration.permission_digest()
        {
            failures.push("stale_revision_or_scope".to_owned());
        }
        CrowdStrikeDetectionVerificationReport {
            valid: failures.is_empty(),
            review_eligible: failures.is_empty() && evidence.review_eligible(),
            state: evidence.state,
            failures,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            outcome_adopted: false,
        }
    }
}

fn failure_receipt(
    error: &CrowdStrikeProviderError,
    provenance: TransportProvenance,
) -> Option<FailureReceipt> {
    match error {
        CrowdStrikeProviderError::Transport(transport) => Some(FailureReceipt {
            operation: transport.retry.operation,
            status_code: transport.status_code,
            error_digest: transport.error_digest.clone(),
            retry: transport.retry.clone(),
            rate_limit: transport.rate_limit.clone(),
            provenance,
        }),
        _ => None,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeDetectionProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project_revision: crate::model::Revision,
    pub mission_revision: crate::model::Revision,
    pub work_product_revision: crate::model::Revision,
    pub state: DetectionEvidenceState,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub evidence: CrowdStrikeDetectionEvidence,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl CrowdStrikeDetectionProposal {
    fn new(
        registration: &CrowdStrikeRegistration,
        evidence: CrowdStrikeDetectionEvidence,
    ) -> Result<Self, ServiceError> {
        let mut value = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            project_revision: evidence.project_revision,
            mission_revision: evidence.mission_revision,
            work_product_revision: evidence.work_product_revision,
            state: evidence.state,
            provenance: evidence.provenance,
            evidence_digest: evidence.evidence_digest.clone(),
            evidence_binding_digest: evidence_binding_digest(
                registration.registration_digest(),
                &evidence.evidence_digest,
            ),
            evidence,
            proposal_digest: Digest::from_text("unsealed-crowdstrike-proposal"),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        value.proposal_digest = value.calculate_digest()?;
        value.validate_integrity()?;
        Ok(value)
    }

    fn calculate_digest(&self) -> Result<Digest, ModelError> {
        crate::model::digest_serializable(&serde_json::json!({
            "serviceId": &self.service_id,
            "consumerId": &self.consumer_id,
            "registrationDigest": &self.registration_digest,
            "scopeDigest": &self.scope_digest,
            "projectRevision": self.project_revision,
            "missionRevision": self.mission_revision,
            "workProductRevision": self.work_product_revision,
            "state": self.state,
            "provenance": self.provenance,
            "evidenceDigest": &self.evidence_digest,
            "evidenceBindingDigest": &self.evidence_binding_digest,
            "reviewOnly": self.review_only,
            "connected": self.connected,
            "native": self.native,
            "firstParty": self.first_party,
            "providerReceipt": self.provider_receipt,
            "outcomeAdopted": self.outcome_adopted,
            "workProductAdopted": self.work_product_adopted,
        }))
    }

    pub fn validate_integrity(&self) -> Result<(), ServiceError> {
        self.evidence
            .validate_integrity()
            .map_err(|_| CrowdStrikeServiceError::TamperedEvidence)?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.state != self.evidence.state
            || self.provenance != self.evidence.provenance
            || self.evidence_digest != self.evidence.evidence_digest
            || self.evidence_binding_digest
                != evidence_binding_digest(&self.registration_digest, &self.evidence_digest)
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()?
        {
            return Err(CrowdStrikeServiceError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdStrikeDetectionVerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub state: DetectionEvidenceState,
    pub failures: Vec<String>,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub kernel_authority: bool,
    pub outcome_adopted: bool,
}

pub type VerificationReport = CrowdStrikeDetectionVerificationReport;

#[allow(dead_code)]
fn _typed_scope_names(
    _: Option<ProjectScope>,
    _: Option<WorkProductScope>,
    _: Option<FalconSeverity>,
    _: Option<FalconDetectionStatus>,
    _: Option<FalconTransportError>,
) {
}
