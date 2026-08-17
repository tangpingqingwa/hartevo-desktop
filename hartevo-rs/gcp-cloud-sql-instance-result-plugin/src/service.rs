//! Typed Cloud SQL result service, registration, recording, and verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionGcpCloudSqlInstanceConsumer;
use crate::model::{
    CloudSqlInstanceSnapshot, CloudSqlOperationSnapshot, Digest, EvidenceDigests,
    GcpCloudSqlInstanceScope, GcpCloudSqlResultState, ModelError, PartialReason,
    ProviderErrorEvidence, ProviderProvenance, RegistrationId, Revision, SecretReference,
    result_state_for_operation,
};
use crate::provider::{
    GcpCloudSqlAdminOperation, GcpCloudSqlAdminProvider, GcpCloudSqlAdminProviderDefinition,
    GcpCloudSqlAdminProviderError, GcpCloudSqlAdminTransport, GetInstanceRequest,
    GetOperationRequest, ListInstancesRequest, ProviderDefinitionError, RecordedRequest,
    TransportError,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_state: RegistrationState,
    pub new_state: RegistrationState,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_state: RegistrationState,
        new_state: RegistrationState,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "gcp-cloud-sql-registration-transition/v1",
            &[
                ("previous", format!("{previous_state:?}")),
                ("new", format!("{new_state:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_state,
            new_state,
            registration_digest,
            transition_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] ProviderDefinitionError),
    #[error("registration is already revoked or reversed")]
    Terminal,
    #[error("registration id is invalid")]
    InvalidId,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpCloudSqlInstanceResultServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Provider(#[from] GcpCloudSqlAdminProviderError),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    #[error("Cloud SQL registration is not active")]
    RegistrationRevoked,
    #[error("Cloud SQL SecretReference is revoked")]
    SecretRevoked,
    #[error("scope, provider, or registration binding does not match")]
    ScopeMismatch,
    #[error("proposal or record was tampered with")]
    TamperedEvidence,
    #[error("idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("idempotency key was replayed with a different proposal")]
    ReplayConflict,
    #[error("operation evidence regressed")]
    OperationRegression,
}

pub type GcpCloudSqlServiceError = GcpCloudSqlInstanceResultServiceError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlServiceDefinition {
    pub plugin_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub api_revision: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for GcpCloudSqlServiceDefinition {
    fn default() -> Self {
        Self {
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST)
                .expect("contract digest constant is valid"),
            api_revision: API_REVISION.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

pub type GcpCloudSqlInstanceResultServiceDefinition = GcpCloudSqlServiceDefinition;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GcpCloudSqlInstanceRegistration {
    id: RegistrationId,
    plugin_version: String,
    plugin_version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
    secret_reference_digest: Digest,
    evidence_digest: Digest,
    registration_revision: Revision,
    state: RegistrationState,
    registration_digest: Digest,
}

impl GcpCloudSqlInstanceRegistration {
    pub fn new(
        id: RegistrationId,
        scope: &GcpCloudSqlInstanceScope,
        secret_reference: &SecretReference,
        provider: &GcpCloudSqlAdminProviderDefinition,
        registration_revision: Revision,
    ) -> Result<Self, RegistrationError> {
        scope.validate()?;
        secret_reference.validate(scope)?;
        provider.validate()?;
        if !provider.provenance.connected()
            && !provider.provenance.native()
            && !provider.provenance.first_party()
        {
            let mut registration = Self {
                id,
                plugin_version: PLUGIN_VERSION.to_owned(),
                plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
                contract_version: CONTRACT_VERSION.to_owned(),
                contract_digest: Digest::parse(CONTRACT_DIGEST)
                    .expect("contract digest constant is valid"),
                provider_id: provider.provider_id.clone(),
                provider_version: provider.provider_version.clone(),
                provider_digest: provider.provider_digest.clone(),
                api_digest: provider.api_digest.clone(),
                permission_digest: scope.permission_digest().clone(),
                consent_digest: scope.consent_digest().clone(),
                scope_digest: scope.digest().clone(),
                secret_reference_digest: secret_reference.reference_digest().clone(),
                evidence_digest: Digest::from_text(crate::EVIDENCE_DIGEST_BINDING),
                registration_revision,
                state: RegistrationState::Active,
                registration_digest: Digest::zero(),
            };
            registration.registration_digest = registration.calculate_digest();
            registration.validate(scope, secret_reference, provider)?;
            Ok(registration)
        } else {
            Err(RegistrationError::Model(ModelError::InvalidRegistration))
        }
    }

    pub fn id(&self) -> &RegistrationId {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn status(&self) -> RegistrationState {
        self.state()
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(
        &self,
        scope: &GcpCloudSqlInstanceScope,
        secret_reference: &SecretReference,
        provider: &GcpCloudSqlAdminProviderDefinition,
    ) -> Result<(), RegistrationError> {
        scope.validate()?;
        secret_reference.validate(scope)?;
        provider.validate()?;
        if self.id.as_str().is_empty()
            || self.plugin_version != PLUGIN_VERSION
            || self.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.provider_id != provider.provider_id
            || self.provider_version != provider.provider_version
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.permission_digest != *scope.permission_digest()
            || self.consent_digest != *scope.consent_digest()
            || self.scope_digest != *scope.digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.evidence_digest != Digest::from_text(crate::EVIDENCE_DIGEST_BINDING)
            || self.registration_revision.get() == 0
            || self.registration_digest != self.calculate_digest()
        {
            return Err(RegistrationError::Model(ModelError::InvalidRegistration));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        self.transition(RegistrationState::Revoked)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        self.transition(RegistrationState::Reversed)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if matches!(self.state, RegistrationState::Reversed) {
            return Err(RegistrationError::Terminal);
        }
        let previous_state = self.state;
        self.state = RegistrationState::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    fn transition(
        &mut self,
        new_state: RegistrationState,
    ) -> Result<RegistrationTransitionEvidence, RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::Terminal);
        }
        let previous_state = self.state;
        self.state = new_state;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_state,
            self.state,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-registration/v1",
            &[
                ("id", self.id.digest().as_str().to_owned()),
                ("plugin_version", self.plugin_version.clone()),
                (
                    "plugin_version_digest",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_version", self.provider_version.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("revision", self.registration_revision.get().to_string()),
                ("state", format!("{:?}", self.state)),
            ],
        )
    }
}

impl fmt::Debug for GcpCloudSqlInstanceRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSqlInstanceRegistration")
            .field("id_digest", &self.id.digest())
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_version", &self.provider_version)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("state", &self.state)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for GcpCloudSqlInstanceRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("GcpCloudSqlInstanceRegistration", 19)?;
        state.serialize_field("idDigest", &self.id.digest())?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("pluginVersionDigest", &self.plugin_version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerVersion", &self.provider_version)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("state", &self.state)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlInstanceReadRequest {
    scope_digest: Digest,
    page_size: u16,
    max_pages: u16,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl GcpCloudSqlInstanceReadRequest {
    pub fn new(
        scope: &GcpCloudSqlInstanceScope,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        if page_size == 0
            || page_size > crate::MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > crate::MAX_PAGES
        {
            return Err(ModelError::InvalidBounds);
        }
        if observed_at.timestamp() < 0 {
            return Err(ModelError::InvalidTimestamp);
        }
        let request_digest = Digest::from_parts(
            "gcp-cloud-sql-instance-read-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest().clone(),
            page_size,
            max_pages,
            observed_at,
            request_digest,
        })
    }

    pub fn for_scope(
        scope: &GcpCloudSqlInstanceScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(scope, crate::MAX_PAGE_SIZE, crate::MAX_PAGES, observed_at)
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlInstanceEvidence {
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub state: GcpCloudSqlResultState,
    pub partial_reason: Option<PartialReason>,
    pub instance: Option<CloudSqlInstanceSnapshot>,
    pub operation: Option<CloudSqlOperationSnapshot>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub page_token_digests: Vec<Digest>,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub request_records: Vec<RecordedRequest>,
    pub observed_at: DateTime<Utc>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub redacted: bool,
    pub evidence: EvidenceDigests,
}

impl GcpCloudSqlInstanceEvidence {
    pub fn validate_integrity(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        self.evidence.validate()?;
        if let Some(instance) = &self.instance {
            instance.validate_integrity()?;
        }
        if let Some(operation) = &self.operation {
            operation.validate_integrity()?;
        }
        for digest in [
            &self.request_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
        ] {
            digest.validate()?;
        }
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.redacted
            || self.provenance.connected()
            || self.provenance.native()
            || self.provenance.first_party()
            || self
                .page_token_digests
                .iter()
                .any(|digest| digest.validate().is_err())
            || self.request_records.iter().any(|record| !record.redacted)
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.instance_digest
                != self
                    .instance
                    .as_ref()
                    .map_or_else(Digest::zero, |instance| instance.instance_digest.clone())
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        if self.evidence.evidence_digest != evidence_digest(self) {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeProjection {
    pub id_digest: Digest,
    pub revision: Revision,
}

impl ScopeProjection {
    fn from_binding(id_digest: Digest, revision: Revision) -> Self {
        Self {
            id_digest,
            revision,
        }
    }
}

pub type ProjectProjection = ScopeProjection;
pub type MissionProjection = ScopeProjection;
pub type WorkProductProjection = ScopeProjection;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlInstanceResultProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: GcpCloudSqlResultState,
    pub partial_reason: Option<PartialReason>,
    pub instance: Option<CloudSqlInstanceSnapshot>,
    pub operation: Option<CloudSqlOperationSnapshot>,
    pub evidence: EvidenceDigests,
    pub provider_error: Option<ProviderErrorEvidence>,
    pub request_records: Vec<RecordedRequest>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub review_only: bool,
    pub sql_executed: bool,
    pub availability_claim: bool,
    pub data_integrity_claim: bool,
    pub recoverability_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl GcpCloudSqlInstanceResultProposal {
    pub fn validate_integrity(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        for digest in [
            &self.registration_digest,
            &self.scope_digest,
            &self.request_digest,
        ] {
            digest.validate()?;
        }
        for projection in [&self.project, &self.mission, &self.work_product] {
            projection.id_digest.validate()?;
            if projection.revision.get() == 0 {
                return Err(ModelError::InvalidRevision.into());
            }
        }
        if let Some(instance) = &self.instance {
            instance.validate_integrity()?;
        }
        if let Some(operation) = &self.operation {
            operation.validate_integrity()?;
        }
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.review_only
            || self.sql_executed
            || self.availability_claim
            || self.data_integrity_claim
            || self.recoverability_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.validate().is_err()
            || self.evidence.scope_digest != self.scope_digest
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-instance-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("project", self.project.id_digest.as_str().to_owned()),
                ("project_revision", self.project.revision.get().to_string()),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("mission_revision", self.mission.revision.get().to_string()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product.revision.get().to_string(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "partial_reason",
                    self.partial_reason
                        .as_ref()
                        .map_or_else(String::new, |reason| format!("{reason:?}")),
                ),
                (
                    "instance",
                    self.instance.as_ref().map_or_else(String::new, |instance| {
                        instance.snapshot_digest.as_str().to_owned()
                    }),
                ),
                (
                    "operation",
                    self.operation
                        .as_ref()
                        .map_or_else(String::new, |operation| {
                            operation.snapshot_digest.as_str().to_owned()
                        }),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "provider_error",
                    self.provider_error
                        .as_ref()
                        .map_or_else(String::new, |error| {
                            error.error_category_digest.as_str().to_owned()
                        }),
                ),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    EvidenceDigestMismatch,
    TamperedEvidence,
    AccessLoss,
    PartialEvidence,
    ProviderUnknown,
    ReplayConflict,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub verified: bool,
    pub state: GcpCloudSqlResultState,
    pub failures: Vec<VerificationFailure>,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpCloudSqlLocalRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: GcpCloudSqlResultState,
    pub replayed: bool,
    pub recording_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl GcpCloudSqlLocalRecord {
    pub fn validate_integrity(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.durable_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(GcpCloudSqlInstanceResultServiceError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-cloud-sql-local-record/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub type GcpCloudSqlInstanceRecord = GcpCloudSqlLocalRecord;
pub type LocalRecord = GcpCloudSqlLocalRecord;

pub struct GcpCloudSqlInstanceResultService<T: GcpCloudSqlAdminTransport> {
    scope: GcpCloudSqlInstanceScope,
    secret_reference: SecretReference,
    provider: GcpCloudSqlAdminProvider<T>,
    service_definition: GcpCloudSqlServiceDefinition,
    registration: GcpCloudSqlInstanceRegistration,
    records: BTreeMap<Digest, GcpCloudSqlLocalRecord>,
    last_operation: Option<CloudSqlOperationSnapshot>,
}

impl<T: GcpCloudSqlAdminTransport> fmt::Debug for GcpCloudSqlInstanceResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSqlInstanceResultService")
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl<T: GcpCloudSqlAdminTransport> GcpCloudSqlInstanceResultService<T> {
    pub fn new(
        scope: GcpCloudSqlInstanceScope,
        secret_reference: SecretReference,
        provider: GcpCloudSqlAdminProvider<T>,
    ) -> Result<Self, GcpCloudSqlInstanceResultServiceError> {
        let registration = GcpCloudSqlInstanceRegistration::new(
            RegistrationId::new("gcp-cloud-sql-instance-registration")?,
            &scope,
            &secret_reference,
            provider.definition(),
            Revision::new(1)?,
        )?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition: GcpCloudSqlServiceDefinition::default(),
            registration,
            records: BTreeMap::new(),
            last_operation: None,
        })
    }

    pub fn with_registration(
        scope: GcpCloudSqlInstanceScope,
        secret_reference: SecretReference,
        registration: GcpCloudSqlInstanceRegistration,
        provider: GcpCloudSqlAdminProvider<T>,
    ) -> Result<Self, GcpCloudSqlInstanceResultServiceError> {
        registration.validate(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            service_definition: GcpCloudSqlServiceDefinition::default(),
            registration,
            records: BTreeMap::new(),
            last_operation: None,
        })
    }

    pub fn service_definition(&self) -> &GcpCloudSqlServiceDefinition {
        &self.service_definition
    }

    pub fn describe_capabilities(&self) -> GcpCloudSqlCapabilities {
        GcpCloudSqlCapabilities {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                GcpCloudSqlAdminOperation::InstancesGet.as_str().to_owned(),
                GcpCloudSqlAdminOperation::InstancesList.as_str().to_owned(),
                GcpCloudSqlAdminOperation::OperationsGet.as_str().to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &GcpCloudSqlInstanceScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &GcpCloudSqlAdminProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut GcpCloudSqlAdminProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &GcpCloudSqlInstanceRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut GcpCloudSqlInstanceRegistration {
        &mut self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<GcpCloudSqlInstanceReadRequest, GcpCloudSqlInstanceResultServiceError> {
        Ok(GcpCloudSqlInstanceReadRequest::new(
            &self.scope,
            page_size,
            max_pages,
            observed_at,
        )?)
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<GcpCloudSqlInstanceReadRequest, GcpCloudSqlInstanceResultServiceError> {
        Ok(GcpCloudSqlInstanceReadRequest::for_scope(
            &self.scope,
            observed_at,
        )?)
    }

    pub fn read(
        &mut self,
        request: GcpCloudSqlInstanceReadRequest,
    ) -> Result<GcpCloudSqlInstanceEvidence, GcpCloudSqlInstanceResultServiceError> {
        self.ensure_active()?;
        if request.scope_digest() != self.scope.digest() {
            return Err(GcpCloudSqlInstanceResultServiceError::ScopeMismatch);
        }
        let mut requests = Vec::new();
        let mut page_token_digests = Vec::new();
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut found = false;
        let mut partial_reason = None;
        let mut list_request = ListInstancesRequest::first(&self.scope, request.page_size())?;
        let mut seen_tokens = BTreeSet::<Digest>::new();

        loop {
            list_pages = list_pages.saturating_add(1);
            requests.push(list_request.recorded_request());
            let response = match self.provider.list_instances(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    let state =
                        state_for_provider_error(&error, GcpCloudSqlAdminOperation::InstancesList);
                    return Ok(self.evidence_for(
                        &request,
                        state,
                        partial_reason,
                        None,
                        None,
                        list_pages,
                        list_complete,
                        page_token_digests,
                        Some(provider_error(&error)),
                        requests,
                    ));
                }
            };
            if response
                .instances
                .iter()
                .any(|instance| instance.instance_digest == self.scope.instance_id().digest())
            {
                found = true;
            }
            if let Some(token) = &response.next_page_token {
                page_token_digests.push(token.digest().clone());
                if !seen_tokens.insert(token.digest().clone()) {
                    partial_reason = Some(PartialReason::PageLoop);
                    break;
                }
                if list_pages >= request.max_pages() {
                    partial_reason = Some(PartialReason::PageBudget);
                    break;
                }
                list_request = ListInstancesRequest::next(
                    &self.scope,
                    request.page_size(),
                    list_pages.saturating_add(1),
                    token.clone(),
                )?;
            } else {
                list_complete = true;
                break;
            }
        }

        if !found {
            let state = if list_complete {
                GcpCloudSqlResultState::Absent
            } else {
                GcpCloudSqlResultState::Partial
            };
            return Ok(self.evidence_for(
                &request,
                state,
                partial_reason,
                None,
                None,
                list_pages,
                list_complete,
                page_token_digests,
                None,
                requests,
            ));
        }

        let get_request = GetInstanceRequest::for_scope(&self.scope)?;
        requests.push(get_request.recorded_request());
        let instance_response = match self.provider.get_instance(&get_request) {
            Ok(response) => response,
            Err(error) => {
                let state =
                    state_for_provider_error(&error, GcpCloudSqlAdminOperation::InstancesGet);
                let reason = partial_reason.or_else(|| partial_reason_for_provider(&error));
                return Ok(self.evidence_for(
                    &request,
                    state,
                    reason,
                    None,
                    None,
                    list_pages,
                    list_complete,
                    page_token_digests,
                    Some(provider_error(&error)),
                    requests,
                ));
            }
        };
        let instance = instance_response.instance;
        let operation_request = GetOperationRequest::for_scope(&self.scope)?;
        requests.push(operation_request.recorded_request());
        let operation_response = match self.provider.get_operation(&operation_request) {
            Ok(response) => response,
            Err(error) => {
                let state = if partial_reason.is_some() {
                    GcpCloudSqlResultState::Partial
                } else {
                    state_for_provider_error(&error, GcpCloudSqlAdminOperation::OperationsGet)
                };
                return Ok(self.evidence_for(
                    &request,
                    state,
                    partial_reason.or_else(|| partial_reason_for_provider(&error)),
                    Some(instance),
                    None,
                    list_pages,
                    list_complete,
                    page_token_digests,
                    Some(provider_error(&error)),
                    requests,
                ));
            }
        };
        let operation = operation_response.operation;
        if let Some(previous) = &self.last_operation
            && previous.merge(&operation).is_err()
        {
            return Ok(self.evidence_for(
                &request,
                GcpCloudSqlResultState::Partial,
                Some(PartialReason::OperationDrift),
                Some(instance),
                Some(operation),
                list_pages,
                list_complete,
                page_token_digests,
                None,
                requests,
            ));
        }
        self.last_operation = Some(operation.clone());
        let state = partial_reason.clone().map_or_else(
            || result_state_for_operation(operation.status),
            |_| GcpCloudSqlResultState::Partial,
        );
        Ok(self.evidence_for(
            &request,
            state,
            partial_reason,
            Some(instance),
            Some(operation),
            list_pages,
            list_complete,
            page_token_digests,
            None,
            requests,
        ))
    }

    pub fn propose(
        &mut self,
        request: GcpCloudSqlInstanceReadRequest,
    ) -> Result<GcpCloudSqlInstanceResultProposal, GcpCloudSqlInstanceResultServiceError> {
        let evidence = self.read(request)?;
        Ok(self.proposal_from_evidence(evidence))
    }

    pub fn propose_default(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<GcpCloudSqlInstanceResultProposal, GcpCloudSqlInstanceResultServiceError> {
        self.propose(self.default_request(observed_at)?)
    }

    pub fn record(
        &mut self,
        proposal: &GcpCloudSqlInstanceResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<GcpCloudSqlLocalRecord, GcpCloudSqlInstanceResultServiceError> {
        self.record_at(proposal, idempotency_key, Utc::now())
    }

    pub fn record_at(
        &mut self,
        proposal: &GcpCloudSqlInstanceResultProposal,
        idempotency_key: impl AsRef<str>,
        _recorded_at: DateTime<Utc>,
    ) -> Result<GcpCloudSqlLocalRecord, GcpCloudSqlInstanceResultServiceError> {
        self.ensure_active()?;
        self.verify_proposal(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(GcpCloudSqlInstanceResultServiceError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key.as_bytes());
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(GcpCloudSqlInstanceResultServiceError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.state = GcpCloudSqlResultState::Replay;
            replay.recording_digest = replay.calculate_digest();
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let mut record = GcpCloudSqlLocalRecord {
            idempotency_key_digest: key_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state.clone(),
            replayed: false,
            recording_digest: Digest::zero(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        record.recording_digest = record.calculate_digest();
        record.validate_integrity()?;
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }

    pub fn verify_proposal(
        &self,
        proposal: &GcpCloudSqlInstanceResultProposal,
    ) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        self.ensure_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.scope.digest()
            || proposal.project.id_digest != self.scope.project().id().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.mission.id_digest != self.scope.mission().id().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.work_product.id_digest != self.scope.work_product().id().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
            || proposal.evidence.provider_digest != *self.provider.definition().provider_digest()
            || proposal.evidence.api_digest != *self.registration.api_digest()
            || proposal.evidence.permission_digest != *self.registration.permission_digest()
            || proposal.evidence.consent_digest != *self.registration.consent_digest()
            || proposal.evidence.scope_digest != *self.registration.scope_digest()
        {
            return Err(GcpCloudSqlInstanceResultServiceError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn verify(&self, proposal: &GcpCloudSqlInstanceResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != *self.provider.definition().provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.api_digest != *self.registration.api_digest() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.permission_digest != *self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            GcpCloudSqlResultState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            GcpCloudSqlResultState::Partial => failures.push(VerificationFailure::PartialEvidence),
            GcpCloudSqlResultState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            GcpCloudSqlResultState::ReplayConflict => {
                failures.push(VerificationFailure::ReplayConflict);
            }
            GcpCloudSqlResultState::Revoked => failures.push(VerificationFailure::Revoked),
            GcpCloudSqlResultState::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            _ => {}
        }
        VerificationReport {
            verified: failures.is_empty(),
            state: proposal.state.clone(),
            failures,
            proposal_digest: proposal.proposal_digest.clone(),
        }
    }

    pub fn verify_record(&self, record: &GcpCloudSqlLocalRecord) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if record.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        VerificationReport {
            verified: failures.is_empty(),
            state: record.state.clone(),
            failures,
            proposal_digest: record.proposal_digest.clone(),
        }
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, GcpCloudSqlInstanceResultServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn reverse_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, GcpCloudSqlInstanceResultServiceError> {
        Ok(self.registration.reverse()?)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, GcpCloudSqlInstanceResultServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, GcpCloudSqlInstanceResultServiceError> {
        self.revoke_registration()
    }

    pub fn reverse(
        &mut self,
    ) -> Result<RegistrationTransitionEvidence, GcpCloudSqlInstanceResultServiceError> {
        self.reverse_registration()
    }

    pub fn consumer(
        &self,
    ) -> Result<MissionGcpCloudSqlInstanceConsumer, GcpCloudSqlInstanceResultServiceError> {
        MissionGcpCloudSqlInstanceConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_active(&self) -> Result<(), GcpCloudSqlInstanceResultServiceError> {
        if !self.registration.is_active() {
            Err(GcpCloudSqlInstanceResultServiceError::RegistrationRevoked)
        } else if self.secret_reference.is_revoked() {
            Err(GcpCloudSqlInstanceResultServiceError::SecretRevoked)
        } else {
            Ok(())
        }
    }

    fn proposal_from_evidence(
        &self,
        evidence: GcpCloudSqlInstanceEvidence,
    ) -> GcpCloudSqlInstanceResultProposal {
        let mut proposal = GcpCloudSqlInstanceResultProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.digest().clone(),
            request_digest: evidence.request_digest.clone(),
            project: ScopeProjection::from_binding(
                self.scope.project().id().digest(),
                self.scope.project().revision(),
            ),
            mission: ScopeProjection::from_binding(
                self.scope.mission().id().digest(),
                self.scope.mission().revision(),
            ),
            work_product: ScopeProjection::from_binding(
                self.scope.work_product().id().digest(),
                self.scope.work_product().revision(),
            ),
            state: evidence.state.clone(),
            partial_reason: evidence.partial_reason.clone(),
            instance: evidence.instance.clone(),
            operation: evidence.operation.clone(),
            evidence: evidence.evidence.clone(),
            provider_error: evidence.provider_error.clone(),
            request_records: evidence.request_records.clone(),
            list_pages: evidence.list_pages,
            list_complete: evidence.list_complete,
            provenance: evidence.provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            review_only: true,
            sql_executed: false,
            availability_claim: false,
            data_integrity_claim: false,
            recoverability_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    #[allow(clippy::too_many_arguments)]
    fn evidence_for(
        &self,
        request: &GcpCloudSqlInstanceReadRequest,
        state: GcpCloudSqlResultState,
        partial_reason: Option<PartialReason>,
        instance: Option<CloudSqlInstanceSnapshot>,
        operation: Option<CloudSqlOperationSnapshot>,
        list_pages: u16,
        list_complete: bool,
        page_token_digests: Vec<Digest>,
        provider_error: Option<ProviderErrorEvidence>,
        request_records: Vec<RecordedRequest>,
    ) -> GcpCloudSqlInstanceEvidence {
        let mut digests = EvidenceDigests::new_with_api(
            self.provider.definition().provider_digest.clone(),
            self.provider.definition().api_digest.clone(),
            &self.scope,
            instance.as_ref(),
            operation.as_ref(),
        );
        let mut evidence = GcpCloudSqlInstanceEvidence {
            request_digest: request.request_digest().clone(),
            scope_digest: self.scope.digest().clone(),
            project_digest: self.scope.project().id().digest(),
            mission_digest: self.scope.mission().id().digest(),
            work_product_digest: self.scope.work_product().id().digest(),
            state,
            partial_reason,
            instance,
            operation,
            list_pages,
            list_complete,
            page_token_digests,
            provider_error,
            request_records,
            observed_at: request.observed_at(),
            provenance: self.provider.definition().provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            redacted: true,
            evidence: digests.clone(),
        };
        digests.evidence_digest = evidence_digest(&evidence);
        evidence.evidence = digests;
        evidence
    }
}

fn provider_error(error: &GcpCloudSqlAdminProviderError) -> ProviderErrorEvidence {
    match error {
        GcpCloudSqlAdminProviderError::Transport(error) => error.provider_error_evidence(),
        GcpCloudSqlAdminProviderError::TamperedResponse => ProviderErrorEvidence::new(
            crate::ProviderErrorKind::MalformedResponse,
            None,
            "tampered_response",
        ),
        GcpCloudSqlAdminProviderError::Model(_) | GcpCloudSqlAdminProviderError::ProviderDrift => {
            ProviderErrorEvidence::new(crate::ProviderErrorKind::Unknown, None, "provider_binding")
        }
        GcpCloudSqlAdminProviderError::Definition(_) => ProviderErrorEvidence::new(
            crate::ProviderErrorKind::Unknown,
            None,
            "provider_definition",
        ),
    }
}

fn partial_reason_for_provider(error: &GcpCloudSqlAdminProviderError) -> Option<PartialReason> {
    match error {
        GcpCloudSqlAdminProviderError::Model(ModelError::InvalidResponseBytes) => {
            Some(PartialReason::ResponseCap)
        }
        GcpCloudSqlAdminProviderError::Model(ModelError::DigestMismatch) => {
            Some(PartialReason::SettingsVersionDrift)
        }
        GcpCloudSqlAdminProviderError::Transport(TransportError::Conflict) => {
            Some(PartialReason::Conflict)
        }
        _ => None,
    }
}

fn state_for_provider_error(
    error: &GcpCloudSqlAdminProviderError,
    operation: GcpCloudSqlAdminOperation,
) -> GcpCloudSqlResultState {
    match error {
        GcpCloudSqlAdminProviderError::Transport(TransportError::NotFound)
            if matches!(operation, GcpCloudSqlAdminOperation::InstancesGet) =>
        {
            GcpCloudSqlResultState::Absent
        }
        GcpCloudSqlAdminProviderError::Transport(
            TransportError::Unauthorized | TransportError::Forbidden,
        ) => GcpCloudSqlResultState::AccessLoss,
        GcpCloudSqlAdminProviderError::Transport(TransportError::Conflict)
        | GcpCloudSqlAdminProviderError::Model(
            ModelError::InvalidResponseBytes | ModelError::DigestMismatch,
        ) => GcpCloudSqlResultState::Partial,
        GcpCloudSqlAdminProviderError::TamperedResponse => GcpCloudSqlResultState::Tampered,
        _ => GcpCloudSqlResultState::ProviderUnknown,
    }
}

fn evidence_digest(evidence: &GcpCloudSqlInstanceEvidence) -> Digest {
    Digest::from_parts(
        "gcp-cloud-sql-instance-evidence/v1",
        &[
            ("request", evidence.request_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("project", evidence.project_digest.as_str().to_owned()),
            ("mission", evidence.mission_digest.as_str().to_owned()),
            (
                "work_product",
                evidence.work_product_digest.as_str().to_owned(),
            ),
            ("state", format!("{:?}", evidence.state)),
            (
                "partial_reason",
                evidence
                    .partial_reason
                    .as_ref()
                    .map_or_else(String::new, |reason| format!("{reason:?}")),
            ),
            (
                "instance",
                evidence
                    .instance
                    .as_ref()
                    .map_or_else(String::new, |instance| {
                        instance.snapshot_digest.as_str().to_owned()
                    }),
            ),
            (
                "operation",
                evidence
                    .operation
                    .as_ref()
                    .map_or_else(String::new, |operation| {
                        operation.snapshot_digest.as_str().to_owned()
                    }),
            ),
            ("list_pages", evidence.list_pages.to_string()),
            ("list_complete", evidence.list_complete.to_string()),
            (
                "page_tokens",
                evidence
                    .page_token_digests
                    .iter()
                    .map(Digest::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "provider_error",
                evidence
                    .provider_error
                    .as_ref()
                    .map_or_else(String::new, |error| {
                        error.error_category_digest.as_str().to_owned()
                    }),
            ),
            (
                "requests",
                evidence
                    .request_records
                    .iter()
                    .map(|record| record.request_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("observed_at", evidence.observed_at.to_rfc3339()),
            ("provenance", evidence.provenance.as_str().to_owned()),
        ],
    )
}
