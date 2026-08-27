use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, ser::SerializeStruct};
use thiserror::Error;

use crate::consumer::MissionDigitalOceanAppDeploymentConsumer;
use crate::error::{DigitalOceanAppDeploymentResultError, DigitalOceanTransportError, Result};
use crate::model::{
    AppProjection, ConsentScope, CostReceipt, CostSummary, DeploymentPhase, DeploymentProjection,
    Digest, DigitalOceanAppDeploymentScope, DigitalOceanEvidenceState, EventProjection,
    EvidenceDigests, HealthProjection, MissionProjection, PermissionSnapshot, ProjectProjection,
    RequestReceipt, SecretReference, TransportProvenance, WorkProductProjection, canonical_digest,
    mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    DigitalOceanAppsOperation, DigitalOceanAppsProvider, DigitalOceanAppsProviderDefinition,
    DigitalOceanAppsTransport, GetAppHealthRequest, GetAppRequest, GetDeploymentRequest,
    ListDeploymentsRequest, ListEventsRequest, PageCursor,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, PROVIDER_VERSION,
    SERVICE_ID,
};
use crate::{MAX_PAGE_SIZE, MAX_PAGES};

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
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub registration_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DigitalOceanAppDeploymentRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: DigitalOceanAppDeploymentScope,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for DigitalOceanAppDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanAppDeploymentRegistration")
            .field("id_digest", &Digest::from_text(self.id.as_bytes()))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
            .field("permission_digest", self.permission_snapshot.digest())
            .field("scope_digest", &self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for DigitalOceanAppDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("DigitalOceanAppDeploymentRegistration", 15)?;
        state.serialize_field("idDigest", &Digest::from_text(self.id.as_bytes()))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("consentDigest", self.consent.digest())?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field("secretReference", &self.secret_reference)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

impl DigitalOceanAppDeploymentRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: DigitalOceanAppDeploymentScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &DigitalOceanAppsProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES || registration_revision == 0 {
            return Err(DigitalOceanAppDeploymentResultError::InvalidRegistration);
        }
        let registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest_value(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: provider.provider_revision,
            provider_release: provider.provider_release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_snapshot,
            consent,
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-digitalocean-registration"),
        };
        let mut registration = registration;
        registration.registration_digest = registration.calculate_binding_digest();
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
    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
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
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    #[must_use]
    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
    }
    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }
    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest.clone()
    }
    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }
    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent.digest.clone()
    }
    #[must_use]
    pub fn scope(&self) -> &DigitalOceanAppDeploymentScope {
        &self.scope
    }
    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        self.scope.digest()
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
    #[must_use]
    pub const fn is_reversible() -> bool {
        true
    }
    #[must_use]
    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest_value()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release != PROVIDER_VERSION
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.registration_digest != self.calculate_binding_digest()
        {
            return Err(DigitalOceanAppDeploymentResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(DigitalOceanAppDeploymentResultError::InvalidConsent);
        }
        self.secret_reference.validate(&self.scope)?;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(DigitalOceanAppDeploymentResultError::InvalidRegistration)?;
        self.registration_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(DigitalOceanAppDeploymentResultError::InvalidRegistration)?;
        self.registration_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(DigitalOceanAppDeploymentResultError::InvalidRegistration)?;
        self.registration_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence {
            previous_status,
            status: self.status,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest.as_str().to_owned(),
                ),
                ("consent", self.consent.digest.as_str().to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type DigitalOceanRegistration = DigitalOceanAppDeploymentRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DigitalOceanAppDeploymentEvidenceRequest {
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
    pub previous_phase: Option<DeploymentPhase>,
    pub expected_source_revision_digest: Digest,
    pub request_digest: Digest,
}

impl DigitalOceanAppDeploymentEvidenceRequest {
    pub fn new(
        scope: &DigitalOceanAppDeploymentScope,
        page_size: u16,
        max_pages: u16,
        provider_digest: Digest,
        registration_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(DigitalOceanAppDeploymentResultError::InvalidRequest);
        }
        let scope_digest = scope.digest();
        let expected_source_revision_digest = scope.source_revision().digest().clone();
        let mut request = Self {
            scope_digest,
            provider_digest,
            registration_digest,
            page_size,
            max_pages,
            observed_at,
            previous_phase: None,
            expected_source_revision_digest,
            request_digest: Digest::from_text(b"unsealed"),
        };
        request.request_digest = request.recalculate_digest();
        Ok(request)
    }

    #[must_use]
    pub fn with_previous_phase(mut self, phase: DeploymentPhase) -> Self {
        self.previous_phase = Some(phase);
        self.request_digest = self.recalculate_digest();
        self
    }

    #[must_use]
    fn recalculate_digest(&self) -> Digest {
        Digest::from_parts(
            "digitalocean-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
                (
                    "previous_phase",
                    self.previous_phase
                        .map_or_else(|| "none".to_owned(), |phase| format!("{phase:?}")),
                ),
                (
                    "source",
                    self.expected_source_revision_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub operation: Option<String>,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub detail_digest: Digest,
    pub non_adoptable: bool,
}

impl FailureEvidence {
    #[must_use]
    pub fn from_transport(
        operation: DigitalOceanAppsOperation,
        error: &DigitalOceanTransportError,
    ) -> Self {
        let category = match error {
            DigitalOceanTransportError::BlockedEnv => "blocked_env",
            DigitalOceanTransportError::BadRequest => "bad_request",
            DigitalOceanTransportError::Unauthorized => "unauthorized",
            DigitalOceanTransportError::Forbidden => "forbidden",
            DigitalOceanTransportError::NotFound => "not_found",
            DigitalOceanTransportError::Conflict => "conflict",
            DigitalOceanTransportError::RateLimited { .. } => "rate_limited",
            DigitalOceanTransportError::ServerError { .. } => "server_error",
            DigitalOceanTransportError::Timeout => "timed_out",
            DigitalOceanTransportError::AccessLost => "access_lost",
            DigitalOceanTransportError::Partial => "partial",
            DigitalOceanTransportError::Unknown => "provider_unknown",
            DigitalOceanTransportError::InvalidResponse => "invalid_response",
            DigitalOceanTransportError::Tampered => "tampered",
            DigitalOceanTransportError::PaginationLoop => "pagination_loop",
        };
        let detail_digest = Digest::from_parts(
            "digitalocean-failure/v1",
            &[
                ("category", category.to_owned()),
                ("operation", operation.as_str().to_owned()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(|| "none".to_owned(), |status| status.to_string()),
                ),
            ],
        );
        let retry_after_seconds = match error {
            DigitalOceanTransportError::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        };
        Self {
            category: category.to_owned(),
            operation: Some(operation.as_str().to_owned()),
            status_code: error.status_code(),
            retry_after_seconds,
            detail_digest,
            non_adoptable: true,
        }
    }

    #[must_use]
    pub fn from_error(error: &DigitalOceanAppDeploymentResultError) -> Self {
        let category = match error {
            DigitalOceanAppDeploymentResultError::TamperedEvidence => "tampered",
            DigitalOceanAppDeploymentResultError::LifecycleRegression => "lifecycle_regression",
            DigitalOceanAppDeploymentResultError::ComponentDrift => "component_drift",
            DigitalOceanAppDeploymentResultError::SourceRevisionDrift => "source_revision_drift",
            DigitalOceanAppDeploymentResultError::PaginationLoop => "pagination_loop",
            DigitalOceanAppDeploymentResultError::PartialEvidence => "partial",
            DigitalOceanAppDeploymentResultError::RegistrationRevoked
            | DigitalOceanAppDeploymentResultError::RegistrationInactive => "registration_revoked",
            _ => "provider_unknown",
        };
        Self {
            category: category.to_owned(),
            operation: None,
            status_code: None,
            retry_after_seconds: None,
            detail_digest: Digest::from_parts(
                "digitalocean-failure/v1",
                &[("category", category.to_owned())],
            ),
            non_adoptable: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DigitalOceanAppDeploymentProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub team_digest: Digest,
    pub app_digest: Digest,
    pub deployment_digest: Digest,
    pub region_digest: Digest,
    pub source_revision_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: DigitalOceanEvidenceState,
    pub phase: Option<DeploymentPhase>,
    pub app: Option<AppProjection>,
    pub deployment: Option<DeploymentProjection>,
    pub health: Option<HealthProjection>,
    pub events: Vec<EventProjection>,
    pub deployment_pages: u16,
    pub event_pages: u16,
    pub list_complete: bool,
    pub events_complete: bool,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub cost_summary: CostSummary,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub failure: Option<FailureEvidence>,
    pub proposal_digest: Digest,
}

impl DigitalOceanAppDeploymentProposal {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
    #[must_use]
    pub const fn is_review_only(&self) -> bool {
        true
    }
    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn calculate_proposal_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!([
            &self.service_id,
            &self.provider_id,
            &self.consumer_id,
            &self.registration_digest,
            &self.scope_digest,
            &self.account_digest,
            &self.team_digest,
            &self.app_digest,
            &self.deployment_digest,
            &self.region_digest,
            &self.source_revision_digest,
            &self.mission,
            &self.project,
            &self.work_product,
            self.state,
            self.phase,
            &self.app,
            &self.deployment,
            &self.health,
            &self.events,
            self.deployment_pages,
            self.event_pages,
            self.list_complete,
            self.events_complete,
            &self.evidence,
            &self.request_receipts,
            &self.cost_receipts,
            &self.provenance,
            self.review_only,
            self.connected,
            self.native,
            self.first_party,
            self.provider_receipt,
            self.outcome_adopted,
            self.work_product_adopted,
            &self.failure,
        ]))
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        self.evidence.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate_integrity()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate_integrity()?;
        }
        if self.cost_summary != CostSummary::from_receipts(&self.cost_receipts) {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    ApiDigestMismatch,
    PartialEvidence,
    AccessLost,
    TamperedEvidence,
    ProviderUnknown,
    LifecycleRegression,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    #[must_use]
    pub fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        Self {
            valid,
            review_eligible,
            failures,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DigitalOceanAppDeploymentServiceError {
    #[error("DigitalOcean registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("DigitalOcean SecretReference is revoked")]
    SecretRevoked,
    #[error("DigitalOcean consent is denied or stale")]
    ConsentMismatch,
    #[error("DigitalOcean request binding does not match")]
    RequestMismatch,
    #[error(transparent)]
    Boundary(#[from] DigitalOceanAppDeploymentResultError),
}

pub struct DigitalOceanAppDeploymentResultService<T: DigitalOceanAppsTransport> {
    registration: DigitalOceanAppDeploymentRegistration,
    provider: DigitalOceanAppsProvider<T>,
    last_phase: Option<DeploymentPhase>,
}

impl<T: DigitalOceanAppsTransport> fmt::Debug for DigitalOceanAppDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanAppDeploymentResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("last_phase", &self.last_phase)
            .finish()
    }
}

impl<T: DigitalOceanAppsTransport> DigitalOceanAppDeploymentResultService<T> {
    pub fn new(
        scope: DigitalOceanAppDeploymentScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: DigitalOceanAppsProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = DigitalOceanAppDeploymentRegistration::new(
            "digitalocean-app-deployment-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            registration,
            provider,
            last_phase: None,
        })
    }

    pub fn with_registration(
        registration: DigitalOceanAppDeploymentRegistration,
        provider: DigitalOceanAppsProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        provider.definition().validate()?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(DigitalOceanAppDeploymentResultError::ProviderDrift);
        }
        Ok(Self {
            registration,
            provider,
            last_phase: None,
        })
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: API_REVISION.to_owned(),
            operations: [
                DigitalOceanAppsOperation::GetApp,
                DigitalOceanAppsOperation::ListDeployments,
                DigitalOceanAppsOperation::GetDeployment,
                DigitalOceanAppsOperation::ListEvents,
                DigitalOceanAppsOperation::GetAppHealth,
            ]
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &DigitalOceanAppDeploymentScope {
        self.registration.scope()
    }
    pub fn register(&mut self) -> Result<&DigitalOceanAppDeploymentRegistration> {
        self.provider.definition().validate()?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationInactive);
        }
        if self.registration.provider_digest() != &self.provider.definition().provider_digest {
            return Err(DigitalOceanAppDeploymentResultError::ProviderDrift);
        }
        Ok(&self.registration)
    }
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }
    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        self.registration.secret_reference()
    }
    #[must_use]
    pub fn registration(&self) -> &DigitalOceanAppDeploymentRegistration {
        &self.registration
    }
    #[must_use]
    pub fn registration_mut(&mut self) -> &mut DigitalOceanAppDeploymentRegistration {
        &mut self.registration
    }
    #[must_use]
    pub fn provider(&self) -> &DigitalOceanAppsProvider<T> {
        &self.provider
    }
    #[must_use]
    pub fn provider_mut(&mut self) -> &mut DigitalOceanAppsProvider<T> {
        &mut self.provider
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<DigitalOceanAppDeploymentEvidenceRequest> {
        self.request(MAX_PAGE_SIZE, MAX_PAGES, observed_at)
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<DigitalOceanAppDeploymentEvidenceRequest> {
        DigitalOceanAppDeploymentEvidenceRequest::new(
            self.scope(),
            page_size,
            max_pages,
            self.provider.provider_digest(),
            self.registration.registration_digest().clone(),
            observed_at,
        )
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }
    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }
    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }
    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }
    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(&self) -> Result<MissionDigitalOceanAppDeploymentConsumer> {
        MissionDigitalOceanAppDeploymentConsumer::new(
            self.scope().clone(),
            self.registration.clone(),
        )
    }

    pub fn verify(&self, proposal: &DigitalOceanAppDeploymentProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.scope_digest != self.registration.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.api_digest != self.registration.api_digest().clone() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            DigitalOceanEvidenceState::AccessLost => failures.push(VerificationFailure::AccessLost),
            DigitalOceanEvidenceState::Partial => {
                failures.push(VerificationFailure::PartialEvidence);
            }
            DigitalOceanEvidenceState::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            DigitalOceanEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            DigitalOceanEvidenceState::Revoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            DigitalOceanEvidenceState::PendingBuild
            | DigitalOceanEvidenceState::Building
            | DigitalOceanEvidenceState::PendingDeploy
            | DigitalOceanEvidenceState::Deploying
            | DigitalOceanEvidenceState::Active
            | DigitalOceanEvidenceState::Superseded
            | DigitalOceanEvidenceState::Error
            | DigitalOceanEvidenceState::Canceled => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.list_complete
            && proposal.events_complete
            && proposal.deployment.is_some()
            && proposal.health.is_some()
            && proposal.state.is_lifecycle()
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt;
        VerificationReport::new(valid, review_eligible, failures)
    }

    pub fn propose(
        &mut self,
        request: DigitalOceanAppDeploymentEvidenceRequest,
    ) -> Result<DigitalOceanAppDeploymentProposal> {
        if !self.registration.is_active() {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Revoked,
                DigitalOceanAppDeploymentResultError::RegistrationInactive,
                Vec::new(),
                Vec::new(),
                0,
                0,
                false,
                false,
            ));
        }
        self.validate_request(&request)?;
        let scope = self.scope().clone();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let secret_digest = self.registration.secret_reference_digest().clone();
        let consent_digest = self.registration.consent_digest();
        let app_request = GetAppRequest::for_scope(&scope, &secret_digest, &consent_digest);
        let app = match self.provider.get_app(&app_request, &scope) {
            Ok(read) => {
                request_receipts.push(read.request_receipt.clone());
                cost_receipts.push(read.cost_receipt.clone());
                Some(read.projection)
            }
            Err(error) => {
                return Ok(self.failed_for_boundary(
                    &request,
                    DigitalOceanAppsOperation::GetApp,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if app
            .as_ref()
            .and_then(|projection| projection.active_deployment_digest.as_ref())
            .is_some_and(|active| active != &scope.deployment().digest())
        {
            return Ok(self.seal_proposal(
                &request,
                DigitalOceanEvidenceState::Superseded,
                app,
                None,
                None,
                Vec::new(),
                request_receipts,
                cost_receipts,
                0,
                0,
                false,
                false,
                None,
            ));
        }

        let mut deployments = Vec::new();
        let mut page = None;
        let mut seen_pages = BTreeSet::new();
        let mut deployment_pages = 0;
        let list_complete;
        loop {
            let list_request = ListDeploymentsRequest::new(
                &scope,
                request.page_size,
                page.clone(),
                &secret_digest,
                &consent_digest,
            )?;
            let page_number = list_request.page_number();
            if !seen_pages.insert(page_number) {
                return Ok(self.failed_for_boundary(
                    &request,
                    DigitalOceanAppsOperation::ListDeployments,
                    DigitalOceanTransportError::PaginationLoop.into(),
                    request_receipts,
                    cost_receipts,
                ));
            }
            deployment_pages += 1;
            match self.provider.list_deployments(&list_request, &scope) {
                Ok(read) => {
                    request_receipts.push(read.request_receipt.clone());
                    cost_receipts.push(read.cost_receipt.clone());
                    deployments.extend(read.deployments);
                    if deployments.iter().any(|deployment| {
                        deployment.deployment_digest == scope.deployment().digest()
                    }) {
                        list_complete = true;
                        break;
                    }
                    let Some(next_page) = read.next_page else {
                        list_complete = true;
                        break;
                    };
                    if deployment_pages >= request.max_pages || seen_pages.contains(&next_page) {
                        return Ok(self.failed_for_boundary(
                            &request,
                            DigitalOceanAppsOperation::ListDeployments,
                            DigitalOceanTransportError::PaginationLoop.into(),
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                    page = Some(PageCursor::new(next_page, request.page_size, &scope)?);
                }
                Err(error) => {
                    return Ok(self.failed_for_boundary(
                        &request,
                        DigitalOceanAppsOperation::ListDeployments,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            }
        }
        let Some(listed_deployment) = deployments
            .into_iter()
            .find(|deployment| deployment.deployment_digest == scope.deployment().digest())
        else {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                DigitalOceanAppDeploymentResultError::PartialEvidence,
                request_receipts,
                cost_receipts,
                deployment_pages,
                0,
                list_complete,
                false,
            ));
        };

        let deployment_request =
            GetDeploymentRequest::for_scope(&scope, &secret_digest, &consent_digest);
        let deployment = match self.provider.get_deployment(&deployment_request, &scope) {
            Ok(read) => {
                request_receipts.push(read.request_receipt.clone());
                cost_receipts.push(read.cost_receipt.clone());
                read.projection
            }
            Err(error) => {
                return Ok(self.failed_for_boundary(
                    &request,
                    DigitalOceanAppsOperation::GetDeployment,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if deployment.phase.rank() < listed_deployment.phase.rank()
            && listed_deployment.phase != DeploymentPhase::Unknown
        {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                DigitalOceanAppDeploymentResultError::LifecycleRegression,
                request_receipts,
                cost_receipts,
                deployment_pages,
                0,
                list_complete,
                false,
            ));
        }
        if deployment.source_revision_digest.as_ref()
            != Some(&request.expected_source_revision_digest)
        {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                DigitalOceanAppDeploymentResultError::SourceRevisionDrift,
                request_receipts,
                cost_receipts,
                deployment_pages,
                0,
                list_complete,
                false,
            ));
        }
        if let Some(previous_phase) = request.previous_phase
            && deployment.phase.rank() < previous_phase.rank()
        {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                DigitalOceanAppDeploymentResultError::LifecycleRegression,
                request_receipts,
                cost_receipts,
                deployment_pages,
                0,
                list_complete,
                false,
            ));
        }
        if let Err(error) = validate_components(&scope, &deployment) {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                error,
                request_receipts,
                cost_receipts,
                deployment_pages,
                0,
                list_complete,
                false,
            ));
        }

        let mut events = Vec::new();
        let mut event_page = None;
        let mut seen_event_pages = BTreeSet::new();
        let mut event_pages = 0;
        let events_complete;
        loop {
            let events_request = ListEventsRequest::new(
                &scope,
                request.page_size,
                event_page.clone(),
                &secret_digest,
                &consent_digest,
            )?;
            let page_number = events_request.page_number();
            if !seen_event_pages.insert(page_number) {
                return Ok(self.failed_for_boundary(
                    &request,
                    DigitalOceanAppsOperation::ListEvents,
                    DigitalOceanTransportError::PaginationLoop.into(),
                    request_receipts,
                    cost_receipts,
                ));
            }
            event_pages += 1;
            match self.provider.list_events(&events_request, &scope) {
                Ok(read) => {
                    request_receipts.push(read.request_receipt.clone());
                    cost_receipts.push(read.cost_receipt.clone());
                    events.extend(read.events);
                    let Some(next_page) = read.next_page else {
                        events_complete = true;
                        break;
                    };
                    if event_pages >= request.max_pages || seen_event_pages.contains(&next_page) {
                        return Ok(self.failed_for_boundary(
                            &request,
                            DigitalOceanAppsOperation::ListEvents,
                            DigitalOceanTransportError::PaginationLoop.into(),
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                    event_page = Some(PageCursor::new(next_page, request.page_size, &scope)?);
                }
                Err(error) => {
                    return Ok(self.failed_for_boundary(
                        &request,
                        DigitalOceanAppsOperation::ListEvents,
                        error,
                        request_receipts,
                        cost_receipts,
                    ));
                }
            }
        }

        let health_request =
            GetAppHealthRequest::for_scope(&scope, &secret_digest, &consent_digest);
        let health = match self.provider.get_app_health(&health_request, &scope) {
            Ok(read) => {
                request_receipts.push(read.request_receipt.clone());
                cost_receipts.push(read.cost_receipt.clone());
                read.projection
            }
            Err(error) => {
                return Ok(self.failed_for_boundary(
                    &request,
                    DigitalOceanAppsOperation::GetAppHealth,
                    error,
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        if let Some(last_phase) = self.last_phase
            && deployment.phase.rank() < last_phase.rank()
        {
            return Ok(self.failed_with_error(
                &request,
                DigitalOceanEvidenceState::Partial,
                DigitalOceanAppDeploymentResultError::LifecycleRegression,
                request_receipts,
                cost_receipts,
                deployment_pages,
                event_pages,
                list_complete,
                events_complete,
            ));
        }
        self.last_phase = Some(deployment.phase);
        Ok(self.success_proposal(
            &request,
            app,
            deployment,
            health,
            events,
            request_receipts,
            cost_receipts,
            deployment_pages,
            event_pages,
            list_complete,
            events_complete,
        ))
    }

    fn validate_request(&self, request: &DigitalOceanAppDeploymentEvidenceRequest) -> Result<()> {
        if !self.registration.is_active() {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationInactive);
        }
        self.registration.validate()?;
        self.provider.definition().validate()?;
        if request.scope_digest != self.registration.scope.digest()
            || request.provider_digest != self.provider.definition().provider_digest
            || request.registration_digest != *self.registration.registration_digest()
            || request.expected_source_revision_digest != *self.scope().source_revision().digest()
            || request.request_digest != request.recalculate_digest()
        {
            return Err(DigitalOceanAppDeploymentResultError::ScopeMismatch);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(DigitalOceanAppDeploymentResultError::ConsentExpired);
        }
        Ok(())
    }

    fn success_proposal(
        &self,
        request: &DigitalOceanAppDeploymentEvidenceRequest,
        app: Option<AppProjection>,
        deployment: DeploymentProjection,
        health: HealthProjection,
        events: Vec<EventProjection>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        deployment_pages: u16,
        event_pages: u16,
        list_complete: bool,
        events_complete: bool,
    ) -> DigitalOceanAppDeploymentProposal {
        let state = match deployment.phase {
            DeploymentPhase::Unknown => DigitalOceanEvidenceState::ProviderUnknown,
            phase => phase.into(),
        };
        self.seal_proposal(
            request,
            state,
            app,
            Some(deployment),
            Some(health),
            events,
            request_receipts,
            cost_receipts,
            deployment_pages,
            event_pages,
            list_complete,
            events_complete,
            None,
        )
    }

    fn failed_for_boundary(
        &self,
        request: &DigitalOceanAppDeploymentEvidenceRequest,
        operation: DigitalOceanAppsOperation,
        error: DigitalOceanAppDeploymentResultError,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> DigitalOceanAppDeploymentProposal {
        let (state, failure) = match &error {
            DigitalOceanAppDeploymentResultError::Transport(transport) => {
                let state = match transport {
                    DigitalOceanTransportError::Unauthorized
                    | DigitalOceanTransportError::Forbidden
                    | DigitalOceanTransportError::AccessLost => {
                        DigitalOceanEvidenceState::AccessLost
                    }
                    DigitalOceanTransportError::Tampered => DigitalOceanEvidenceState::Tampered,
                    DigitalOceanTransportError::PaginationLoop => {
                        DigitalOceanEvidenceState::Partial
                    }
                    DigitalOceanTransportError::BlockedEnv
                    | DigitalOceanTransportError::BadRequest
                    | DigitalOceanTransportError::NotFound
                    | DigitalOceanTransportError::Conflict
                    | DigitalOceanTransportError::RateLimited { .. }
                    | DigitalOceanTransportError::ServerError { .. }
                    | DigitalOceanTransportError::Timeout
                    | DigitalOceanTransportError::Partial
                    | DigitalOceanTransportError::Unknown
                    | DigitalOceanTransportError::InvalidResponse => {
                        DigitalOceanEvidenceState::ProviderUnknown
                    }
                };
                (state, FailureEvidence::from_transport(operation, transport))
            }
            DigitalOceanAppDeploymentResultError::RegistrationRevoked
            | DigitalOceanAppDeploymentResultError::RegistrationInactive => (
                DigitalOceanEvidenceState::Revoked,
                FailureEvidence::from_error(&error),
            ),
            DigitalOceanAppDeploymentResultError::TamperedEvidence => (
                DigitalOceanEvidenceState::Tampered,
                FailureEvidence::from_error(&error),
            ),
            _ => (
                DigitalOceanEvidenceState::Partial,
                FailureEvidence::from_error(&error),
            ),
        };
        let deployment_pages = request_receipts
            .iter()
            .filter(|receipt| {
                receipt.operation == DigitalOceanAppsOperation::ListDeployments.as_str()
            })
            .count() as u16;
        let event_pages = request_receipts
            .iter()
            .filter(|receipt| receipt.operation == DigitalOceanAppsOperation::ListEvents.as_str())
            .count() as u16;
        self.seal_proposal(
            request,
            state,
            None,
            None,
            None,
            Vec::new(),
            request_receipts,
            cost_receipts,
            deployment_pages,
            event_pages,
            false,
            false,
            Some(failure),
        )
    }

    fn failed_with_error(
        &self,
        request: &DigitalOceanAppDeploymentEvidenceRequest,
        state: DigitalOceanEvidenceState,
        error: DigitalOceanAppDeploymentResultError,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        deployment_pages: u16,
        event_pages: u16,
        list_complete: bool,
        events_complete: bool,
    ) -> DigitalOceanAppDeploymentProposal {
        self.seal_proposal(
            request,
            state,
            None,
            None,
            None,
            Vec::new(),
            request_receipts,
            cost_receipts,
            deployment_pages,
            event_pages,
            list_complete,
            events_complete,
            Some(FailureEvidence::from_error(&error)),
        )
    }

    fn seal_proposal(
        &self,
        request: &DigitalOceanAppDeploymentEvidenceRequest,
        state: DigitalOceanEvidenceState,
        app: Option<AppProjection>,
        deployment: Option<DeploymentProjection>,
        health: Option<HealthProjection>,
        events: Vec<EventProjection>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        deployment_pages: u16,
        event_pages: u16,
        list_complete: bool,
        events_complete: bool,
        failure: Option<FailureEvidence>,
    ) -> DigitalOceanAppDeploymentProposal {
        let deployment_digest = deployment.as_ref().map_or_else(
            || self.scope().deployment().digest(),
            |deployment| deployment.deployment_digest.clone(),
        );
        let app_digest = app
            .as_ref()
            .map_or_else(|| self.scope().app().digest(), |app| app.app_digest.clone());
        let result_digest = Digest::from_parts(
            "digitalocean-result/v1",
            &[
                ("app", app_digest.as_str().to_owned()),
                ("deployment", deployment_digest.as_str().to_owned()),
                (
                    "health",
                    health.as_ref().map_or_else(
                        || "none".to_owned(),
                        |health| health.digest.as_str().to_owned(),
                    ),
                ),
                (
                    "events",
                    events
                        .iter()
                        .map(|event| event.event_id_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "failure",
                    failure.as_ref().map_or_else(
                        || "none".to_owned(),
                        |failure| failure.detail_digest.as_str().to_owned(),
                    ),
                ),
            ],
        );
        let page_digest = Digest::from_parts(
            "digitalocean-pages/v1",
            &[
                (
                    "requests",
                    request_receipts
                        .iter()
                        .map(|receipt| receipt.request_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("list_complete", list_complete.to_string()),
                ("events_complete", events_complete.to_string()),
            ],
        );
        let source_revision_digest = deployment
            .as_ref()
            .and_then(|deployment| deployment.source_revision_digest.clone())
            .unwrap_or_else(|| self.scope().source_revision().digest().clone());
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: crate::contract_digest_value(),
            provider_digest: self.provider.definition().provider_digest.clone(),
            api_digest: self.provider.definition().api_digest.clone(),
            permission_digest: self.registration.permission_digest(),
            scope_digest: self.scope().digest(),
            request_digest: request.request_digest.clone(),
            page_digest,
            app_digest: app_digest.clone(),
            deployment_digest: deployment_digest.clone(),
            source_revision_digest: source_revision_digest.clone(),
            result_digest,
            registration_digest: self.registration.registration_digest().clone(),
            evidence_digest: Digest::from_text("unsealed-digitalocean-evidence"),
        };
        evidence.evidence_digest = evidence.calculate();
        let provenance = self.provider.provenance();
        let mut proposal = DigitalOceanAppDeploymentProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope().digest(),
            account_digest: self.scope().account().digest(),
            team_digest: self.scope().team().digest(),
            app_digest,
            deployment_digest,
            region_digest: self.scope().region().digest(),
            source_revision_digest,
            mission: mission_projection(self.scope().mission()),
            project: project_projection(self.scope().project()),
            work_product: work_product_projection(self.scope().work_product()),
            state,
            phase: deployment.as_ref().map(|deployment| deployment.phase),
            app,
            deployment,
            health,
            events,
            deployment_pages,
            event_pages,
            list_complete,
            events_complete,
            evidence,
            cost_summary: CostSummary::from_receipts(&cost_receipts),
            request_receipts,
            cost_receipts,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            failure,
            proposal_digest: Digest::from_text("unsealed-digitalocean-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }
}

fn validate_components(
    scope: &DigitalOceanAppDeploymentScope,
    deployment: &DeploymentProjection,
) -> Result<()> {
    if deployment.components.is_empty() {
        return Err(DigitalOceanAppDeploymentResultError::PartialEvidence);
    }
    for component in &deployment.components {
        let Some(selector) = scope
            .components()
            .iter()
            .find(|selector| selector.name == component.name)
        else {
            return Err(DigitalOceanAppDeploymentResultError::ComponentDrift);
        };
        if selector.component_type != component.component_type
            && component.component_type != "UNKNOWN"
        {
            return Err(DigitalOceanAppDeploymentResultError::ComponentDrift);
        }
    }
    if scope.components().iter().any(|selector| {
        !deployment
            .components
            .iter()
            .any(|component| component.name == selector.name)
    }) {
        return Err(DigitalOceanAppDeploymentResultError::ComponentDrift);
    }
    Ok(())
}

pub type DigitalOceanAppDeploymentResult = DigitalOceanAppDeploymentProposal;
pub type DigitalOceanAppDeploymentService<T> = DigitalOceanAppDeploymentResultService<T>;
