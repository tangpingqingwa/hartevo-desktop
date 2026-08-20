//! Registration, proposal, evidence, and verification seams.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::error::{FreshserviceIncidentResultError, Result};
use crate::model::{
    AssetMetadata, ChangeMetadata, ConsentScope, Digest, FreshserviceIncidentResultScope,
    FreshservicePermissionSnapshot, MissionProjection, ProjectProjection, SecretReference,
    TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    AssetRequest, ChangeRequest, FreshserviceProvider, FreshserviceTransport,
    FreshserviceTransportError, IncidentRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES, MAX_RECORDS_PER_KIND, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

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
    pub before_status: RegistrationStatus,
    pub after_status: RegistrationStatus,
    pub before_digest: Digest,
    pub after_digest: Digest,
    pub registration_revision: u64,
    pub transition_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct FreshserviceIncidentResultRegistration {
    registration_id: String,
    scope_digest: Digest,
    provider_digest: Digest,
    provider_revision: String,
    permission_snapshot: FreshservicePermissionSnapshot,
    consent: ConsentScope,
    secret_reference_digest: Digest,
    project_revision: u64,
    mission_revision: u64,
    work_product_revision: u64,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

pub type FreshserviceRegistration = FreshserviceIncidentResultRegistration;

impl fmt::Debug for FreshserviceIncidentResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshserviceIncidentResultRegistration")
            .field("registration_digest", &self.registration_digest)
            .field("scope_digest", &self.scope_digest)
            .field("status", &self.status)
            .field("registration_revision", &self.registration_revision)
            .finish()
    }
}

impl FreshserviceIncidentResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_id: impl Into<String>,
        scope: &FreshserviceIncidentResultScope,
        secret_reference: &SecretReference,
        permission_snapshot: FreshservicePermissionSnapshot,
        consent: ConsentScope,
        provider_id: &str,
        provider_revision: impl Into<String>,
        provider_digest: &Digest,
        registration_revision: u64,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration_id = registration_id.into();
        if registration_id.is_empty() || provider_id != PROVIDER_ID || registration_revision == 0 {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(FreshserviceIncidentResultError::InvalidSecretReference);
        }
        permission_snapshot.validate()?;
        consent.validate(registration_time)?;
        provider_digest.validate()?;
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(FreshserviceIncidentResultError::ProviderDefinitionDrift);
        }
        let mut registration = Self {
            registration_id,
            scope_digest: scope.digest(),
            provider_digest: provider_digest.clone(),
            provider_revision,
            permission_snapshot,
            consent,
            secret_reference_digest: secret_reference.digest(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-freshservice-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    pub fn registration_id(&self) -> &str {
        &self.registration_id
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn permission_snapshot(&self) -> &FreshservicePermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.registration_id.is_empty()
            || self.provider_revision.is_empty()
            || self.registration_revision == 0
        {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        self.scope_digest.validate()?;
        self.provider_digest.validate()?;
        self.permission_snapshot.validate()?;
        self.consent.reference_digest.validate()?;
        self.secret_reference_digest.validate()?;
        if self.registration_digest != self.calculate_digest() {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !self.is_active() {
            return Err(FreshserviceIncidentResultError::RegistrationAlreadyRevoked);
        }
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !matches!(self.status, RegistrationStatus::Revoked) {
            return Err(FreshserviceIncidentResultError::RegistrationNotRevoked);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    pub fn activate(&mut self) -> Result<RegistrationTransitionEvidence> {
        if !matches!(self.status, RegistrationStatus::Reversed) {
            return Err(FreshserviceIncidentResultError::RegistrationNotRevoked);
        }
        self.transition(RegistrationStatus::Active)
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let before_status = self.status;
        let before_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .checked_add(1)
            .ok_or(FreshserviceIncidentResultError::RegistrationRevisionOverflow)?;
        self.status = status;
        self.registration_digest = self.calculate_digest();
        let after_digest = self.registration_digest.clone();
        let transition_digest = Digest::from_parts(
            "freshservice-registration-transition/v1",
            &[
                ("before", before_digest.as_str().to_owned()),
                ("after", after_digest.as_str().to_owned()),
                ("before_status", format!("{before_status:?}")),
                ("after_status", format!("{status:?}")),
                ("revision", self.registration_revision.to_string()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            before_status,
            after_status: status,
            before_digest,
            after_digest,
            registration_revision: self.registration_revision,
            transition_digest,
        })
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-incident-result-registration/v1",
            &[
                ("id", self.registration_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("provider_revision", self.provider_revision.clone()),
                (
                    "permissions",
                    self.permission_snapshot.digest.as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference_digest.as_str().to_owned(),
                ),
                ("project_revision", self.project_revision.to_string()),
                ("mission_revision", self.mission_revision.to_string()),
                (
                    "work_product_revision",
                    self.work_product_revision.to_string(),
                ),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("status", format!("{:?}", self.status)),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("contract_digest", contract_digest()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshserviceResultState {
    Complete,
    Denied,
    Partial,
    Stale,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NotFound,
    Tampered,
    RegistrationRevoked,
}

impl FreshserviceResultState {
    pub const fn can_be_adopted(self) -> bool {
        false
    }

    pub const fn is_non_adoptable(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum ObservationFailure {
    Denied,
    Partial,
    Stale,
    AccessLoss,
    RateLimited { retry_after_seconds: u32 },
    ProviderUnknown,
    NotFound,
    Tampered,
    MalformedResponse,
    ResponseTooLarge,
    BlockedEnv,
    RegistrationRevoked,
}

impl ObservationFailure {
    pub const fn state(&self) -> FreshserviceResultState {
        match self {
            Self::Denied => FreshserviceResultState::Denied,
            Self::Partial => FreshserviceResultState::Partial,
            Self::Stale => FreshserviceResultState::Stale,
            Self::AccessLoss => FreshserviceResultState::AccessLoss,
            Self::RateLimited { .. } => FreshserviceResultState::RateLimited,
            Self::ProviderUnknown | Self::BlockedEnv => FreshserviceResultState::ProviderUnknown,
            Self::NotFound => FreshserviceResultState::NotFound,
            Self::Tampered | Self::MalformedResponse | Self::ResponseTooLarge => {
                FreshserviceResultState::Tampered
            }
            Self::RegistrationRevoked => FreshserviceResultState::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshserviceIncidentResultEvidence {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub incident: Vec<crate::model::IncidentMetadata>,
    pub change: Vec<ChangeMetadata>,
    pub asset: Vec<AssetMetadata>,
    pub incident_digest: Option<Digest>,
    pub change_digest: Option<Digest>,
    pub asset_digest: Option<Digest>,
    pub response_digests: Vec<Digest>,
    pub incident_pages: u16,
    pub change_pages: u16,
    pub asset_pages: u16,
    pub complete_incident: bool,
    pub complete_change: bool,
    pub complete_asset: bool,
    pub failures: Vec<ObservationFailure>,
    pub evidence_digest: Digest,
}

impl FreshserviceIncidentResultEvidence {
    fn calculate_digest(&self, state: FreshserviceResultState) -> Digest {
        Digest::from_parts(
            "freshservice-incident-result-evidence/v1",
            &[
                (
                    "plugin_version",
                    self.plugin_version_digest.as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("consent", self.consent_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("project", self.project_digest.as_str().to_owned()),
                ("mission", self.mission_digest.as_str().to_owned()),
                ("work_product", self.work_product_digest.as_str().to_owned()),
                (
                    "incident",
                    serde_json::to_string(&self.incident).expect("incident evidence serializes"),
                ),
                (
                    "change",
                    serde_json::to_string(&self.change).expect("change evidence serializes"),
                ),
                (
                    "asset",
                    serde_json::to_string(&self.asset).expect("asset evidence serializes"),
                ),
                (
                    "incident_digest",
                    self.incident_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "change_digest",
                    self.change_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "asset_digest",
                    self.asset_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "responses",
                    self.response_digests
                        .iter()
                        .map(|value| value.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                ("incident_pages", self.incident_pages.to_string()),
                ("change_pages", self.change_pages.to_string()),
                ("asset_pages", self.asset_pages.to_string()),
                ("complete_incident", self.complete_incident.to_string()),
                ("complete_change", self.complete_change.to_string()),
                ("complete_asset", self.complete_asset.to_string()),
                (
                    "failures",
                    serde_json::to_string(&self.failures).expect("failures serialize"),
                ),
                ("state", format!("{state:?}")),
            ],
        )
    }

    pub fn validate_integrity(&self, state: FreshserviceResultState) -> Result<()> {
        for digest in [
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
        ] {
            digest.validate()?;
        }
        for digest in self
            .incident_digest
            .iter()
            .chain(self.change_digest.iter())
            .chain(self.asset_digest.iter())
            .chain(self.response_digests.iter())
        {
            digest.validate()?;
        }
        if self.incident.len() > MAX_RECORDS_PER_KIND
            || self.change.len() > MAX_RECORDS_PER_KIND
            || self.asset.len() > MAX_RECORDS_PER_KIND
            || self.response_digests.len() > usize::from(MAX_PAGES) * 3
            || self.incident_pages > MAX_PAGES
            || self.change_pages > MAX_PAGES
            || self.asset_pages > MAX_PAGES
            || self.incident.iter().any(|item| item.validate().is_err())
            || self.change.iter().any(|item| item.validate().is_err())
            || self.asset.iter().any(|item| item.validate().is_err())
            || self.evidence_digest != self.calculate_digest(state)
        {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshserviceIncidentResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub state: FreshserviceResultState,
    pub evidence: FreshserviceIncidentResultEvidence,
    pub failures: Vec<ObservationFailure>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub ticket_mutation: bool,
    pub raw_notes: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl FreshserviceIncidentResultProposal {
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-incident-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project projection serializes"),
                ),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission projection serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product)
                        .expect("work product projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failures",
                    serde_json::to_string(&self.failures).expect("failures serialize"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("ticket_mutation", self.ticket_mutation.to_string()),
                ("raw_notes", self.raw_notes.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.registration_digest.validate()?;
        self.scope_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.ticket_mutation
            || self.raw_notes
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.validate_integrity(self.state).is_err()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(FreshserviceIncidentResultError::TamperedProposal);
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
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    ProjectRevisionMismatch,
    MissionRevisionMismatch,
    WorkProductRevisionMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    Denied,
    Stale,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NotFound,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "freshservice-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshserviceIncidentResultRequest {
    pub page_size: u16,
    pub max_pages: u16,
    pub request_digest: Digest,
}

impl FreshserviceIncidentResultRequest {
    pub fn new(page_size: u16, max_pages: u16) -> Result<Self> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        let mut request = Self {
            page_size,
            max_pages,
            request_digest: Digest::from_text("unsealed-freshservice-request"),
        };
        request.request_digest = Digest::from_parts(
            "freshservice-incident-result-request/v1",
            &[
                ("page_size", page_size.to_string()),
                ("max_pages", max_pages.to_string()),
            ],
        );
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.request_digest
                != Digest::from_parts(
                    "freshservice-incident-result-request/v1",
                    &[
                        ("page_size", self.page_size.to_string()),
                        ("max_pages", self.max_pages.to_string()),
                    ],
                )
        {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        Ok(())
    }
}

struct Collected<T> {
    items: Vec<T>,
    response_digests: Vec<Digest>,
    pages: u16,
    complete: bool,
    failure: Option<ObservationFailure>,
}

impl<T> Collected<T> {
    fn empty(failure: ObservationFailure) -> Self {
        Self {
            items: Vec::new(),
            response_digests: Vec::new(),
            pages: 0,
            complete: false,
            failure: Some(failure),
        }
    }
}

pub struct FreshserviceIncidentResultService<T: FreshserviceTransport> {
    scope: FreshserviceIncidentResultScope,
    registration: FreshserviceIncidentResultRegistration,
    provider: FreshserviceProvider<T>,
}

impl<T: FreshserviceTransport> fmt::Debug for FreshserviceIncidentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshserviceIncidentResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: FreshserviceTransport> FreshserviceIncidentResultService<T> {
    pub fn new(
        scope: FreshserviceIncidentResultScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: FreshserviceProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let permission_snapshot = FreshservicePermissionSnapshot::for_layer_one(1)?;
        Self::with_registration(
            "freshservice-incident-result-registration",
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: FreshserviceIncidentResultScope,
        secret_reference: SecretReference,
        permission_snapshot: FreshservicePermissionSnapshot,
        consent: ConsentScope,
        provider: FreshserviceProvider<T>,
        registration_revision: u64,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = FreshserviceIncidentResultRegistration::new(
            registration_id,
            &scope,
            &secret_reference,
            permission_snapshot,
            consent,
            provider.definition().id.as_str(),
            provider.definition().api_revision.clone(),
            provider.definition().digest(),
            registration_revision,
            registration_time,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
        })
    }

    pub fn scope(&self) -> &FreshserviceIncidentResultScope {
        &self.scope
    }

    pub fn registration(&self) -> &FreshserviceIncidentResultRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &FreshserviceProvider<T> {
        &self.provider
    }

    pub fn describe_scope(&self) -> &FreshserviceIncidentResultScope {
        &self.scope
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            operations: vec![
                "read_incident_metadata".to_owned(),
                "read_change_window_metadata".to_owned(),
                "read_asset_metadata".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn default_request(&self) -> Result<FreshserviceIncidentResultRequest> {
        FreshserviceIncidentResultRequest::new(MAX_PAGE_SIZE.min(10), MAX_PAGES)
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
    ) -> Result<FreshserviceIncidentResultRequest> {
        FreshserviceIncidentResultRequest::new(page_size, max_pages)
    }

    pub fn propose(
        &mut self,
        request: FreshserviceIncidentResultRequest,
    ) -> Result<FreshserviceIncidentResultProposal> {
        request.validate()?;
        if !self.registration.is_active() {
            return Ok(self.revoked_proposal());
        }
        self.registration.validate()?;

        let incident = self.collect_incident(&request);
        let change = self.collect_change(&request);
        let asset = self.collect_asset(&request);
        let mut failures = Vec::new();
        for failure in [
            incident.failure.clone(),
            change.failure.clone(),
            asset.failure.clone(),
        ]
        .into_iter()
        .flatten()
        {
            failures.push(failure);
        }
        let success_count = [incident.complete, change.complete, asset.complete]
            .into_iter()
            .filter(|complete| *complete)
            .count();
        let state = state_for(&failures, success_count);
        let evidence = self.build_evidence(&incident, &change, &asset, &failures, state);
        let mut proposal = FreshserviceIncidentResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.digest(),
            project: ProjectProjection::from(self.scope.project()),
            mission: MissionProjection::from(self.scope.mission()),
            work_product: WorkProductProjection::from(self.scope.work_product()),
            state,
            evidence,
            failures,
            provenance: self.provider.provenance(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            ticket_mutation: false,
            raw_notes: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-freshservice-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn verify(&self, proposal: &FreshserviceIncidentResultProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.scope_digest != self.scope.digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.project.digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
        {
            failures.push(VerificationFailure::ProjectRevisionMismatch);
        }
        if proposal.mission.digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
        {
            failures.push(VerificationFailure::MissionRevisionMismatch);
        }
        if proposal.work_product.digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            failures.push(VerificationFailure::WorkProductRevisionMismatch);
        }
        if proposal.evidence.provider_digest != *self.registration.provider_digest() {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_snapshot().digest {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent().digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        for failure in &proposal.failures {
            failures.push(match failure {
                ObservationFailure::Partial => VerificationFailure::PartialEvidence,
                ObservationFailure::Denied => VerificationFailure::Denied,
                ObservationFailure::Stale => VerificationFailure::Stale,
                ObservationFailure::AccessLoss => VerificationFailure::AccessLoss,
                ObservationFailure::RateLimited { .. } => VerificationFailure::RateLimited,
                ObservationFailure::ProviderUnknown | ObservationFailure::BlockedEnv => {
                    VerificationFailure::ProviderUnknown
                }
                ObservationFailure::NotFound => VerificationFailure::NotFound,
                ObservationFailure::Tampered
                | ObservationFailure::MalformedResponse
                | ObservationFailure::ResponseTooLarge => VerificationFailure::TamperedEvidence,
                ObservationFailure::RegistrationRevoked => {
                    VerificationFailure::RegistrationInactive
                }
            });
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state == FreshserviceResultState::Complete,
            failures,
        )
    }

    pub fn consumer(&self) -> Result<crate::MissionFreshserviceIncidentConsumer> {
        crate::MissionFreshserviceIncidentConsumer::new(
            self.scope.clone(),
            self.registration.clone(),
        )
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()?;
        self.registration.activate()
    }

    fn revoked_proposal(&self) -> FreshserviceIncidentResultProposal {
        let mut evidence = FreshserviceIncidentResultEvidence {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::parse(contract_digest()).expect("contract digest is valid"),
            provider_digest: self.provider.definition().provider_digest.clone(),
            permission_digest: self.registration.permission_snapshot().digest.clone(),
            consent_digest: self.registration.consent().digest(),
            scope_digest: self.scope.digest(),
            project_digest: self.scope.project().digest(),
            mission_digest: self.scope.mission().digest(),
            work_product_digest: self.scope.work_product().digest(),
            incident: Vec::new(),
            change: Vec::new(),
            asset: Vec::new(),
            incident_digest: None,
            change_digest: None,
            asset_digest: None,
            response_digests: Vec::new(),
            incident_pages: 0,
            change_pages: 0,
            asset_pages: 0,
            complete_incident: false,
            complete_change: false,
            complete_asset: false,
            failures: vec![ObservationFailure::RegistrationRevoked],
            evidence_digest: Digest::from_text("unsealed-freshservice-revoked-evidence"),
        };
        evidence.evidence_digest =
            evidence.calculate_digest(FreshserviceResultState::RegistrationRevoked);
        let mut proposal = FreshserviceIncidentResultProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest().clone(),
            scope_digest: self.scope.digest(),
            project: ProjectProjection::from(self.scope.project()),
            mission: MissionProjection::from(self.scope.mission()),
            work_product: WorkProductProjection::from(self.scope.work_product()),
            state: FreshserviceResultState::RegistrationRevoked,
            evidence,
            failures: vec![ObservationFailure::RegistrationRevoked],
            provenance: self.provider.provenance(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            ticket_mutation: false,
            raw_notes: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-freshservice-revoked-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    fn build_evidence(
        &self,
        incident: &Collected<crate::model::IncidentMetadata>,
        change: &Collected<ChangeMetadata>,
        asset: &Collected<AssetMetadata>,
        failures: &[ObservationFailure],
        state: FreshserviceResultState,
    ) -> FreshserviceIncidentResultEvidence {
        let mut evidence = FreshserviceIncidentResultEvidence {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::parse(contract_digest()).expect("contract digest is valid"),
            provider_digest: self.provider.definition().provider_digest.clone(),
            permission_digest: self.registration.permission_snapshot().digest.clone(),
            consent_digest: self.registration.consent().digest(),
            scope_digest: self.scope.digest(),
            project_digest: self.scope.project().digest(),
            mission_digest: self.scope.mission().digest(),
            work_product_digest: self.scope.work_product().digest(),
            incident: incident.items.clone(),
            change: change.items.clone(),
            asset: asset.items.clone(),
            incident_digest: aggregate_digest(&incident.items),
            change_digest: aggregate_digest(&change.items),
            asset_digest: aggregate_digest(&asset.items),
            response_digests: incident
                .response_digests
                .iter()
                .chain(change.response_digests.iter())
                .chain(asset.response_digests.iter())
                .cloned()
                .collect(),
            incident_pages: incident.pages,
            change_pages: change.pages,
            asset_pages: asset.pages,
            complete_incident: incident.complete,
            complete_change: change.complete,
            complete_asset: asset.complete,
            failures: failures.to_vec(),
            evidence_digest: Digest::from_text("unsealed-freshservice-evidence"),
        };
        evidence.evidence_digest = evidence.calculate_digest(state);
        evidence
    }

    fn collect_incident(
        &mut self,
        request: &FreshserviceIncidentResultRequest,
    ) -> Collected<crate::model::IncidentMetadata> {
        let Ok(mut current) = IncidentRequest::for_scope(&self.scope, request.page_size, None)
        else {
            return Collected::empty(ObservationFailure::Stale);
        };
        let mut collected = Collected {
            items: Vec::new(),
            response_digests: Vec::new(),
            pages: 0,
            complete: false,
            failure: None,
        };
        for _ in 0..request.max_pages {
            let page = match self.provider.read_incident(&current) {
                Ok(page) => page,
                Err(error) => {
                    collected.failure = Some(map_error(error));
                    return collected;
                }
            };
            collected.pages = collected.pages.saturating_add(1);
            collected
                .response_digests
                .push(page.response_digest.clone());
            for item in page.items {
                if item.id_digest == self.scope.incident().digest() {
                    if collected.items.len() < MAX_RECORDS_PER_KIND {
                        collected.items.push(item);
                    }
                } else {
                    collected.failure = Some(ObservationFailure::Stale);
                    return collected;
                }
            }
            if page.complete {
                collected.complete = true;
                return collected;
            }
            current = if let Ok(next) =
                IncidentRequest::for_scope(&self.scope, request.page_size, page.next_cursor)
            {
                next
            } else {
                collected.failure = Some(ObservationFailure::Stale);
                return collected;
            };
        }
        collected.failure = Some(ObservationFailure::Partial);
        collected
    }

    fn collect_change(
        &mut self,
        request: &FreshserviceIncidentResultRequest,
    ) -> Collected<ChangeMetadata> {
        let Ok(mut current) = ChangeRequest::for_scope(&self.scope, request.page_size, None) else {
            return Collected::empty(ObservationFailure::Stale);
        };
        let mut collected = Collected {
            items: Vec::new(),
            response_digests: Vec::new(),
            pages: 0,
            complete: false,
            failure: None,
        };
        for _ in 0..request.max_pages {
            let page = match self.provider.read_change(&current) {
                Ok(page) => page,
                Err(error) => {
                    collected.failure = Some(map_error(error));
                    return collected;
                }
            };
            collected.pages = collected.pages.saturating_add(1);
            collected
                .response_digests
                .push(page.response_digest.clone());
            for item in page.items {
                if item.id_digest == self.scope.change().digest() {
                    if collected.items.len() < MAX_RECORDS_PER_KIND {
                        collected.items.push(item);
                    }
                } else {
                    collected.failure = Some(ObservationFailure::Stale);
                    return collected;
                }
            }
            if page.complete {
                collected.complete = true;
                return collected;
            }
            current = if let Ok(next) =
                ChangeRequest::for_scope(&self.scope, request.page_size, page.next_cursor)
            {
                next
            } else {
                collected.failure = Some(ObservationFailure::Stale);
                return collected;
            };
        }
        collected.failure = Some(ObservationFailure::Partial);
        collected
    }

    fn collect_asset(
        &mut self,
        request: &FreshserviceIncidentResultRequest,
    ) -> Collected<AssetMetadata> {
        let Ok(mut current) = AssetRequest::for_scope(&self.scope, request.page_size, None) else {
            return Collected::empty(ObservationFailure::Stale);
        };
        let mut collected = Collected {
            items: Vec::new(),
            response_digests: Vec::new(),
            pages: 0,
            complete: false,
            failure: None,
        };
        for _ in 0..request.max_pages {
            let page = match self.provider.read_asset(&current) {
                Ok(page) => page,
                Err(error) => {
                    collected.failure = Some(map_error(error));
                    return collected;
                }
            };
            collected.pages = collected.pages.saturating_add(1);
            collected
                .response_digests
                .push(page.response_digest.clone());
            for item in page.items {
                if item.id_digest == self.scope.asset().digest() {
                    if collected.items.len() < MAX_RECORDS_PER_KIND {
                        collected.items.push(item);
                    }
                } else {
                    collected.failure = Some(ObservationFailure::Stale);
                    return collected;
                }
            }
            if page.complete {
                collected.complete = true;
                return collected;
            }
            current = if let Ok(next) =
                AssetRequest::for_scope(&self.scope, request.page_size, page.next_cursor)
            {
                next
            } else {
                collected.failure = Some(ObservationFailure::Stale);
                return collected;
            };
        }
        collected.failure = Some(ObservationFailure::Partial);
        collected
    }
}

fn aggregate_digest<T: Serialize>(items: &[T]) -> Option<Digest> {
    if items.is_empty() {
        None
    } else {
        Some(Digest::from_text(
            serde_json::to_vec(items).expect("metadata serializes"),
        ))
    }
}

fn map_error(error: FreshserviceIncidentResultError) -> ObservationFailure {
    match error {
        FreshserviceIncidentResultError::Provider(provider_error) => match provider_error {
            FreshserviceTransportError::Denied => ObservationFailure::Denied,
            FreshserviceTransportError::AccessLoss => ObservationFailure::AccessLoss,
            FreshserviceTransportError::NotFound => ObservationFailure::NotFound,
            FreshserviceTransportError::RateLimited {
                retry_after_seconds,
            } => ObservationFailure::RateLimited {
                retry_after_seconds,
            },
            FreshserviceTransportError::ProviderUnknown => ObservationFailure::ProviderUnknown,
            FreshserviceTransportError::MalformedResponse => ObservationFailure::MalformedResponse,
            FreshserviceTransportError::ResponseTooLarge => ObservationFailure::ResponseTooLarge,
            FreshserviceTransportError::BlockedEnv => ObservationFailure::BlockedEnv,
            FreshserviceTransportError::StaleRevision => ObservationFailure::Stale,
            FreshserviceTransportError::TamperedResponse => ObservationFailure::Tampered,
        },
        FreshserviceIncidentResultError::TamperedEvidence
        | FreshserviceIncidentResultError::TamperedProposal
        | FreshserviceIncidentResultError::ContractMismatch => ObservationFailure::Tampered,
        FreshserviceIncidentResultError::PaginationDrift
        | FreshserviceIncidentResultError::RevisionMismatch
        | FreshserviceIncidentResultError::ScopeMismatch
        | FreshserviceIncidentResultError::ConsentMismatch => ObservationFailure::Stale,
        FreshserviceIncidentResultError::ResponseTooLarge => ObservationFailure::ResponseTooLarge,
        FreshserviceIncidentResultError::MalformedResponse => ObservationFailure::MalformedResponse,
        _ => ObservationFailure::ProviderUnknown,
    }
}

fn state_for(failures: &[ObservationFailure], success_count: usize) -> FreshserviceResultState {
    if failures.is_empty() && success_count == 3 {
        return FreshserviceResultState::Complete;
    }
    if failures.iter().any(|failure| {
        matches!(
            failure,
            ObservationFailure::Tampered
                | ObservationFailure::MalformedResponse
                | ObservationFailure::ResponseTooLarge
        )
    }) {
        return FreshserviceResultState::Tampered;
    }
    if failures
        .iter()
        .any(|failure| matches!(failure, ObservationFailure::Stale))
    {
        return FreshserviceResultState::Stale;
    }
    if failures
        .iter()
        .any(|failure| matches!(failure, ObservationFailure::AccessLoss))
    {
        return FreshserviceResultState::AccessLoss;
    }
    if failures
        .iter()
        .any(|failure| matches!(failure, ObservationFailure::RateLimited { .. }))
    {
        return FreshserviceResultState::RateLimited;
    }
    if failures
        .iter()
        .any(|failure| matches!(failure, ObservationFailure::Denied))
    {
        return FreshserviceResultState::Denied;
    }
    if failures
        .iter()
        .any(|failure| matches!(failure, ObservationFailure::NotFound))
    {
        return FreshserviceResultState::NotFound;
    }
    if failures.iter().any(|failure| {
        matches!(
            failure,
            ObservationFailure::ProviderUnknown | ObservationFailure::BlockedEnv
        )
    }) {
        return FreshserviceResultState::ProviderUnknown;
    }
    if success_count > 0 {
        FreshserviceResultState::Partial
    } else {
        FreshserviceResultState::ProviderUnknown
    }
}
