use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::error::{RenderDeploymentError, RenderTransportError, Result};
use crate::model::{
    BackoffReceipt, ConsentScope, Digest, MAX_PAGES, MissionProjection, PermissionSnapshot,
    ProjectProjection, ProviderProvenance, RegistrationStatus, RenderDeployProjection,
    RenderDeployStatus, RenderDeploymentScope, RenderHealthProjection, RenderHealthState,
    RenderResultState, RenderServiceProjection, RenderServiceStatus, Revision, SecretReference,
    WorkProductProjection,
};
use crate::provider::{RenderDeploySnapshot, RenderProvider};
use crate::transport::RenderTransport;
use crate::{
    CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, MISSION_CONSUMER_ID, PLUGIN_VERSION,
    PROVIDER_ID, RENDER_PROVIDER_API_REVISION, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderDeploymentServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub live_external_io: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl Default for RenderDeploymentServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: MISSION_CONSUMER_ID.to_owned(),
            contract_digest: Digest::parse(contract_digest()).expect("static contract digest"),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            live_external_io: false,
            external_writes: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderCapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RenderDeploymentRegistration {
    id_digest: Digest,
    contract_digest: Digest,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: RenderDeploymentScope,
    secret_reference: SecretReference,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for RenderDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderDeploymentRegistration")
            .field("id_digest", &self.id_digest)
            .field("contract_digest", &self.contract_digest)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("consent_digest", &self.consent.digest())
            .field("scope_digest", &self.scope.digest())
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for RenderDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RenderDeploymentRegistration", 12)?;
        state.serialize_field("idDigest", &self.id_digest)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", self.permission_snapshot.digest())?;
        state.serialize_field("consentDigest", self.consent.digest())?;
        state.serialize_field("scopeDigest", &self.scope.digest())?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("reversible", &true)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub previous_revision: Revision,
    pub new_revision: Revision,
    pub previous_digest: Digest,
    pub new_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        previous_revision: Revision,
        new_revision: Revision,
        previous_digest: Digest,
        new_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "render-registration-transition/v1",
            &[
                ("previous_status", format!("{previous_status:?}")),
                ("new_status", format!("{new_status:?}")),
                ("previous_revision", previous_revision.get().to_string()),
                ("new_revision", new_revision.get().to_string()),
                ("previous_digest", previous_digest.as_str().to_owned()),
                ("new_digest", new_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            previous_revision,
            new_revision,
            previous_digest,
            new_digest,
            transition_digest,
            reversible: true,
        }
    }
}

impl RenderDeploymentRegistration {
    pub fn new<T: RenderTransport>(
        id: impl AsRef<str>,
        provider: &RenderProvider<T>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration_revision = Revision::new(registration_revision)?;
        permission_snapshot.validate()?;
        consent.validate()?;
        provider.secret_reference().validate(provider.scope())?;
        let mut registration = Self {
            id_digest: Digest::from_text(id.as_ref()),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_api_revision: provider.definition().api_revision.clone(),
            provider_digest: provider.provider_digest().clone(),
            permission_snapshot,
            consent,
            scope: provider.scope().clone(),
            secret_reference: provider.secret_reference().clone(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::pending(),
        };
        if id.as_ref().is_empty() {
            return Err(RenderDeploymentError::InvalidIdentifier {
                field: "registration",
            });
        }
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id_digest(&self) -> &Digest {
        &self.id_digest
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
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
    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn consent_digest(&self) -> &Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn scope(&self) -> &RenderDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    #[must_use]
    pub const fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract_digest.as_str() != contract_digest()
            || self.provider_api_revision != RENDER_PROVIDER_API_REVISION
            || self.registration_revision.get() == 0
        {
            return Err(RenderDeploymentError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self.registration_digest != self.calculate_digest() {
            return Err(RenderDeploymentError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(RegistrationStatus::Revoked)
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(RenderDeploymentError::RegistrationReversed);
        }
        self.transition(RegistrationStatus::Active)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(RenderDeploymentError::AlreadyReversed);
        }
        self.transition(RegistrationStatus::Reversed)
    }

    fn transition(&mut self, status: RegistrationStatus) -> Result<RegistrationTransitionEvidence> {
        let previous_status = self.status;
        if previous_status == RegistrationStatus::Revoked && status == RegistrationStatus::Revoked {
            return Err(RenderDeploymentError::AlreadyRevoked);
        }
        let previous_revision = self.registration_revision;
        let previous_digest = self.registration_digest.clone();
        self.registration_revision = self.registration_revision.bump()?;
        self.status = status;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            status,
            previous_revision,
            self.registration_revision,
            previous_digest,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "render-registration/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_api", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.get().to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_error(error: &RenderDeploymentError) -> Self {
        let (category, status_code, retry_after_seconds) = match error {
            RenderDeploymentError::Transport(transport) => (
                transport.category().to_owned(),
                transport.status_code(),
                match transport {
                    RenderTransportError::RateLimited {
                        retry_after_seconds,
                    } => *retry_after_seconds,
                    _ => None,
                },
            ),
            RenderDeploymentError::InvalidResponse | RenderDeploymentError::TamperedEvidence => {
                ("tampered".to_owned(), None, None)
            }
            RenderDeploymentError::ScopeMismatch => ("scope_mismatch".to_owned(), None, None),
            RenderDeploymentError::PaginationBound => ("pagination_bound".to_owned(), None, None),
            RenderDeploymentError::PaginationLoop => ("pagination_loop".to_owned(), None, None),
            RenderDeploymentError::StaleRevision => ("stale_revision".to_owned(), None, None),
            other => (format!("{other:?}"), None, None),
        };
        let failure_digest = Digest::from_parts(
            "render-failure/v1",
            &[
                ("category", category.clone()),
                (
                    "status_code",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "retry_after",
                    retry_after_seconds.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            category,
            status_code,
            retry_after_seconds,
            failure_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub service_digest: Digest,
    pub deploy_digest: Digest,
    pub health_digest: Digest,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    fn new(
        registration: &RenderDeploymentRegistration,
        service: Option<&RenderServiceProjection>,
        deploy: Option<&RenderDeployProjection>,
        health: Option<&RenderHealthProjection>,
        cursor_digests: Vec<Digest>,
    ) -> Self {
        Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_snapshot.digest().clone(),
            consent_digest: registration.consent.digest().clone(),
            scope_digest: registration.scope.digest(),
            service_digest: service
                .map_or_else(Digest::pending, |value| value.service_digest.clone()),
            deploy_digest: deploy.map_or_else(Digest::pending, |value| value.deploy_digest.clone()),
            health_digest: health.map_or_else(Digest::pending, |value| value.health_digest.clone()),
            cursor_digests,
            evidence_digest: Digest::pending(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderDeploymentEvidence {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub service: Option<RenderServiceProjection>,
    pub deployment: Option<RenderDeployProjection>,
    pub health: Option<RenderHealthProjection>,
    pub state: RenderResultState,
    pub page_count: u16,
    pub deploy_count: u32,
    pub listing_complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub backoff: Option<BackoffReceipt>,
    pub failure: Option<FailureEvidence>,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub evidence_digests: EvidenceDigests,
    pub evidence_digest: Digest,
}

impl RenderDeploymentEvidence {
    fn new(
        registration: &RenderDeploymentRegistration,
        provenance: ProviderProvenance,
        service: Option<RenderServiceProjection>,
        deployment: Option<RenderDeployProjection>,
        health: Option<RenderHealthProjection>,
        state: RenderResultState,
        page_count: u16,
        deploy_count: u32,
        listing_complete: bool,
        cursor_digests: Vec<Digest>,
        backoff: Option<BackoffReceipt>,
        failure: Option<FailureEvidence>,
    ) -> Self {
        let mut evidence = Self {
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            scope_digest: registration.scope.digest(),
            permission_digest: registration.permission_snapshot.digest().clone(),
            consent_digest: registration.consent.digest().clone(),
            project: ProjectProjection::from(registration.scope.project()),
            mission: MissionProjection::from(registration.scope.mission()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            service,
            deployment,
            health,
            state,
            page_count,
            deploy_count,
            listing_complete,
            cursor_digests,
            backoff,
            failure,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            evidence_digests: EvidenceDigests::new(registration, None, None, None, Vec::new()),
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digests = EvidenceDigests::new(
            registration,
            evidence.service.as_ref(),
            evidence.deployment.as_ref(),
            evidence.health.as_ref(),
            evidence.cursor_digests.clone(),
        );
        evidence.evidence_digest = evidence.compute_digest();
        evidence.evidence_digests.evidence_digest = evidence.evidence_digest.clone();
        evidence
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        if let Some(service) = &self.service {
            service.validate()?;
        }
        if let Some(deployment) = &self.deployment {
            deployment.validate()?;
        }
        if let Some(health) = &self.health {
            health.validate()?;
        }
        if self.evidence_digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.compute_digest()
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        value.evidence_digests.evidence_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderDeploymentProposal {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub state: RenderResultState,
    pub evidence: RenderDeploymentEvidence,
    pub provenance: ProviderProvenance,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl RenderDeploymentProposal {
    fn from_evidence(evidence: RenderDeploymentEvidence) -> Self {
        let mut proposal = Self {
            registration_digest: evidence.registration_digest.clone(),
            registration_revision: evidence.registration_revision,
            scope_digest: evidence.scope_digest.clone(),
            state: evidence.state,
            provenance: evidence.provenance.clone(),
            evidence,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.proposal_digest.clone()
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if !self.proposal_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.registration_digest != self.evidence.registration_digest
            || self.scope_digest != self.evidence.scope_digest
            || self.state != self.evidence.state
            || self.provenance != self.evidence.provenance
            || self.proposal_digest != self.compute_digest()
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        self.evidence.validate_integrity()
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenderDeploymentReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub recorded_at: u64,
    pub provenance: ProviderProvenance,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub receipt_digest: Digest,
}

impl RenderDeploymentReceipt {
    fn new(proposal: &RenderDeploymentProposal, recorded_at: u64) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            recorded_at,
            provenance: proposal.provenance.clone(),
            durable_provider_receipt: false,
            connected: false,
            native: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.durable_provider_receipt
            || self.connected
            || self.native
            || self.receipt_digest != self.compute_digest()
        {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.receipt_digest = Digest::pending();
        canonical_digest(&value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Tampered,
    RegistrationMismatch,
    ScopeMismatch,
    ConsentMismatch,
    StaleRevision,
    NotReady,
    Partial,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NativeClaim,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub proposal_digest: Digest,
    pub verified: bool,
    pub adoptable: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(proposal: &RenderDeploymentProposal, failures: Vec<VerificationFailure>) -> Self {
        let verified = failures.is_empty();
        let mut report = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            verified,
            adoptable: false,
            failures,
            verification_digest: Digest::pending(),
        };
        report.verification_digest = canonical_digest(&report);
        report
    }

    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Typed Layer-1 service for bounded Render service/deployment/health
/// metadata. It has no deploy, restart, rollback, or environment authority.
pub struct RenderDeploymentResultService<T: RenderTransport> {
    provider: RenderProvider<T>,
    registration: RenderDeploymentRegistration,
    definition: RenderDeploymentServiceDefinition,
}

impl<T: RenderTransport> fmt::Debug for RenderDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderDeploymentResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: RenderTransport> RenderDeploymentResultService<T> {
    pub fn register(
        provider: RenderProvider<T>,
        registration_id: impl AsRef<str>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = RenderDeploymentRegistration::new(
            registration_id,
            &provider,
            permission_snapshot,
            consent,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    pub fn new(
        provider: RenderProvider<T>,
        registration: RenderDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope().digest() != provider.scope().digest()
            || registration.provider_digest() != provider.provider_digest()
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(RenderDeploymentError::InvalidRegistration);
        }
        Ok(Self {
            provider,
            registration,
            definition: RenderDeploymentServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &RenderProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut RenderProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &RenderDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut RenderDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &RenderDeploymentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn service_definition(&self) -> &RenderDeploymentServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> RenderCapabilityDescription {
        RenderCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: RENDER_PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                "read_service_metadata".to_owned(),
                "read_bounded_deploy_metadata".to_owned(),
                "read_health_metadata".to_owned(),
                "compile_deployment_result_proposal".to_owned(),
                "record_observation".to_owned(),
                "verify_proposal".to_owned(),
            ],
            permissions: crate::model::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            connected: false,
            native: false,
        }
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.registration.consent().clone()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read(&mut self, observed_at: u64) -> Result<RenderDeploymentEvidence> {
        self.ensure_readable(observed_at)?;
        let mut cursor: Option<String> = None;
        let mut pages: u16 = 0;
        let mut deploy_count: u32 = 0;
        let mut listing_complete = false;
        let mut cursor_digests = Vec::new();
        let mut seen_cursors = BTreeSet::new();
        let mut backoff: Option<BackoffReceipt>;
        let mut failure: Option<FailureEvidence> = None;

        let service = match self.provider.read_service() {
            Ok(value) => {
                backoff = self.provider.take_backoff();
                value
            }
            Err(error) => {
                backoff = self.provider.take_backoff();
                return self.failure_evidence(error, 0, 0, false, Vec::new(), backoff);
            }
        };
        let service_projection = match service.to_projection() {
            Ok(value) => value,
            Err(error) => {
                return self.failure_evidence(error, 0, 0, false, Vec::new(), backoff);
            }
        };
        let mut target_deploy: Option<RenderDeploySnapshot> = None;
        let mut state_override = None;

        loop {
            if pages >= MAX_PAGES {
                state_override = Some(RenderResultState::PaginationBound);
                failure = Some(FailureEvidence::from_error(
                    &RenderDeploymentError::PaginationBound,
                ));
                break;
            }
            let cursor_arg = cursor.as_deref().map(|value| (value, pages + 1));
            let page = match self.provider.list_deploys(cursor_arg) {
                Ok(value) => {
                    if let Some(value) = self.provider.take_backoff() {
                        backoff = Some(value);
                    }
                    value
                }
                Err(error) => {
                    if let Some(value) = self.provider.take_backoff() {
                        backoff = Some(value);
                    }
                    state_override = Some(state_for_error(&error));
                    return self.build_evidence(
                        Some(service_projection),
                        None,
                        None,
                        state_override.unwrap_or(RenderResultState::ProviderUnknown),
                        pages,
                        deploy_count,
                        false,
                        cursor_digests,
                        backoff,
                        Some(FailureEvidence::from_error(&error)),
                    );
                }
            };
            pages += 1;
            deploy_count = deploy_count
                .saturating_add(u32::try_from(page.deploys().len()).unwrap_or(u32::MAX));
            if let Some(deploy) = page
                .deploys()
                .iter()
                .find(|deploy| deploy.deploy_id() == self.scope().deploy_id())
            {
                target_deploy = Some(deploy.clone());
            }
            if let Some(next_cursor) = page.next_cursor.clone() {
                let next_digest = page
                    .next_cursor_digest()
                    .ok_or(RenderDeploymentError::InvalidResponse)?;
                if !seen_cursors.insert(next_digest.clone()) {
                    cursor_digests.push(next_digest);
                    state_override = Some(RenderResultState::PaginationLoop);
                    failure = Some(FailureEvidence::from_error(
                        &RenderDeploymentError::PaginationLoop,
                    ));
                    break;
                }
                cursor_digests.push(next_digest);
                cursor = Some(next_cursor);
            } else {
                listing_complete = true;
                break;
            }
        }

        let deployment = if state_override.is_none() {
            match target_deploy {
                Some(_) => match self.provider.read_deploy() {
                    Ok(value) => {
                        if let Some(value) = self.provider.take_backoff() {
                            backoff = Some(value);
                        }
                        Some(value)
                    }
                    Err(error) => {
                        if let Some(value) = self.provider.take_backoff() {
                            backoff = Some(value);
                        }
                        state_override = Some(state_for_error(&error));
                        failure = Some(FailureEvidence::from_error(&error));
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let deployment_projection = match deployment.as_ref() {
            Some(value) => match value.to_projection() {
                Ok(projection) => Some(projection),
                Err(error) => {
                    state_override = Some(RenderResultState::Tampered);
                    failure = Some(FailureEvidence::from_error(&error));
                    None
                }
            },
            None => None,
        };
        let state = state_override.unwrap_or_else(|| {
            let Some(deployment) = &deployment else {
                return if listing_complete {
                    RenderResultState::NotFound
                } else {
                    RenderResultState::Partial
                };
            };
            if deployment.commit_digest() != self.scope().commit_digest() {
                return RenderResultState::StaleRevision;
            }
            match (
                service.status(),
                deployment.status(),
                service.health().state(),
                deployment.health().state(),
            ) {
                (_, _, RenderHealthState::Unknown, _) | (_, _, _, RenderHealthState::Unknown) => {
                    RenderResultState::HealthUnknown
                }
                (
                    _,
                    RenderDeployStatus::Live,
                    RenderHealthState::Healthy,
                    RenderHealthState::Healthy,
                ) => RenderResultState::Ready,
                (_, status, _, _) if status.is_in_progress() => RenderResultState::InProgress,
                (_, RenderDeployStatus::Failed, _, _) => RenderResultState::Failed,
                (_, RenderDeployStatus::Canceled, _, _) => RenderResultState::Canceled,
                (
                    RenderServiceStatus::Available,
                    _,
                    RenderHealthState::Degraded | RenderHealthState::Unhealthy,
                    _,
                ) => RenderResultState::HealthUnknown,
                _ => RenderResultState::ProviderUnknown,
            }
        });
        let health_projection = Some(service.health().projection()?);
        self.build_evidence(
            Some(service_projection),
            deployment_projection,
            health_projection,
            state,
            pages,
            deploy_count,
            listing_complete,
            cursor_digests,
            backoff,
            failure,
        )
    }

    pub fn read_with_fence(
        &mut self,
        request: &crate::model::RenderReadRequest,
        observed_at: u64,
    ) -> Result<RenderDeploymentEvidence> {
        request.validate_for(
            self.scope(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
        )?;
        self.read(observed_at)
    }

    pub fn compile_proposal(&mut self, observed_at: u64) -> Result<RenderDeploymentProposal> {
        let evidence = self.read(observed_at)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: RenderDeploymentEvidence,
    ) -> Result<RenderDeploymentProposal> {
        self.registration.validate()?;
        evidence.validate_integrity()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.scope().digest()
            || evidence.registration_revision != self.registration.registration_revision
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.consent_digest != *self.registration.consent_digest()
        {
            return Err(RenderDeploymentError::InvalidProposal);
        }
        if evidence.state == RenderResultState::Tampered {
            return Err(RenderDeploymentError::TamperedEvidence);
        }
        Ok(RenderDeploymentProposal::from_evidence(evidence))
    }

    pub fn record_observation(
        &self,
        proposal: &RenderDeploymentProposal,
        recorded_at: u64,
    ) -> Result<RenderDeploymentReceipt> {
        self.verify_proposal(proposal)?;
        let receipt = RenderDeploymentReceipt::new(proposal, recorded_at);
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    #[must_use]
    pub fn verify(&self, proposal: &RenderDeploymentProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::Tampered);
        }
        if proposal.registration_digest != self.registration.registration_digest {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope().digest() {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.registration_revision != self.registration.registration_revision {
            failures.push(VerificationFailure::StaleRevision);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationMismatch);
        }
        match proposal.state {
            RenderResultState::Ready => {}
            RenderResultState::Partial
            | RenderResultState::PaginationBound
            | RenderResultState::PaginationLoop => {
                failures.push(VerificationFailure::Partial);
            }
            RenderResultState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            RenderResultState::RateLimited => failures.push(VerificationFailure::RateLimited),
            RenderResultState::ProviderUnknown
            | RenderResultState::Timeout
            | RenderResultState::NotFound
            | RenderResultState::Conflict
            | RenderResultState::HealthUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            RenderResultState::StaleRevision => failures.push(VerificationFailure::StaleRevision),
            RenderResultState::RegistrationRevoked | RenderResultState::ConsentDenied => {
                failures.push(VerificationFailure::ConsentMismatch);
            }
            RenderResultState::Failed
            | RenderResultState::Canceled
            | RenderResultState::InProgress => failures.push(VerificationFailure::NotReady),
            RenderResultState::Tampered => failures.push(VerificationFailure::Tampered),
        }
        if proposal.connected || proposal.native || proposal.first_party {
            failures.push(VerificationFailure::NativeClaim);
        }
        VerificationReport::new(proposal, failures)
    }

    pub fn verify_proposal(
        &self,
        proposal: &RenderDeploymentProposal,
    ) -> Result<VerificationReport> {
        let report = self.verify(proposal);
        if report.failures.contains(&VerificationFailure::Tampered) {
            Err(RenderDeploymentError::TamperedEvidence)
        } else {
            Ok(report)
        }
    }

    fn ensure_readable(&self, observed_at: u64) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(RenderDeploymentError::RegistrationInactive);
        }
        if !self.registration.consent().is_active_at(observed_at) {
            return Err(RenderDeploymentError::ConsentMismatch);
        }
        Ok(())
    }

    fn failure_evidence(
        &self,
        error: RenderDeploymentError,
        page_count: u16,
        deploy_count: u32,
        listing_complete: bool,
        cursor_digests: Vec<Digest>,
        backoff: Option<BackoffReceipt>,
    ) -> Result<RenderDeploymentEvidence> {
        let state = state_for_error(&error);
        self.build_evidence(
            // An error before service metadata has no safe service projection.
            // The exact Project/Mission/Work Product scope still remains bound.
            empty_service_projection(),
            None,
            None,
            state,
            page_count,
            deploy_count,
            listing_complete,
            cursor_digests,
            backoff,
            Some(FailureEvidence::from_error(&error)),
        )
    }

    fn build_evidence(
        &self,
        service: Option<RenderServiceProjection>,
        deployment: Option<RenderDeployProjection>,
        health: Option<RenderHealthProjection>,
        state: RenderResultState,
        page_count: u16,
        deploy_count: u32,
        listing_complete: bool,
        cursor_digests: Vec<Digest>,
        backoff: Option<BackoffReceipt>,
        failure: Option<FailureEvidence>,
    ) -> Result<RenderDeploymentEvidence> {
        let evidence = RenderDeploymentEvidence::new(
            &self.registration,
            self.provider.provenance(),
            service,
            deployment,
            health,
            state,
            page_count,
            deploy_count,
            listing_complete,
            cursor_digests,
            backoff,
            failure,
        );
        evidence.validate_integrity()?;
        Ok(evidence)
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded Render value serializes");
    Digest::from_bytes(&bytes)
}

fn state_for_error(error: &RenderDeploymentError) -> RenderResultState {
    match error {
        RenderDeploymentError::Transport(RenderTransportError::AccessLost) => {
            RenderResultState::AccessLoss
        }
        RenderDeploymentError::Transport(RenderTransportError::RateLimited { .. }) => {
            RenderResultState::RateLimited
        }
        RenderDeploymentError::Transport(RenderTransportError::Timeout) => {
            RenderResultState::Timeout
        }
        RenderDeploymentError::Transport(RenderTransportError::NotFound) => {
            RenderResultState::NotFound
        }
        RenderDeploymentError::Transport(RenderTransportError::Conflict) => {
            RenderResultState::Conflict
        }
        RenderDeploymentError::Transport(RenderTransportError::Partial) => {
            RenderResultState::Partial
        }
        RenderDeploymentError::PaginationBound => RenderResultState::PaginationBound,
        RenderDeploymentError::PaginationLoop => RenderResultState::PaginationLoop,
        RenderDeploymentError::StaleRevision => RenderResultState::StaleRevision,
        RenderDeploymentError::ScopeMismatch
        | RenderDeploymentError::InvalidResponse
        | RenderDeploymentError::TamperedEvidence
        | RenderDeploymentError::ProviderTamper => RenderResultState::Tampered,
        RenderDeploymentError::RegistrationInactive | RenderDeploymentError::SecretRevoked => {
            RenderResultState::RegistrationRevoked
        }
        RenderDeploymentError::ConsentMismatch | RenderDeploymentError::InvalidConsent => {
            RenderResultState::ConsentDenied
        }
        _ => RenderResultState::ProviderUnknown,
    }
}

fn empty_service_projection() -> Option<RenderServiceProjection> {
    None
}
