use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::error::{HerokuDeploymentError, HerokuTransportError, Result};
use crate::model::{
    BackoffReceipt, ConsentScope, Digest, HerokuAppProjection, HerokuBuildProjection,
    HerokuDeploymentScope, HerokuDeploymentState, HerokuDynoProjection, HerokuReadRequest,
    HerokuReleaseProjection, HerokuSlugProjection, MissionProjection, PermissionSnapshot,
    ProjectProjection, ProviderProvenance, RegistrationStatus, Revision, SecretReference,
    WorkProductProjection, idempotency_digest,
};
use crate::provider::{HerokuProvider, HerokuProviderSnapshot};
use crate::transport::HerokuTransport;
use crate::{
    CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, HEROKU_PROVIDER_API_REVISION,
    MISSION_CONSUMER_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuDeploymentServiceDefinition {
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
    pub work_product_adoption: bool,
}

impl Default for HerokuDeploymentServiceDefinition {
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
            work_product_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuCapabilityDescription {
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
    pub first_party: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct HerokuDeploymentRegistration {
    id_digest: Digest,
    contract_digest: Digest,
    provider_api_revision: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: HerokuDeploymentScope,
    secret_reference: SecretReference,
    registration_revision: Revision,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl fmt::Debug for HerokuDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerokuDeploymentRegistration")
            .field("id_digest", &self.id_digest)
            .field("contract_digest", &self.contract_digest)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", self.permission_snapshot.digest())
            .field("consent_digest", self.consent.digest())
            .field("scope_digest", &self.scope.digest())
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

impl Serialize for HerokuDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HerokuDeploymentRegistration", 12)?;
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
        state.serialize_field("revocable", &true)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
}

impl HerokuDeploymentRegistration {
    pub fn new<T: HerokuTransport>(
        registration_id: impl AsRef<str>,
        provider: &HerokuProvider<T>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        if registration_id.as_ref().is_empty() {
            return Err(HerokuDeploymentError::InvalidRegistration);
        }
        permission_snapshot.validate()?;
        consent.validate_at(0)?;
        provider
            .definition()
            .is_layer_one_honest()
            .then_some(())
            .ok_or(HerokuDeploymentError::InvalidRegistration)?;
        let registration_revision = Revision::new(registration_revision)?;
        let mut registration = Self {
            id_digest: Digest::from_text(registration_id.as_ref()),
            contract_digest: Digest::parse(CONTRACT_DIGEST)?,
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
        registration.registration_digest = registration.compute_digest();
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
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.permission_snapshot.digest()
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
    pub fn scope(&self) -> &HerokuDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    #[must_use]
    pub fn registration_revision(&self) -> Revision {
        self.registration_revision
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn validate(&self) -> Result<()> {
        self.permission_snapshot.validate()?;
        self.consent.validate_at(0)?;
        self.scope.digest().validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self.contract_digest != Digest::parse(CONTRACT_DIGEST)?
            || self.registration_digest != self.compute_digest()
        {
            return Err(HerokuDeploymentError::InvalidRegistration);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(
            RegistrationStatus::Revoked,
            HerokuDeploymentError::AlreadyRevoked,
        )
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status == RegistrationStatus::Reversed {
            return Err(HerokuDeploymentError::RegistrationReversed);
        }
        self.transition(
            RegistrationStatus::Active,
            HerokuDeploymentError::InvalidRegistration,
        )
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.transition(
            RegistrationStatus::Reversed,
            HerokuDeploymentError::AlreadyReversed,
        )
    }

    fn transition(
        &mut self,
        to: RegistrationStatus,
        already: HerokuDeploymentError,
    ) -> Result<RegistrationTransitionEvidence> {
        if self.status == to {
            return Err(already);
        }
        let from = self.status;
        self.status = to;
        self.registration_revision = self.registration_revision.bump()?;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationTransitionEvidence {
            from,
            to,
            registration_revision: self.registration_revision,
            registration_digest: self.registration_digest.clone(),
        })
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "heroku-registration/v1",
            &[
                ("id", self.id_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_api", self.provider_api_revision.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "secret_reference",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_scope",
                    self.secret_reference.scope_digest().as_str().to_owned(),
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
    pub detail_digest: Digest,
}

impl FailureEvidence {
    fn from_error(error: &HerokuDeploymentError) -> Self {
        let (category, status_code) =
            match error {
                HerokuDeploymentError::Transport(transport) => {
                    (transport.category(), transport.status_code())
                }
                HerokuDeploymentError::ScopeMismatch => ("scope_mismatch", None),
                HerokuDeploymentError::StaleRevision => ("stale_revision", None),
                HerokuDeploymentError::TamperedEvidence | HerokuDeploymentError::ProviderTamper => {
                    ("tamper", None)
                }
                HerokuDeploymentError::PaginationLoop => ("pagination_loop", None),
                HerokuDeploymentError::PaginationBound => ("pagination_bound", None),
                HerokuDeploymentError::RecordingConflict
                | HerokuDeploymentError::ReplayDetected => ("replay", None),
                HerokuDeploymentError::ConsentMismatch
                | HerokuDeploymentError::Expired
                | HerokuDeploymentError::InvalidConsent => ("consent_denied", None),
                HerokuDeploymentError::RegistrationInactive
                | HerokuDeploymentError::SecretRevoked => ("registration_revoked", None),
                _ => ("provider_unknown", None),
            };
        Self {
            category: category.to_owned(),
            status_code,
            detail_digest: Digest::from_parts(
                "heroku-failure/v1",
                &[("category", category.to_owned())],
            ),
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
    pub app_digest: Digest,
    pub build_digest: Digest,
    pub release_digest: Digest,
    pub slug_digest: Digest,
    pub dyno_digest: Digest,
    pub cursor_digests: Vec<Digest>,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    fn new(
        registration: &HerokuDeploymentRegistration,
        app: Option<&HerokuAppProjection>,
        build: Option<&HerokuBuildProjection>,
        release: Option<&HerokuReleaseProjection>,
        slug: Option<&HerokuSlugProjection>,
        dyno: Option<&HerokuDynoProjection>,
        cursor_digests: Vec<Digest>,
    ) -> Self {
        Self {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_digest().clone(),
            consent_digest: registration.consent_digest().clone(),
            scope_digest: registration.scope.digest(),
            app_digest: app.map_or_else(Digest::pending, |value| value.app_digest.clone()),
            build_digest: build.map_or_else(Digest::pending, |value| value.build_digest.clone()),
            release_digest: release
                .map_or_else(Digest::pending, |value| value.release_digest.clone()),
            slug_digest: slug.map_or_else(Digest::pending, |value| value.slug_digest.clone()),
            dyno_digest: dyno.map_or_else(Digest::pending, |value| value.dyno_digest.clone()),
            cursor_digests,
            evidence_digest: Digest::pending(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HerokuDeploymentEvidence {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub app: Option<HerokuAppProjection>,
    pub build: Option<HerokuBuildProjection>,
    pub release: Option<HerokuReleaseProjection>,
    pub slug: Option<HerokuSlugProjection>,
    pub dyno: Option<HerokuDynoProjection>,
    pub state: HerokuDeploymentState,
    pub page_count: u16,
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

impl HerokuDeploymentEvidence {
    fn new(
        registration: &HerokuDeploymentRegistration,
        provenance: ProviderProvenance,
        projections: Option<HerokuProviderSnapshot>,
        state: HerokuDeploymentState,
        page_count: u16,
        listing_complete: bool,
        cursor_digests: Vec<Digest>,
        backoff: Option<BackoffReceipt>,
        failure: Option<FailureEvidence>,
    ) -> Self {
        let (app, build, release, slug, dyno) =
            projections.map_or((None, None, None, None, None), |snapshot| {
                (
                    Some(snapshot.app),
                    Some(snapshot.build),
                    Some(snapshot.release),
                    Some(snapshot.slug),
                    Some(snapshot.dyno),
                )
            });
        let mut evidence = Self {
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            scope_digest: registration.scope.digest(),
            permission_digest: registration.permission_digest().clone(),
            consent_digest: registration.consent_digest().clone(),
            project: ProjectProjection::from(registration.scope.project()),
            mission: MissionProjection::from(registration.scope.mission()),
            work_product: WorkProductProjection::from(registration.scope.work_product()),
            app,
            build,
            release,
            slug,
            dyno,
            state,
            page_count,
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
            evidence_digests: EvidenceDigests::new(
                registration,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
            ),
            evidence_digest: Digest::pending(),
        };
        evidence.evidence_digests = EvidenceDigests::new(
            registration,
            evidence.app.as_ref(),
            evidence.build.as_ref(),
            evidence.release.as_ref(),
            evidence.slug.as_ref(),
            evidence.dyno.as_ref(),
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
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        for projection in [
            self.app.as_ref().map(HerokuAppProjection::validate),
            self.build.as_ref().map(HerokuBuildProjection::validate),
            self.release.as_ref().map(HerokuReleaseProjection::validate),
            self.slug.as_ref().map(HerokuSlugProjection::validate),
            self.dyno.as_ref().map(HerokuDynoProjection::validate),
        ]
        .into_iter()
        .flatten()
        {
            projection?;
        }
        if self.evidence_digests.evidence_digest != self.evidence_digest
            || self.evidence_digest != self.compute_digest()
        {
            return Err(HerokuDeploymentError::TamperedEvidence);
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
pub struct HerokuDeploymentProposal {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub state: HerokuDeploymentState,
    pub evidence: HerokuDeploymentEvidence,
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

impl HerokuDeploymentProposal {
    fn from_evidence(evidence: HerokuDeploymentEvidence) -> Self {
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
            return Err(HerokuDeploymentError::TamperedEvidence);
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
pub struct HerokuDeploymentReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub recorded_at: u64,
    pub replayed: bool,
    pub provenance: ProviderProvenance,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub receipt_digest: Digest,
}

impl HerokuDeploymentReceipt {
    fn new(
        proposal: &HerokuDeploymentProposal,
        idempotency_key_digest: Digest,
        recorded_at: u64,
        replayed: bool,
    ) -> Self {
        let mut receipt = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            idempotency_key_digest,
            recorded_at,
            replayed,
            provenance: proposal.provenance.clone(),
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            receipt_digest: Digest::pending(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.durable_provider_receipt
            || self.connected
            || self.native
            || self.first_party
            || self.receipt_digest != self.compute_digest()
        {
            return Err(HerokuDeploymentError::TamperedEvidence);
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
    NotReleased,
    Partial,
    Denied,
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
    fn new(proposal: &HerokuDeploymentProposal, failures: Vec<VerificationFailure>) -> Self {
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

/// Typed Layer-1 service for bounded Heroku app/build/release/slug/dyno
/// metadata. It has no effect, receipt, or Work Product adoption authority.
pub struct HerokuDeploymentResultService<T: HerokuTransport> {
    provider: HerokuProvider<T>,
    registration: HerokuDeploymentRegistration,
    definition: HerokuDeploymentServiceDefinition,
    recordings: BTreeMap<Digest, Digest>,
}

impl<T: HerokuTransport> fmt::Debug for HerokuDeploymentResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HerokuDeploymentResultService")
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("definition", &self.definition)
            .field("recording_count", &self.recordings.len())
            .finish()
    }
}

impl<T: HerokuTransport> HerokuDeploymentResultService<T> {
    pub fn register(
        provider: HerokuProvider<T>,
        registration_id: impl AsRef<str>,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = HerokuDeploymentRegistration::new(
            registration_id,
            &provider,
            permission_snapshot,
            consent,
            registration_revision,
        )?;
        Self::new(provider, registration)
    }

    pub fn new(
        provider: HerokuProvider<T>,
        registration: HerokuDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope().digest() != provider.scope().digest()
            || registration.provider_digest() != provider.provider_digest()
            || registration.secret_reference_digest()
                != provider.secret_reference().reference_digest()
        {
            return Err(HerokuDeploymentError::InvalidRegistration);
        }
        Ok(Self {
            provider,
            registration,
            definition: HerokuDeploymentServiceDefinition::default(),
            recordings: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn provider(&self) -> &HerokuProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut HerokuProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> &HerokuDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut HerokuDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &HerokuDeploymentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn service_definition(&self) -> &HerokuDeploymentServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> HerokuCapabilityDescription {
        HerokuCapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: HEROKU_PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                "read_app_metadata".to_owned(),
                "read_build_metadata".to_owned(),
                "read_bounded_release_metadata".to_owned(),
                "read_slug_metadata".to_owned(),
                "read_dyno_metadata".to_owned(),
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
            first_party: false,
        }
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.registration.consent().clone()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read(&mut self, observed_at: u64) -> Result<HerokuDeploymentEvidence> {
        self.ensure_readable(observed_at)?;
        let provenance = self.provider.provenance();
        let snapshot = match self.provider.read_snapshot() {
            Ok(snapshot) => {
                let state = state_for_snapshot(&snapshot);
                let page_count = snapshot.page_count;
                let cursors = snapshot.cursor_digests.clone();
                let backoff = snapshot.backoff.clone();
                return Ok(self.build_evidence(
                    provenance,
                    Some(snapshot),
                    state,
                    page_count,
                    true,
                    cursors,
                    backoff,
                    None,
                ));
            }
            Err(error) => error,
        };
        let backoff = self.provider.take_backoff();
        Ok(self.build_evidence(
            provenance,
            None,
            state_for_error(&snapshot),
            0,
            false,
            Vec::new(),
            backoff,
            Some(FailureEvidence::from_error(&snapshot)),
        ))
    }

    pub fn read_with_fence(
        &mut self,
        request: &HerokuReadRequest,
        observed_at: u64,
    ) -> Result<HerokuDeploymentEvidence> {
        request.validate_for(
            self.scope(),
            self.registration.registration_digest(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
        )?;
        self.read(observed_at)
    }

    pub fn compile_proposal(&mut self, observed_at: u64) -> Result<HerokuDeploymentProposal> {
        let evidence = self.read(observed_at)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: HerokuDeploymentEvidence,
    ) -> Result<HerokuDeploymentProposal> {
        self.registration.validate()?;
        evidence.validate_integrity()?;
        if evidence.registration_digest != self.registration.registration_digest
            || evidence.scope_digest != self.scope().digest()
            || evidence.registration_revision != self.registration.registration_revision
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.consent_digest != *self.registration.consent_digest()
        {
            return Err(HerokuDeploymentError::InvalidProposal);
        }
        if evidence.state == HerokuDeploymentState::Tampered {
            return Err(HerokuDeploymentError::TamperedEvidence);
        }
        Ok(HerokuDeploymentProposal::from_evidence(evidence))
    }

    pub fn record_observation(
        &mut self,
        proposal: &HerokuDeploymentProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: u64,
    ) -> Result<HerokuDeploymentReceipt> {
        self.verify_proposal(proposal)?;
        let key_digest = idempotency_digest(idempotency_key)?;
        let replayed = match self.recordings.get(&key_digest) {
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(HerokuDeploymentError::RecordingConflict),
            None => false,
        };
        self.recordings
            .entry(key_digest.clone())
            .or_insert_with(|| proposal.proposal_digest.clone());
        let receipt = HerokuDeploymentReceipt::new(proposal, key_digest, recorded_at, replayed);
        receipt.validate_integrity()?;
        Ok(receipt)
    }

    #[must_use]
    pub fn verify(&self, proposal: &HerokuDeploymentProposal) -> VerificationReport {
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
            HerokuDeploymentState::Released => {}
            HerokuDeploymentState::Building | HerokuDeploymentState::Failed => {
                failures.push(VerificationFailure::NotReleased);
            }
            HerokuDeploymentState::Partial
            | HerokuDeploymentState::PaginationBound
            | HerokuDeploymentState::PaginationLoop => {
                failures.push(VerificationFailure::Partial);
            }
            HerokuDeploymentState::Denied | HerokuDeploymentState::ConsentDenied => {
                failures.push(VerificationFailure::Denied);
            }
            HerokuDeploymentState::RateLimited => failures.push(VerificationFailure::RateLimited),
            HerokuDeploymentState::StaleRevision => {
                failures.push(VerificationFailure::StaleRevision);
            }
            HerokuDeploymentState::Tampered | HerokuDeploymentState::Replay => {
                failures.push(VerificationFailure::Tampered);
            }
            HerokuDeploymentState::Unknown
            | HerokuDeploymentState::ProviderUnknown
            | HerokuDeploymentState::RegistrationRevoked
            | HerokuDeploymentState::NotFound
            | HerokuDeploymentState::Conflict => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
        }
        if proposal.connected || proposal.native || proposal.first_party {
            failures.push(VerificationFailure::NativeClaim);
        }
        VerificationReport::new(proposal, failures)
    }

    pub fn verify_proposal(
        &self,
        proposal: &HerokuDeploymentProposal,
    ) -> Result<VerificationReport> {
        let report = self.verify(proposal);
        if report.failures.contains(&VerificationFailure::Tampered) {
            Err(HerokuDeploymentError::TamperedEvidence)
        } else {
            Ok(report)
        }
    }

    fn ensure_readable(&self, observed_at: u64) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(HerokuDeploymentError::RegistrationInactive);
        }
        self.registration.consent().validate_at(observed_at)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence(
        &self,
        provenance: ProviderProvenance,
        snapshot: Option<HerokuProviderSnapshot>,
        state: HerokuDeploymentState,
        page_count: u16,
        listing_complete: bool,
        cursor_digests: Vec<Digest>,
        backoff: Option<BackoffReceipt>,
        failure: Option<FailureEvidence>,
    ) -> HerokuDeploymentEvidence {
        HerokuDeploymentEvidence::new(
            &self.registration,
            provenance,
            snapshot,
            state,
            page_count,
            listing_complete,
            cursor_digests,
            backoff,
            failure,
        )
    }
}

fn state_for_snapshot(snapshot: &HerokuProviderSnapshot) -> HerokuDeploymentState {
    if matches!(
        snapshot.build.status,
        crate::model::HerokuBuildStatus::Pending | crate::model::HerokuBuildStatus::Building
    ) || matches!(
        snapshot.release.status,
        crate::model::HerokuReleaseStatus::Pending
    ) || matches!(snapshot.dyno.state, crate::model::HerokuDynoState::Starting)
    {
        HerokuDeploymentState::Building
    } else if matches!(
        snapshot.build.status,
        crate::model::HerokuBuildStatus::Failed
    ) || matches!(
        snapshot.release.status,
        crate::model::HerokuReleaseStatus::Failed
    ) || matches!(snapshot.dyno.state, crate::model::HerokuDynoState::Crashed)
    {
        HerokuDeploymentState::Failed
    } else if matches!(
        snapshot.build.status,
        crate::model::HerokuBuildStatus::Unknown
    ) || matches!(
        snapshot.release.status,
        crate::model::HerokuReleaseStatus::Unknown
    ) || matches!(
        snapshot.slug.status,
        crate::model::HerokuSlugStatus::Unknown
    ) || matches!(snapshot.dyno.state, crate::model::HerokuDynoState::Unknown)
    {
        HerokuDeploymentState::Unknown
    } else if matches!(
        snapshot.release.status,
        crate::model::HerokuReleaseStatus::Released
    ) {
        HerokuDeploymentState::Released
    } else {
        HerokuDeploymentState::Unknown
    }
}

fn state_for_error(error: &HerokuDeploymentError) -> HerokuDeploymentState {
    match error {
        HerokuDeploymentError::Transport(HerokuTransportError::AccessDenied) => {
            HerokuDeploymentState::Denied
        }
        HerokuDeploymentError::Transport(HerokuTransportError::NotFound) => {
            HerokuDeploymentState::NotFound
        }
        HerokuDeploymentError::Transport(HerokuTransportError::Conflict) => {
            HerokuDeploymentState::Conflict
        }
        HerokuDeploymentError::Transport(HerokuTransportError::RateLimited { .. }) => {
            HerokuDeploymentState::RateLimited
        }
        HerokuDeploymentError::Transport(HerokuTransportError::Partial) => {
            HerokuDeploymentState::Partial
        }
        HerokuDeploymentError::TamperedEvidence | HerokuDeploymentError::ProviderTamper => {
            HerokuDeploymentState::Tampered
        }
        HerokuDeploymentError::StaleRevision => HerokuDeploymentState::StaleRevision,
        HerokuDeploymentError::PaginationLoop => HerokuDeploymentState::PaginationLoop,
        HerokuDeploymentError::PaginationBound => HerokuDeploymentState::PaginationBound,
        HerokuDeploymentError::RegistrationInactive | HerokuDeploymentError::SecretRevoked => {
            HerokuDeploymentState::RegistrationRevoked
        }
        HerokuDeploymentError::ConsentMismatch
        | HerokuDeploymentError::Expired
        | HerokuDeploymentError::InvalidConsent => HerokuDeploymentState::ConsentDenied,
        HerokuDeploymentError::ReplayDetected | HerokuDeploymentError::RecordingConflict => {
            HerokuDeploymentState::Replay
        }
        _ => HerokuDeploymentState::ProviderUnknown,
    }
}

fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    Digest::from_bytes(&serde_json::to_vec(value).expect("Layer-1 values serialize"))
}
