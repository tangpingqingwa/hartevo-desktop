use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionHcpPackerArtifactConsumer;
use crate::error::{HcpPackerArtifactResultError, Result};
use crate::model::{
    Digest, EvidenceDigests, FailureEvidence, HcpPackerArtifactEvidence, HcpPackerArtifactScope,
    HcpPackerEvidenceState, PermissionFence, SecretReference, TransportProvenance,
};
use crate::provider::{
    GetBucketRequest, GetChannelRequest, GetVersionRequest, HcpPackerProvider,
    HcpPackerProviderDefinition, HcpPackerTransport, ListArtifactsRequest, ListBuildsRequest,
};
use crate::{
    CONTRACT_DIGEST, CONTRACT_VERSION, MAX_ARTIFACTS, MAX_BUILDS, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_REQUESTS_PER_READ, MAX_RESPONSE_BYTES, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    SERVICE_ID,
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
        let transition_digest = Digest::from_parts(
            "hcp-packer-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
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
pub struct HcpPackerArtifactResultRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope: HcpPackerArtifactScope,
    scope_digest: Digest,
    evidence_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl HcpPackerArtifactResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: HcpPackerArtifactScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: &HcpPackerProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty()
            || id.len() > crate::MAX_IDENTIFIER_BYTES
            || id.chars().any(char::is_control)
        {
            return Err(HcpPackerArtifactResultError::InvalidRegistration);
        }
        permission.validate()?;
        provider.validate()?;
        scope.validate()?;
        secret_reference.validate(&scope)?;
        if registration_revision == 0 {
            return Err(HcpPackerArtifactResultError::InvalidRegistration);
        }
        let contract_digest = Digest::parse(CONTRACT_DIGEST.to_owned())?;
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_digest: permission.digest().clone(),
            scope_digest: scope.digest(),
            scope,
            evidence_digest: Digest::zero(),
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::zero(),
        };
        registration.evidence_digest = registration.compute_evidence_digest();
        registration.registration_digest = registration.compute_registration_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
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

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
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

    pub fn scope(&self) -> &HcpPackerArtifactScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > crate::MAX_IDENTIFIER_BYTES
            || self.id.chars().any(char::is_control)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != crate::contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_digest != Digest::from_text(PROVIDER_API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != self.compute_evidence_digest()
            || self.registration_digest != self.compute_registration_digest()
        {
            return Err(HcpPackerArtifactResultError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.permission_digest.validate()?;
        self.provider_digest.validate()?;
        Ok(())
    }

    pub fn recomputed_digest(&self) -> Digest {
        self.compute_registration_digest()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(HcpPackerArtifactResultError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(HcpPackerArtifactResultError::RegistrationStateConflict);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.compute_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(HcpPackerArtifactResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.compute_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(HcpPackerArtifactResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.compute_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn compute_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-evidence-binding/v1",
            &[
                (
                    "plugin",
                    Digest::from_text(PLUGIN_VERSION).as_str().to_owned(),
                ),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
            ],
        )
    }

    fn compute_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
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

impl fmt::Debug for HcpPackerArtifactResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HcpPackerArtifactResultRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("evidence_digest", &self.evidence_digest)
            .field("secret_reference", &self.secret_reference)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for HcpPackerArtifactResultRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut value = serializer.serialize_struct("HcpPackerArtifactResultRegistration", 16)?;
        value.serialize_field("id", &self.id)?;
        value.serialize_field("pluginVersion", &self.plugin_version)?;
        value.serialize_field("contractVersion", &self.contract_version)?;
        value.serialize_field("contractDigest", &self.contract_digest)?;
        value.serialize_field("providerId", &self.provider_id)?;
        value.serialize_field("providerRevision", &self.provider_revision)?;
        value.serialize_field("providerRelease", &self.provider_release)?;
        value.serialize_field("providerDigest", &self.provider_digest)?;
        value.serialize_field("apiDigest", &self.api_digest)?;
        value.serialize_field("permissionDigest", &self.permission_digest)?;
        value.serialize_field("scopeDigest", &self.scope_digest)?;
        value.serialize_field("evidenceDigest", &self.evidence_digest)?;
        value.serialize_field("secretReference", &self.secret_reference)?;
        value.serialize_field("registrationRevision", &self.registration_revision)?;
        value.serialize_field("status", &self.status)?;
        value.serialize_field("registrationDigest", &self.registration_digest)?;
        value.end()
    }
}

pub type HcpPackerRegistration = HcpPackerArtifactResultRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HcpPackerCapabilities {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HcpPackerReadRequest {
    scope_digest: Digest,
    page_size: u16,
    max_pages: u16,
    max_builds: usize,
    max_artifacts: usize,
    max_response_bytes: usize,
    observed_at: DateTime<Utc>,
}

impl HcpPackerReadRequest {
    pub fn new(scope: &HcpPackerArtifactScope, page_size: u16, max_pages: u16) -> Result<Self> {
        Self::with_limits(
            scope,
            page_size,
            max_pages,
            MAX_BUILDS,
            MAX_ARTIFACTS,
            MAX_RESPONSE_BYTES,
            Utc::now(),
        )
    }

    pub fn new_at(
        scope: &HcpPackerArtifactScope,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_limits(
            scope,
            page_size,
            max_pages,
            MAX_BUILDS,
            MAX_ARTIFACTS,
            MAX_RESPONSE_BYTES,
            observed_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_limits(
        scope: &HcpPackerArtifactScope,
        page_size: u16,
        max_pages: u16,
        max_builds: usize,
        max_artifacts: usize,
        max_response_bytes: usize,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        if page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_builds == 0
            || max_builds > MAX_BUILDS
            || max_artifacts == 0
            || max_artifacts > MAX_ARTIFACTS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            page_size,
            max_pages,
            max_builds,
            max_artifacts,
            max_response_bytes,
            observed_at,
        })
    }

    pub fn default_for_scope(scope: &HcpPackerArtifactScope) -> Result<Self> {
        Self::new(scope, MAX_PAGE_SIZE, MAX_PAGES)
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

    pub const fn max_builds(&self) -> usize {
        self.max_builds
    }

    pub const fn max_artifacts(&self) -> usize {
        self.max_artifacts
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn validate(&self, scope: &HcpPackerArtifactScope) -> Result<()> {
        if self.scope_digest != scope.digest() {
            Err(HcpPackerArtifactResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

pub type HcpPackerEvidenceRequest = HcpPackerReadRequest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HcpPackerReadResult {
    pub state: HcpPackerEvidenceState,
    pub evidence: HcpPackerArtifactEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HcpPackerArtifactResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub state: HcpPackerEvidenceState,
    pub evidence: Option<HcpPackerArtifactEvidence>,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl HcpPackerArtifactResultProposal {
    pub(crate) fn from_read_result(
        registration: &HcpPackerArtifactResultRegistration,
        read: HcpPackerReadResult,
        provenance: TransportProvenance,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            state: read.state,
            evidence: Some(read.evidence),
            failure: None,
            provenance,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub(crate) fn from_failure(
        registration: &HcpPackerArtifactResultRegistration,
        provenance: TransportProvenance,
        state: HcpPackerEvidenceState,
        error: &HcpPackerArtifactResultError,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            state,
            evidence: None,
            failure: Some(FailureEvidence::from_error(error)),
            provenance,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::zero(),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn evidence_digests(&self) -> Option<&EvidenceDigests> {
        self.evidence.as_ref().map(|evidence| &evidence.digests)
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn review_eligible(&self) -> bool {
        self.state.is_review_complete() && self.evidence.is_some() && self.failure.is_none()
    }

    pub fn validate_integrity(&self, scope: &HcpPackerArtifactScope) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.scope_digest != scope.digest()
            || self.registration_digest.validate().is_err()
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.compute_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        match (&self.evidence, &self.failure) {
            (Some(evidence), None) => evidence.validate_integrity(scope)?,
            (None, Some(failure)) => failure.validate()?,
            _ => return Err(HcpPackerArtifactResultError::TamperedEvidence),
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                (
                    "evidence",
                    self.evidence.as_ref().map_or_else(String::new, |evidence| {
                        evidence.evidence_digest().as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |failure| {
                        failure.failure_digest.as_str().to_owned()
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("read_only", self.read_only.to_string()),
                ("proposal_only", self.proposal_only.to_string()),
                ("recording_only", self.recording_only.to_string()),
            ],
        )
    }
}

pub type HcpPackerArtifactProposal = HcpPackerArtifactResultProposal;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    Registration,
    Scope,
    Tampered,
    Incomplete,
    ProviderUnknown,
    AccessLoss,
    Truncated,
    PaginationReplay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failure: Option<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn valid(
        failure: Option<VerificationFailure>,
        proposal: &HcpPackerArtifactResultProposal,
    ) -> Self {
        let valid = failure.is_none();
        let review_eligible = valid && proposal.review_eligible();
        let verification_digest = Digest::from_parts(
            "hcp-packer-verification/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                ("failure", format!("{failure:?}")),
            ],
        );
        Self {
            valid,
            review_eligible,
            failure,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HcpPackerArtifactRecordReceipt {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: HcpPackerEvidenceState,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl HcpPackerArtifactRecordReceipt {
    pub(crate) fn new(
        proposal: &HcpPackerArtifactResultProposal,
        idempotency_key: &str,
        replayed: bool,
    ) -> Self {
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let mut receipt = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            durable_provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
        };
        receipt.recording_digest = receipt.compute_digest();
        receipt
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.durable_provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.compute_digest()
        {
            Err(HcpPackerArtifactResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-local-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub struct HcpPackerArtifactResultService<T: HcpPackerTransport> {
    scope: HcpPackerArtifactScope,
    registration: HcpPackerArtifactResultRegistration,
    provider: HcpPackerProvider<T>,
}

impl<T: HcpPackerTransport> fmt::Debug for HcpPackerArtifactResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HcpPackerArtifactResultService")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: HcpPackerTransport> HcpPackerArtifactResultService<T> {
    pub fn new(
        scope: HcpPackerArtifactScope,
        secret_reference: SecretReference,
        permission: PermissionFence,
        provider: HcpPackerProvider<T>,
    ) -> Result<Self> {
        let registration = HcpPackerArtifactResultRegistration::new(
            "hcp-packer-registration",
            scope.clone(),
            secret_reference,
            permission,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
        })
    }

    pub fn with_registration(
        scope: HcpPackerArtifactScope,
        registration: HcpPackerArtifactResultRegistration,
        provider: HcpPackerProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> HcpPackerCapabilities {
        HcpPackerCapabilities {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: [
                "GetBucket",
                "GetChannel",
                "GetVersion",
                "ListBuilds",
                "ListArtifacts",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn scope(&self) -> &HcpPackerArtifactScope {
        &self.scope
    }

    pub fn registration(&self) -> &HcpPackerArtifactResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut HcpPackerArtifactResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &HcpPackerProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut HcpPackerProvider<T> {
        &mut self.provider
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.registration.secret_reference()
    }

    pub fn request(&self, page_size: u16, max_pages: u16) -> Result<HcpPackerReadRequest> {
        HcpPackerReadRequest::new(&self.scope, page_size, max_pages)
    }

    pub fn default_request(&self) -> Result<HcpPackerReadRequest> {
        HcpPackerReadRequest::default_for_scope(&self.scope)
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.registration.secret_reference_mut().revoke()
    }

    pub fn read_bounded(&mut self, request: HcpPackerReadRequest) -> Result<HcpPackerReadResult> {
        self.ensure_registration(&request)?;
        let observed_at = request.observed_at();
        let bucket_request = GetBucketRequest::for_scope_at(&self.scope, observed_at)?;
        let bucket_response = self.provider.get_bucket(&bucket_request)?;
        if bucket_response.response_bytes > request.max_response_bytes() {
            return Err(HcpPackerArtifactResultError::ResponseTooLarge);
        }
        let bucket =
            crate::model::BucketProjection::from_input(&bucket_response.bucket, &self.scope)?;

        let channel_request = GetChannelRequest::for_scope_at(&self.scope, observed_at)?;
        let channel_response = self.provider.get_channel(&channel_request)?;
        if channel_response.response_bytes > request.max_response_bytes() {
            return Err(HcpPackerArtifactResultError::ResponseTooLarge);
        }
        let channel =
            crate::model::ChannelProjection::from_input(&channel_response.channel, &self.scope)?;
        if channel.assigned_version_digest.as_ref()
            != Some(&self.scope.version_fingerprint().digest())
        {
            return Err(HcpPackerArtifactResultError::StaleState);
        }

        let version_request = GetVersionRequest::for_scope_at(&self.scope, observed_at)?;
        let version_response = self.provider.get_version(&version_request)?;
        if version_response.response_bytes > request.max_response_bytes() {
            return Err(HcpPackerArtifactResultError::ResponseTooLarge);
        }
        let version =
            crate::model::VersionProjection::from_input(&version_response.version, &self.scope)?;

        let mut builds = Vec::new();
        let mut artifacts = Vec::new();
        let mut build_cursor = None;
        let mut seen_build_tokens = BTreeSet::new();
        let mut build_pages = 0;
        let mut artifact_pages = 0;
        let mut requests = 3_u16;
        loop {
            build_pages += 1;
            let build_request = ListBuildsRequest::new_at(
                &self.scope,
                request.page_size(),
                build_cursor.clone(),
                observed_at,
            )?;
            let build_response = self.provider.list_builds(&build_request)?;
            if build_response.response_bytes > request.max_response_bytes() {
                return Err(HcpPackerArtifactResultError::ResponseTooLarge);
            }
            requests = requests.saturating_add(1);
            if requests > MAX_REQUESTS_PER_READ {
                return Err(HcpPackerArtifactResultError::PaginationExceeded);
            }
            for input in &build_response.builds {
                let build = crate::model::BuildProjection::from_input(input, &self.scope)?;
                if builds.len() >= request.max_builds() {
                    return Err(HcpPackerArtifactResultError::Truncated);
                }
                builds.push((input.id.clone(), build));
            }
            match build_response.next_cursor {
                Some(cursor) => {
                    if !seen_build_tokens.insert(cursor.token_digest().clone()) {
                        return Err(HcpPackerArtifactResultError::PaginationReplay);
                    }
                    if build_pages >= request.max_pages() {
                        return Err(HcpPackerArtifactResultError::Truncated);
                    }
                    build_cursor = Some(cursor);
                }
                None => break,
            }
        }

        let mut projected_builds = Vec::with_capacity(builds.len());
        for (build_id, build) in builds {
            projected_builds.push(build);
            let mut artifact_cursor = None;
            let mut seen_artifact_tokens = BTreeSet::new();
            let mut pages_for_build = 0;
            loop {
                pages_for_build += 1;
                let artifact_request = ListArtifactsRequest::new_at(
                    &self.scope,
                    &build_id,
                    request.page_size(),
                    artifact_cursor.clone(),
                    observed_at,
                )?;
                let artifact_response = self.provider.list_artifacts(&artifact_request)?;
                if artifact_response.response_bytes > request.max_response_bytes() {
                    return Err(HcpPackerArtifactResultError::ResponseTooLarge);
                }
                requests = requests.saturating_add(1);
                if requests > MAX_REQUESTS_PER_READ {
                    return Err(HcpPackerArtifactResultError::PaginationExceeded);
                }
                artifact_pages += 1;
                for input in &artifact_response.artifacts {
                    if artifacts.len() >= request.max_artifacts() {
                        return Err(HcpPackerArtifactResultError::Truncated);
                    }
                    artifacts.push(crate::model::ArtifactProjection::from_input(
                        input,
                        &self.scope,
                    )?);
                }
                match artifact_response.next_cursor {
                    Some(cursor) => {
                        if !seen_artifact_tokens.insert(cursor.token_digest().clone()) {
                            return Err(HcpPackerArtifactResultError::PaginationReplay);
                        }
                        if pages_for_build >= request.max_pages() {
                            return Err(HcpPackerArtifactResultError::Truncated);
                        }
                        artifact_cursor = Some(cursor);
                    }
                    None => break,
                }
            }
        }

        let evidence = HcpPackerArtifactEvidence::new(
            &self.scope,
            bucket,
            channel,
            version.clone(),
            projected_builds,
            artifacts,
            build_pages,
            artifact_pages,
            self.provider.provenance(),
            self.registration.evidence_digest.clone(),
            self.registration.provider_digest.clone(),
            self.registration.permission_digest.clone(),
        );
        Ok(HcpPackerReadResult {
            state: version.state.evidence_state(),
            evidence,
        })
    }

    pub fn propose(
        &mut self,
        request: HcpPackerReadRequest,
    ) -> Result<HcpPackerArtifactResultProposal> {
        request.validate(&self.scope)?;
        self.ensure_registration(&request)?;
        match self.read_bounded(request) {
            Ok(read) => Ok(HcpPackerArtifactResultProposal::from_read_result(
                &self.registration,
                read,
                self.provider.provenance(),
            )),
            Err(error) => {
                let state = state_for_error(&error);
                Ok(HcpPackerArtifactResultProposal::from_failure(
                    &self.registration,
                    self.provider.provenance(),
                    state,
                    &error,
                ))
            }
        }
    }

    pub fn verify(&self, proposal: &HcpPackerArtifactResultProposal) -> VerificationReport {
        let registration_invalid = self.registration.validate().is_err()
            || !self.registration.is_active()
            || self.registration.scope_digest() != &self.scope.digest()
            || self.provider.definition().validate().is_err()
            || self.provider.definition().provider_digest != *self.registration.provider_digest()
            || self.provider.definition().api_digest != *self.registration.api_digest()
            || self.registration.secret_reference().is_revoked()
            || proposal.registration_digest != *self.registration.registration_digest();
        let failure = if registration_invalid {
            Some(VerificationFailure::Registration)
        } else if proposal.validate_integrity(&self.scope).is_err() {
            Some(VerificationFailure::Tampered)
        } else {
            match proposal.state {
                HcpPackerEvidenceState::AccessLoss => Some(VerificationFailure::AccessLoss),
                HcpPackerEvidenceState::ProviderUnknown => {
                    Some(VerificationFailure::ProviderUnknown)
                }
                HcpPackerEvidenceState::Truncated => Some(VerificationFailure::Truncated),
                HcpPackerEvidenceState::PaginationReplay => {
                    Some(VerificationFailure::PaginationReplay)
                }
                HcpPackerEvidenceState::Incomplete
                | HcpPackerEvidenceState::Running
                | HcpPackerEvidenceState::Cancelled
                | HcpPackerEvidenceState::Failed
                | HcpPackerEvidenceState::Revoked
                | HcpPackerEvidenceState::Partial
                | HcpPackerEvidenceState::Stale
                | HcpPackerEvidenceState::Tampered
                | HcpPackerEvidenceState::RegistrationRevoked => {
                    Some(VerificationFailure::Incomplete)
                }
                HcpPackerEvidenceState::Ready => None,
            }
        };
        VerificationReport::valid(failure, proposal)
    }

    pub fn consumer(&self) -> Result<MissionHcpPackerArtifactConsumer> {
        self.ensure_registration(&self.default_request()?)?;
        MissionHcpPackerArtifactConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_registration(&self, request: &HcpPackerReadRequest) -> Result<()> {
        crate::validate_contract()?;
        request.validate(&self.scope)?;
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(HcpPackerArtifactResultError::RegistrationInactive);
        }
        if self.registration.scope_digest() != &self.scope.digest()
            || self.registration.provider_id() != PROVIDER_ID
            || self.registration.provider_digest() != &self.provider.definition().provider_digest
            || self.registration.api_digest() != &self.provider.definition().api_digest
        {
            return Err(HcpPackerArtifactResultError::ProviderDrift);
        }
        self.provider.definition().validate()?;
        self.registration.secret_reference().validate(&self.scope)?;
        Ok(())
    }
}

fn state_for_error(error: &HcpPackerArtifactResultError) -> HcpPackerEvidenceState {
    match error {
        HcpPackerArtifactResultError::AccessLoss
        | HcpPackerArtifactResultError::Transport(
            crate::error::HcpPackerTransportError::Unauthorized
            | crate::error::HcpPackerTransportError::Forbidden
            | crate::error::HcpPackerTransportError::AccessLoss,
        ) => HcpPackerEvidenceState::AccessLoss,
        HcpPackerArtifactResultError::PaginationReplay
        | HcpPackerArtifactResultError::ReplayConflict
        | HcpPackerArtifactResultError::Transport(crate::error::HcpPackerTransportError::Replay) => {
            HcpPackerEvidenceState::PaginationReplay
        }
        HcpPackerArtifactResultError::Truncated
        | HcpPackerArtifactResultError::PaginationExceeded
        | HcpPackerArtifactResultError::ResponseTooLarge
        | HcpPackerArtifactResultError::Transport(
            crate::error::HcpPackerTransportError::ResponseTruncated,
        ) => HcpPackerEvidenceState::Truncated,
        HcpPackerArtifactResultError::StaleState => HcpPackerEvidenceState::Stale,
        HcpPackerArtifactResultError::TamperedEvidence => HcpPackerEvidenceState::Tampered,
        HcpPackerArtifactResultError::RegistrationInactive
        | HcpPackerArtifactResultError::RegistrationReversed
        | HcpPackerArtifactResultError::SecretRevoked => {
            HcpPackerEvidenceState::RegistrationRevoked
        }
        HcpPackerArtifactResultError::ProviderUnknown
        | HcpPackerArtifactResultError::Transport(
            crate::error::HcpPackerTransportError::BlockedEnvironment
            | crate::error::HcpPackerTransportError::ProviderUnknown
            | crate::error::HcpPackerTransportError::MalformedResponse,
        ) => HcpPackerEvidenceState::ProviderUnknown,
        _ => HcpPackerEvidenceState::Partial,
    }
}
