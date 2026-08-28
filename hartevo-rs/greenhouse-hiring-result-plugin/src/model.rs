use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::GreenhouseError;
use crate::{
    MAX_IDENTIFIER_BYTES, MAX_STAGE_TRANSITIONS, MAX_TEXT_BYTES, digest_serialized,
    validate_digest, validate_identifier, validate_text, validate_timestamp,
};

macro_rules! identifier_type {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, GreenhouseError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identifier_type!(OrganizationId, "organizationId");
identifier_type!(JobId, "jobId");
identifier_type!(ApplicationId, "applicationId");
identifier_type!(StageId, "stageId");
identifier_type!(ScorecardId, "scorecardId");
identifier_type!(OfferId, "offerId");
identifier_type!(MissionId, "missionId");
identifier_type!(ProjectId, "projectId");
identifier_type!(WorkProductId, "workProductId");
identifier_type!(ProviderId, "providerId");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut output = String::with_capacity(64);
        for byte in Sha256::digest(bytes) {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(output)
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, GreenhouseError> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), GreenhouseError> {
        validate_digest(&self.0, "digest")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, GreenhouseError> {
        if value == 0 {
            Err(GreenhouseError::InvalidRevision { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn from_digest(digest: &Digest) -> Self {
        let mut value = 0_u64;
        for byte in digest.as_str().as_bytes().iter().take(16) {
            value = value.wrapping_mul(16).wrapping_add(match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' => u64::from(byte - b'a' + 10),
                _ => 0,
            });
        }
        Self(value.max(1))
    }
}

pub type ProviderRevision = Revision;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedTimestamp(String);

impl BoundedTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, GreenhouseError> {
        let value = value.into();
        validate_timestamp(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Only a digest of a provider credential reference is retained.  This type
/// intentionally implements neither `Serialize` nor `Deserialize`.
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        reference_digest: Digest,
        credential_revision: Revision,
        kind: SecretKind,
    ) -> Result<Self, GreenhouseError> {
        reference_digest.validate()?;
        Ok(Self {
            reference_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    /// Test-only construction still hashes the supplied label before storing it.
    pub fn for_testing(
        label: &str,
        revision: u64,
        kind: SecretKind,
    ) -> Result<Self, GreenhouseError> {
        Self::new(Digest::from_text(label), Revision::new(revision)?, kind)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    HarvestApiKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    OrganizationRead,
    JobRead,
    ApplicationRead,
    StageRead,
    ScorecardAggregateRead,
    OfferAggregateRead,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrganizationRead => "organization.read",
            Self::JobRead => "job.read",
            Self::ApplicationRead => "application.read",
            Self::StageRead => "stage.read",
            Self::ScorecardAggregateRead => "scorecard.aggregate.read",
            Self::OfferAggregateRead => "offer.aggregate.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilitySet {
    capabilities: BTreeSet<Capability>,
    digest: Digest,
}

impl CapabilitySet {
    pub fn read_only() -> Self {
        Self::new([
            Capability::OrganizationRead,
            Capability::JobRead,
            Capability::ApplicationRead,
            Capability::StageRead,
            Capability::ScorecardAggregateRead,
            Capability::OfferAggregateRead,
        ])
    }

    pub fn new<I>(capabilities: I) -> Self
    where
        I: IntoIterator<Item = Capability>,
    {
        let capabilities = capabilities.into_iter().collect::<BTreeSet<_>>();
        let digest = digest_serialized(
            &capabilities
                .iter()
                .map(|capability| capability.as_str())
                .collect::<Vec<_>>(),
        );
        Self {
            capabilities,
            digest,
        }
    }

    pub fn validate(&self) -> Result<(), GreenhouseError> {
        let expected = Self::new(self.capabilities.iter().copied());
        if self.capabilities.is_empty() || self.digest != expected.digest {
            Err(GreenhouseError::InvalidCapabilitySet)
        } else {
            Ok(())
        }
    }

    pub fn contains(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.capabilities
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentField {
    Organization,
    Job,
    Application,
    CandidateReference,
    StageTransition,
    ScorecardAggregate,
    OfferEvidence,
    DecisionProposal,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    purpose: String,
    allowed_fields: BTreeSet<ConsentField>,
    expires_at_epoch_seconds: u64,
    revision: Revision,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(
        purpose: impl Into<String>,
        allowed_fields: impl IntoIterator<Item = ConsentField>,
        expires_at_epoch_seconds: u64,
        revision: Revision,
    ) -> Result<Self, GreenhouseError> {
        let purpose = purpose.into();
        validate_text(&purpose, "consentPurpose", MAX_TEXT_BYTES)?;
        if expires_at_epoch_seconds == 0 {
            return Err(GreenhouseError::InvalidConsent);
        }
        let allowed_fields = allowed_fields.into_iter().collect::<BTreeSet<_>>();
        if allowed_fields.is_empty() {
            return Err(GreenhouseError::InvalidConsent);
        }
        let digest = digest_serialized(&(
            purpose.clone(),
            allowed_fields.iter().copied().collect::<Vec<_>>(),
            expires_at_epoch_seconds,
            revision,
        ));
        Ok(Self {
            purpose,
            allowed_fields,
            expires_at_epoch_seconds,
            revision,
            digest,
        })
    }

    pub fn read_only_hiring_evidence(
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, GreenhouseError> {
        Self::new(
            "hiring-evidence-proposal",
            [
                ConsentField::Organization,
                ConsentField::Job,
                ConsentField::Application,
                ConsentField::CandidateReference,
                ConsentField::StageTransition,
                ConsentField::ScorecardAggregate,
                ConsentField::OfferEvidence,
                ConsentField::DecisionProposal,
            ],
            expires_at_epoch_seconds,
            Revision::new(1)?,
        )
    }

    pub fn validate(&self) -> Result<(), GreenhouseError> {
        let expected = Self::new(
            self.purpose.clone(),
            self.allowed_fields.iter().copied(),
            self.expires_at_epoch_seconds,
            self.revision,
        )?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(GreenhouseError::InvalidConsent)
        }
    }

    pub fn is_active_at(&self, now_epoch_seconds: u64) -> bool {
        now_epoch_seconds <= self.expires_at_epoch_seconds
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn allowed_fields(&self) -> &BTreeSet<ConsentField> {
        &self.allowed_fields
    }

    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentStatus {
    Granted,
    Withdrawn,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReceipt {
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub revision: Revision,
    pub expires_at_epoch_seconds: u64,
    pub status: ConsentStatus,
    pub native: bool,
}

impl ConsentReceipt {
    pub fn grant(scope: &GreenhouseScope, now_epoch_seconds: u64) -> Result<Self, GreenhouseError> {
        scope.consent.validate()?;
        if !scope.consent.is_active_at(now_epoch_seconds) {
            return Err(GreenhouseError::ConsentUnavailable);
        }
        Ok(Self {
            scope_digest: scope.digest(),
            consent_digest: scope.consent.digest().clone(),
            revision: scope.consent.revision(),
            expires_at_epoch_seconds: scope.consent.expires_at_epoch_seconds(),
            status: ConsentStatus::Granted,
            native: false,
        })
    }

    pub fn withdraw(&mut self) {
        self.status = ConsentStatus::Withdrawn;
    }

    pub fn is_usable_for(&self, scope: &GreenhouseScope, now_epoch_seconds: u64) -> bool {
        self.scope_digest == scope.digest()
            && self.consent_digest == *scope.consent.digest()
            && self.revision == scope.consent.revision()
            && self.status == ConsentStatus::Granted
            && now_epoch_seconds <= self.expires_at_epoch_seconds
            && !self.native
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GreenhouseScope {
    pub organization_id: OrganizationId,
    pub job_id: JobId,
    pub application_id: ApplicationId,
    pub candidate_reference_id: Option<CandidateReferenceId>,
    pub stage_id: Option<StageId>,
    pub scorecard_id: Option<ScorecardId>,
    pub offer_id: Option<OfferId>,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub capabilities: CapabilitySet,
    pub consent: ConsentScope,
}

impl GreenhouseScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        job_id: JobId,
        application_id: ApplicationId,
        candidate_reference_id: Option<CandidateReferenceId>,
        stage_id: Option<StageId>,
        scorecard_id: Option<ScorecardId>,
        offer_id: Option<OfferId>,
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        capabilities: CapabilitySet,
        consent: ConsentScope,
    ) -> Result<Self, GreenhouseError> {
        capabilities.validate()?;
        consent.validate()?;
        for capability in [
            Capability::OrganizationRead,
            Capability::JobRead,
            Capability::ApplicationRead,
            Capability::StageRead,
            Capability::ScorecardAggregateRead,
            Capability::OfferAggregateRead,
        ] {
            if !capabilities.contains(capability) {
                return Err(GreenhouseError::InvalidScope);
            }
        }
        for field in [
            ConsentField::Organization,
            ConsentField::Job,
            ConsentField::Application,
            ConsentField::CandidateReference,
            ConsentField::StageTransition,
            ConsentField::ScorecardAggregate,
            ConsentField::OfferEvidence,
            ConsentField::DecisionProposal,
        ] {
            if !consent.allowed_fields().contains(&field) {
                return Err(GreenhouseError::InvalidScope);
            }
        }
        Ok(Self {
            organization_id,
            job_id,
            application_id,
            candidate_reference_id,
            stage_id,
            scorecard_id,
            offer_id,
            mission_id,
            project_id,
            work_product_id,
            capabilities,
            consent,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }

    pub fn validate(&self) -> Result<(), GreenhouseError> {
        self.capabilities.validate()?;
        if self.capabilities != CapabilitySet::read_only() {
            return Err(GreenhouseError::InvalidScope);
        }
        self.consent.validate()?;
        for field in [
            ConsentField::Organization,
            ConsentField::Job,
            ConsentField::Application,
            ConsentField::CandidateReference,
            ConsentField::StageTransition,
            ConsentField::ScorecardAggregate,
            ConsentField::OfferEvidence,
            ConsentField::DecisionProposal,
        ] {
            if !self.consent.allowed_fields().contains(&field) {
                return Err(GreenhouseError::InvalidScope);
            }
        }
        if self.organization_id.as_str().len() > MAX_IDENTIFIER_BYTES
            || self.job_id.as_str().len() > MAX_IDENTIFIER_BYTES
            || self.application_id.as_str().len() > MAX_IDENTIFIER_BYTES
        {
            return Err(GreenhouseError::InvalidScope);
        }
        if let Some(candidate) = &self.candidate_reference_id {
            candidate.as_digest().validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CandidateReferenceId(Digest);

impl CandidateReferenceId {
    pub fn from_provider_id(value: &str) -> Self {
        Self(Digest::from_text(value))
    }

    pub fn from_digest(digest: Digest) -> Result<Self, GreenhouseError> {
        digest.validate()?;
        Ok(Self(digest))
    }

    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateReference {
    pub candidate_reference_id: CandidateReferenceId,
    pub redacted: bool,
}

impl CandidateReference {
    pub fn from_provider_id(value: &str) -> Self {
        Self {
            candidate_reference_id: CandidateReferenceId::from_provider_id(value),
            redacted: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageTransition {
    pub stage_id: StageId,
    pub stage_label_digest: Digest,
    pub entered_at: Option<BoundedTimestamp>,
    pub exited_at: Option<BoundedTimestamp>,
    pub revision: Revision,
}

impl StageTransition {
    pub fn from_provider(
        stage_id: StageId,
        stage_label: Option<&str>,
        entered_at: Option<BoundedTimestamp>,
        exited_at: Option<BoundedTimestamp>,
        revision: Revision,
    ) -> Self {
        Self {
            stage_id,
            stage_label_digest: Digest::from_text(stage_label.unwrap_or("unknown-stage")),
            entered_at,
            exited_at,
            revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferState {
    Draft,
    Sent,
    Accepted,
    Rejected,
    Withdrawn,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OfferEvidence {
    pub offer_id: OfferId,
    pub state: OfferState,
    pub created_at: Option<BoundedTimestamp>,
    pub sent_at: Option<BoundedTimestamp>,
    pub decided_at: Option<BoundedTimestamp>,
    pub content_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScorecardAggregate {
    pub scorecard_id: ScorecardId,
    pub sections_completed: u16,
    pub sections_total: u16,
    pub average_score_bps: Option<u16>,
    pub submitted_at: Option<BoundedTimestamp>,
    pub answer_digest: Digest,
    pub raw_answers_retained: bool,
    pub interview_notes_retained: bool,
}

impl ScorecardAggregate {
    pub fn is_complete(&self) -> bool {
        self.sections_total > 0 && self.sections_completed >= self.sections_total
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    Active,
    Converted,
    Hired,
    Rejected,
    Stalled,
    Incomplete,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompleteness {
    Complete,
    Partial,
    Redacted,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn claims_connected(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Reversed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub candidate_name_redacted: bool,
    pub candidate_email_redacted: bool,
    pub candidate_phone_redacted: bool,
    pub resume_and_attachment_urls_redacted: bool,
    pub demographic_and_eeoc_data_redacted: bool,
    pub interview_notes_redacted: bool,
    pub raw_scorecard_answers_redacted: bool,
    pub raw_provider_payload_retained: bool,
}

impl RedactionSummary {
    pub const fn strict() -> Self {
        Self {
            candidate_name_redacted: true,
            candidate_email_redacted: true,
            candidate_phone_redacted: true,
            resume_and_attachment_urls_redacted: true,
            demographic_and_eeoc_data_redacted: true,
            interview_notes_redacted: true,
            raw_scorecard_answers_redacted: true,
            raw_provider_payload_retained: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestReceipt {
    pub endpoint: String,
    pub method: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status: u16,
    pub attempts: u8,
    pub backoff_delays_ms: Vec<u64>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GreenhouseHiringEvidence {
    pub scope_digest: Digest,
    pub organization_id: OrganizationId,
    pub job_id: JobId,
    pub application_id: ApplicationId,
    pub candidate_reference: CandidateReference,
    pub stage_transitions: Vec<StageTransition>,
    pub scorecard: Option<ScorecardAggregate>,
    pub offer: Option<OfferEvidence>,
    pub state: ApplicationState,
    pub completeness: EvidenceCompleteness,
    pub observed_at: BoundedTimestamp,
    pub provider_revision: Revision,
    pub redaction: RedactionSummary,
    pub request_receipts: Vec<RequestReceipt>,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl GreenhouseHiringEvidence {
    pub(crate) fn seal(mut self) -> Self {
        self.evidence_digest = self.compute_digest();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serialized(&(
            self.scope_digest.clone(),
            self.organization_id.clone(),
            self.job_id.clone(),
            self.application_id.clone(),
            self.candidate_reference.clone(),
            self.stage_transitions.clone(),
            self.scorecard.clone(),
            self.offer.clone(),
            self.state,
            self.completeness,
            self.observed_at.clone(),
            self.provider_revision,
            self.redaction.clone(),
            self.request_receipts.clone(),
        ))
    }

    pub fn validate_integrity(&self) -> Result<(), GreenhouseError> {
        self.scope_digest.validate()?;
        self.evidence_digest.validate()?;
        if !self.candidate_reference.redacted {
            return Err(GreenhouseError::RestrictedData);
        }
        self.candidate_reference
            .candidate_reference_id
            .as_digest()
            .validate()?;
        validate_identifier(self.organization_id.as_str(), "organizationId")?;
        validate_identifier(self.job_id.as_str(), "jobId")?;
        validate_identifier(self.application_id.as_str(), "applicationId")?;
        for stage in &self.stage_transitions {
            validate_identifier(stage.stage_id.as_str(), "stageId")?;
            stage.stage_label_digest.validate()?;
            if stage.revision.get() == 0 {
                return Err(GreenhouseError::InvalidRevision {
                    field: "stageRevision",
                });
            }
            if let Some(timestamp) = &stage.entered_at {
                validate_timestamp(timestamp.as_str())?;
            }
            if let Some(timestamp) = &stage.exited_at {
                validate_timestamp(timestamp.as_str())?;
            }
        }
        if let Some(scorecard) = &self.scorecard {
            validate_identifier(scorecard.scorecard_id.as_str(), "scorecardId")?;
            scorecard.answer_digest.validate()?;
            if scorecard.raw_answers_retained
                || scorecard.interview_notes_retained
                || scorecard.sections_completed > scorecard.sections_total
                || scorecard
                    .average_score_bps
                    .is_some_and(|score| score > 10_000)
            {
                return Err(GreenhouseError::RestrictedData);
            }
        }
        if let Some(offer) = &self.offer {
            validate_identifier(offer.offer_id.as_str(), "offerId")?;
            offer.content_digest.validate()?;
            for timestamp in [&offer.created_at, &offer.sent_at, &offer.decided_at]
                .into_iter()
                .flatten()
            {
                validate_timestamp(timestamp.as_str())?;
            }
        }
        validate_timestamp(self.observed_at.as_str())?;
        if self.provider_revision.get() == 0 {
            return Err(GreenhouseError::InvalidRevision {
                field: "providerRevision",
            });
        }
        for receipt in &self.request_receipts {
            receipt.request_digest.validate()?;
            receipt.response_digest.validate()?;
            if receipt.endpoint.is_empty()
                || receipt.method != "GET"
                || receipt.connected
                || receipt.native
                || receipt.provenance.is_native()
                || receipt.endpoint.len() > 512
                || receipt.endpoint.chars().any(char::is_control)
            {
                return Err(GreenhouseError::TamperedEvidence);
            }
            if let Some(candidate_path) = receipt.endpoint.strip_prefix("/v1/candidates/") {
                let candidate_digest = candidate_path.split(['/', '?']).next().unwrap_or_default();
                validate_digest(candidate_digest, "redactedCandidateReferenceId")?;
            }
        }
        if self.connected
            || self.native
            || self.evidence_digest != self.compute_digest()
            || self.stage_transitions.len() > MAX_STAGE_TRANSITIONS
            || self.scorecard.as_ref().is_some_and(|scorecard| {
                scorecard.raw_answers_retained
                    || scorecard.interview_notes_retained
                    || scorecard.sections_total > 10_000
            })
            || self.redaction != RedactionSummary::strict()
        {
            return Err(GreenhouseError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_hiring_success_claim(&self) -> bool {
        self.state == ApplicationState::Hired
            && self
                .scorecard
                .as_ref()
                .is_some_and(ScorecardAggregate::is_complete)
    }

    pub fn scorecard_missing(&self) -> bool {
        self.scorecard.is_none()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HiringDecision {
    RecommendHumanReview,
    HoldForEvidence,
    EscalateAccessReview,
    DoNotAdvance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOperation {
    HumanReviewRecommendation,
    AdvanceStage,
    RejectApplication,
    HireApplication,
    SendCandidateMessage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectIntent {
    pub operation: EffectOperation,
    pub application_id: ApplicationId,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub registration_revision: Revision,
    pub required_layer: u8,
    pub executable: bool,
    pub native: bool,
}

impl EffectIntent {
    pub(crate) fn proposal_only(
        operation: EffectOperation,
        application_id: ApplicationId,
        scope_digest: Digest,
        consent_digest: Digest,
        registration_revision: Revision,
    ) -> Self {
        Self {
            operation,
            application_id,
            scope_digest,
            consent_digest,
            registration_revision,
            required_layer: 2,
            executable: false,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HiringObjective {
    pub text: String,
    pub digest: Digest,
}

impl HiringObjective {
    pub fn new(text: impl Into<String>) -> Result<Self, GreenhouseError> {
        let text = text.into();
        validate_text(&text, "objective", MAX_TEXT_BYTES)?;
        Ok(Self {
            digest: Digest::from_text(&text),
            text,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposalRequest {
    pub objective: HiringObjective,
    pub consent: ConsentReceipt,
    pub expected_provider_revision: Option<Revision>,
    pub expected_evidence_digest: Option<Digest>,
    pub now_epoch_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProposalResult {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub provider_revision: Revision,
    pub registration_revision: Revision,
    pub objective_digest: Digest,
    pub decision: HiringDecision,
    pub effect: EffectIntent,
    pub consent_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

impl ProposalResult {
    pub(crate) fn seal(mut self) -> Self {
        self.proposal_digest = digest_serialized(&(
            self.mission_id.clone(),
            self.project_id.clone(),
            self.work_product_id.clone(),
            self.scope_digest.clone(),
            self.evidence_digest.clone(),
            self.provider_revision,
            self.registration_revision,
            self.objective_digest.clone(),
            self.decision,
            self.effect.clone(),
            self.consent_digest.clone(),
        ));
        self
    }

    pub fn validate_integrity(&self) -> Result<(), GreenhouseError> {
        self.proposal_digest.validate()?;
        if self.connected
            || self.native
            || self.adopted_outcome
            || self.proposal_digest
                != digest_serialized(&(
                    self.mission_id.clone(),
                    self.project_id.clone(),
                    self.work_product_id.clone(),
                    self.scope_digest.clone(),
                    self.evidence_digest.clone(),
                    self.provider_revision,
                    self.registration_revision,
                    self.objective_digest.clone(),
                    self.decision,
                    self.effect.clone(),
                    self.consent_digest.clone(),
                ))
            || self.effect.executable
            || self.effect.native
            || self.effect.required_layer != 2
        {
            return Err(GreenhouseError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceReceipt {
    pub receipt_id: Digest,
    pub provider_id: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub result_digest: Digest,
    pub registration_revision: Revision,
    pub provenance: TransportProvenance,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_native_receipt: bool,
}

impl EvidenceReceipt {
    pub fn validate(&self) -> Result<(), GreenhouseError> {
        for digest in [
            &self.receipt_id,
            &self.scope_digest,
            &self.evidence_digest,
            &self.proposal_digest,
            &self.request_digest,
            &self.result_digest,
        ] {
            digest.validate()?;
        }
        if !self.redacted
            || self.connected
            || self.native
            || self.durable_native_receipt
            || self.provenance.is_native()
        {
            return Err(GreenhouseError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Layer1Recording {
    pub receipt: EvidenceReceipt,
    pub evidence: GreenhouseHiringEvidence,
    pub proposal: ProposalResult,
}

impl Layer1Recording {
    pub fn validate(&self) -> Result<(), GreenhouseError> {
        self.receipt.validate()?;
        self.evidence.validate_integrity()?;
        self.proposal.validate_integrity()?;
        if self.receipt.evidence_digest != self.evidence.evidence_digest
            || self.receipt.proposal_digest != self.proposal.proposal_digest
            || self.receipt.scope_digest != self.evidence.scope_digest
            || self.proposal.scope_digest != self.evidence.scope_digest
        {
            return Err(GreenhouseError::ReceiptMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBackRequest {
    pub receipt_id: Digest,
    pub scope_digest: Digest,
    pub expected_evidence_digest: Digest,
    pub registration_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBackResult {
    pub recording: Layer1Recording,
    pub verified: bool,
    pub independent_provider_read_back: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDigestInput {
    pub endpoint: String,
    pub method: String,
}

impl RequestDigestInput {
    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}
