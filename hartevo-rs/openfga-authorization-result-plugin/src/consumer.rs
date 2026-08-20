use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    CONSUMER_ID, SERVICE_ID,
    error::{OpenFgaAuthorizationResultError, Result},
    model::{
        Digest, EvidenceDigests, OpenFgaEvidenceState, OpenFgaScope, ScopeEvidence,
        TransportProvenance,
    },
    service::{
        OpenFgaAuthorizationResultProposal, OpenFgaAuthorizationResultRegistration,
        RegistrationStatus,
    },
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenFgaProposalDisposition {
    Ready,
    Denied,
    Partial,
    Stale,
    Tampered,
    ProviderUnknown,
    RateLimited,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    TimedOut,
    ConsentExpired,
    RegistrationRevoked,
}

impl From<OpenFgaEvidenceState> for OpenFgaProposalDisposition {
    fn from(state: OpenFgaEvidenceState) -> Self {
        match state {
            OpenFgaEvidenceState::Ready => Self::Ready,
            OpenFgaEvidenceState::Denied => Self::Denied,
            OpenFgaEvidenceState::Partial => Self::Partial,
            OpenFgaEvidenceState::Stale => Self::Stale,
            OpenFgaEvidenceState::Tampered => Self::Tampered,
            OpenFgaEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            OpenFgaEvidenceState::RateLimited => Self::RateLimited,
            OpenFgaEvidenceState::Unauthorized => Self::Unauthorized,
            OpenFgaEvidenceState::Forbidden => Self::Forbidden,
            OpenFgaEvidenceState::NotFound => Self::NotFound,
            OpenFgaEvidenceState::Conflict => Self::Conflict,
            OpenFgaEvidenceState::TimedOut => Self::TimedOut,
            OpenFgaEvidenceState::ConsentExpired => Self::ConsentExpired,
            OpenFgaEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionOpenFgaAuthorizationResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope: ScopeEvidence,
    pub scope_digest: Digest,
    pub state: OpenFgaEvidenceState,
    pub disposition: OpenFgaProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub authorization_granted: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionOpenFgaAuthorizationResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedOpenFgaAuthorizationResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: OpenFgaEvidenceState,
    pub disposition: OpenFgaProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub authorization_granted: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedOpenFgaAuthorizationResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &OpenFgaAuthorizationResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            authorization_granted: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-openfga-recording"),
        };
        result.recording_digest = result.compute_digest();
        result
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "openfga-recording/v1",
            &[
                ("idempotency", self.idempotency_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.authorization_granted
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.compute_digest()
        {
            return Err(OpenFgaAuthorizationResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub struct MissionOpenFgaAuthorizationConsumer {
    scope: OpenFgaScope,
    registration: OpenFgaAuthorizationResultRegistration,
    records: BTreeMap<Digest, RecordedOpenFgaAuthorizationResult>,
}

impl fmt::Debug for MissionOpenFgaAuthorizationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionOpenFgaAuthorizationConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionOpenFgaAuthorizationConsumer {
    pub fn new(
        scope: OpenFgaScope,
        registration: OpenFgaAuthorizationResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(OpenFgaAuthorizationResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &OpenFgaAuthorizationResultRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &OpenFgaAuthorizationResultProposal,
    ) -> Result<MissionOpenFgaAuthorizationResult> {
        proposal.validate_integrity()?;
        if self.registration.status != RegistrationStatus::Active {
            return Err(OpenFgaAuthorizationResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.scope != ScopeEvidence::from_scope(&self.scope)
            || proposal.scope.project_digest != self.scope.project().digest()
            || proposal.scope.mission_digest != self.scope.mission().digest()
            || proposal.scope.work_product_digest != self.scope.work_product().digest()
        {
            return Err(OpenFgaAuthorizationResultError::ScopeMismatch);
        }
        Ok(MissionOpenFgaAuthorizationResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope: proposal.scope.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            authorization_granted: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &OpenFgaAuthorizationResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedOpenFgaAuthorizationResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.trim() != key
            || key.chars().any(char::is_control)
        {
            return Err(OpenFgaAuthorizationResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(OpenFgaAuthorizationResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.compute_digest();
            return Ok(replay);
        }
        let result = RecordedOpenFgaAuthorizationResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
