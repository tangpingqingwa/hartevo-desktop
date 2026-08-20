use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use thiserror::Error;

use crate::model::{BrexSpendScope, Digest, SpendEvidenceState};
use crate::service::{BrexSpendEvidence, BrexSpendProposal, BrexSpendServiceError};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionBrexSpendConsumerError {
    #[error("Mission Brex spend consumer is revoked")]
    Revoked,
    #[error("Mission Brex spend registration does not match the evidence")]
    RegistrationMismatch,
    #[error("Mission, Project, Work Product, or scope revision is stale")]
    StaleRevision,
    #[error("Mission Brex spend evidence is outside the consumer scope")]
    ScopeMismatch,
    #[error("Mission Brex spend evidence replay was rejected")]
    ReplayDetected,
    #[error("Mission Brex spend evidence is invalid")]
    InvalidEvidence,
    #[error(transparent)]
    Service(#[from] BrexSpendServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionBrexSpendResultState {
    DecisionReady,
    NeedsMoreEvidence,
    Denied,
    Expired,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionBrexSpendResult {
    pub project: crate::model::ProjectBinding,
    pub mission: crate::model::MissionBinding,
    pub work_product: crate::model::WorkProductBinding,
    pub evidence: BrexSpendEvidence,
    pub proposal_digest: Digest,
    pub state: MissionBrexSpendResultState,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordedBrexSpendResult {
    pub result: MissionBrexSpendResult,
    pub idempotency_key: Digest,
    pub replayed: bool,
}

pub struct MissionBrexSpendConsumer {
    scope: BrexSpendScope,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
    recorded: BTreeMap<Digest, RecordedBrexSpendResult>,
}

impl fmt::Debug for MissionBrexSpendConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBrexSpendConsumer")
            .field("scope_digest", &self.scope.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .field("recorded", &self.recorded.len())
            .finish()
    }
}

impl MissionBrexSpendConsumer {
    #[must_use]
    pub fn new(scope: BrexSpendScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
            recorded: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn scope(&self) -> &BrexSpendScope {
        &self.scope
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.recorded.len()
    }

    pub fn consume(
        &mut self,
        evidence: &BrexSpendEvidence,
    ) -> Result<MissionBrexSpendResult, MissionBrexSpendConsumerError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        if !self
            .consumed_proposals
            .insert(evidence.proposal_digest.clone())
        {
            return Err(MissionBrexSpendConsumerError::ReplayDetected);
        }
        Ok(self.result_from_evidence(evidence))
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &BrexSpendProposal,
        evidence: &BrexSpendEvidence,
    ) -> Result<MissionBrexSpendResult, MissionBrexSpendConsumerError> {
        proposal.verify()?;
        if proposal.proposal_digest != evidence.proposal_digest {
            return Err(MissionBrexSpendConsumerError::InvalidEvidence);
        }
        self.consume(evidence)
    }

    pub fn record(
        &mut self,
        evidence: &BrexSpendEvidence,
    ) -> Result<RecordedBrexSpendResult, MissionBrexSpendConsumerError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let key = evidence.digests.request_digest.clone();
        if let Some(recorded) = self.recorded.get(&key) {
            let mut replay = recorded.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let result = self.result_from_evidence(evidence);
        let recorded = RecordedBrexSpendResult {
            result,
            idempotency_key: key.clone(),
            replayed: false,
        };
        self.recorded.insert(key, recorded.clone());
        self.consumed_proposals
            .insert(evidence.proposal_digest.clone());
        Ok(recorded)
    }

    pub fn verify(
        &self,
        evidence: &BrexSpendEvidence,
    ) -> Result<(), MissionBrexSpendConsumerError> {
        self.validate_evidence(evidence)
    }

    pub fn revoke(&mut self) -> Result<(), MissionBrexSpendConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionBrexSpendConsumerError> {
        if self.active {
            return Err(MissionBrexSpendConsumerError::InvalidEvidence);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionBrexSpendConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionBrexSpendConsumerError::Revoked)
        }
    }

    fn validate_evidence(
        &self,
        evidence: &BrexSpendEvidence,
    ) -> Result<(), MissionBrexSpendConsumerError> {
        evidence.verify()?;
        if evidence.digests.registration_digest != self.registration_digest {
            return Err(MissionBrexSpendConsumerError::RegistrationMismatch);
        }
        if evidence.digests.scope_digest != self.scope.scope_digest
            || evidence.digests.consent_digest != self.scope.consent.digest()
            || evidence.mission != self.scope.mission
            || evidence.project != self.scope.project
            || evidence.work_product != self.scope.work_product
        {
            return Err(MissionBrexSpendConsumerError::ScopeMismatch);
        }
        if evidence.digests.request_digest.as_str().is_empty() {
            return Err(MissionBrexSpendConsumerError::StaleRevision);
        }
        Ok(())
    }

    fn result_from_evidence(&self, evidence: &BrexSpendEvidence) -> MissionBrexSpendResult {
        MissionBrexSpendResult {
            project: self.scope.project.clone(),
            mission: self.scope.mission.clone(),
            work_product: self.scope.work_product.clone(),
            evidence: evidence.clone(),
            proposal_digest: evidence.proposal_digest.clone(),
            state: result_state(evidence.status),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        }
    }
}

fn result_state(state: SpendEvidenceState) -> MissionBrexSpendResultState {
    match state {
        SpendEvidenceState::Complete => MissionBrexSpendResultState::DecisionReady,
        SpendEvidenceState::Partial => MissionBrexSpendResultState::NeedsMoreEvidence,
        SpendEvidenceState::Denied => MissionBrexSpendResultState::Denied,
        SpendEvidenceState::Expired => MissionBrexSpendResultState::Expired,
        SpendEvidenceState::RateLimited => MissionBrexSpendResultState::RateLimited,
        SpendEvidenceState::ProviderUnknown | SpendEvidenceState::RegistrationRevoked => {
            MissionBrexSpendResultState::ProviderUnknown
        }
        SpendEvidenceState::Tampered => MissionBrexSpendResultState::Tampered,
    }
}
