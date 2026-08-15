use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use thiserror::Error;

use crate::{
    Digest, HightouchEvidenceState, HightouchObservationReceipt, HightouchProvider,
    HightouchSyncResultEvidence, HightouchSyncResultProposal, HightouchSyncResultService,
    HightouchSyncResultServiceError, HightouchTransport, IdempotencyKey, MissionProjection,
    ProjectProjection, WorkProductProjection,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionHightouchSyncConsumerError {
    #[error("Mission Hightouch sync consumer is revoked")]
    Revoked,
    #[error("Mission Hightouch registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Hightouch proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Hightouch idempotency key conflicts with another proposal")]
    IdempotencyConflict,
    #[error("Mission Hightouch proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] HightouchSyncResultServiceError),
}

pub type ConsumerError = MissionHightouchSyncConsumerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionHightouchSyncResultState {
    DecisionReady,
    Queued,
    Running,
    Failed,
    Partial,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

pub type HightouchMissionResultState = MissionHightouchSyncResultState;
pub type MissionResultState = MissionHightouchSyncResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionHightouchSyncResult {
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub evidence: HightouchSyncResultEvidence,
    pub proposal_digest: Digest,
    pub idempotency_digest: Digest,
    pub state: MissionHightouchSyncResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

pub type HightouchMissionResult = MissionHightouchSyncResult;

#[derive(Clone, Debug, PartialEq)]
pub struct HightouchObservationResult {
    pub receipt: HightouchObservationReceipt,
    pub replayed: bool,
}

/// Mission-facing consumer for metadata-only Hightouch sync evidence. It
/// performs no kernel Outcome adoption and keeps a deterministic in-memory
/// replay/idempotency fence.
pub struct MissionHightouchSyncConsumer<T: HightouchTransport> {
    service: HightouchSyncResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
    idempotency: BTreeMap<Digest, Digest>,
}

impl<T: HightouchTransport> fmt::Debug for MissionHightouchSyncConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHightouchSyncConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .field("idempotency_entries", &self.idempotency.len())
            .finish()
    }
}

impl<T: HightouchTransport> MissionHightouchSyncConsumer<T> {
    pub fn new(provider: HightouchProvider<T>) -> Result<Self, MissionHightouchSyncConsumerError> {
        let service = HightouchSyncResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: HightouchSyncResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
            idempotency: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &HightouchSyncResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut HightouchSyncResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<HightouchSyncResultEvidence, MissionHightouchSyncConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<HightouchSyncResultProposal, MissionHightouchSyncConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &HightouchSyncResultProposal,
    ) -> Result<MissionHightouchSyncResult, MissionHightouchSyncConsumerError> {
        self.ensure_active()?;
        self.verify_consumer_binding(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionHightouchSyncConsumerError::ReplayDetected);
        }
        Ok(MissionHightouchSyncResult {
            project: ProjectProjection::from(self.service.scope().project()),
            mission: MissionProjection::from(self.service.scope().mission()),
            work_product: WorkProductProjection::from(self.service.scope().work_product()),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            state: result_state(&proposal.evidence.state),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &HightouchSyncResultProposal,
    ) -> Result<MissionHightouchSyncResult, MissionHightouchSyncConsumerError> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &HightouchSyncResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<HightouchObservationResult, MissionHightouchSyncConsumerError> {
        self.ensure_active()?;
        self.verify_consumer_binding(proposal)?;
        let key =
            IdempotencyKey::new(idempotency_key).map_err(HightouchSyncResultServiceError::Model)?;
        if let Some(previous_proposal) = self.idempotency.get(&key.digest) {
            if previous_proposal != &proposal.proposal_digest {
                return Err(MissionHightouchSyncConsumerError::IdempotencyConflict);
            }
            let receipt = HightouchObservationReceipt::new(proposal, key.digest, true, false);
            return Ok(HightouchObservationResult {
                receipt,
                replayed: true,
            });
        }
        self.idempotency
            .insert(key.digest.clone(), proposal.proposal_digest.clone());
        let receipt = HightouchObservationReceipt::new(proposal, key.digest, false, false);
        Ok(HightouchObservationResult {
            receipt,
            replayed: false,
        })
    }

    pub fn revoke(&mut self) -> Result<(), MissionHightouchSyncConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionHightouchSyncConsumerError> {
        if self.active {
            return Err(MissionHightouchSyncConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn verify_consumer_binding(
        &self,
        proposal: &HightouchSyncResultProposal,
    ) -> Result<(), MissionHightouchSyncConsumerError> {
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionHightouchSyncConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if proposal.evidence.mission != MissionProjection::from(self.service.scope().mission())
            || proposal.evidence.project != ProjectProjection::from(self.service.scope().project())
            || proposal.evidence.work_product
                != WorkProductProjection::from(self.service.scope().work_product())
        {
            return Err(MissionHightouchSyncConsumerError::InvalidProposal);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionHightouchSyncConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionHightouchSyncConsumerError::Revoked)
        }
    }
}

fn result_state(state: &HightouchEvidenceState) -> MissionHightouchSyncResultState {
    match state {
        HightouchEvidenceState::Queued => MissionHightouchSyncResultState::Queued,
        HightouchEvidenceState::Running => MissionHightouchSyncResultState::Running,
        HightouchEvidenceState::Succeeded => MissionHightouchSyncResultState::DecisionReady,
        HightouchEvidenceState::Failed => MissionHightouchSyncResultState::Failed,
        HightouchEvidenceState::Partial => MissionHightouchSyncResultState::Partial,
        HightouchEvidenceState::Denied => MissionHightouchSyncResultState::Denied,
        HightouchEvidenceState::RateLimited => MissionHightouchSyncResultState::RateLimited,
        HightouchEvidenceState::ProviderUnknown => MissionHightouchSyncResultState::ProviderUnknown,
        HightouchEvidenceState::Tampered => MissionHightouchSyncResultState::Tampered,
    }
}
