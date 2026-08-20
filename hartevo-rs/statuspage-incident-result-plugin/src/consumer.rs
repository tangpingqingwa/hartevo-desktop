use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, EvidenceState, MissionBinding, ProjectBinding, StatuspageIncidentResultEvidence,
    StatuspageIncidentResultProposal, StatuspageIncidentResultScope,
    StatuspageIncidentResultService, StatuspageIncidentResultServiceError, StatuspageTransport,
    WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionStatuspageIncidentConsumerError {
    #[error("Mission Statuspage incident consumer is revoked")]
    Revoked,
    #[error("Mission Statuspage registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Statuspage proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Statuspage proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] StatuspageIncidentResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionStatuspageIncidentResultState {
    DecisionReady,
    NeedsMoreEvidence,
    Maintenance,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

pub type MissionStatuspageIncidentState = MissionStatuspageIncidentResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionStatuspageIncidentResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: StatuspageIncidentResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionStatuspageIncidentResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
}

/// Mission-facing consumer for proposal-only Statuspage evidence. It owns no
/// kernel Outcome authority and keeps only an in-memory replay fence.
pub struct MissionStatuspageIncidentConsumer<T: StatuspageTransport> {
    service: StatuspageIncidentResultService<T>,
    registration_digest: Digest,
    mission_scope: StatuspageIncidentResultScope,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

#[allow(clippy::missing_fields_in_debug)]
impl<T: StatuspageTransport> fmt::Debug for MissionStatuspageIncidentConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionStatuspageIncidentConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: StatuspageTransport> MissionStatuspageIncidentConsumer<T> {
    pub fn new(
        provider: crate::StatuspageProvider<T>,
    ) -> Result<Self, MissionStatuspageIncidentConsumerError> {
        let service = StatuspageIncidentResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: StatuspageIncidentResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        let mission_scope = service.scope().clone();
        Self {
            service,
            registration_digest,
            mission_scope,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &StatuspageIncidentResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut StatuspageIncidentResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<StatuspageIncidentResultEvidence, MissionStatuspageIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<StatuspageIncidentResultProposal, MissionStatuspageIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<StatuspageIncidentResultProposal, MissionStatuspageIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal_with_consent(consent)?)
    }

    pub fn consume(
        &mut self,
        proposal: &StatuspageIncidentResultProposal,
    ) -> Result<MissionStatuspageIncidentResult, MissionStatuspageIncidentConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionStatuspageIncidentConsumerError::RegistrationMismatch);
        }
        if self.service.scope().mission() != self.mission_scope.mission() {
            return Err(MissionStatuspageIncidentConsumerError::StaleMission);
        }
        if self.service.scope().work_product() != self.mission_scope.work_product() {
            return Err(MissionStatuspageIncidentConsumerError::StaleWorkProduct);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionStatuspageIncidentConsumerError::ReplayDetected);
        }
        Ok(MissionStatuspageIncidentResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: result_state(&proposal.evidence.state),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &StatuspageIncidentResultProposal,
    ) -> Result<MissionStatuspageIncidentResult, MissionStatuspageIncidentConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionStatuspageIncidentConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionStatuspageIncidentConsumerError> {
        if self.active {
            return Err(MissionStatuspageIncidentConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionStatuspageIncidentConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionStatuspageIncidentConsumerError::Revoked)
        }
    }
}

fn result_state(state: &EvidenceState) -> MissionStatuspageIncidentResultState {
    match state {
        EvidenceState::Complete => MissionStatuspageIncidentResultState::DecisionReady,
        EvidenceState::Partial | EvidenceState::Empty => {
            MissionStatuspageIncidentResultState::NeedsMoreEvidence
        }
        EvidenceState::Maintenance => MissionStatuspageIncidentResultState::Maintenance,
        EvidenceState::RateLimited => MissionStatuspageIncidentResultState::RateLimited,
        EvidenceState::AccessLost => MissionStatuspageIncidentResultState::AccessLost,
        EvidenceState::ProviderUnknown => MissionStatuspageIncidentResultState::ProviderUnknown,
    }
}
