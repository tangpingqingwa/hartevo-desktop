use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AwsHealthEventEvidence, AwsHealthEventProposal, AwsHealthEventScope, AwsHealthEventService,
    AwsHealthEventServiceError, AwsHealthEvidenceState, AwsHealthProvider, AwsHealthTransport,
    Digest, MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionAwsHealthConsumerError {
    #[error("Mission AWS Health consumer is revoked")]
    Revoked,
    #[error("Mission AWS Health registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission AWS Health proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission AWS Health proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AwsHealthEventServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionAwsHealthResultState {
    DecisionReady,
    NeedsMoreEvidence,
    RateLimited,
    AccessLost,
    Stale,
    ProviderUnknown,
}

pub type MissionResultState = MissionAwsHealthResultState;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsHealthResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AwsHealthEventEvidence,
    pub proposal_digest: Digest,
    pub state: MissionAwsHealthResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub outage_causality: bool,
    pub operational_truth: bool,
}

pub struct MissionAwsHealthConsumer<T: AwsHealthTransport> {
    service: AwsHealthEventService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: AwsHealthTransport> fmt::Debug for MissionAwsHealthConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsHealthConsumer")
            .field("scope_digest", self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: AwsHealthTransport> MissionAwsHealthConsumer<T> {
    pub fn new(provider: AwsHealthProvider<T>) -> Result<Self, MissionAwsHealthConsumerError> {
        let service = AwsHealthEventService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: AwsHealthEventService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &AwsHealthEventService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AwsHealthEventService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &AwsHealthEventScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(&mut self) -> Result<AwsHealthEventEvidence, MissionAwsHealthConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AwsHealthEventProposal, MissionAwsHealthConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<MissionAwsHealthResult, MissionAwsHealthConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionAwsHealthConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionAwsHealthConsumerError::ReplayDetected);
        }
        Ok(MissionAwsHealthResult {
            project: self.scope().project().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: result_state(proposal.evidence.state),
            proposal_only: true,
            native: false,
            connected: false,
            outage_causality: false,
            operational_truth: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &AwsHealthEventProposal,
    ) -> Result<MissionAwsHealthResult, MissionAwsHealthConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAwsHealthConsumerError> {
        self.ensure_active()?;
        self.service.revoke()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAwsHealthConsumerError> {
        if self.active {
            return Err(MissionAwsHealthConsumerError::InvalidProposal);
        }
        self.service.restore()?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAwsHealthConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionAwsHealthConsumerError::Revoked)
        }
    }
}

fn result_state(state: AwsHealthEvidenceState) -> MissionAwsHealthResultState {
    match state {
        AwsHealthEvidenceState::Complete | AwsHealthEvidenceState::Empty => {
            MissionAwsHealthResultState::DecisionReady
        }
        AwsHealthEvidenceState::PartialFailure => MissionAwsHealthResultState::NeedsMoreEvidence,
        AwsHealthEvidenceState::RateLimited => MissionAwsHealthResultState::RateLimited,
        AwsHealthEvidenceState::AccessLost => MissionAwsHealthResultState::AccessLost,
        AwsHealthEvidenceState::Stale => MissionAwsHealthResultState::Stale,
        AwsHealthEvidenceState::ProviderUnknown => MissionAwsHealthResultState::ProviderUnknown,
    }
}
