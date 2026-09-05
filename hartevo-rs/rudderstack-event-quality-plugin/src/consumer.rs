use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    model::{
        EvidenceState, MissionResultState, MissionRudderStackEventResult,
        RudderStackEventQualityEvidence, RudderStackEventQualityProposal,
    },
    provider::RudderStackTransport,
    service::{RudderStackEventQualityService, RudderStackEventQualityServiceError},
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MissionRudderStackEventConsumerError {
    #[error("the Mission consumer detected a proposal replay")]
    ReplayDetected,
    #[error("the Mission consumer rejected the proposal: {0}")]
    Service(#[from] RudderStackEventQualityServiceError),
}

pub type ConsumerError = MissionRudderStackEventConsumerError;

pub struct MissionRudderStackEventConsumer<T = crate::BlockedEnvRudderStackTransport>
where
    T: RudderStackTransport,
{
    service: RudderStackEventQualityService<T>,
    consumed_proposals: BTreeSet<crate::Digest>,
}

impl<T> fmt::Debug for MissionRudderStackEventConsumer<T>
where
    T: RudderStackTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionRudderStackEventConsumer")
            .field("registration", self.service.registration())
            .field("consumed_proposal_count", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T> MissionRudderStackEventConsumer<T>
where
    T: RudderStackTransport,
{
    pub fn new(
        provider: crate::RudderStackProvider<T>,
    ) -> Result<Self, MissionRudderStackEventConsumerError> {
        Ok(Self {
            service: RudderStackEventQualityService::new(provider)?,
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn from_service(service: RudderStackEventQualityService<T>) -> Self {
        Self {
            service,
            consumed_proposals: BTreeSet::new(),
        }
    }

    pub fn service(&self) -> &RudderStackEventQualityService<T> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut RudderStackEventQualityService<T> {
        &mut self.service
    }

    pub fn read(
        &mut self,
    ) -> Result<RudderStackEventQualityEvidence, MissionRudderStackEventConsumerError> {
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<RudderStackEventQualityProposal, MissionRudderStackEventConsumerError> {
        Ok(self.service.compile_proposal()?)
    }

    pub fn verify(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<crate::RudderStackVerificationReceipt, MissionRudderStackEventConsumerError> {
        Ok(self.service.verify(proposal)?)
    }

    pub fn consume(
        &mut self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<MissionRudderStackEventResult, MissionRudderStackEventConsumerError> {
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionRudderStackEventConsumerError::ReplayDetected);
        }
        Ok(MissionRudderStackEventResult::new(
            mission_state(proposal.evidence.state),
            proposal,
        ))
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<crate::RegistrationRevocation, MissionRudderStackEventConsumerError> {
        Ok(self.service.revoke_registration()?)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<crate::RegistrationRevocation, MissionRudderStackEventConsumerError> {
        Ok(self.service.restore_registration()?)
    }
}

pub type MissionRudderStackEventQualityConsumer<T = crate::BlockedEnvRudderStackTransport> =
    MissionRudderStackEventConsumer<T>;
pub type MissionEventQualityConsumer<T = crate::BlockedEnvRudderStackTransport> =
    MissionRudderStackEventConsumer<T>;
pub type MissionRudderStackResult = MissionRudderStackEventResult;

fn mission_state(state: EvidenceState) -> MissionResultState {
    match state {
        EvidenceState::Complete => MissionResultState::DecisionReady,
        EvidenceState::Partial => MissionResultState::PartialEvidence,
        EvidenceState::Empty => MissionResultState::EmptyEvidence,
        EvidenceState::RateLimited => MissionResultState::RateLimited,
        EvidenceState::AccessLost => MissionResultState::AccessLost,
        EvidenceState::ProviderUnknown => MissionResultState::ProviderUnknown,
        EvidenceState::Tamper => MissionResultState::TamperDetected,
        EvidenceState::Stale => MissionResultState::StaleEvidence,
        EvidenceState::Revoked => MissionResultState::Revoked,
    }
}
