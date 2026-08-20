use std::{collections::BTreeSet, fmt};

use crate::error::MissionMailgunDeliveryConsumerError;
use crate::{
    Digest, EvidenceState, MailgunDeliveryEvidence, MailgunDeliveryResultProposal,
    MailgunDeliveryResultRecord, MailgunDeliveryResultService, MailgunProvider, MailgunTransport,
    MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionMailgunDeliveryResultState {
    DecisionReady,
    NeedsMoreEvidence,
    Denied,
    Expired,
    RateLimited,
    ProviderUnknown,
    Tampered,
    ReplayRejected,
}

pub type MissionResultState = MissionMailgunDeliveryResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionMailgunDeliveryResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: MailgunDeliveryEvidence,
    pub proposal_digest: Digest,
    pub state: MissionMailgunDeliveryResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

pub struct MissionMailgunDeliveryConsumer<T: MailgunTransport> {
    service: MailgunDeliveryResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: MailgunTransport> fmt::Debug for MissionMailgunDeliveryConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMailgunDeliveryConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: MailgunTransport> MissionMailgunDeliveryConsumer<T> {
    pub fn new(provider: MailgunProvider<T>) -> Result<Self, MissionMailgunDeliveryConsumerError> {
        let service = MailgunDeliveryResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: MailgunDeliveryResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &MailgunDeliveryResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut MailgunDeliveryResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(&mut self) -> Result<MailgunDeliveryEvidence, MissionMailgunDeliveryConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn propose(
        &mut self,
    ) -> Result<MailgunDeliveryResultProposal, MissionMailgunDeliveryConsumerError> {
        self.ensure_active()?;
        Ok(self.service.propose()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<MailgunDeliveryResultProposal, MissionMailgunDeliveryConsumerError> {
        self.propose()
    }

    pub fn consume(
        &mut self,
        proposal: &MailgunDeliveryResultProposal,
    ) -> Result<MissionMailgunDeliveryResult, MissionMailgunDeliveryConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionMailgunDeliveryConsumerError::RegistrationMismatch);
        }
        if proposal.mission != self.service.scope().mission
            || proposal.work_product != self.service.scope().work_product
        {
            return Err(MissionMailgunDeliveryConsumerError::InvalidProposal);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionMailgunDeliveryConsumerError::ReplayDetected);
        }
        Ok(MissionMailgunDeliveryResult {
            project: self.service.scope().project.clone(),
            mission: self.service.scope().mission.clone(),
            work_product: self.service.scope().work_product.clone(),
            state: result_state(&proposal.evidence.state),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &MailgunDeliveryResultProposal,
    ) -> Result<MissionMailgunDeliveryResult, MissionMailgunDeliveryConsumerError> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &MailgunDeliveryResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<MailgunDeliveryResultRecord, MissionMailgunDeliveryConsumerError> {
        self.ensure_active()?;
        Ok(self.service.record(proposal, idempotency_key)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionMailgunDeliveryConsumerError> {
        self.ensure_active()?;
        self.service.revoke_registration()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionMailgunDeliveryConsumerError> {
        if self.active {
            return Err(MissionMailgunDeliveryConsumerError::InvalidProposal);
        }
        self.service.restore_registration()?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionMailgunDeliveryConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionMailgunDeliveryConsumerError::Revoked)
        }
    }
}

fn result_state(state: &EvidenceState) -> MissionMailgunDeliveryResultState {
    match state {
        EvidenceState::Ready => MissionMailgunDeliveryResultState::DecisionReady,
        EvidenceState::Partial | EvidenceState::Empty | EvidenceState::PaginationLoop => {
            MissionMailgunDeliveryResultState::NeedsMoreEvidence
        }
        EvidenceState::Denied => MissionMailgunDeliveryResultState::Denied,
        EvidenceState::Expired => MissionMailgunDeliveryResultState::Expired,
        EvidenceState::RateLimited => MissionMailgunDeliveryResultState::RateLimited,
        EvidenceState::ProviderUnknown => MissionMailgunDeliveryResultState::ProviderUnknown,
        EvidenceState::Tampered => MissionMailgunDeliveryResultState::Tampered,
        EvidenceState::ReplayRejected => MissionMailgunDeliveryResultState::ReplayRejected,
        EvidenceState::RegistrationRevoked => MissionMailgunDeliveryResultState::Denied,
    }
}
