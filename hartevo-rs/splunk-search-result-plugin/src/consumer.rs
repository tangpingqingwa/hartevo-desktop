use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, MissionBinding, ProjectBinding, RegistrationChange, SplunkEvidenceStatus,
    SplunkSavedSearchResultEvidence, SplunkSavedSearchResultProposal,
    SplunkSavedSearchResultService, SplunkSavedSearchResultServiceError, SplunkTransport,
    WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionSplunkSearchConsumerError {
    #[error("Mission Splunk search consumer is revoked")]
    Revoked,
    #[error("Mission Splunk registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Splunk proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Splunk proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] SplunkSavedSearchResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionSplunkSearchResultState {
    DecisionReady,
    Queued,
    Running,
    Failed,
    Expired,
    Empty,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionSplunkSearchResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: SplunkSavedSearchResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionSplunkSearchResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

/// Mission-facing proposal consumer. It keeps an in-memory replay fence and
/// performs no kernel Outcome or Work Product adoption.
pub struct MissionSplunkSearchConsumer<T: SplunkTransport> {
    service: SplunkSavedSearchResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: SplunkTransport> fmt::Debug for MissionSplunkSearchConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSplunkSearchConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: SplunkTransport> MissionSplunkSearchConsumer<T> {
    pub fn new(
        provider: crate::SplunkProvider<T>,
    ) -> Result<Self, MissionSplunkSearchConsumerError> {
        let service = SplunkSavedSearchResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: SplunkSavedSearchResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &SplunkSavedSearchResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut SplunkSavedSearchResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<SplunkSavedSearchResultEvidence, MissionSplunkSearchConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<SplunkSavedSearchResultProposal, MissionSplunkSearchConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &SplunkSavedSearchResultProposal,
    ) -> Result<MissionSplunkSearchResult, MissionSplunkSearchConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionSplunkSearchConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionSplunkSearchConsumerError::ReplayDetected);
        }
        Ok(MissionSplunkSearchResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: mission_state(proposal.evidence.status),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationChange, MissionSplunkSearchConsumerError> {
        self.ensure_active()?;
        let change = self.service.revoke()?;
        self.active = false;
        Ok(change)
    }

    pub fn restore(&mut self) -> Result<RegistrationChange, MissionSplunkSearchConsumerError> {
        if self.active {
            return Err(MissionSplunkSearchConsumerError::InvalidProposal);
        }
        let change = self.service.restore()?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        self.active = true;
        self.consumed_proposals.clear();
        Ok(change)
    }

    fn ensure_active(&self) -> Result<(), MissionSplunkSearchConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionSplunkSearchConsumerError::Revoked)
        }
    }
}

fn mission_state(status: SplunkEvidenceStatus) -> MissionSplunkSearchResultState {
    match status {
        SplunkEvidenceStatus::Queued => MissionSplunkSearchResultState::Queued,
        SplunkEvidenceStatus::Running => MissionSplunkSearchResultState::Running,
        SplunkEvidenceStatus::Done => MissionSplunkSearchResultState::DecisionReady,
        SplunkEvidenceStatus::Failed => MissionSplunkSearchResultState::Failed,
        SplunkEvidenceStatus::Expired => MissionSplunkSearchResultState::Expired,
        SplunkEvidenceStatus::Partial => MissionSplunkSearchResultState::Partial,
        SplunkEvidenceStatus::Empty => MissionSplunkSearchResultState::Empty,
        SplunkEvidenceStatus::AccessLost => MissionSplunkSearchResultState::AccessLost,
        SplunkEvidenceStatus::ProviderUnknown => MissionSplunkSearchResultState::ProviderUnknown,
        SplunkEvidenceStatus::Tampered => MissionSplunkSearchResultState::Tampered,
        SplunkEvidenceStatus::Revoked => MissionSplunkSearchResultState::Revoked,
    }
}
