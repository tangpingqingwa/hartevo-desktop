use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    Digest, DockerHubEvidenceState, DockerHubImageResultEvidence, DockerHubImageResultProposal,
    DockerHubImageResultService, DockerHubTransport, MissionBinding, ProjectBinding,
    WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionDockerHubImageConsumerError {
    #[error("Mission Docker Hub image consumer is revoked")]
    Revoked,
    #[error("Mission Docker Hub registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Docker Hub proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Docker Hub proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] crate::DockerHubImageResultError),
}

pub type DockerHubConsumerError = MissionDockerHubImageConsumerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionDockerHubImageResultState {
    DecisionReady,
    NeedsMoreEvidence,
    AccessLost,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    TimedOut,
    ConfigDrift,
    ProviderUnknown,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionDockerHubImageResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: DockerHubImageResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionDockerHubImageResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

pub struct MissionDockerHubImageConsumer<T: DockerHubTransport> {
    service: DockerHubImageResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: DockerHubTransport> fmt::Debug for MissionDockerHubImageConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDockerHubImageConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: DockerHubTransport> MissionDockerHubImageConsumer<T> {
    pub fn new(
        provider: crate::DockerHubProvider<T>,
    ) -> Result<Self, MissionDockerHubImageConsumerError> {
        let service = DockerHubImageResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: DockerHubImageResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest().clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &DockerHubImageResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut DockerHubImageResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<DockerHubImageResultEvidence, MissionDockerHubImageConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<DockerHubImageResultProposal, MissionDockerHubImageConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &DockerHubImageResultProposal,
    ) -> Result<MissionDockerHubImageResult, MissionDockerHubImageConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest() != &self.registration_digest {
            return Err(MissionDockerHubImageConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionDockerHubImageConsumerError::ReplayDetected);
        }
        Ok(MissionDockerHubImageResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: result_state(proposal.evidence.state),
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &DockerHubImageResultProposal,
    ) -> Result<MissionDockerHubImageResult, MissionDockerHubImageConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionDockerHubImageConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionDockerHubImageConsumerError> {
        if self.active {
            return Err(MissionDockerHubImageConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionDockerHubImageConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionDockerHubImageConsumerError::Revoked)
        }
    }
}

fn result_state(state: DockerHubEvidenceState) -> MissionDockerHubImageResultState {
    match state {
        DockerHubEvidenceState::Ready => MissionDockerHubImageResultState::DecisionReady,
        DockerHubEvidenceState::Partial => MissionDockerHubImageResultState::NeedsMoreEvidence,
        DockerHubEvidenceState::AccessLoss => MissionDockerHubImageResultState::AccessLost,
        DockerHubEvidenceState::Unauthorized => MissionDockerHubImageResultState::Unauthorized,
        DockerHubEvidenceState::Forbidden => MissionDockerHubImageResultState::Forbidden,
        DockerHubEvidenceState::NotFound => MissionDockerHubImageResultState::NotFound,
        DockerHubEvidenceState::Throttled => MissionDockerHubImageResultState::RateLimited,
        DockerHubEvidenceState::TimedOut => MissionDockerHubImageResultState::TimedOut,
        DockerHubEvidenceState::ConfigDrift => MissionDockerHubImageResultState::ConfigDrift,
        DockerHubEvidenceState::Tampered
        | DockerHubEvidenceState::ProviderUnknown
        | DockerHubEvidenceState::RegistrationRevoked => {
            MissionDockerHubImageResultState::ProviderUnknown
        }
    }
}
