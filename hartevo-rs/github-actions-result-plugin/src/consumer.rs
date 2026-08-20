use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, GithubActionsEvidence, GithubActionsEvidenceState, GithubActionsResultProposal,
    GithubActionsResultService, GithubActionsResultServiceError, GithubActionsTransport,
    GithubArtifactMetadata, GithubJobMetadata, GithubWorkflowRunMetadata, MissionBinding,
    ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGithubActionsConsumerError {
    #[error("Mission GitHub Actions consumer is revoked")]
    Revoked,
    #[error("Mission GitHub Actions registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission GitHub Actions proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission GitHub Actions proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] GithubActionsResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGithubActionsResultState {
    DecisionReady,
    NeedsMoreEvidence,
    RunInProgress,
    ArtifactExpired,
    AccessLost,
    RateLimited,
    ProviderUnknown,
}

pub type MissionResultState = MissionGithubActionsResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGithubActionsResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub run: Option<GithubWorkflowRunMetadata>,
    pub jobs: Vec<GithubJobMetadata>,
    pub artifacts: Vec<GithubArtifactMetadata>,
    pub evidence: GithubActionsEvidence,
    pub proposal_digest: Digest,
    pub state: MissionGithubActionsResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub green_ci_claim: bool,
}

/// Mission-facing consumer for proposal-only GitHub Actions result evidence.
/// It maintains an in-memory replay fence and never adopts a kernel Outcome.
pub struct MissionGithubActionsConsumer<T: GithubActionsTransport> {
    service: GithubActionsResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: GithubActionsTransport> fmt::Debug for MissionGithubActionsConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGithubActionsConsumer")
            .field("scope_digest", self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: GithubActionsTransport> MissionGithubActionsConsumer<T> {
    pub fn new(
        provider: crate::GithubActionsProvider<T>,
    ) -> Result<Self, MissionGithubActionsConsumerError> {
        let service = GithubActionsResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: GithubActionsResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GithubActionsResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GithubActionsResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(&mut self) -> Result<GithubActionsEvidence, MissionGithubActionsConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<GithubActionsResultProposal, MissionGithubActionsConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<MissionGithubActionsResult, MissionGithubActionsConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionGithubActionsConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionGithubActionsConsumerError::ReplayDetected);
        }
        Ok(MissionGithubActionsResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            run: proposal.evidence.run.clone(),
            jobs: proposal.evidence.jobs.clone(),
            artifacts: proposal.evidence.artifacts.clone(),
            state: result_state(proposal.evidence.state),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            green_ci_claim: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &GithubActionsResultProposal,
    ) -> Result<MissionGithubActionsResult, MissionGithubActionsConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionGithubActionsConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGithubActionsConsumerError> {
        if self.active {
            return Err(MissionGithubActionsConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionGithubActionsConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGithubActionsConsumerError::Revoked)
        }
    }
}

fn result_state(state: GithubActionsEvidenceState) -> MissionGithubActionsResultState {
    match state {
        GithubActionsEvidenceState::Complete => MissionGithubActionsResultState::DecisionReady,
        GithubActionsEvidenceState::Partial => MissionGithubActionsResultState::NeedsMoreEvidence,
        GithubActionsEvidenceState::RunInProgress => MissionGithubActionsResultState::RunInProgress,
        GithubActionsEvidenceState::ArtifactExpired => {
            MissionGithubActionsResultState::ArtifactExpired
        }
        GithubActionsEvidenceState::AccessLost => MissionGithubActionsResultState::AccessLost,
        GithubActionsEvidenceState::RateLimited => MissionGithubActionsResultState::RateLimited,
        GithubActionsEvidenceState::ProviderUnknown => {
            MissionGithubActionsResultState::ProviderUnknown
        }
    }
}
