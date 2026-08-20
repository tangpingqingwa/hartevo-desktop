use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, GithubDeploymentMetadata, GithubDeploymentStatusEvidence,
    GithubDeploymentStatusEvidenceState, GithubDeploymentStatusMetadata,
    GithubDeploymentStatusResultProposal, GithubDeploymentStatusService,
    GithubDeploymentStatusServiceError, GithubDeploymentStatusState,
    GithubDeploymentStatusTransport, MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGithubDeploymentStatusConsumerError {
    #[error("Mission GitHub Deployment Status consumer is revoked")]
    Revoked,
    #[error("Mission GitHub Deployment Status registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission GitHub Deployment Status proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission GitHub Deployment Status proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] GithubDeploymentStatusServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGithubDeploymentStatusResultState {
    DecisionReady,
    NeedsMoreEvidence,
    HistoryTruncated,
    AccessLost,
    NotFound,
    RateLimited,
    StaleState,
    ProviderUnknown,
}

pub type MissionResultState = MissionGithubDeploymentStatusResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGithubDeploymentStatusResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub deployment: Option<GithubDeploymentMetadata>,
    pub statuses: Vec<GithubDeploymentStatusMetadata>,
    pub latest_status: Option<GithubDeploymentStatusMetadata>,
    pub latest_provider_state: Option<GithubDeploymentStatusState>,
    pub evidence: GithubDeploymentStatusEvidence,
    pub proposal_digest: Digest,
    pub state: MissionGithubDeploymentStatusResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
}

/// Mission-facing consumer for proposal-only GitHub Deployment Status
/// evidence. It maintains an in-memory replay fence and never adopts a
/// kernel Truth, Receipt, Verification, or Outcome.
pub struct MissionGithubDeploymentStatusConsumer<T: GithubDeploymentStatusTransport> {
    service: GithubDeploymentStatusService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: GithubDeploymentStatusTransport> fmt::Debug for MissionGithubDeploymentStatusConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGithubDeploymentStatusConsumer")
            .field("scope_digest", self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: GithubDeploymentStatusTransport> MissionGithubDeploymentStatusConsumer<T> {
    pub fn new(
        provider: crate::GithubDeploymentStatusProvider<T>,
    ) -> Result<Self, MissionGithubDeploymentStatusConsumerError> {
        let service = GithubDeploymentStatusService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: GithubDeploymentStatusService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GithubDeploymentStatusService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GithubDeploymentStatusService<T> {
        &mut self.service
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<GithubDeploymentStatusEvidence, MissionGithubDeploymentStatusConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<GithubDeploymentStatusResultProposal, MissionGithubDeploymentStatusConsumerError>
    {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn consume(
        &mut self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<MissionGithubDeploymentStatusResult, MissionGithubDeploymentStatusConsumerError>
    {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionGithubDeploymentStatusConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionGithubDeploymentStatusConsumerError::ReplayDetected);
        }
        Ok(MissionGithubDeploymentStatusResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            deployment: proposal.evidence.deployment.clone(),
            statuses: proposal.evidence.statuses.clone(),
            latest_status: proposal.evidence.latest_status.clone(),
            latest_provider_state: proposal.evidence.latest_state(),
            state: result_state(proposal.evidence.state),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<MissionGithubDeploymentStatusResult, MissionGithubDeploymentStatusConsumerError>
    {
        self.consume(proposal)
    }

    pub fn record(
        &self,
        proposal: &GithubDeploymentStatusResultProposal,
    ) -> Result<
        crate::GithubDeploymentStatusObservationReceipt,
        MissionGithubDeploymentStatusConsumerError,
    > {
        self.service.record(proposal).map_err(Into::into)
    }

    pub fn revoke(&mut self) -> Result<(), MissionGithubDeploymentStatusConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGithubDeploymentStatusConsumerError> {
        if self.active {
            return Err(MissionGithubDeploymentStatusConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionGithubDeploymentStatusConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGithubDeploymentStatusConsumerError::Revoked)
        }
    }
}

fn result_state(
    state: GithubDeploymentStatusEvidenceState,
) -> MissionGithubDeploymentStatusResultState {
    match state {
        GithubDeploymentStatusEvidenceState::Complete => {
            MissionGithubDeploymentStatusResultState::DecisionReady
        }
        GithubDeploymentStatusEvidenceState::Partial => {
            MissionGithubDeploymentStatusResultState::NeedsMoreEvidence
        }
        GithubDeploymentStatusEvidenceState::HistoryTruncated => {
            MissionGithubDeploymentStatusResultState::HistoryTruncated
        }
        GithubDeploymentStatusEvidenceState::AccessLost => {
            MissionGithubDeploymentStatusResultState::AccessLost
        }
        GithubDeploymentStatusEvidenceState::NotFound => {
            MissionGithubDeploymentStatusResultState::NotFound
        }
        GithubDeploymentStatusEvidenceState::RateLimited => {
            MissionGithubDeploymentStatusResultState::RateLimited
        }
        GithubDeploymentStatusEvidenceState::StaleState => {
            MissionGithubDeploymentStatusResultState::StaleState
        }
        GithubDeploymentStatusEvidenceState::ProviderUnknown => {
            MissionGithubDeploymentStatusResultState::ProviderUnknown
        }
    }
}
