use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AlgoliaAnalyticsProvider, AlgoliaAnalyticsTransport, AlgoliaEvidenceState,
    AlgoliaSearchQualityEvidence, AlgoliaSearchQualityProposal, AlgoliaSearchQualityService,
    AlgoliaSearchQualityServiceError, Digest, MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAlgoliaSearchConsumerError {
    #[error("Mission Algolia search consumer is revoked")]
    Revoked,
    #[error("Mission Algolia registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Algolia proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Algolia proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AlgoliaSearchQualityServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionAlgoliaSearchResultState {
    DecisionReady,
    NeedsMoreEvidence,
    PlanUnavailable,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

pub type MissionResultState = MissionAlgoliaSearchResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionAlgoliaSearchResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AlgoliaSearchQualityEvidence,
    pub proposal_digest: Digest,
    pub state: MissionAlgoliaSearchResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
}

/// Mission-facing consumer for proposal-only search-quality evidence. It
/// performs no kernel Outcome adoption and maintains an in-memory replay fence.
pub struct MissionAlgoliaSearchConsumer<T: AlgoliaAnalyticsTransport> {
    service: AlgoliaSearchQualityService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: AlgoliaAnalyticsTransport> fmt::Debug for MissionAlgoliaSearchConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAlgoliaSearchConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: AlgoliaAnalyticsTransport> MissionAlgoliaSearchConsumer<T> {
    pub fn new(
        provider: AlgoliaAnalyticsProvider<T>,
    ) -> Result<Self, MissionAlgoliaSearchConsumerError> {
        let service = AlgoliaSearchQualityService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: AlgoliaSearchQualityService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &AlgoliaSearchQualityService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AlgoliaSearchQualityService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<AlgoliaSearchQualityEvidence, MissionAlgoliaSearchConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AlgoliaSearchQualityProposal, MissionAlgoliaSearchConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<AlgoliaSearchQualityProposal, MissionAlgoliaSearchConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal_with_consent(consent)?)
    }

    pub fn consume(
        &mut self,
        proposal: &AlgoliaSearchQualityProposal,
    ) -> Result<MissionAlgoliaSearchResult, MissionAlgoliaSearchConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionAlgoliaSearchConsumerError::RegistrationMismatch);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionAlgoliaSearchConsumerError::ReplayDetected);
        }
        let state = result_state(&proposal.evidence.state);
        Ok(MissionAlgoliaSearchResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state,
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &AlgoliaSearchQualityProposal,
    ) -> Result<MissionAlgoliaSearchResult, MissionAlgoliaSearchConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAlgoliaSearchConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAlgoliaSearchConsumerError> {
        if self.active {
            return Err(MissionAlgoliaSearchConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAlgoliaSearchConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionAlgoliaSearchConsumerError::Revoked)
        }
    }
}

fn result_state(state: &AlgoliaEvidenceState) -> MissionAlgoliaSearchResultState {
    match state {
        AlgoliaEvidenceState::Complete => MissionAlgoliaSearchResultState::DecisionReady,
        AlgoliaEvidenceState::Partial | AlgoliaEvidenceState::Empty => {
            MissionAlgoliaSearchResultState::NeedsMoreEvidence
        }
        AlgoliaEvidenceState::PlanUnavailable => MissionAlgoliaSearchResultState::PlanUnavailable,
        AlgoliaEvidenceState::RateLimited => MissionAlgoliaSearchResultState::RateLimited,
        AlgoliaEvidenceState::AccessLost => MissionAlgoliaSearchResultState::AccessLost,
        AlgoliaEvidenceState::ProviderUnknown => MissionAlgoliaSearchResultState::ProviderUnknown,
    }
}
