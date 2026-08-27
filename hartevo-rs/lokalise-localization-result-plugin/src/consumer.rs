use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, LokaliseEvidenceState, LokaliseLocalizationResultEvidence,
    LokaliseLocalizationResultProposal, LokaliseLocalizationResultService,
    LokaliseLocalizationResultServiceError, LokaliseTransport, MissionBinding, ProjectBinding,
    TransportProvenance, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionLokaliseLocalizationConsumerError {
    #[error("Mission Lokalise localization consumer is revoked")]
    Revoked,
    #[error("Mission Lokalise registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Lokalise proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Lokalise proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] LokaliseLocalizationResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionLokaliseLocalizationResultState {
    NeedsTranslation,
    NeedsVerification,
    NeedsReview,
    NeedsQaRemediation,
    Building,
    DecisionReady,
    Expired,
    Partial,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

pub type MissionLokaliseResultState = MissionLokaliseLocalizationResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionLokaliseLocalizationResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: LokaliseLocalizationResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionLokaliseLocalizationResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
}

/// Mission-facing consumer for proposal-only Lokalise evidence. It validates
/// mission/work-product revision fences and maintains an in-memory replay
/// fence; it never adopts a kernel Outcome.
pub struct MissionLokaliseLocalizationConsumer<T: LokaliseTransport> {
    service: LokaliseLocalizationResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: LokaliseTransport> fmt::Debug for MissionLokaliseLocalizationConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionLokaliseLocalizationConsumer")
            .field("scope_digest", self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: LokaliseTransport> MissionLokaliseLocalizationConsumer<T> {
    pub fn new(
        provider: crate::LokaliseProvider<T>,
    ) -> Result<Self, MissionLokaliseLocalizationConsumerError> {
        let service = LokaliseLocalizationResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: LokaliseLocalizationResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &LokaliseLocalizationResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut LokaliseLocalizationResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<LokaliseLocalizationResultEvidence, MissionLokaliseLocalizationConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<LokaliseLocalizationResultProposal, MissionLokaliseLocalizationConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_localization_result_proposal(
        &mut self,
    ) -> Result<LokaliseLocalizationResultProposal, MissionLokaliseLocalizationConsumerError> {
        self.compile_proposal()
    }

    pub fn consume(
        &mut self,
        proposal: &LokaliseLocalizationResultProposal,
    ) -> Result<MissionLokaliseLocalizationResult, MissionLokaliseLocalizationConsumerError> {
        let mission_revision = self.service.scope().mission().revision().get();
        let work_product_revision = self.service.scope().work_product().revision().get();
        self.consume_at_revisions(proposal, mission_revision, work_product_revision)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &LokaliseLocalizationResultProposal,
    ) -> Result<MissionLokaliseLocalizationResult, MissionLokaliseLocalizationConsumerError> {
        self.consume(proposal)
    }

    pub fn consume_at_revisions(
        &mut self,
        proposal: &LokaliseLocalizationResultProposal,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<MissionLokaliseLocalizationResult, MissionLokaliseLocalizationConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionLokaliseLocalizationConsumerError::RegistrationMismatch);
        }
        if mission_revision != self.service.scope().mission().revision().get() {
            return Err(MissionLokaliseLocalizationConsumerError::StaleMission);
        }
        if work_product_revision != self.service.scope().work_product().revision().get() {
            return Err(MissionLokaliseLocalizationConsumerError::StaleWorkProduct);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionLokaliseLocalizationConsumerError::ReplayDetected);
        }
        let state = result_state(&proposal.evidence.state);
        Ok(MissionLokaliseLocalizationResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
        })
    }

    pub fn revoke(&mut self) -> Result<(), MissionLokaliseLocalizationConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionLokaliseLocalizationConsumerError> {
        if self.active {
            return Err(MissionLokaliseLocalizationConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionLokaliseLocalizationConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionLokaliseLocalizationConsumerError::Revoked)
        }
    }
}

fn result_state(state: &LokaliseEvidenceState) -> MissionLokaliseLocalizationResultState {
    match state {
        LokaliseEvidenceState::Untranslated => {
            MissionLokaliseLocalizationResultState::NeedsTranslation
        }
        LokaliseEvidenceState::Unverified => {
            MissionLokaliseLocalizationResultState::NeedsVerification
        }
        LokaliseEvidenceState::QaIssue => {
            MissionLokaliseLocalizationResultState::NeedsQaRemediation
        }
        LokaliseEvidenceState::Translated => MissionLokaliseLocalizationResultState::NeedsReview,
        LokaliseEvidenceState::Reviewed | LokaliseEvidenceState::Ready => {
            MissionLokaliseLocalizationResultState::DecisionReady
        }
        LokaliseEvidenceState::Building => MissionLokaliseLocalizationResultState::Building,
        LokaliseEvidenceState::Expired => MissionLokaliseLocalizationResultState::Expired,
        LokaliseEvidenceState::Partial => MissionLokaliseLocalizationResultState::Partial,
        LokaliseEvidenceState::RateLimited => MissionLokaliseLocalizationResultState::RateLimited,
        LokaliseEvidenceState::AccessLost => MissionLokaliseLocalizationResultState::AccessLost,
        LokaliseEvidenceState::ProviderUnknown => {
            MissionLokaliseLocalizationResultState::ProviderUnknown
        }
    }
}

#[allow(dead_code)]
const fn _transport_honesty(provenance: TransportProvenance) -> (bool, bool, bool) {
    (
        provenance.is_connected(),
        provenance.is_native(),
        provenance.is_first_party(),
    )
}
