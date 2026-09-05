//! Mission-facing proposal consumer below Kernel authority.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, EvidenceState, MissionBinding, OpsgenieIncidentResultEvidence,
    OpsgenieIncidentResultProposal, OpsgenieIncidentResultScope, OpsgenieIncidentResultService,
    OpsgenieIncidentResultServiceError, OpsgenieTransport, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionOpsgenieIncidentConsumerError {
    #[error("Mission Opsgenie incident consumer is revoked")]
    Revoked,
    #[error("Mission Opsgenie registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
    #[error("Mission Opsgenie proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Opsgenie proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] OpsgenieIncidentResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionOpsgenieIncidentResultState {
    DecisionReady,
    NeedsMoreEvidence,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

pub type MissionOpsgenieIncidentState = MissionOpsgenieIncidentResultState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionOpsgenieIncidentResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: OpsgenieIncidentResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionOpsgenieIncidentResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

/// Mission consumer that records only an in-memory replay fence and a
/// proposal/result envelope. It has no Kernel Outcome or Work Product write.
pub struct MissionOpsgenieIncidentConsumer<T: OpsgenieTransport> {
    service: OpsgenieIncidentResultService<T>,
    registration_digest: Digest,
    mission_scope: OpsgenieIncidentResultScope,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: OpsgenieTransport> fmt::Debug for MissionOpsgenieIncidentConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionOpsgenieIncidentConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: OpsgenieTransport> MissionOpsgenieIncidentConsumer<T> {
    pub fn new(
        provider: crate::OpsgenieProvider<T>,
    ) -> Result<Self, MissionOpsgenieIncidentConsumerError> {
        let service = OpsgenieIncidentResultService::new(provider)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: OpsgenieIncidentResultService<T>) -> Self {
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
    pub fn service(&self) -> &OpsgenieIncidentResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut OpsgenieIncidentResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &OpsgenieIncidentResultScope {
        self.service.scope()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
    ) -> Result<OpsgenieIncidentResultEvidence, MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpsgenieIncidentResultEvidence, MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read_with_consent(consent)?)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<OpsgenieIncidentResultProposal, MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn compile_incident_result_proposal(
        &mut self,
    ) -> Result<OpsgenieIncidentResultProposal, MissionOpsgenieIncidentConsumerError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpsgenieIncidentResultProposal, MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal_with_consent(consent)?)
    }

    pub fn consume(
        &mut self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<MissionOpsgenieIncidentResult, MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionOpsgenieIncidentConsumerError::RegistrationMismatch);
        }
        if self.service.scope().mission() != self.mission_scope.mission() {
            return Err(MissionOpsgenieIncidentConsumerError::StaleMission);
        }
        if self.service.scope().work_product() != self.mission_scope.work_product() {
            return Err(MissionOpsgenieIncidentConsumerError::StaleWorkProduct);
        }
        self.service.verify_proposal(proposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionOpsgenieIncidentConsumerError::ReplayDetected);
        }
        Ok(MissionOpsgenieIncidentResult {
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
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<MissionOpsgenieIncidentResult, MissionOpsgenieIncidentConsumerError> {
        self.consume(proposal)
    }

    pub fn record_observation(
        &self,
        proposal: &OpsgenieIncidentResultProposal,
    ) -> Result<crate::OpsgenieObservationReceipt, MissionOpsgenieIncidentConsumerError> {
        Ok(self.service.record_observation(proposal)?)
    }

    pub fn revoke(&mut self) -> Result<(), MissionOpsgenieIncidentConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionOpsgenieIncidentConsumerError> {
        if self.active {
            return Err(MissionOpsgenieIncidentConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionOpsgenieIncidentConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionOpsgenieIncidentConsumerError::Revoked)
        }
    }
}

fn result_state(state: EvidenceState) -> MissionOpsgenieIncidentResultState {
    match state {
        EvidenceState::Complete => MissionOpsgenieIncidentResultState::DecisionReady,
        EvidenceState::Empty | EvidenceState::Partial => {
            MissionOpsgenieIncidentResultState::NeedsMoreEvidence
        }
        EvidenceState::RateLimited => MissionOpsgenieIncidentResultState::RateLimited,
        EvidenceState::AccessLoss | EvidenceState::Denied => {
            MissionOpsgenieIncidentResultState::AccessLost
        }
        EvidenceState::ProviderUnknown
        | EvidenceState::NotFound
        | EvidenceState::Stale
        | EvidenceState::Tampered
        | EvidenceState::RegistrationRevoked => MissionOpsgenieIncidentResultState::ProviderUnknown,
    }
}

pub type OpsgenieIncidentConsumer<T> = MissionOpsgenieIncidentConsumer<T>;
pub type MissionOpsgenieResult<T> = MissionOpsgenieIncidentResultConsumer<T>;

pub type MissionOpsgenieIncidentResultConsumer<T> = MissionOpsgenieIncidentConsumer<T>;
