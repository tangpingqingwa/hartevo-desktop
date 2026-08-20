//! Mission-facing proposal-only Dataflow result consumer.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::model::{
    DataflowEvidence, DataflowJobState, Digest, EvidenceState, GcpDataflowJobResultScope,
    MissionBinding, ProjectBinding, WorkProductBinding,
};
use crate::provider::{DataflowReadProposal, DataflowReadRecord};
use crate::service::{GcpDataflowJobResultService, GcpDataflowJobResultServiceError};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGcpDataflowConsumerError {
    #[error("Mission Dataflow consumer is revoked")]
    Revoked,
    #[error("Mission Dataflow registration does not match the observation")]
    RegistrationMismatch,
    #[error("Mission Dataflow observation replay was rejected")]
    ReplayDetected,
    #[error("Mission Dataflow evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("Mission Dataflow proposal is not for the exact scope")]
    ScopeMismatch,
    #[error("Mission Dataflow consumer service error: {0}")]
    Service(#[from] GcpDataflowJobResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpDataflowState {
    EvidenceReady,
    Pending,
    Queued,
    Running,
    Draining,
    Drained,
    Done,
    Failed,
    Cancelled,
    Updated,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    Stale,
    NotFound,
    Conflict,
    RateLimited,
    TimedOut,
}

impl MissionGcpDataflowState {
    #[must_use]
    pub fn from_evidence(evidence: &DataflowEvidence) -> Self {
        if evidence.state != EvidenceState::Complete && evidence.state != EvidenceState::Ready {
            return match evidence.state {
                EvidenceState::Partial => Self::Partial,
                EvidenceState::Stale => Self::Stale,
                EvidenceState::AccessLost => Self::AccessLost,
                EvidenceState::NotFound => Self::NotFound,
                EvidenceState::Conflict => Self::Conflict,
                EvidenceState::RateLimited => Self::RateLimited,
                EvidenceState::TimedOut => Self::TimedOut,
                EvidenceState::ProviderUnknown => Self::ProviderUnknown,
                EvidenceState::Tampered => Self::Tampered,
                EvidenceState::Replayed => Self::Tampered,
                EvidenceState::RegistrationRevoked => Self::Revoked,
                EvidenceState::Complete | EvidenceState::Ready => Self::EvidenceReady,
            };
        }
        match evidence.jobs.first().map(|job| &job.state) {
            Some(DataflowJobState::Pending) => Self::Pending,
            Some(DataflowJobState::Queued) => Self::Queued,
            Some(DataflowJobState::Running) => Self::Running,
            Some(DataflowJobState::Cancellable) => Self::Running,
            Some(DataflowJobState::Draining) => Self::Draining,
            Some(DataflowJobState::Drained) => Self::Drained,
            Some(DataflowJobState::Done) => Self::Done,
            Some(DataflowJobState::Failed) => Self::Failed,
            Some(DataflowJobState::Cancelled) => Self::Cancelled,
            Some(DataflowJobState::Updated) => Self::Updated,
            Some(DataflowJobState::Expired) => Self::Expired,
            Some(DataflowJobState::Partial) => Self::Partial,
            Some(DataflowJobState::AccessLost) => Self::AccessLost,
            Some(DataflowJobState::ProviderUnknown) => Self::ProviderUnknown,
            Some(DataflowJobState::Tampered) => Self::Tampered,
            Some(DataflowJobState::Revoked) => Self::Revoked,
            None => Self::EvidenceReady,
        }
    }
}

pub type MissionGcpDataflowResultState = MissionGcpDataflowState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGcpDataflowResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: DataflowEvidence,
    pub observation_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MissionGcpDataflowState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub work_product_adoption: bool,
}

pub struct MissionGcpDataflowConsumer<T>
where
    T: crate::GcpDataflowTransport,
{
    service: GcpDataflowJobResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_observations: BTreeSet<Digest>,
}

impl<T> fmt::Debug for MissionGcpDataflowConsumer<T>
where
    T: crate::GcpDataflowTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpDataflowConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_observations", &self.consumed_observations.len())
            .finish()
    }
}

impl<T> MissionGcpDataflowConsumer<T>
where
    T: crate::GcpDataflowTransport,
{
    pub fn new(
        service: GcpDataflowJobResultService<T>,
    ) -> Result<Self, MissionGcpDataflowConsumerError> {
        if !service.registration().is_active() || !service.registration().verify_digest() {
            return Err(MissionGcpDataflowConsumerError::RegistrationMismatch);
        }
        let registration_digest = service.registration().registration_digest.clone();
        Ok(Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn from_service(service: GcpDataflowJobResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GcpDataflowJobResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GcpDataflowJobResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &GcpDataflowJobResultScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionGcpDataflowConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGcpDataflowConsumerError> {
        if self.active {
            return Err(MissionGcpDataflowConsumerError::InvalidEvidence);
        }
        self.active = true;
        Ok(())
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<DataflowReadProposal, MissionGcpDataflowConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn read(&mut self) -> Result<DataflowEvidence, MissionGcpDataflowConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn consume(
        &mut self,
        evidence: DataflowEvidence,
    ) -> Result<MissionGcpDataflowResult, MissionGcpDataflowConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest
            || evidence.registration_digest != self.registration_digest
        {
            return Err(MissionGcpDataflowConsumerError::RegistrationMismatch);
        }
        self.service.verify_observation(&evidence)?;
        let observation_digest = evidence.evidence_digest().clone();
        if !self
            .consumed_observations
            .insert(observation_digest.clone())
        {
            return Err(MissionGcpDataflowConsumerError::ReplayDetected);
        }
        Ok(self.result(
            evidence,
            observation_digest,
            Digest::from_text("mission-dataflow-observation"),
        ))
    }

    pub fn consume_observation(
        &mut self,
        evidence: DataflowEvidence,
    ) -> Result<MissionGcpDataflowResult, MissionGcpDataflowConsumerError> {
        self.consume(evidence)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &DataflowReadProposal,
        record: &DataflowReadRecord,
    ) -> Result<MissionGcpDataflowResult, MissionGcpDataflowConsumerError> {
        self.ensure_active()?;
        self.service.verify_proposal(proposal, record)?;
        if proposal.request.scope_digest != self.service.scope().scope_digest() {
            return Err(MissionGcpDataflowConsumerError::ScopeMismatch);
        }
        let evidence = self.service.evidence_from_record(record)?;
        let result = self.consume(evidence)?;
        Ok(MissionGcpDataflowResult {
            proposal_digest: proposal.proposal_digest.clone(),
            ..result
        })
    }

    fn result(
        &self,
        evidence: DataflowEvidence,
        observation_digest: Digest,
        proposal_digest: Digest,
    ) -> MissionGcpDataflowResult {
        MissionGcpDataflowResult {
            project: self.service.scope().project.clone(),
            mission: self.service.scope().mission.clone(),
            work_product: self.service.scope().work_product.clone(),
            state: MissionGcpDataflowState::from_evidence(&evidence),
            evidence,
            proposal_digest,
            observation_digest,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            work_product_adoption: false,
        }
    }

    fn ensure_active(&self) -> Result<(), MissionGcpDataflowConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGcpDataflowConsumerError::Revoked)
        }
    }
}

pub type MissionGcpDataflowResultProjection = MissionGcpDataflowResult;
pub type MissionDataflowConsumer<T> = MissionGcpDataflowConsumer<T>;
