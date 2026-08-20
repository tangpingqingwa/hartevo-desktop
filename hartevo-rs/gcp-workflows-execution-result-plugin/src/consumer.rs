//! Mission-facing, proposal-only observation consumer.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::Digest;
use crate::model::{
    EvidenceState, GcpWorkflowsExecutionEvidence, GcpWorkflowsScope, MissionBinding,
    ProjectBinding, WorkProductBinding,
};
use crate::provider::{ExecutionReadProposal, ExecutionReadRecord, GcpWorkflowsTransport};
use crate::service::{GcpWorkflowsExecutionService, GcpWorkflowsExecutionServiceError};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Workflows consumer is revoked")]
    Revoked,
    #[error("Mission GCP Workflows registration does not match the observation")]
    RegistrationMismatch,
    #[error("Mission GCP Workflows observation replay was rejected")]
    ReplayDetected,
    #[error("Mission GCP Workflows evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("Mission GCP Workflows proposal is not for the exact Mission scope")]
    ScopeMismatch,
    #[error("Mission GCP Workflows service error: {0}")]
    Service(#[from] GcpWorkflowsExecutionServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpWorkflowState {
    EvidenceReady,
    PartialEvidence,
    Unknown,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl MissionGcpWorkflowState {
    pub const fn from_evidence(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Complete => Self::EvidenceReady,
            EvidenceState::Partial => Self::PartialEvidence,
            EvidenceState::Unknown => Self::Unknown,
            EvidenceState::AccessLost => Self::AccessLost,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::RateLimited => Self::RateLimited,
            EvidenceState::Timeout => Self::Timeout,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

pub type MissionGcpWorkflowResultState = MissionGcpWorkflowState;
pub type MissionResultState = MissionGcpWorkflowState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGcpWorkflowResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: GcpWorkflowsExecutionEvidence,
    pub observation_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MissionGcpWorkflowState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub work_product_adoption: bool,
}

pub struct MissionGcpWorkflowConsumer<T>
where
    T: GcpWorkflowsTransport,
{
    service: GcpWorkflowsExecutionService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_observations: BTreeSet<Digest>,
}

impl<T> fmt::Debug for MissionGcpWorkflowConsumer<T>
where
    T: GcpWorkflowsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpWorkflowConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_observations", &self.consumed_observations.len())
            .finish()
    }
}

impl<T> MissionGcpWorkflowConsumer<T>
where
    T: GcpWorkflowsTransport,
{
    pub fn new(service: GcpWorkflowsExecutionService<T>) -> Result<Self, ConsumerError> {
        let registration_digest = service.registration().registration_digest.clone();
        Ok(Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        })
    }

    pub fn from_service(service: GcpWorkflowsExecutionService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        }
    }

    pub fn service(&self) -> &GcpWorkflowsExecutionService<T> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut GcpWorkflowsExecutionService<T> {
        &mut self.service
    }

    pub fn scope(&self) -> &GcpWorkflowsScope {
        self.service.scope()
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            return Err(ConsumerError::InvalidEvidence);
        }
        self.active = true;
        Ok(())
    }

    pub fn compile_proposal(&self) -> Result<ExecutionReadProposal, ConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn read(&mut self) -> Result<GcpWorkflowsExecutionEvidence, ConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read_bounded()?)
    }

    pub fn consume(
        &mut self,
        evidence: GcpWorkflowsExecutionEvidence,
    ) -> Result<MissionGcpWorkflowResult, ConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest
            || evidence.registration_digest != self.registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !evidence.verify_digest()
            || evidence.scope_digest != self.service.scope().scope_digest()
            || evidence.permission_digest != self.service.scope().permission_digest()
            || evidence.provider_digest != self.service.registration().provider_digest
            || evidence.provider_revision != self.service.registration().provider_revision
            || evidence.native
            || evidence.connected
            || evidence.outcome_authority
            || evidence.work_product_adoption
        {
            return Err(ConsumerError::InvalidEvidence);
        }
        let observation_digest = evidence.digests.evidence_digest.clone();
        if !self
            .consumed_observations
            .insert(observation_digest.clone())
        {
            return Err(ConsumerError::ReplayDetected);
        }
        Ok(self.result(evidence, observation_digest))
    }

    pub fn consume_observation(
        &mut self,
        evidence: GcpWorkflowsExecutionEvidence,
    ) -> Result<MissionGcpWorkflowResult, ConsumerError> {
        self.consume(evidence)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &ExecutionReadProposal,
        record: &ExecutionReadRecord,
    ) -> Result<MissionGcpWorkflowResult, ConsumerError> {
        self.ensure_active()?;
        self.service.verify_proposal(proposal, record)?;
        if proposal.request().scope_digest != self.service.scope().scope_digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        let evidence = self.service.evidence_from_record(record)?;
        let result = self.consume(evidence)?;
        Ok(MissionGcpWorkflowResult {
            proposal_digest: proposal.proposal_digest().clone(),
            ..result
        })
    }

    fn result(
        &self,
        evidence: GcpWorkflowsExecutionEvidence,
        observation_digest: Digest,
    ) -> MissionGcpWorkflowResult {
        let state = MissionGcpWorkflowState::from_evidence(evidence.state);
        MissionGcpWorkflowResult {
            project: self.service.scope().project.clone(),
            mission: self.service.scope().mission.clone(),
            work_product: self.service.scope().work_product.clone(),
            proposal_digest: observation_digest.clone(),
            observation_digest,
            evidence,
            state,
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            work_product_adoption: false,
        }
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }
}

pub type MissionGcpWorkflowsConsumer<T> = MissionGcpWorkflowConsumer<T>;
pub type MissionGcpWorkflowResultProjection = MissionGcpWorkflowResult;
