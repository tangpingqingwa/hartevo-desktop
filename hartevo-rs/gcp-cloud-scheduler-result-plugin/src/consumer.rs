//! Mission-facing, proposal-only observation consumer.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::Digest;
use crate::model::{
    EvidenceState, GcpCloudSchedulerEvidence, GcpCloudSchedulerScope, MissionBinding,
    ProjectBinding, WorkProductBinding,
};
use crate::provider::{
    CloudSchedulerReadProposal, CloudSchedulerReadRecord, GcpCloudSchedulerTransport,
};
use crate::service::{GcpCloudSchedulerResultService, GcpCloudSchedulerResultServiceError};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGcpCloudSchedulerConsumerError {
    #[error("Mission GCP Cloud Scheduler consumer is revoked")]
    Revoked,
    #[error("Mission GCP Cloud Scheduler registration does not match the observation")]
    RegistrationMismatch,
    #[error("Mission GCP Cloud Scheduler observation replay was rejected")]
    ReplayDetected,
    #[error("Mission GCP Cloud Scheduler evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("Mission GCP Cloud Scheduler proposal is not for the exact Mission scope")]
    ScopeMismatch,
    #[error("Mission GCP Cloud Scheduler service error: {0}")]
    Service(#[from] GcpCloudSchedulerResultServiceError),
}

pub type ConsumerError = MissionGcpCloudSchedulerConsumerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpCloudSchedulerState {
    EvidenceReady,
    PartialEvidence,
    Stale,
    Unknown,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl MissionGcpCloudSchedulerState {
    #[must_use]
    pub const fn from_evidence(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Complete => Self::EvidenceReady,
            EvidenceState::Partial => Self::PartialEvidence,
            EvidenceState::Stale => Self::Stale,
            EvidenceState::AccessLost => Self::AccessLost,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::RateLimited => Self::RateLimited,
            EvidenceState::Timeout => Self::Timeout,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

pub type MissionGcpCloudSchedulerResultState = MissionGcpCloudSchedulerState;
pub type MissionResultState = MissionGcpCloudSchedulerState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGcpCloudSchedulerResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: GcpCloudSchedulerEvidence,
    pub observation_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MissionGcpCloudSchedulerState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub work_product_adoption: bool,
}

pub struct MissionGcpCloudSchedulerConsumer<T>
where
    T: GcpCloudSchedulerTransport,
{
    service: GcpCloudSchedulerResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_observations: BTreeSet<Digest>,
}

impl<T> fmt::Debug for MissionGcpCloudSchedulerConsumer<T>
where
    T: GcpCloudSchedulerTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpCloudSchedulerConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_observations", &self.consumed_observations.len())
            .finish()
    }
}

impl<T> MissionGcpCloudSchedulerConsumer<T>
where
    T: GcpCloudSchedulerTransport,
{
    pub fn new(
        service: GcpCloudSchedulerResultService<T>,
    ) -> Result<Self, MissionGcpCloudSchedulerConsumerError> {
        if !service.is_registered() {
            return Err(MissionGcpCloudSchedulerConsumerError::RegistrationMismatch);
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
    pub fn from_service(service: GcpCloudSchedulerResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GcpCloudSchedulerResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GcpCloudSchedulerResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudSchedulerScope {
        self.service.scope()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionGcpCloudSchedulerConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGcpCloudSchedulerConsumerError> {
        if self.active {
            return Err(MissionGcpCloudSchedulerConsumerError::InvalidEvidence);
        }
        self.active = true;
        Ok(())
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<CloudSchedulerReadProposal, MissionGcpCloudSchedulerConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn read(
        &mut self,
    ) -> Result<GcpCloudSchedulerEvidence, MissionGcpCloudSchedulerConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn consume(
        &mut self,
        evidence: GcpCloudSchedulerEvidence,
    ) -> Result<MissionGcpCloudSchedulerResult, MissionGcpCloudSchedulerConsumerError> {
        self.ensure_active()?;
        self.validate_evidence(&evidence)?;
        let observation_digest = evidence.evidence_digest().clone();
        if !self
            .consumed_observations
            .insert(observation_digest.clone())
        {
            return Err(MissionGcpCloudSchedulerConsumerError::ReplayDetected);
        }
        Ok(self.result(evidence, observation_digest.clone(), observation_digest))
    }

    pub fn consume_observation(
        &mut self,
        evidence: GcpCloudSchedulerEvidence,
    ) -> Result<MissionGcpCloudSchedulerResult, MissionGcpCloudSchedulerConsumerError> {
        self.consume(evidence)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &CloudSchedulerReadProposal,
        record: &CloudSchedulerReadRecord,
    ) -> Result<MissionGcpCloudSchedulerResult, MissionGcpCloudSchedulerConsumerError> {
        self.ensure_active()?;
        self.service.verify_proposal(proposal, record)?;
        if proposal.request.scope_digest != self.service.scope().scope_digest() {
            return Err(MissionGcpCloudSchedulerConsumerError::ScopeMismatch);
        }
        let evidence = self.service.evidence_from_record(record)?;
        let result = self.consume(evidence)?;
        Ok(MissionGcpCloudSchedulerResult {
            proposal_digest: proposal.proposal_digest().clone(),
            ..result
        })
    }

    fn validate_evidence(
        &self,
        evidence: &GcpCloudSchedulerEvidence,
    ) -> Result<(), MissionGcpCloudSchedulerConsumerError> {
        if self.service.registration().registration_digest != self.registration_digest
            || evidence.registration_digest != self.registration_digest
        {
            return Err(MissionGcpCloudSchedulerConsumerError::RegistrationMismatch);
        }
        let registration = self.service.registration();
        if !evidence.verify_digest()
            || evidence.scope_digest != self.service.scope().scope_digest()
            || evidence.permission_digest != self.service.scope().permission_digest()
            || evidence.provider_digest != registration.provider_digest
            || evidence.provider_revision != registration.provider_revision
            || evidence.project_revision != self.service.scope().project_revision()
            || evidence.mission_revision != self.service.scope().mission_revision()
            || evidence.work_product_revision != self.service.scope().work_product_revision()
            || evidence.digests.provider_digest != registration.provider_digest
            || evidence.digests.permission_digest != registration.permission_digest
            || evidence.digests.scope_digest != registration.scope_digest
            || evidence.digests.secret_reference_digest != registration.secret_reference_digest
            || evidence.native
            || evidence.connected
            || evidence.first_party
            || !evidence.proposal_only
            || evidence.outcome_authority
            || evidence.work_product_adoption
        {
            return Err(MissionGcpCloudSchedulerConsumerError::InvalidEvidence);
        }
        Ok(())
    }

    fn result(
        &self,
        evidence: GcpCloudSchedulerEvidence,
        observation_digest: Digest,
        proposal_digest: Digest,
    ) -> MissionGcpCloudSchedulerResult {
        let state = MissionGcpCloudSchedulerState::from_evidence(evidence.state);
        MissionGcpCloudSchedulerResult {
            project: self.service.scope().project.clone(),
            mission: self.service.scope().mission.clone(),
            work_product: self.service.scope().work_product.clone(),
            evidence,
            observation_digest,
            proposal_digest,
            state,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            work_product_adoption: false,
        }
    }

    fn ensure_active(&self) -> Result<(), MissionGcpCloudSchedulerConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGcpCloudSchedulerConsumerError::Revoked)
        }
    }
}

pub type MissionGcpCloudSchedulerResultConsumer<T> = MissionGcpCloudSchedulerConsumer<T>;
pub type MissionGcpCloudSchedulerProjection = MissionGcpCloudSchedulerResult;
