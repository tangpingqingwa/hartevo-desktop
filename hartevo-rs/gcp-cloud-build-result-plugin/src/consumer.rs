//! Mission-facing proposal-only Cloud Build result consumer.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::model::{
    CloudBuildOperation, EvidenceState, GcpCloudBuildEvidence, GcpCloudBuildScope, Revision,
};
use crate::provider::{CloudBuildReadProposal, CloudBuildReadRecord, GcpCloudBuildTransport};
use crate::service::{GcpCloudBuildResultService, GcpCloudBuildResultServiceError};
use crate::{CloudBuildSummary, Digest, MissionBinding, ProjectBinding, WorkProductBinding};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGcpBuildConsumerError {
    #[error("Mission GCP Build consumer is revoked")]
    Revoked,
    #[error("Mission GCP Build registration does not match the observation")]
    RegistrationMismatch,
    #[error("Mission GCP Build observation replay was rejected")]
    ReplayDetected,
    #[error("Mission GCP Build evidence is invalid or tampered")]
    InvalidEvidence,
    #[error("Mission GCP Build proposal is not for the exact Mission scope")]
    ScopeMismatch,
    #[error("Mission GCP Build revision is stale")]
    StaleMissionRevision,
    #[error("Mission GCP Build service error: {0}")]
    Service(#[from] GcpCloudBuildResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpBuildState {
    EvidenceReady,
    PartialEvidence,
    Stale,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl MissionGcpBuildState {
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

pub type MissionGcpBuildResultState = MissionGcpBuildState;
pub type MissionResultState = MissionGcpBuildState;

#[derive(Clone, Debug, PartialEq)]
pub struct MissionGcpBuildResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub operation: CloudBuildOperation,
    pub builds: Vec<CloudBuildSummary>,
    pub evidence: GcpCloudBuildEvidence,
    pub observation_digest: Digest,
    pub proposal_digest: Option<Digest>,
    pub state: MissionGcpBuildState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub work_product_adoption: bool,
}

pub struct MissionGcpBuildConsumer<T>
where
    T: GcpCloudBuildTransport,
{
    service: GcpCloudBuildResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_observations: BTreeSet<Digest>,
}

impl<T> fmt::Debug for MissionGcpBuildConsumer<T>
where
    T: GcpCloudBuildTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpBuildConsumer")
            .field("scope_digest", &self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_observations", &self.consumed_observations.len())
            .finish()
    }
}

impl<T> MissionGcpBuildConsumer<T>
where
    T: GcpCloudBuildTransport,
{
    pub fn new(
        service: GcpCloudBuildResultService<T>,
    ) -> Result<Self, MissionGcpBuildConsumerError> {
        let registration_digest = service.registration().registration_digest.clone();
        Ok(Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn from_service(service: GcpCloudBuildResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_observations: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GcpCloudBuildResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GcpCloudBuildResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudBuildScope {
        self.service.scope()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGcpBuildConsumerError> {
        if self.active {
            return Err(MissionGcpBuildConsumerError::InvalidEvidence);
        }
        self.active = true;
        Ok(())
    }

    pub fn compile_proposal(&self) -> Result<CloudBuildReadProposal, MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        Ok(self.service.compile_proposal()?)
    }

    pub fn read(&mut self) -> Result<GcpCloudBuildEvidence, MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read()?)
    }

    pub fn read_at_mission_revision(
        &mut self,
        revision: u64,
    ) -> Result<GcpCloudBuildEvidence, MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        Ok(self.service.read_at_mission_revision(revision)?)
    }

    pub fn consume(
        &mut self,
        evidence: GcpCloudBuildEvidence,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        self.consume_internal(evidence, None)
    }

    pub fn consume_at_mission_revision(
        &mut self,
        evidence: GcpCloudBuildEvidence,
        expected_revision: u64,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        let expected = Revision::new(expected_revision)
            .map_err(|_| MissionGcpBuildConsumerError::StaleMissionRevision)?;
        self.consume_internal(evidence, Some(expected))
    }

    pub fn consume_observation(
        &mut self,
        evidence: GcpCloudBuildEvidence,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        self.consume(evidence)
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &CloudBuildReadProposal,
        record: &CloudBuildReadRecord,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        self.consume_proposal_at_mission_revision(
            proposal,
            record,
            self.scope().mission_revision().get(),
        )
    }

    pub fn consume_proposal_at_mission_revision(
        &mut self,
        proposal: &CloudBuildReadProposal,
        record: &CloudBuildReadRecord,
        expected_revision: u64,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        let expected = Revision::new(expected_revision)
            .map_err(|_| MissionGcpBuildConsumerError::StaleMissionRevision)?;
        if proposal.mission_revision != expected
            || expected != self.scope().mission_revision()
            || proposal.request.scope_digest != self.scope().scope_digest()
        {
            return Err(MissionGcpBuildConsumerError::StaleMissionRevision);
        }
        self.service.verify_proposal(proposal, record)?;
        let evidence = self.service.evidence_from_record(record)?;
        let mut result = self.consume_internal(evidence, Some(expected))?;
        result.proposal_digest = Some(proposal.proposal_digest().clone());
        Ok(result)
    }

    fn consume_internal(
        &mut self,
        evidence: GcpCloudBuildEvidence,
        expected_revision: Option<Revision>,
    ) -> Result<MissionGcpBuildResult, MissionGcpBuildConsumerError> {
        self.ensure_active()?;
        if expected_revision.is_some_and(|expected| {
            expected != self.scope().mission_revision() || expected != evidence.mission_revision
        }) {
            return Err(MissionGcpBuildConsumerError::StaleMissionRevision);
        }
        if self.service.registration().registration_digest != self.registration_digest
            || evidence.registration_digest != self.registration_digest
        {
            return Err(MissionGcpBuildConsumerError::RegistrationMismatch);
        }
        if !evidence.verify_digest()
            || evidence.scope_digest != self.scope().scope_digest()
            || evidence.permission_digest != self.scope().permission_digest()
            || evidence.source_digest != self.scope().source_digest()
            || evidence.trigger_digest != self.scope().trigger_digest()
            || evidence.provider_digest != self.service.registration().provider_digest
            || evidence.native
            || evidence.connected
            || evidence.first_party
            || evidence.outcome_authority
            || evidence.work_product_adoption
            || !evidence.proposal_only
        {
            return Err(MissionGcpBuildConsumerError::InvalidEvidence);
        }
        let observation_digest = evidence.evidence_digest.clone();
        if !self
            .consumed_observations
            .insert(observation_digest.clone())
        {
            return Err(MissionGcpBuildConsumerError::ReplayDetected);
        }
        Ok(self.result(evidence, observation_digest, None))
    }

    fn result(
        &self,
        evidence: GcpCloudBuildEvidence,
        observation_digest: Digest,
        proposal_digest: Option<Digest>,
    ) -> MissionGcpBuildResult {
        MissionGcpBuildResult {
            project: self.scope().project.clone(),
            mission: self.scope().mission.clone(),
            work_product: self.scope().work_product.clone(),
            operation: evidence.operation,
            builds: evidence.builds.clone(),
            state: MissionGcpBuildState::from_evidence(evidence.state),
            evidence,
            observation_digest,
            proposal_digest,
            proposal_only: true,
            native: false,
            connected: false,
            first_party: false,
            adopts_outcome: false,
            work_product_adoption: false,
        }
    }

    fn ensure_active(&self) -> Result<(), MissionGcpBuildConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGcpBuildConsumerError::Revoked)
        }
    }
}

pub type MissionGcpBuildResultProjection = MissionGcpBuildResult;
pub type MissionGcpCloudBuildConsumer<T> = MissionGcpBuildConsumer<T>;
