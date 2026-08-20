//! Mission-facing, proposal-only Jenkins build-result consumer.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::model::{
    Digest, JenkinsBuildResultEvidence, JenkinsBuildResultScope, JenkinsBuildResultStatus,
    MissionBinding, ProjectBinding, WorkProductBinding,
};
use crate::provider::JenkinsTransport;
use crate::service::{
    JenkinsBuildResultProposal, JenkinsBuildResultRequest, JenkinsBuildResultService,
    JenkinsBuildResultServiceError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionJenkinsBuildConsumerError {
    #[error("Mission Jenkins build-result consumer is revoked")]
    Revoked,
    #[error("Mission Jenkins build-result registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Jenkins build-result proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Jenkins build-result proposal is stale or tampered")]
    StaleProposal,
    #[error(transparent)]
    Service(#[from] JenkinsBuildResultServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionJenkinsBuildResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: JenkinsBuildResultEvidence,
    pub proposal_digest: Digest,
    pub status: JenkinsBuildResultStatus,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

pub type MissionJenkinsBuildResultState = JenkinsBuildResultStatus;
pub type MissionResultState = JenkinsBuildResultStatus;

/// Mission consumer for one exact Jenkins build and one exact
/// Project/Mission/Work Product binding. It owns only an in-memory replay
/// fence; durable adoption remains outside this Layer-1 root.
pub struct MissionJenkinsBuildConsumer<T: JenkinsTransport> {
    service: JenkinsBuildResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: JenkinsTransport> fmt::Debug for MissionJenkinsBuildConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionJenkinsBuildConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: JenkinsTransport> MissionJenkinsBuildConsumer<T> {
    pub fn new(
        provider: crate::JenkinsProvider<T>,
    ) -> Result<Self, MissionJenkinsBuildConsumerError> {
        Ok(Self::from_service(JenkinsBuildResultService::new(
            provider,
        )?))
    }

    #[must_use]
    pub fn from_service(service: JenkinsBuildResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest().clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    pub fn service(&self) -> &JenkinsBuildResultService<T> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut JenkinsBuildResultService<T> {
        &mut self.service
    }

    pub fn scope(&self) -> &JenkinsBuildResultScope {
        self.service.scope()
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn read(
        &mut self,
        request: &JenkinsBuildResultRequest,
    ) -> Result<JenkinsBuildResultEvidence, MissionJenkinsBuildConsumerError> {
        self.ensure_active()?;
        self.service.read(request).map_err(Into::into)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<JenkinsBuildResultProposal, MissionJenkinsBuildConsumerError> {
        self.ensure_active()?;
        self.service.compile_proposal().map_err(Into::into)
    }

    pub fn consume(
        &mut self,
        proposal: &JenkinsBuildResultProposal,
    ) -> Result<MissionJenkinsBuildResult, MissionJenkinsBuildConsumerError> {
        self.ensure_active()?;
        if proposal.registration_digest != self.registration_digest {
            return Err(MissionJenkinsBuildConsumerError::RegistrationMismatch);
        }
        self.service
            .verify_proposal(proposal)
            .map_err(|_| MissionJenkinsBuildConsumerError::StaleProposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionJenkinsBuildConsumerError::ReplayDetected);
        }
        Ok(MissionJenkinsBuildResult {
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            status: proposal.status(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &JenkinsBuildResultProposal,
    ) -> Result<MissionJenkinsBuildResult, MissionJenkinsBuildConsumerError> {
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionJenkinsBuildConsumerError> {
        self.ensure_active()?;
        self.service.revoke_registration()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionJenkinsBuildConsumerError> {
        if self.active {
            return Err(MissionJenkinsBuildConsumerError::Service(
                JenkinsBuildResultServiceError::Contract(
                    "Mission Jenkins consumer is already active".to_owned(),
                ),
            ));
        }
        self.service.restore_registration()?;
        self.registration_digest = self.service.registration().registration_digest().clone();
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionJenkinsBuildConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionJenkinsBuildConsumerError::Revoked)
        }
    }
}

pub type MissionJenkinsBuildResultConsumer<T> = MissionJenkinsBuildConsumer<T>;
