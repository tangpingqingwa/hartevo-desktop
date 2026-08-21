//! Mission-bound consumer for bounded AWS Glue job-run evidence.

use std::fmt;

use thiserror::Error;

use crate::{
    AdoptionAvailability, AwsGlueJobResultEvidence, AwsGlueJobResultProposal, AwsGlueRegistration,
    AwsGlueScope, Digest, Layer1Authority, MissionId, RegistrationState, ResultProjection,
    ResultStatus, Revision, WorkProductId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Glue consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed AWS Glue service")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsGlueJobResult {
    pub mission_id: MissionId,
    pub project_id: crate::ProjectId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub projection: ResultProjection,
    pub status: ResultStatus,
    pub state: MissionResultState,
    pub evidence: AwsGlueJobResultEvidence,
    pub proposal_digest: Digest,
    pub authority: Layer1Authority,
    pub adoption: AdoptionAvailability,
}

pub struct MissionAwsGlueJobConsumer {
    scope: AwsGlueScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionAwsGlueJobConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsGlueJobConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionAwsGlueJobConsumer {
    pub fn new(
        scope: AwsGlueScope,
        registration: &AwsGlueRegistration,
    ) -> Result<Self, ConsumerError> {
        registration
            .validate_digest()
            .map_err(|_| ConsumerError::RegistrationMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
            || registration.permission_digest != *scope.permission_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsGlueScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: AwsGlueJobResultProposal,
    ) -> Result<MissionAwsGlueJobResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::InvalidProposal)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.request.job_name.as_str().is_empty()
            || !self.scope.contains_job(&proposal.request.job_name)
            || proposal.request.work_product_revision != self.scope.work_product_revision()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.mission_id != *self.scope.mission_id()
            || proposal.evidence.project_id != *self.scope.project_id()
            || proposal.evidence.work_product_id != *self.scope.work_product_id()
            || proposal.evidence.work_product_revision != self.scope.work_product_revision()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        let state = if proposal.projection == ResultProjection::Succeeded {
            MissionResultState::PendingDecision
        } else {
            MissionResultState::Layer2AdoptionRequired
        };
        Ok(MissionAwsGlueJobResult {
            mission_id: self.scope.mission_id().clone(),
            project_id: self.scope.project_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            projection: proposal.projection,
            status: proposal.status(),
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            authority: Layer1Authority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }
}

pub type MissionAwsGlueConsumer = MissionAwsGlueJobConsumer;
