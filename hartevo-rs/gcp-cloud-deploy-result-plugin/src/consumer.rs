use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{Digest, EvidenceProjection, GcpCloudDeployScope, ModelError, Revision},
    provider::GcpCloudDeployTransport,
    service::{
        GcpCloudDeployProposal, GcpCloudDeployRegistration, GcpCloudDeployService,
        GcpCloudDeployServiceError, RegistrationState,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    PendingDecision,
    AccessLost,
    Layer2AdoptionRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerRegistration {
    registration_digest: Digest,
    scope_digest: Digest,
    release_digest: Digest,
    revision: Revision,
    state: RegistrationState,
}

impl ConsumerRegistration {
    fn from_registration(registration: &GcpCloudDeployRegistration) -> Self {
        Self {
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            release_digest: registration.release_digest().clone(),
            revision: registration.revision(),
            state: registration.state(),
        }
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn release_digest(&self) -> &Digest {
        &self.release_digest
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGcpCloudDeployResult {
    mission_id: crate::model::MissionId,
    mission_revision: Revision,
    project_id: crate::model::ProjectId,
    project_revision: Revision,
    work_product_id: crate::model::WorkProductId,
    work_product_revision: Revision,
    release_digest: Digest,
    rollout_digests: Vec<Digest>,
    job_run_digests: Vec<Digest>,
    projection: EvidenceProjection,
    state: MissionResultState,
    adoption: AdoptionAvailability,
    evidence_digest: Digest,
    proposal_digest: Digest,
    connected: bool,
    native: bool,
    deployment_success_claimed: bool,
    work_product_adopted: bool,
    outcome_adopted: bool,
}

impl MissionGcpCloudDeployResult {
    pub fn mission_id(&self) -> &crate::model::MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn project_id(&self) -> &crate::model::ProjectId {
        &self.project_id
    }

    pub fn work_product_id(&self) -> &crate::model::WorkProductId {
        &self.work_product_id
    }

    pub const fn projection(&self) -> EvidenceProjection {
        self.projection
    }

    pub const fn state(&self) -> MissionResultState {
        self.state
    }

    pub const fn adoption(&self) -> AdoptionAvailability {
        self.adoption
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn deployment_success_claimed(&self) -> bool {
        self.deployment_success_claimed
    }

    pub const fn work_product_adopted(&self) -> bool {
        self.work_product_adopted
    }

    pub const fn outcome_adopted(&self) -> bool {
        self.outcome_adopted
    }

    pub fn rollout_digests(&self) -> &[Digest] {
        &self.rollout_digests
    }

    pub fn job_run_digests(&self) -> &[Digest] {
        &self.job_run_digests
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConsumerError {
    #[error("consumer scope or release fence mismatch")]
    ScopeMismatch,
    #[error("consumer registration is revoked")]
    Revoked,
    #[error("proposal is invalid or tampered")]
    InvalidProposal,
    #[error("service read failed: {0}")]
    Service(String),
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
}

pub struct MissionGcpCloudDeployConsumer {
    scope: GcpCloudDeployScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl std::fmt::Debug for MissionGcpCloudDeployConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionGcpCloudDeployConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGcpCloudDeployConsumer {
    pub fn new(
        scope: GcpCloudDeployScope,
        registration: &GcpCloudDeployRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate()?;
        if registration.state() != RegistrationState::Active
            || registration.scope_digest() != &scope.digest()
            || registration.release_digest() != &scope.release_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration::from_registration(registration),
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &GcpCloudDeployScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    pub fn consume(
        &self,
        proposal: GcpCloudDeployProposal,
    ) -> Result<MissionGcpCloudDeployResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest() != self.registration.registration_digest()
            || proposal.registration_revision() != self.registration.revision
            || proposal.scope_digest() != self.registration.scope_digest()
            || proposal.evidence().release_digest() != self.registration.release_digest()
            || proposal.validate_digest().is_err()
        {
            return Err(ConsumerError::InvalidProposal);
        }
        let state = match proposal.projection() {
            EvidenceProjection::AccessLost => MissionResultState::AccessLost,
            EvidenceProjection::Unknown => MissionResultState::Layer2AdoptionRequired,
            EvidenceProjection::Complete
            | EvidenceProjection::Partial
            | EvidenceProjection::RateLimited => MissionResultState::PendingDecision,
        };
        Ok(MissionGcpCloudDeployResult {
            mission_id: self.scope.mission().id().clone(),
            mission_revision: self.scope.mission().revision(),
            project_id: self.scope.project().id().clone(),
            project_revision: self.scope.project().revision(),
            work_product_id: self.scope.work_product().id().clone(),
            work_product_revision: self.scope.work_product().revision(),
            release_digest: proposal.evidence().release_digest().clone(),
            rollout_digests: proposal.evidence().rollout_digests().to_vec(),
            job_run_digests: proposal.evidence().job_run_digests().to_vec(),
            projection: proposal.projection(),
            state,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            evidence_digest: proposal.evidence().evidence_digest().clone(),
            proposal_digest: proposal.proposal_digest().clone(),
            connected: false,
            native: false,
            deployment_success_claimed: false,
            work_product_adopted: false,
            outcome_adopted: false,
        })
    }

    pub fn read<T>(
        &self,
        service: &mut GcpCloudDeployService<T>,
    ) -> Result<MissionGcpCloudDeployResult, ConsumerError>
    where
        T: GcpCloudDeployTransport,
    {
        if service.scope().digest() != self.scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        let proposal = service
            .propose()
            .map_err(|error| map_service_error(&error))?;
        self.consume(proposal)
    }
}

fn map_service_error(error: &GcpCloudDeployServiceError) -> ConsumerError {
    match error {
        GcpCloudDeployServiceError::ScopeMismatch
        | GcpCloudDeployServiceError::RegistrationMismatch => ConsumerError::ScopeMismatch,
        GcpCloudDeployServiceError::RegistrationRevoked
        | GcpCloudDeployServiceError::SecretRevoked => ConsumerError::Revoked,
        GcpCloudDeployServiceError::InvalidProposal
        | GcpCloudDeployServiceError::PhaseRegression => ConsumerError::InvalidProposal,
        GcpCloudDeployServiceError::InvalidRecord => ConsumerError::InvalidProposal,
        GcpCloudDeployServiceError::DefinitionDrift
        | GcpCloudDeployServiceError::Provider(_)
        | GcpCloudDeployServiceError::Model(_) => ConsumerError::Service(error.to_string()),
    }
}
