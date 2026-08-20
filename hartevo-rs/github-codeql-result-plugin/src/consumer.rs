//! Mission-scoped consumption of below-kernel CodeQL evidence proposals.

use std::fmt;

use thiserror::Error;

use crate::{
    model::{
        Digest, GithubCodeqlScope, MissionId, ProjectId, RegistrationId, RegistrationState,
        Revision, WorkProductId,
    },
    service::{
        CodeqlResultEvidence, CodeqlResultProposal, GithubCodeqlRegistration, ProjectionState,
        ServiceError,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Github CodeQL consumer is revoked")]
    Revoked,
    #[error("consumer registration is inactive or mismatched")]
    RegistrationMismatch,
    #[error("proposal scope, registration, or evidence fence is stale")]
    FenceMismatch,
    #[error("proposal integrity did not verify")]
    InvalidProposal,
    #[error("proposal is not a below-kernel CodeQL result")]
    InvalidAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_id: RegistrationId,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionCodeqlDecisionState {
    ReviewRequired,
    Layer2AdoptionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGithubCodeqlResult {
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub projection: ProjectionState,
    pub state: MissionCodeqlDecisionState,
    pub evidence: Option<CodeqlResultEvidence>,
    pub proposal_digest: Digest,
    pub adoption: AdoptionAvailability,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adopted: bool,
}

impl MissionGithubCodeqlResult {
    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }
}

pub struct MissionGithubCodeqlConsumer {
    scope: GithubCodeqlScope,
    registration: ConsumerRegistration,
    registration_fence: GithubCodeqlRegistration,
    active: bool,
}

impl fmt::Debug for MissionGithubCodeqlConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGithubCodeqlConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field(
                "registration_fence_digest",
                &self.registration_fence.registration_digest,
            )
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGithubCodeqlConsumer {
    pub fn new(
        scope: GithubCodeqlScope,
        registration: &GithubCodeqlRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::FenceMismatch)?;
        if !registration.is_active() || registration.scope_digest != *scope.digest() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_id: registration.registration_id.clone(),
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.registration_revision,
                state: registration.state,
            },
            registration_fence: registration.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &GithubCodeqlScope {
        &self.scope
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
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
        proposal: &CodeqlResultProposal,
    ) -> Result<MissionGithubCodeqlResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_id != self.registration.registration_id
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.scope_digest != self.registration.scope_digest
        {
            return Err(ConsumerError::FenceMismatch);
        }
        proposal
            .validate_integrity(&self.scope, &self.registration_fence)
            .map_err(|error| match error {
                ServiceError::ProposalTampered
                | ServiceError::ProviderEvidence(_)
                | ServiceError::RecordingTampered => ConsumerError::InvalidProposal,
                _ => ConsumerError::FenceMismatch,
            })?;
        if proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.provider_receipt
            || proposal.outcome_adopted
            || proposal.projection.provenance.connected()
            || proposal.projection.provenance.native()
            || proposal.projection.provenance.first_party()
        {
            return Err(ConsumerError::InvalidAuthority);
        }
        let state = match proposal.projection.state {
            ProjectionState::AlertEvidence
            | ProjectionState::NoAlertEvidence
            | ProjectionState::AnalysisNotFound => MissionCodeqlDecisionState::ReviewRequired,
            ProjectionState::AnalysisIncomplete
            | ProjectionState::Partial
            | ProjectionState::AccessLoss
            | ProjectionState::ProviderUnknown => {
                MissionCodeqlDecisionState::Layer2AdoptionRequired
            }
        };
        Ok(MissionGithubCodeqlResult {
            project_id: self.scope.mission.project_id.clone(),
            project_revision: self.scope.mission.project_revision,
            mission_id: self.scope.mission.mission_id.clone(),
            mission_revision: self.scope.mission.mission_revision,
            work_product_id: self.scope.mission.work_product_id.clone(),
            work_product_revision: self.scope.mission.work_product_revision,
            projection: proposal.projection.state,
            state,
            evidence: proposal.projection.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            connected: false,
            native: false,
            first_party: false,
            outcome_adopted: false,
        })
    }
}
