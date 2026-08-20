//! Mission-scoped consumer for bounded Boundary session-result proposals.
//!
//! The consumer checks exact Mission/Project/Work Product and provider
//! registration bindings. It returns a local typed observation and never
//! adopts a Work Product or becomes Truth, Consent, Effect, Receipt,
//! Verification, or Outcome authority.

use std::fmt;

use thiserror::Error;

use crate::model::{
    BoundaryModelError, BoundaryRegistration, BoundaryScope, BoundarySessionResultProposal,
    BoundarySessionResultState, Digest, RegistrationState,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MissionBoundarySessionConsumerError {
    #[error("Boundary consumer model error: {0}")]
    Model(#[from] BoundaryModelError),
    #[error("Boundary consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Boundary consumer registration is stale or drifted")]
    RegistrationDrift,
    #[error("Boundary consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Boundary consumer Mission/Project/Work Product scope is stale")]
    StaleMission,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionBoundarySessionObservation {
    pub accepted: bool,
    pub state: BoundarySessionResultState,
    pub scope_digest: Digest,
    pub mission_digest: Digest,
    pub project_digest: Digest,
    pub work_product_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

pub type MissionBoundarySessionResult = MissionBoundarySessionObservation;

pub struct MissionBoundarySessionConsumer {
    scope_digest: Digest,
    mission_digest: Digest,
    project_digest: Digest,
    work_product_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
}

impl fmt::Debug for MissionBoundarySessionConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionBoundarySessionConsumer")
            .field("scope_digest", &self.scope_digest)
            .field("mission_digest", &self.mission_digest)
            .field("project_digest", &self.project_digest)
            .field("work_product_digest", &self.work_product_digest)
            .field("registration_digest", &self.registration_digest)
            .field("state", &self.state)
            .finish()
    }
}

impl MissionBoundarySessionConsumer {
    pub fn new(
        scope: &BoundaryScope,
        registration: &BoundaryRegistration,
    ) -> Result<Self, MissionBoundarySessionConsumerError> {
        scope.validate()?;
        if scope.scope_digest() != &scope.recompute_digest() {
            return Err(MissionBoundarySessionConsumerError::RegistrationDrift);
        }
        if !registration.is_active() {
            return Err(MissionBoundarySessionConsumerError::RegistrationRevoked);
        }
        if registration.scope_digest != *scope.scope_digest() {
            return Err(MissionBoundarySessionConsumerError::RegistrationDrift);
        }
        Ok(Self {
            scope_digest: scope.scope_digest().clone(),
            mission_digest: scope.mission.digest(),
            project_digest: scope.project.digest(),
            work_product_digest: scope.work_product.digest(),
            registration_digest: registration.registration_digest.clone(),
            state: RegistrationState::Active,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<(), MissionBoundarySessionConsumerError> {
        if !self.is_active() {
            return Err(MissionBoundarySessionConsumerError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<MissionBoundarySessionObservation, MissionBoundarySessionConsumerError> {
        if !self.is_active() {
            return Err(MissionBoundarySessionConsumerError::RegistrationRevoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| MissionBoundarySessionConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration_digest {
            return Err(MissionBoundarySessionConsumerError::RegistrationDrift);
        }
        if proposal.scope_digest != self.scope_digest
            || proposal.evidence.scope_digest != self.scope_digest
        {
            return Err(MissionBoundarySessionConsumerError::StaleMission);
        }
        Ok(MissionBoundarySessionObservation {
            accepted: true,
            state: proposal.state(),
            scope_digest: self.scope_digest.clone(),
            mission_digest: self.mission_digest.clone(),
            project_digest: self.project_digest.clone(),
            work_product_digest: self.work_product_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adopted: false,
        })
    }

    pub fn consume_result(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<MissionBoundarySessionResult, MissionBoundarySessionConsumerError> {
        self.consume(proposal)
    }

    pub fn propose_adoption(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<MissionBoundarySessionResult, MissionBoundarySessionConsumerError> {
        self.consume(proposal)
    }
}
