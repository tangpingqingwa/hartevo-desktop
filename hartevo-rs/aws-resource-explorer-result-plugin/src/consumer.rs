//! Mission-facing proposal consumer. It never adopts a kernel Outcome.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AwsResourceExplorerEvidence, AwsResourceExplorerProposal, AwsResourceExplorerRegistration,
    AwsResourceExplorerScope, Digest, InventoryState, RegistrationState,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAwsResourceExplorerConsumerError {
    #[error("Mission AWS Resource Explorer consumer is revoked")]
    Revoked,
    #[error("Mission AWS Resource Explorer registration is not active")]
    RegistrationRevoked,
    #[error("Mission AWS Resource Explorer proposal does not match its registration")]
    RegistrationMismatch,
    #[error("Mission AWS Resource Explorer proposal is invalid")]
    InvalidProposal,
    #[error("Mission AWS Resource Explorer proposal replay was rejected")]
    ReplayDetected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionAwsResourceExplorerState {
    DecisionReady,
    NeedsMoreEvidence,
    AccessLost,
    ProviderUnknown,
}

impl MissionAwsResourceExplorerState {
    #[must_use]
    pub const fn from_inventory(state: InventoryState) -> Self {
        match state {
            InventoryState::Complete | InventoryState::Empty => Self::DecisionReady,
            InventoryState::Partial => Self::NeedsMoreEvidence,
            InventoryState::AccessLost => Self::AccessLost,
            InventoryState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsResourceExplorerResult {
    pub mission: crate::MissionBinding,
    pub evidence: AwsResourceExplorerEvidence,
    pub proposal_digest: Digest,
    pub state: MissionAwsResourceExplorerState,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub deployability_claim: bool,
    pub compliance_claim: bool,
    pub adopted_outcome: bool,
}

pub struct MissionAwsResourceExplorerConsumer {
    scope: AwsResourceExplorerScope,
    registration: AwsResourceExplorerRegistration,
    registration_digest: Digest,
    registration_state: RegistrationState,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl fmt::Debug for MissionAwsResourceExplorerConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsResourceExplorerConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("registration_digest", &self.registration_digest)
            .field("registration_state", &self.registration_state)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl MissionAwsResourceExplorerConsumer {
    pub fn new(
        scope: AwsResourceExplorerScope,
        registration: &AwsResourceExplorerRegistration,
    ) -> Result<Self, MissionAwsResourceExplorerConsumerError> {
        if registration.scope_digest != *scope.scope_digest()
            || registration.mission_digest != scope.mission().digest()
        {
            return Err(MissionAwsResourceExplorerConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            registration_digest: registration.registration_digest.clone(),
            registration_state: registration.state,
            active: true,
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn from_registration(
        scope: AwsResourceExplorerScope,
        registration: &AwsResourceExplorerRegistration,
    ) -> Result<Self, MissionAwsResourceExplorerConsumerError> {
        Self::new(scope, registration)
    }

    #[must_use]
    pub fn scope(&self) -> &AwsResourceExplorerScope {
        &self.scope
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), MissionAwsResourceExplorerConsumerError> {
        if !self.active {
            return Err(MissionAwsResourceExplorerConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAwsResourceExplorerConsumerError> {
        if self.active {
            return Err(MissionAwsResourceExplorerConsumerError::InvalidProposal);
        }
        self.active = true;
        Ok(())
    }

    pub fn consume(
        &mut self,
        proposal: AwsResourceExplorerProposal,
    ) -> Result<MissionAwsResourceExplorerResult, MissionAwsResourceExplorerConsumerError> {
        if !self.active {
            return Err(MissionAwsResourceExplorerConsumerError::Revoked);
        }
        if self.registration_state != RegistrationState::Active {
            return Err(MissionAwsResourceExplorerConsumerError::RegistrationRevoked);
        }
        if proposal.registration_digest != self.registration_digest
            || proposal.evidence.digests.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.digests.query_digest != *self.scope.query_digest()
            || proposal.evidence.digests.version_digest != self.registration.version_digest
            || proposal.evidence.digests.contract_digest != self.registration.contract_digest
            || proposal.evidence.digests.provider_digest != self.registration.provider_digest
            || proposal.evidence.digests.permission_digest != self.registration.permission_digest
            || proposal.evidence.digests.scope_digest != self.registration.scope_digest
        {
            return Err(MissionAwsResourceExplorerConsumerError::RegistrationMismatch);
        }
        proposal
            .validate()
            .map_err(|_| MissionAwsResourceExplorerConsumerError::InvalidProposal)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionAwsResourceExplorerConsumerError::ReplayDetected);
        }
        Ok(MissionAwsResourceExplorerResult {
            mission: self.scope.mission().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest,
            state: MissionAwsResourceExplorerState::from_inventory(proposal.evidence.state),
            proposal_only: true,
            connected: false,
            native: false,
            deployability_claim: false,
            compliance_claim: false,
            adopted_outcome: false,
        })
    }

    pub fn consume_observation(
        &mut self,
        proposal: AwsResourceExplorerProposal,
    ) -> Result<MissionAwsResourceExplorerResult, MissionAwsResourceExplorerConsumerError> {
        self.consume(proposal)
    }
}

pub type MissionAwsResourceExplorerResultConsumer = MissionAwsResourceExplorerConsumer;
pub type MissionAwsResourceExplorerObservation = MissionAwsResourceExplorerResult;
