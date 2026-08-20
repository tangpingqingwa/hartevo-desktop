//! Mission-facing consumer for bounded, proposal-only ECR image evidence.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::model::{Digest, EcrImageScanEvidence, EcrImageScanScope, ScanProjection};
use crate::service::{
    EcrImageScanProposal, EcrImageScanRegistration, EcrImageScanResultService, RegistrationState,
};
use crate::{EcrTransport, MISSION_ECR_IMAGE_SCAN_CONSUMER_ID};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionEcrImageScanState {
    DecisionReady,
    Pending,
    Failed,
    Inactive,
    Expired,
    NeedsMoreEvidence,
    Stale,
    AccessLost,
    Tampered,
    ProviderUnknown,
}

impl MissionEcrImageScanState {
    #[must_use]
    pub const fn from_projection(projection: ScanProjection) -> Self {
        match projection {
            ScanProjection::Complete => Self::DecisionReady,
            ScanProjection::Pending => Self::Pending,
            ScanProjection::Failed => Self::Failed,
            ScanProjection::Inactive => Self::Inactive,
            ScanProjection::Expired => Self::Expired,
            ScanProjection::Partial => Self::NeedsMoreEvidence,
            ScanProjection::Stale => Self::Stale,
            ScanProjection::AccessLost => Self::AccessLost,
            ScanProjection::Tampered => Self::Tampered,
            ScanProjection::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

pub type MissionEcrImageState = MissionEcrImageScanState;
pub type MissionResultState = MissionEcrImageScanState;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionEcrImageConsumerError {
    #[error("Mission ECR image consumer is revoked")]
    Revoked,
    #[error("Mission ECR image registration is not active")]
    RegistrationRevoked,
    #[error("Mission ECR image registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission ECR image proposal does not match its Mission scope")]
    ScopeMismatch,
    #[error("Mission ECR image proposal has already been consumed")]
    ReplayDetected,
    #[error("Mission ECR image proposal is tampered or invalid")]
    Tampered,
    #[error("Mission ECR image contract or authority drifted")]
    ContractDrift,
    #[error("Mission ECR image service failed: {0}")]
    Service(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionEcrImageScanResult {
    pub consumer_id: String,
    pub mission: crate::MissionBinding,
    pub project: crate::ProjectBinding,
    pub work_product: crate::WorkProductBinding,
    pub state: MissionEcrImageScanState,
    pub proposal_digest: Digest,
    pub evidence: EcrImageScanEvidence,
    pub proposal: EcrImageScanProposal,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub independent_readback: bool,
    pub adopted_outcome: bool,
}

pub type MissionEcrImageResult = MissionEcrImageScanResult;
pub type MissionEcrImageObservation = MissionEcrImageScanResult;

#[derive(Clone)]
pub struct MissionEcrImageConsumer {
    scope: EcrImageScanScope,
    registration_digest: Digest,
    registration_state: RegistrationState,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl fmt::Debug for MissionEcrImageConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionEcrImageConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_state", &self.registration_state)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl MissionEcrImageConsumer {
    pub fn new(
        scope: EcrImageScanScope,
        registration: &EcrImageScanRegistration,
    ) -> Result<Self, MissionEcrImageConsumerError> {
        if !registration.is_active() || registration.scope_digest != *scope.scope_digest() {
            return Err(MissionEcrImageConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_state: registration.state,
            active: true,
            consumed_proposals: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn from_scope(scope: EcrImageScanScope) -> Self {
        Self {
            scope,
            registration_digest: Digest::zero(),
            registration_state: RegistrationState::Active,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn scope(&self) -> &EcrImageScanScope {
        &self.scope
    }

    #[must_use]
    pub const fn consumer_id(&self) -> &'static str {
        MISSION_ECR_IMAGE_SCAN_CONSUMER_ID
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed_proposals.len()
    }

    #[must_use]
    pub fn has_consumed(&self, digest: &Digest) -> bool {
        self.consumed_proposals.contains(digest)
    }

    pub fn consume(
        &mut self,
        proposal: EcrImageScanProposal,
    ) -> Result<MissionEcrImageScanResult, MissionEcrImageConsumerError> {
        if !self.active {
            return Err(MissionEcrImageConsumerError::Revoked);
        }
        if self.registration_state != RegistrationState::Active {
            return Err(MissionEcrImageConsumerError::RegistrationRevoked);
        }
        if self.registration_digest != proposal.registration_digest {
            return Err(MissionEcrImageConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.digests.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.mission != *self.scope.mission()
            || proposal.evidence.project != *self.scope.project()
            || proposal.evidence.work_product != *self.scope.work_product()
        {
            return Err(MissionEcrImageConsumerError::ScopeMismatch);
        }
        if proposal.contract_digest != crate::contract_digest()
            || proposal.evidence.digests.contract_digest != crate::contract_digest()
            || proposal.evidence.digests.provider_digest != proposal.provider_digest
            || proposal.evidence.digests.permission_digest != proposal.permission_digest
            || proposal.evidence.digests.registration_digest != proposal.registration_digest
            || proposal.evidence.digests.version_digest != crate::version_digest()
            || !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.durable_receipt
            || proposal.independent_readback
            || proposal.adopted_outcome
            || proposal.evidence.native
            || proposal.evidence.connected
            || proposal.evidence.durable_receipt
            || proposal.evidence.independent_readback
            || proposal.evidence.adopted_outcome
        {
            return Err(MissionEcrImageConsumerError::ContractDrift);
        }
        if proposal.evidence.validate(&self.scope).is_err()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(MissionEcrImageConsumerError::Tampered);
        }
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionEcrImageConsumerError::ReplayDetected);
        }
        Ok(MissionEcrImageScanResult {
            consumer_id: MISSION_ECR_IMAGE_SCAN_CONSUMER_ID.to_owned(),
            mission: self.scope.mission().clone(),
            project: self.scope.project().clone(),
            work_product: self.scope.work_product().clone(),
            state: MissionEcrImageScanState::from_projection(proposal.evidence.state),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence: proposal.evidence.clone(),
            proposal,
            proposal_only: true,
            native: false,
            connected: false,
            durable_receipt: false,
            independent_readback: false,
            adopted_outcome: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: EcrImageScanProposal,
    ) -> Result<MissionEcrImageScanResult, MissionEcrImageConsumerError> {
        self.consume(proposal)
    }

    pub fn read<T: EcrTransport>(
        &mut self,
        service: &mut EcrImageScanResultService<T>,
    ) -> Result<MissionEcrImageScanResult, MissionEcrImageConsumerError> {
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(MissionEcrImageConsumerError::ScopeMismatch);
        }
        if self.registration_digest == Digest::zero() {
            self.registration_digest = service.registration().registration_digest.clone();
        }
        if self.registration_digest != service.registration().registration_digest {
            return Err(MissionEcrImageConsumerError::RegistrationMismatch);
        }
        if !service.registration().is_active() {
            self.registration_state = RegistrationState::Revoked;
            return Err(MissionEcrImageConsumerError::RegistrationRevoked);
        }
        let proposal = service
            .propose()
            .map_err(|error| MissionEcrImageConsumerError::Service(error.to_string()))?;
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionEcrImageConsumerError> {
        if !self.active {
            return Err(MissionEcrImageConsumerError::Revoked);
        }
        self.active = false;
        self.registration_state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionEcrImageConsumerError> {
        if self.active {
            return Err(MissionEcrImageConsumerError::ContractDrift);
        }
        self.active = true;
        self.registration_state = RegistrationState::Active;
        Ok(())
    }
}

pub type MissionEcrImageScanResultConsumer = MissionEcrImageConsumer;
