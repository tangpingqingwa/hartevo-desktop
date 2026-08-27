use std::fmt;

use thiserror::Error;

use crate::provider::PlanetScaleTransport;
use crate::{
    BranchResultEvidence, BranchResultProposal, BranchResultReceipt, Digest, EvidenceState,
    MissionId, PlanetScaleBranchResultError, PlanetScaleBranchResultService, PlanetScaleScope,
    ProjectId, RegistrationReceipt, VerificationResult, WorkProductId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission PlanetScale consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed PlanetScale service")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] PlanetScaleBranchResultError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionPlanetScaleBranchResult {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: crate::Revision,
    pub scope_digest: Digest,
    pub evidence: BranchResultEvidence,
    pub proposal_digest: Digest,
    pub state: MissionResultState,
    pub verification: VerificationResult,
    pub connected: bool,
    pub native: bool,
    pub adopts_work_product: bool,
}

pub struct MissionPlanetScaleBranchConsumer<T: PlanetScaleTransport> {
    service: PlanetScaleBranchResultService<T>,
    scope: PlanetScaleScope,
    registration: RegistrationReceipt,
    active: bool,
}

impl<T: PlanetScaleTransport> fmt::Debug for MissionPlanetScaleBranchConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionPlanetScaleBranchConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl<T: PlanetScaleTransport> MissionPlanetScaleBranchConsumer<T> {
    pub fn new(service: PlanetScaleBranchResultService<T>) -> Result<Self, ConsumerError> {
        let scope = service.scope().clone();
        let registration = service.registration_receipt()?;
        Ok(Self {
            service,
            scope,
            registration,
            active: true,
        })
    }

    pub fn with_registration(
        service: PlanetScaleBranchResultService<T>,
        registration: RegistrationReceipt,
    ) -> Result<Self, ConsumerError> {
        registration.validate()?;
        let scope = service.scope().clone();
        let expected = service.registration_receipt()?;
        if !registration.active
            || registration.scope_digest != expected.scope_digest
            || registration.registration_digest != expected.registration_digest
            || registration.manifest_digest != expected.manifest_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            service,
            scope,
            registration,
            active: true,
        })
    }

    #[must_use]
    pub fn service(&self) -> &PlanetScaleBranchResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut PlanetScaleBranchResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &PlanetScaleScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &RegistrationReceipt {
        &self.registration
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn bind_registration(
        &mut self,
        registration: RegistrationReceipt,
    ) -> Result<(), ConsumerError> {
        registration.validate()?;
        if !registration.active
            || registration.scope_digest != self.scope.digest()
            || registration.registration_digest != self.service.registration().registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        self.registration = registration;
        self.active = true;
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    /// Consume only an independently verified record. This returns a Mission
    /// projection; it never writes or adopts the Work Product.
    pub fn consume(
        &self,
        proposal: &BranchResultProposal,
        evidence: &BranchResultEvidence,
        receipt: &BranchResultReceipt,
    ) -> Result<MissionPlanetScaleBranchResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.scope != self.scope
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.scope.mission != self.scope.mission
            || proposal.scope.work_product != self.scope.work_product
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.revision_fence_digest != self.scope.revision_fence().digest()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        let verification = self.service.verify(proposal, evidence, receipt)?;
        let state = match evidence.state {
            EvidenceState::Complete => MissionResultState::PendingDecision,
            EvidenceState::Denied
            | EvidenceState::Partial
            | EvidenceState::Stale
            | EvidenceState::AccessLost
            | EvidenceState::RateLimited
            | EvidenceState::ProviderUnknown
            | EvidenceState::Tampered
            | EvidenceState::Revoked => MissionResultState::Layer2AdoptionRequired,
        };
        Ok(MissionPlanetScaleBranchResult {
            project_id: self
                .scope
                .project
                .id()
                .parse()
                .map_err(|_| ConsumerError::InvalidProposal)?,
            mission_id: self
                .scope
                .mission
                .id()
                .parse()
                .map_err(|_| ConsumerError::InvalidProposal)?,
            work_product_id: self
                .scope
                .work_product
                .id()
                .parse()
                .map_err(|_| ConsumerError::InvalidProposal)?,
            work_product_revision: self.scope.work_product.revision(),
            scope_digest: self.scope.digest(),
            evidence: evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state,
            verification,
            connected: false,
            native: false,
            adopts_work_product: false,
        })
    }
}
