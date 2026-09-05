use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, MissionBinding, ProductboardEvidenceState, ProductboardRegistration,
    ProductboardRoadmapRequest, ProductboardRoadmapResultProposal,
    ProductboardRoadmapResultReceipt, ProductboardRoadmapResultService,
    ProductboardRoadmapResultServiceError, ProductboardRoadmapScope, ProductboardTransport,
    ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionProductboardRoadmapConsumerError {
    #[error("Mission Productboard roadmap consumer is revoked")]
    Revoked,
    #[error("Mission Productboard registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Productboard proposal does not match the exact scope")]
    ScopeMismatch,
    #[error("Mission Productboard proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Productboard proposal or evidence is tampered")]
    Tampered,
    #[error("Mission Productboard contract or authority flags drifted")]
    ContractDrift,
    #[error("Mission Productboard service failed: {0}")]
    Service(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionProductboardRoadmapResultState {
    DecisionReady,
    Archived,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
    RateLimited,
    Timeout,
    BlockedEnv,
}

pub type MissionProductboardRoadmapState = MissionProductboardRoadmapResultState;
pub type MissionResultState = MissionProductboardRoadmapResultState;

impl From<ProductboardEvidenceState> for MissionProductboardRoadmapResultState {
    fn from(value: ProductboardEvidenceState) -> Self {
        match value {
            ProductboardEvidenceState::Present | ProductboardEvidenceState::Complete => {
                Self::DecisionReady
            }
            ProductboardEvidenceState::Archived => Self::Archived,
            ProductboardEvidenceState::Empty => Self::Empty,
            ProductboardEvidenceState::Partial => Self::Partial,
            ProductboardEvidenceState::AccessLoss => Self::AccessLoss,
            ProductboardEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            ProductboardEvidenceState::Tamper => Self::Tamper,
            ProductboardEvidenceState::Stale => Self::Stale,
            ProductboardEvidenceState::Revoked => Self::Revoked,
            ProductboardEvidenceState::RateLimited => Self::RateLimited,
            ProductboardEvidenceState::Timeout => Self::Timeout,
            ProductboardEvidenceState::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionProductboardRoadmapResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: MissionProductboardRoadmapResultState,
    pub proposal_digest: Digest,
    pub evidence: crate::ProductboardRoadmapEvidence,
    pub receipt: ProductboardRoadmapResultReceipt,
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

/// Mission-facing projection for one exact Productboard scope. It keeps an
/// in-memory replay fence and never adopts a Work Product or kernel Outcome.
pub struct MissionProductboardRoadmapConsumer {
    scope: ProductboardRoadmapScope,
    registration: Option<ProductboardRegistration>,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl fmt::Debug for MissionProductboardRoadmapConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionProductboardRoadmapConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field(
                "registration_digest",
                &self
                    .registration
                    .as_ref()
                    .map(|registration| &registration.registration_digest),
            )
            .field("consumed", &self.consumed.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionProductboardRoadmapConsumer {
    #[must_use]
    pub fn new(scope: ProductboardRoadmapScope) -> Self {
        Self {
            scope,
            registration: None,
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    pub fn new_bound(
        scope: ProductboardRoadmapScope,
        registration: ProductboardRegistration,
    ) -> Result<Self, MissionProductboardRoadmapConsumerError> {
        if registration.scope_digest != *scope.scope_digest()
            || registration.state != crate::RegistrationState::Active
        {
            return Err(MissionProductboardRoadmapConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: Some(registration),
            consumed: BTreeSet::new(),
            active: true,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &ProductboardRoadmapScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> Option<&ProductboardRegistration> {
        self.registration.as_ref()
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    pub fn consume(
        &mut self,
        proposal: ProductboardRoadmapResultProposal,
    ) -> Result<MissionProductboardRoadmapResult, MissionProductboardRoadmapConsumerError> {
        self.ensure_active()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.revision_digest != *self.scope.revision_digest()
            || proposal.evidence.permission_digest != self.scope.permission_digest()
        {
            return Err(MissionProductboardRoadmapConsumerError::ScopeMismatch);
        }
        if matches!(
            proposal.state,
            ProductboardEvidenceState::Tamper
                | ProductboardEvidenceState::Stale
                | ProductboardEvidenceState::Revoked
        ) {
            return Err(MissionProductboardRoadmapConsumerError::Tampered);
        }
        if let Some(registration) = &self.registration {
            if proposal.registration_digest != registration.registration_digest {
                return Err(MissionProductboardRoadmapConsumerError::RegistrationMismatch);
            }
            proposal
                .validate(&self.scope, registration, &proposal.provider_digest)
                .map_err(|_| MissionProductboardRoadmapConsumerError::Tampered)?;
        } else {
            proposal
                .validate_for_consumer(
                    &self.scope,
                    &proposal.registration_digest,
                    &proposal.evidence.registration_evidence_digest,
                    &proposal.provider_digest,
                )
                .map_err(|_| MissionProductboardRoadmapConsumerError::Tampered)?;
        }
        if !self.consumed.insert(proposal.proposal_digest.clone()) {
            return Err(MissionProductboardRoadmapConsumerError::ReplayDetected);
        }
        let receipt = proposal.receipt();
        Ok(MissionProductboardRoadmapResult {
            consumer_id: crate::MISSION_PRODUCTBOARD_ROADMAP_CONSUMER_ID.to_owned(),
            contract_version: crate::PRODUCTBOARD_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            state: proposal.state.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence: proposal.evidence,
            receipt,
            review_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            outcome_authority: false,
            work_product_adopted: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: ProductboardRoadmapResultProposal,
    ) -> Result<MissionProductboardRoadmapResult, MissionProductboardRoadmapConsumerError> {
        self.consume(proposal)
    }

    pub fn read<T: ProductboardTransport>(
        &mut self,
        service: &mut ProductboardRoadmapResultService<T>,
        request: &ProductboardRoadmapRequest,
    ) -> Result<MissionProductboardRoadmapResult, MissionProductboardRoadmapConsumerError> {
        self.ensure_active()?;
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(MissionProductboardRoadmapConsumerError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if service.registration().registration_digest != registration.registration_digest {
                return Err(MissionProductboardRoadmapConsumerError::RegistrationMismatch);
            }
        } else {
            self.registration = Some(service.registration().clone());
        }
        let proposal = service.propose(request).map_err(map_service_error)?;
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionProductboardRoadmapConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionProductboardRoadmapConsumerError> {
        if self.active {
            return Err(MissionProductboardRoadmapConsumerError::Tampered);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionProductboardRoadmapConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionProductboardRoadmapConsumerError::Revoked)
        }
    }
}

fn map_service_error(
    error: ProductboardRoadmapResultServiceError,
) -> MissionProductboardRoadmapConsumerError {
    match error {
        ProductboardRoadmapResultServiceError::RegistrationRevoked
        | ProductboardRoadmapResultServiceError::SecretRevoked => {
            MissionProductboardRoadmapConsumerError::RegistrationMismatch
        }
        ProductboardRoadmapResultServiceError::ScopeMismatch
        | ProductboardRoadmapResultServiceError::RevisionMismatch
        | ProductboardRoadmapResultServiceError::IdempotencyConflict => {
            MissionProductboardRoadmapConsumerError::ScopeMismatch
        }
        ProductboardRoadmapResultServiceError::EvidenceTampered
        | ProductboardRoadmapResultServiceError::ReplayDetected
        | ProductboardRoadmapResultServiceError::InvalidProposal
        | ProductboardRoadmapResultServiceError::DefinitionDrift => {
            MissionProductboardRoadmapConsumerError::Tampered
        }
        other => MissionProductboardRoadmapConsumerError::Service(other.to_string()),
    }
}
