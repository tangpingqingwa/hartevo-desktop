use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    AhaEvidenceState, AhaRegistration, AhaRoadmapRequest, AhaRoadmapResultProposal,
    AhaRoadmapResultReceipt, AhaRoadmapResultService, AhaRoadmapResultServiceError,
    AhaRoadmapScope, AhaTransport, Digest, MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAhaRoadmapConsumerError {
    #[error("Mission Aha roadmap consumer is revoked")]
    Revoked,
    #[error("Mission Aha registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Aha proposal does not match the exact scope")]
    ScopeMismatch,
    #[error("Mission Aha proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Aha proposal or evidence is tampered")]
    Tampered,
    #[error("Mission Aha contract or authority flags drifted")]
    ContractDrift,
    #[error("Mission Aha service failed: {0}")]
    Service(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionAhaRoadmapResultState {
    DecisionReady,
    Empty,
    Partial,
    RateLimited,
    Timeout,
    ProviderUnknown,
    BlockedEnv,
}

pub type MissionAhaRoadmapState = MissionAhaRoadmapResultState;
pub type MissionResultState = MissionAhaRoadmapResultState;

impl From<AhaEvidenceState> for MissionAhaRoadmapResultState {
    fn from(value: AhaEvidenceState) -> Self {
        match value {
            AhaEvidenceState::Complete => Self::DecisionReady,
            AhaEvidenceState::Empty => Self::Empty,
            AhaEvidenceState::Partial => Self::Partial,
            AhaEvidenceState::RateLimited => Self::RateLimited,
            AhaEvidenceState::Timeout => Self::Timeout,
            AhaEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            AhaEvidenceState::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionAhaRoadmapResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: MissionAhaRoadmapResultState,
    pub proposal_digest: Digest,
    pub evidence: crate::AhaRoadmapEvidence,
    pub receipt: AhaRoadmapResultReceipt,
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

/// Mission-facing projection for one exact Aha scope. It keeps an in-memory
/// replay fence and never adopts a Work Product or kernel Outcome.
pub struct MissionAhaRoadmapConsumer {
    scope: AhaRoadmapScope,
    registration: Option<AhaRegistration>,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl fmt::Debug for MissionAhaRoadmapConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAhaRoadmapConsumer")
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

impl MissionAhaRoadmapConsumer {
    #[must_use]
    pub fn new(scope: AhaRoadmapScope) -> Self {
        Self {
            scope,
            registration: None,
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    pub fn new_bound(
        scope: AhaRoadmapScope,
        registration: AhaRegistration,
    ) -> Result<Self, MissionAhaRoadmapConsumerError> {
        if registration.scope_digest != *scope.scope_digest()
            || registration.state != crate::RegistrationState::Active
        {
            return Err(MissionAhaRoadmapConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: Some(registration),
            consumed: BTreeSet::new(),
            active: true,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AhaRoadmapScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> Option<&AhaRegistration> {
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
        proposal: AhaRoadmapResultProposal,
    ) -> Result<MissionAhaRoadmapResult, MissionAhaRoadmapConsumerError> {
        self.ensure_active()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.revision_digest != *self.scope.revision_digest()
            || proposal.evidence.permission_digest != self.scope.permission_digest()
        {
            return Err(MissionAhaRoadmapConsumerError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if proposal.registration_digest != registration.registration_digest {
                return Err(MissionAhaRoadmapConsumerError::RegistrationMismatch);
            }
            proposal
                .validate(&self.scope, registration, &proposal.provider_digest)
                .map_err(|_| MissionAhaRoadmapConsumerError::Tampered)?;
        } else {
            proposal
                .validate_for_consumer(
                    &self.scope,
                    &proposal.registration_digest,
                    &proposal.evidence.registration_evidence_digest,
                    &proposal.provider_digest,
                )
                .map_err(|_| MissionAhaRoadmapConsumerError::Tampered)?;
        }
        if !self.consumed.insert(proposal.proposal_digest.clone()) {
            return Err(MissionAhaRoadmapConsumerError::ReplayDetected);
        }
        let receipt = proposal.receipt();
        Ok(MissionAhaRoadmapResult {
            consumer_id: crate::MISSION_AHA_ROADMAP_CONSUMER_ID.to_owned(),
            contract_version: crate::AHA_ROADMAP_RESULT_CONTRACT_VERSION.to_owned(),
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
        proposal: AhaRoadmapResultProposal,
    ) -> Result<MissionAhaRoadmapResult, MissionAhaRoadmapConsumerError> {
        self.consume(proposal)
    }

    pub fn read<T: AhaTransport>(
        &mut self,
        service: &mut AhaRoadmapResultService<T>,
        request: &AhaRoadmapRequest,
    ) -> Result<MissionAhaRoadmapResult, MissionAhaRoadmapConsumerError> {
        self.ensure_active()?;
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(MissionAhaRoadmapConsumerError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if service.registration().registration_digest != registration.registration_digest {
                return Err(MissionAhaRoadmapConsumerError::RegistrationMismatch);
            }
        } else {
            self.registration = Some(service.registration().clone());
        }
        let proposal = service.propose(request).map_err(map_service_error)?;
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionAhaRoadmapConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAhaRoadmapConsumerError> {
        if self.active {
            return Err(MissionAhaRoadmapConsumerError::Tampered);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionAhaRoadmapConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionAhaRoadmapConsumerError::Revoked)
        }
    }
}

fn map_service_error(error: AhaRoadmapResultServiceError) -> MissionAhaRoadmapConsumerError {
    match error {
        AhaRoadmapResultServiceError::RegistrationRevoked
        | AhaRoadmapResultServiceError::SecretRevoked => {
            MissionAhaRoadmapConsumerError::RegistrationMismatch
        }
        AhaRoadmapResultServiceError::ScopeMismatch
        | AhaRoadmapResultServiceError::RevisionMismatch
        | AhaRoadmapResultServiceError::IdempotencyConflict => {
            MissionAhaRoadmapConsumerError::ScopeMismatch
        }
        AhaRoadmapResultServiceError::EvidenceTampered
        | AhaRoadmapResultServiceError::ReplayDetected
        | AhaRoadmapResultServiceError::InvalidProposal
        | AhaRoadmapResultServiceError::DefinitionDrift => MissionAhaRoadmapConsumerError::Tampered,
        other => MissionAhaRoadmapConsumerError::Service(other.to_string()),
    }
}
