use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, LookerAnalyticsRequest, LookerAnalyticsResultProposal, LookerAnalyticsResultService,
    LookerAnalyticsResultServiceError, LookerAnalyticsScope, LookerEvidenceState,
    LookerRegistration, LookerTransport, MissionBinding, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionLookerAnalyticsConsumerError {
    #[error("Mission Looker Analytics consumer is revoked")]
    Revoked,
    #[error("Mission Looker registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Looker proposal does not match the exact scope")]
    ScopeMismatch,
    #[error("Mission Looker proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Looker proposal or evidence is tampered")]
    Tampered,
    #[error("Mission Looker contract or authority flags drifted")]
    ContractDrift,
    #[error("Mission Looker service failed: {0}")]
    Service(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionLookerAnalyticsResultState {
    DecisionReady,
    Empty,
    Partial,
    RateLimited,
    AccessLost,
    NotFound,
    ProviderUnknown,
}

pub type MissionResultState = MissionLookerAnalyticsResultState;

impl From<LookerEvidenceState> for MissionLookerAnalyticsResultState {
    fn from(value: LookerEvidenceState) -> Self {
        match value {
            LookerEvidenceState::Complete => Self::DecisionReady,
            LookerEvidenceState::Empty => Self::Empty,
            LookerEvidenceState::Partial => Self::Partial,
            LookerEvidenceState::RateLimited => Self::RateLimited,
            LookerEvidenceState::AccessLost => Self::AccessLost,
            LookerEvidenceState::NotFound => Self::NotFound,
            LookerEvidenceState::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionLookerAnalyticsResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: MissionLookerAnalyticsResultState,
    pub proposal_digest: Digest,
    pub evidence: crate::LookerAnalyticsEvidence,
    pub receipt: crate::LookerAnalyticsResultReceipt,
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

/// Mission-facing projection for one exact Looker scope. It is proposal-only,
/// keeps an in-memory replay fence, and never adopts an Outcome or Work Product.
pub struct MissionLookerAnalyticsConsumer {
    scope: LookerAnalyticsScope,
    registration: Option<LookerRegistration>,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl fmt::Debug for MissionLookerAnalyticsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionLookerAnalyticsConsumer")
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

impl MissionLookerAnalyticsConsumer {
    #[must_use]
    pub fn new(scope: LookerAnalyticsScope) -> Self {
        Self {
            scope,
            registration: None,
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    pub fn new_bound(
        scope: LookerAnalyticsScope,
        registration: LookerRegistration,
    ) -> Result<Self, MissionLookerAnalyticsConsumerError> {
        if registration.scope_digest != *scope.scope_digest()
            || registration.state != crate::RegistrationState::Active
        {
            return Err(MissionLookerAnalyticsConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: Some(registration),
            consumed: BTreeSet::new(),
            active: true,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &LookerAnalyticsScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> Option<&LookerRegistration> {
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
        proposal: LookerAnalyticsResultProposal,
    ) -> Result<MissionLookerAnalyticsResult, MissionLookerAnalyticsConsumerError> {
        self.ensure_active()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.revision_digest != *self.scope.revision_digest()
            || proposal.evidence.project_digest != self.scope.project_digest()
            || proposal.evidence.mission_digest != self.scope.mission_digest()
            || proposal.evidence.work_product_digest != self.scope.work_product_digest()
        {
            return Err(MissionLookerAnalyticsConsumerError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if proposal.registration_digest != registration.registration_digest {
                return Err(MissionLookerAnalyticsConsumerError::RegistrationMismatch);
            }
            proposal
                .validate(&self.scope, registration, &proposal.provider_digest)
                .map_err(|_| MissionLookerAnalyticsConsumerError::Tampered)?;
        } else {
            proposal
                .validate_for_consumer(
                    &self.scope,
                    &proposal.registration_digest,
                    &proposal.provider_digest,
                )
                .map_err(|_| MissionLookerAnalyticsConsumerError::Tampered)?;
        }
        if !self.consumed.insert(proposal.proposal_digest.clone()) {
            return Err(MissionLookerAnalyticsConsumerError::ReplayDetected);
        }
        let receipt = proposal.receipt();
        Ok(MissionLookerAnalyticsResult {
            consumer_id: crate::MISSION_LOOKER_ANALYTICS_CONSUMER_ID.to_owned(),
            contract_version: crate::LOOKER_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
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
        proposal: LookerAnalyticsResultProposal,
    ) -> Result<MissionLookerAnalyticsResult, MissionLookerAnalyticsConsumerError> {
        self.consume(proposal)
    }

    pub fn read<T: LookerTransport>(
        &mut self,
        service: &mut LookerAnalyticsResultService<T>,
        request: &LookerAnalyticsRequest,
    ) -> Result<MissionLookerAnalyticsResult, MissionLookerAnalyticsConsumerError> {
        self.ensure_active()?;
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(MissionLookerAnalyticsConsumerError::ScopeMismatch);
        }
        if let Some(registration) = &self.registration {
            if service.registration().registration_digest != registration.registration_digest {
                return Err(MissionLookerAnalyticsConsumerError::RegistrationMismatch);
            }
        } else {
            self.registration = Some(service.registration().clone());
        }
        let proposal = service
            .propose(request)
            .map_err(|error| map_service_error(&error))?;
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionLookerAnalyticsConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionLookerAnalyticsConsumerError> {
        if self.active {
            return Err(MissionLookerAnalyticsConsumerError::Tampered);
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionLookerAnalyticsConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionLookerAnalyticsConsumerError::Revoked)
        }
    }
}

fn map_service_error(
    error: &LookerAnalyticsResultServiceError,
) -> MissionLookerAnalyticsConsumerError {
    match error {
        LookerAnalyticsResultServiceError::RegistrationRevoked
        | LookerAnalyticsResultServiceError::SecretRevoked
        | LookerAnalyticsResultServiceError::ConsentMismatch => {
            MissionLookerAnalyticsConsumerError::RegistrationMismatch
        }
        LookerAnalyticsResultServiceError::ScopeMismatch
        | LookerAnalyticsResultServiceError::RevisionMismatch
        | LookerAnalyticsResultServiceError::IdempotencyConflict => {
            MissionLookerAnalyticsConsumerError::ScopeMismatch
        }
        LookerAnalyticsResultServiceError::EvidenceTampered
        | LookerAnalyticsResultServiceError::ReplayDetected
        | LookerAnalyticsResultServiceError::InvalidProposal
        | LookerAnalyticsResultServiceError::DefinitionDrift => {
            MissionLookerAnalyticsConsumerError::Tampered
        }
        other => MissionLookerAnalyticsConsumerError::Service(other.to_string()),
    }
}
