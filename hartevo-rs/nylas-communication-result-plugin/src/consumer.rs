use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::service::{
    NylasCommunicationRecordReceipt, NylasCommunicationResultProposal,
    NylasCommunicationResultService, NylasCommunicationResultServiceError, NylasVerificationReport,
};
use crate::{
    Digest, IdempotencyKey, MissionBinding, NylasCommunicationEvidence, NylasCommunicationRequest,
    NylasEvidenceState, NylasProvider, NylasTransport, ProjectBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionNylasCommunicationConsumerError {
    #[error("Mission Nylas communication consumer is revoked")]
    Revoked,
    #[error("Mission Nylas registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Nylas proposal does not match the exact scope")]
    ScopeMismatch,
    #[error("Mission Nylas proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Nylas proposal or evidence is tampered")]
    Tampered,
    #[error("Mission Nylas contract or authority flags drifted")]
    ContractDrift,
    #[error("Mission Nylas service failed: {0}")]
    Service(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionNylasCommunicationResultState {
    DecisionReady,
    Sent,
    Delivered,
    Bounced,
    Failed,
    Cancelled,
    Updated,
    Empty,
    Partial,
    AccessLoss,
    ProviderUnknown,
    BlockedEnv,
    Tamper,
    Stale,
    Revoked,
    Timeout,
    RateLimited,
}

pub type MissionNylasCommunicationState = MissionNylasCommunicationResultState;
pub type MissionResultState = MissionNylasCommunicationResultState;

impl From<NylasEvidenceState> for MissionNylasCommunicationResultState {
    fn from(value: NylasEvidenceState) -> Self {
        match value {
            NylasEvidenceState::Complete => Self::DecisionReady,
            NylasEvidenceState::Sent => Self::Sent,
            NylasEvidenceState::Delivered => Self::Delivered,
            NylasEvidenceState::Bounced => Self::Bounced,
            NylasEvidenceState::Failed => Self::Failed,
            NylasEvidenceState::Cancelled => Self::Cancelled,
            NylasEvidenceState::Updated => Self::Updated,
            NylasEvidenceState::Empty => Self::Empty,
            NylasEvidenceState::Partial => Self::Partial,
            NylasEvidenceState::AccessLoss => Self::AccessLoss,
            NylasEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            NylasEvidenceState::BlockedEnv => Self::BlockedEnv,
            NylasEvidenceState::Tamper => Self::Tamper,
            NylasEvidenceState::Stale => Self::Stale,
            NylasEvidenceState::Revoked => Self::Revoked,
            NylasEvidenceState::Timeout => Self::Timeout,
            NylasEvidenceState::RateLimited => Self::RateLimited,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionNylasCommunicationResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub state: MissionNylasCommunicationResultState,
    pub proposal_digest: Digest,
    pub evidence: NylasCommunicationEvidence,
    pub receipt: crate::NylasCommunicationResultReceipt,
    pub review_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

pub struct MissionNylasCommunicationConsumer<T: NylasTransport> {
    service: NylasCommunicationResultService<T>,
    registration_digest: Digest,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: NylasTransport> fmt::Debug for MissionNylasCommunicationConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionNylasCommunicationConsumer")
            .field("scope_digest", self.service.scope().scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: NylasTransport> MissionNylasCommunicationConsumer<T> {
    pub fn new(provider: NylasProvider<T>) -> Result<Self, MissionNylasCommunicationConsumerError> {
        let service = NylasCommunicationResultService::new(provider).map_err(map_service_error)?;
        Ok(Self::from_service(service))
    }

    #[must_use]
    pub fn from_service(service: NylasCommunicationResultService<T>) -> Self {
        let registration_digest = service.registration().registration_digest.clone();
        Self {
            service,
            registration_digest,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &NylasCommunicationResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut NylasCommunicationResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed_proposals.len()
    }

    pub fn read(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<MissionNylasCommunicationResult, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        let proposal = self.propose(request)?;
        self.consume(&proposal)
    }

    pub fn read_evidence(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationEvidence, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        self.service.read(request).map_err(map_service_error)
    }

    pub fn propose(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationResultProposal, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        self.service.propose(request).map_err(map_service_error)
    }

    pub fn compile_proposal(
        &mut self,
        request: &NylasCommunicationRequest,
    ) -> Result<NylasCommunicationResultProposal, MissionNylasCommunicationConsumerError> {
        self.propose(request)
    }

    pub fn consume(
        &mut self,
        proposal: &NylasCommunicationResultProposal,
    ) -> Result<MissionNylasCommunicationResult, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        if self.service.registration().registration_digest != self.registration_digest {
            return Err(MissionNylasCommunicationConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != *self.service.scope().scope_digest()
            || proposal.evidence.scope_digest != *self.service.scope().scope_digest()
        {
            return Err(MissionNylasCommunicationConsumerError::ScopeMismatch);
        }
        self.service
            .verify_proposal(proposal)
            .map_err(map_service_error)?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionNylasCommunicationConsumerError::ReplayDetected);
        }
        Ok(MissionNylasCommunicationResult {
            consumer_id: crate::CONSUMER_ID.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            project: self.service.scope().project().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            state: proposal.state.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence: proposal.evidence.clone(),
            receipt: proposal.receipt(),
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
        proposal: &NylasCommunicationResultProposal,
    ) -> Result<MissionNylasCommunicationResult, MissionNylasCommunicationConsumerError> {
        self.consume(proposal)
    }

    pub fn verify(
        &self,
        proposal: &NylasCommunicationResultProposal,
    ) -> Result<NylasVerificationReport, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        self.service
            .verify_proposal(proposal)
            .map_err(map_service_error)
    }

    pub fn record(
        &mut self,
        proposal: &NylasCommunicationResultProposal,
        idempotency_key: &IdempotencyKey,
    ) -> Result<NylasCommunicationRecordReceipt, MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        self.service
            .record(proposal, idempotency_key)
            .map_err(map_service_error)
    }

    pub fn revoke(&mut self) -> Result<(), MissionNylasCommunicationConsumerError> {
        self.ensure_active()?;
        self.service
            .revoke_registration()
            .map_err(map_service_error)?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionNylasCommunicationConsumerError> {
        if self.active {
            return Err(MissionNylasCommunicationConsumerError::ContractDrift);
        }
        self.service
            .restore_registration()
            .map_err(map_service_error)?;
        self.registration_digest = self.service.registration().registration_digest.clone();
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionNylasCommunicationConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionNylasCommunicationConsumerError::Revoked)
        }
    }
}

fn map_service_error(
    error: NylasCommunicationResultServiceError,
) -> MissionNylasCommunicationConsumerError {
    match error {
        NylasCommunicationResultServiceError::RegistrationRevoked
        | NylasCommunicationResultServiceError::SecretRevoked => {
            MissionNylasCommunicationConsumerError::RegistrationMismatch
        }
        NylasCommunicationResultServiceError::ScopeMismatch
        | NylasCommunicationResultServiceError::RevisionMismatch
        | NylasCommunicationResultServiceError::CursorInvalid
        | NylasCommunicationResultServiceError::IdempotencyConflict => {
            MissionNylasCommunicationConsumerError::ScopeMismatch
        }
        NylasCommunicationResultServiceError::EvidenceTampered
        | NylasCommunicationResultServiceError::ProposalTampered
        | NylasCommunicationResultServiceError::ReplayDetected
        | NylasCommunicationResultServiceError::DefinitionDrift
        | NylasCommunicationResultServiceError::RecordingConflict => {
            MissionNylasCommunicationConsumerError::Tampered
        }
        other => MissionNylasCommunicationConsumerError::Service(other.to_string()),
    }
}

pub type MissionNylasCommunicationResultStateProjection = MissionNylasCommunicationResultState;
