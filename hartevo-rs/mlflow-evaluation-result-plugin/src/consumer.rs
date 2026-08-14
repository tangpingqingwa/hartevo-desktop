use std::fmt;

use thiserror::Error;

use crate::{
    AdoptionAvailability, Digest, MissionId, MlflowAuthority, MlflowEvidence, MlflowRegistration,
    MlflowResultProposal, MlflowScope, ProjectId, RegistrationState, ResultStatus, Revision,
    ScopeRevisions, WorkProductId,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission MLflow consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("proposal was not produced by the governed MLflow service")]
    InvalidProposal,
    #[error("proposal evidence digest is invalid")]
    TamperedEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionMlflowResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MissionMlflowEvaluationResult {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub revisions: ScopeRevisions,
    pub status: ResultStatus,
    pub state: MissionMlflowResultState,
    pub evidence: MlflowEvidence,
    pub proposal_digest: Digest,
    pub authority: MlflowAuthority,
    pub adoption: AdoptionAvailability,
}

pub struct MissionMlflowEvaluationConsumer {
    scope: MlflowScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionMlflowEvaluationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMlflowEvaluationConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionMlflowEvaluationConsumer {
    pub fn new(
        scope: MlflowScope,
        registration: &MlflowRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
            || registration.consumer_id.as_str() != crate::MLFLOW_EVALUATION_RESULT_CONSUMER_ID
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MlflowScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: MlflowResultProposal,
    ) -> Result<MissionMlflowEvaluationResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.revisions != self.scope.revisions()
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest()
            || proposal.evidence.digests.contract_digest
                != crate::Digest::from_text(crate::MLFLOW_EVALUATION_RESULT_CONTRACT_JSON)
        {
            return Err(ConsumerError::FenceMismatch);
        }
        proposal
            .evidence
            .validate_digest()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if proposal.status != proposal.evidence.status {
            return Err(ConsumerError::InvalidProposal);
        }
        let state = match proposal.status {
            ResultStatus::Complete => MissionMlflowResultState::PendingDecision,
            ResultStatus::Stale
            | ResultStatus::Partial(_)
            | ResultStatus::AccessLoss
            | ResultStatus::ProviderUnknown
            | ResultStatus::FinalError => MissionMlflowResultState::Layer2AdoptionRequired,
        };
        Ok(MissionMlflowEvaluationResult {
            mission_id: self.scope.mission_id().clone(),
            project_id: self.scope.project_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            revisions: self.scope.revisions(),
            status: proposal.status,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            authority: MlflowAuthority,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }
}
