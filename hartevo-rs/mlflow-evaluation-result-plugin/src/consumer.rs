use std::fmt;

use thiserror::Error;

use crate::model::LiveRevocationFence;
use crate::{
    AdoptionAvailability, Digest, MissionId, MlflowAuthority, MlflowEvidence, MlflowReadProposal,
    MlflowReadRequest, MlflowRegistration, MlflowResultProposal, MlflowScope, ProjectId,
    RegistrationState, ResultStatus, Revision, ScopeRevisions, SecretReference, WorkProductId,
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
    #[error("proposal digest does not match the consumed read proposal")]
    ProposalMismatch,
    #[error("proposal evidence exceeds a governed bound")]
    BoundExceeded,
    #[error("proposal evidence digest is invalid")]
    TamperedEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub generation: u64,
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
    registration_fence: LiveRevocationFence,
    registration_generation: u64,
    secret_fence: LiveRevocationFence,
    secret_generation: u64,
    secret_reference_digest: Digest,
    credential_revision: Revision,
    active: bool,
}

impl fmt::Debug for MissionMlflowEvaluationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMlflowEvaluationConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("registration_fence", &self.registration_fence)
            .field("registration_generation", &self.registration_generation)
            .field("secret_fence", &self.secret_fence)
            .field("secret_generation", &self.secret_generation)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionMlflowEvaluationConsumer {
    pub fn new(
        scope: MlflowScope,
        registration: &MlflowRegistration,
        secret: &SecretReference,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest()
            || registration.schema_version != crate::MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION
            || registration.contract_version != crate::MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION
            || registration.service_id.as_str() != crate::MLFLOW_EVALUATION_RESULT_SERVICE_ID
            || registration.provider_id.as_str() != crate::MLFLOW_EVALUATION_RESULT_PROVIDER_ID
            || registration.consumer_id.as_str() != crate::MLFLOW_EVALUATION_RESULT_CONSUMER_ID
            || !registration.revocation_fence().is_active()
            || secret.scope_digest() != &scope.scope_digest()
            || secret.is_revoked()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        let registration_fence = registration.revocation_fence();
        let secret_fence = secret.revocation_fence();
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                generation: registration_fence.generation(),
                state: registration.state,
            },
            registration_generation: registration_fence.generation(),
            registration_fence,
            secret_generation: secret_fence.generation(),
            secret_fence,
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &MlflowScope {
        &self.scope
    }

    pub const fn registration_generation(&self) -> u64 {
        self.registration_generation
    }

    pub const fn secret_generation(&self) -> u64 {
        self.secret_generation
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
        read_proposal: &MlflowReadProposal,
    ) -> Result<MissionMlflowEvaluationResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if !self.registration_fence.is_active()
            || self.registration_fence.generation() != self.registration_generation
            || !self.secret_fence.is_active()
            || self.secret_fence.generation() != self.secret_generation
        {
            return Err(ConsumerError::Revoked);
        }
        read_proposal
            .validate_digest()
            .map_err(|_| ConsumerError::InvalidProposal)?;
        proposal
            .evidence
            .validate_bounds(read_proposal.bounds())
            .map_err(|error| match error {
                crate::ServiceError::BoundExceeded => ConsumerError::BoundExceeded,
                _ => ConsumerError::TamperedEvidence,
            })?;
        if read_proposal.registration_digest() != &self.registration.registration_digest
            || read_proposal.registration_revision() != self.registration.revision
            || read_proposal.registration_generation() != self.registration_generation
            || read_proposal.secret_reference_digest() != &self.secret_reference_digest
            || read_proposal.credential_revision() != self.credential_revision
            || read_proposal.secret_generation() != self.secret_generation
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.proposal_digest != *read_proposal.proposal_digest()
            || proposal.operation != read_proposal.operation()
            || proposal.evidence.proposal_digest != *read_proposal.proposal_digest()
            || proposal.evidence.registration_digest != *read_proposal.registration_digest()
            || proposal.evidence.registration_revision != read_proposal.registration_revision()
            || proposal.evidence.registration_generation != read_proposal.registration_generation()
            || proposal.evidence.secret_reference_digest != *read_proposal.secret_reference_digest()
            || proposal.evidence.secret_generation != read_proposal.secret_generation()
            || proposal.evidence.credential_revision != read_proposal.credential_revision()
        {
            return Err(ConsumerError::ProposalMismatch);
        }
        if proposal.evidence.operation != read_proposal.operation()
            || proposal.evidence.provider_version != read_proposal.provider_version()
            || proposal.evidence.scope_digest != *read_proposal.scope_digest()
            || proposal.evidence.permission_digest != *read_proposal.permission_digest()
            || proposal.evidence.consent_digest != *read_proposal.consent_digest()
            || proposal.evidence.revisions != read_proposal.revisions()
            || proposal.evidence.digests.scope_digest != *read_proposal.scope_digest()
            || proposal.evidence.digests.version_digest != *read_proposal.version_digest()
            || proposal.evidence.digests.provider_digest != *read_proposal.provider_digest()
            || proposal.evidence.digests.contract_digest != *read_proposal.contract_digest()
            || proposal.evidence.digests.permission_digest != *read_proposal.permission_digest()
            || proposal.evidence.digests.consent_digest != *read_proposal.consent_digest()
            || proposal.evidence.digests.query_digest != *read_proposal.query_digest()
            || proposal.evidence.digests.config_digest != *read_proposal.config_digest()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || proposal.evidence.consent_digest != *self.scope.consent_digest()
            || proposal.evidence.revisions != self.scope.revisions()
        {
            return Err(ConsumerError::FenceMismatch);
        }
        match read_proposal.request() {
            MlflowReadRequest::GetExperiment { experiment_id, .. }
                if proposal.status == ResultStatus::Complete
                    && (proposal.evidence.experiments.len() != 1
                        || proposal.evidence.experiments[0].experiment_id != *experiment_id
                        || !proposal.evidence.runs.is_empty()
                        || !proposal.evidence.metric_history.is_empty()) =>
            {
                return Err(ConsumerError::InvalidProposal);
            }
            MlflowReadRequest::GetRun { run_id, .. }
                if proposal.status == ResultStatus::Complete
                    && (proposal.evidence.runs.len() != 1
                        || proposal.evidence.runs[0].run_id != *run_id
                        || !proposal.evidence.experiments.is_empty()
                        || !proposal.evidence.metric_history.is_empty()) =>
            {
                return Err(ConsumerError::InvalidProposal);
            }
            _ => {}
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
