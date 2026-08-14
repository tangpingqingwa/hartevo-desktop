use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    Digest, JobProjection, MissionId, ProjectId, RecipeProjection, RecipeVersionProjection,
    StepProjection, WorkProductId,
    model::{RegistrationState, Revision, WorkatoRegistration, WorkatoResultStatus, WorkatoScope},
    service::WorkatoResultProposal,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Workato consumer is inactive")]
    Inactive,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Work Product scope")]
    ScopeMismatch,
    #[error("proposal carries a stale Mission revision")]
    StaleMissionRevision,
    #[error("proposal was tampered with or is not canonical")]
    ProposalTampered,
    #[error("the same retry identity was consumed with different evidence")]
    DuplicateRerun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionWorkatoRecipeState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionWorkatoRecipeResult {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
    pub result_status: WorkatoResultStatus,
    pub state: MissionWorkatoRecipeState,
    pub recipe: Option<RecipeProjection>,
    pub recipe_version: Option<RecipeVersionProjection>,
    pub job: Option<JobProjection>,
    pub steps: Vec<StepProjection>,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

pub struct MissionWorkatoRecipeConsumer {
    scope: WorkatoScope,
    registration: ConsumerRegistration,
    consumed: BTreeMap<Digest, Digest>,
    active: bool,
}

impl fmt::Debug for MissionWorkatoRecipeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionWorkatoRecipeConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionWorkatoRecipeConsumer {
    pub fn new(
        scope: WorkatoScope,
        registration: &WorkatoRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active() || registration.scope_digest != scope.scope_digest() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope: scope.clone(),
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.registration_revision,
                state: registration.state,
            },
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &WorkatoScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Inactive)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &mut self,
        proposal: &WorkatoResultProposal,
    ) -> Result<MissionWorkatoRecipeResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Inactive);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.registration_digest != self.registration.registration_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.scope_digest()
            || proposal.evidence.scope_digest != self.scope.scope_digest()
            || proposal.project_id != *self.scope.mission().project_id()
            || proposal.mission_id != *self.scope.mission().mission_id()
            || proposal.work_product_id != *self.scope.mission().work_product_id()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.mission_revision != self.scope.mission().mission_revision()
            || proposal.evidence.mission_revision != self.scope.mission().mission_revision()
        {
            return Err(ConsumerError::StaleMissionRevision);
        }
        if proposal.status != proposal.evidence.status
            || proposal.evidence_digest != proposal.evidence.evidence_digest
            || proposal.evidence.evidence_digest != proposal.evidence.compute_digest()
            || proposal.proposal_digest != proposal.compute_digest()
            || proposal.connected
            || proposal.native
            || proposal.adopted_outcome
            || !proposal.is_non_native()
        {
            return Err(ConsumerError::ProposalTampered);
        }
        let retry_key = self.scope.job().retry_key_digest();
        let replay = match self.consumed.get(&retry_key) {
            None => {
                self.consumed
                    .insert(retry_key, proposal.proposal_digest.clone());
                false
            }
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(ConsumerError::DuplicateRerun),
        };
        let state = if proposal.status.needs_layer2_adoption() {
            MissionWorkatoRecipeState::Layer2AdoptionRequired
        } else {
            MissionWorkatoRecipeState::PendingDecision
        };
        let _ = replay;
        Ok(MissionWorkatoRecipeResult {
            schema_version: crate::WORKATO_RECIPE_RESULT_SCHEMA_VERSION.to_owned(),
            project_id: proposal.project_id.clone(),
            mission_id: proposal.mission_id.clone(),
            work_product_id: proposal.work_product_id.clone(),
            mission_revision: proposal.mission_revision,
            scope_digest: proposal.scope_digest.clone(),
            result_status: proposal.status,
            state,
            recipe: proposal.evidence.recipe.clone(),
            recipe_version: proposal.evidence.recipe_version.clone(),
            job: proposal.evidence.job.clone(),
            steps: proposal.evidence.steps.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            connected: false,
            native: false,
            adopted_outcome: false,
        })
    }
}
