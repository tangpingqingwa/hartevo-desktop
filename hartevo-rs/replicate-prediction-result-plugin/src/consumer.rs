use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{
        Digest, PredictionStatus, RegistrationState, ReplicateRegistration, ReplicateScope,
        Revision,
    },
    service::ReplicatePredictionResultProposal,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Replicate result consumer is revoked")]
    Revoked,
    #[error("the proposal registration does not match the Mission consumer")]
    RegistrationMismatch,
    #[error("the proposal digest or evidence fence is invalid")]
    InvalidProposal,
    #[error("the proposal contains a stale Mission revision")]
    StaleMissionRevision,
    #[error("the proposal contains a stale Project revision")]
    StaleProjectRevision,
    #[error("the proposal contains a stale Work Product revision")]
    StaleWorkProductRevision,
    #[error("the proposal status regressed")]
    StatusRegression,
    #[error("the proposal replay diverged from the already consumed result")]
    ReplayConflict,
    #[error("provider evidence claimed Connected or native authority")]
    NativeEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionReplicateResult {
    pub project_id: crate::model::ProjectId,
    pub project_revision: Revision,
    pub mission_id: crate::model::MissionId,
    pub mission_revision: Revision,
    pub work_product_id: crate::model::WorkProductId,
    pub work_product_revision: Revision,
    pub prediction_id: crate::model::PredictionId,
    pub status: PredictionStatus,
    pub state: MissionResultState,
    pub evidence: crate::service::ReplicatePredictionEvidence,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub adoption: AdoptionAvailability,
    pub durable_adoption: bool,
    pub kernel_authority: bool,
}

impl MissionReplicateResult {
    pub const fn is_adopted(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }
}

pub struct MissionReplicateResultConsumer {
    scope: ReplicateScope,
    registration: ReplicateRegistration,
    last_status: Option<PredictionStatus>,
    last_proposal_digest: Option<Digest>,
    last_result: Option<MissionReplicateResult>,
}

impl fmt::Debug for MissionReplicateResultConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionReplicateResultConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("last_status", &self.last_status)
            .field("last_proposal_digest", &self.last_proposal_digest)
            .finish_non_exhaustive()
    }
}

impl MissionReplicateResultConsumer {
    pub fn new(
        scope: ReplicateScope,
        registration: ReplicateRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state() != RegistrationState::Active
            || registration.scope().scope_digest() != scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration,
            last_status: None,
            last_proposal_digest: None,
            last_result: None,
        })
    }

    pub fn from_registration(registration: &ReplicateRegistration) -> Result<Self, ConsumerError> {
        Self::new(registration.scope().clone(), registration.clone())
    }

    pub fn scope(&self) -> &ReplicateScope {
        &self.scope
    }

    pub fn registration(&self) -> &ReplicateRegistration {
        &self.registration
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn revoke(&self) -> Result<crate::model::RevocationReceipt, ConsumerError> {
        self.registration
            .revoke()
            .map_err(|_| ConsumerError::Revoked)
    }

    pub fn consume(
        &mut self,
        proposal: &ReplicatePredictionResultProposal,
    ) -> Result<MissionReplicateResult, ConsumerError> {
        if !self.registration.is_active() {
            return Err(ConsumerError::Revoked);
        }
        if !proposal.verify_digest() || proposal.service_id != crate::SERVICE_ID {
            return Err(ConsumerError::InvalidProposal);
        }
        if self.last_proposal_digest.as_ref() == Some(&proposal.proposal_digest) {
            return self
                .last_result
                .clone()
                .ok_or(ConsumerError::ReplayConflict);
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.registration_revision != self.registration.registration_revision()
            || proposal.scope_digest != *self.scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        let evidence = &proposal.evidence;
        if evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permission_digest()
            || evidence.revision_digest != *self.scope.revision_digest()
            || evidence.digests != *self.registration.provider_definition().digests()
            || evidence.account_id != *self.scope.account_id()
            || evidence.prediction_id != *self.scope.prediction().prediction_id()
            || evidence.model != *self.scope.prediction().model()
            || evidence.connected
            || evidence.native
        {
            return Err(if evidence.connected || evidence.native {
                ConsumerError::NativeEvidence
            } else {
                ConsumerError::InvalidProposal
            });
        }
        if evidence.digests.revision_digest != *self.scope.revision_digest() {
            return Err(ConsumerError::StaleMissionRevision);
        }
        if let Some(previous) = self.last_status
            && !PredictionStatus::can_follow(previous, evidence.status)
        {
            return Err(ConsumerError::StatusRegression);
        }
        let state =
            if evidence.status == PredictionStatus::Succeeded && !evidence.is_non_adoptable() {
                MissionResultState::PendingDecision
            } else {
                MissionResultState::Layer2AdoptionRequired
            };
        let result = MissionReplicateResult {
            project_id: self.scope.project().project_id().clone(),
            project_revision: self.scope.project().project_revision(),
            mission_id: self.scope.mission().mission_id().clone(),
            mission_revision: self.scope.mission().mission_revision(),
            work_product_id: self.scope.work_product().work_product_id().clone(),
            work_product_revision: self.scope.work_product().work_product_revision(),
            prediction_id: evidence.prediction_id.clone(),
            status: evidence.status,
            state,
            evidence: evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            durable_adoption: false,
            kernel_authority: false,
        };
        self.last_status = Some(evidence.status);
        self.last_proposal_digest = Some(proposal.proposal_digest.clone());
        self.last_result = Some(result.clone());
        Ok(result)
    }

    pub fn consume_result(
        &mut self,
        proposal: &ReplicatePredictionResultProposal,
    ) -> Result<MissionReplicateResult, ConsumerError> {
        self.consume(proposal)
    }
}
