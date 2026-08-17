//! Mission-scoped proposal consumption and redacted idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    AWS_ECS_CONSUMER_ID, AWS_ECS_SERVICE_ID,
    model::{
        Digest, EcsDeploymentScope, EvidenceState, MissionBinding, MissionProjection,
        ProjectBinding, ProjectProjection, WorkProductBinding, WorkProductProjection,
        mission_projection, project_projection, work_product_projection,
    },
    service::{
        EcsDeploymentProposal, EcsDeploymentRecord, EcsDeploymentRegistration, RegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("ECS consumer registration is not active")]
    RegistrationRevoked,
    #[error("ECS consumer registration is reversed")]
    RegistrationReversed,
    #[error("ECS consumer is revoked")]
    Revoked,
    #[error("ECS proposal is stale or tampered")]
    ProposalTampered,
    #[error("ECS evidence is stale or tampered")]
    EvidenceTampered,
    #[error("ECS proposal does not match the consumer scope")]
    ScopeMismatch,
    #[error("ECS proposal Mission revision is stale")]
    StaleMission,
    #[error("ECS proposal Project revision is stale")]
    StaleProject,
    #[error("ECS proposal Work Product revision is stale")]
    StaleWorkProduct,
    #[error("ECS recording idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("ECS recording idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error("ECS recorded result is stale or tampered")]
    RecordTampered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionEcsDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub operation: crate::ReadOperation,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub accepted: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionEcsDeploymentResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A consumer-side record contains only digests and redacted status. It is
/// intentionally not a durable provider receipt and cannot adopt an Outcome.
pub type RecordedEcsDeploymentResult = EcsDeploymentRecord;

pub struct MissionEcsDeploymentConsumer {
    scope: EcsDeploymentScope,
    registration: EcsDeploymentRegistration,
    mission: MissionBinding,
    project: ProjectBinding,
    work_product: WorkProductBinding,
    records: BTreeMap<Digest, EcsDeploymentRecord>,
    revoked: bool,
}

impl fmt::Debug for MissionEcsDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionEcsDeploymentConsumer")
            .field("scope_digest", &self.scope.scope_digest)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl MissionEcsDeploymentConsumer {
    pub fn new(
        scope: EcsDeploymentScope,
        registration: EcsDeploymentRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state == RegistrationState::Revoked {
            return Err(ConsumerError::RegistrationRevoked);
        }
        if registration.state == RegistrationState::Reversed {
            return Err(ConsumerError::RegistrationReversed);
        }
        if registration.registration_digest != registration.recomputed_digest()
            || registration.scope_digest != scope.scope_digest
            || registration.permission_digest != scope.permission.permission_digest
            || registration.consent_digest != scope.consent.consent_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            work_product: scope.work_product.clone(),
            scope,
            registration,
            records: BTreeMap::new(),
            revoked: false,
        })
    }

    pub fn registration(&self) -> &EcsDeploymentRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &EcsDeploymentScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn replace_mission(&mut self, mission: MissionBinding) {
        self.mission = mission;
    }

    pub fn replace_project(&mut self, project: ProjectBinding) {
        self.project = project;
    }

    pub fn replace_work_product(&mut self, work_product: WorkProductBinding) {
        self.work_product = work_product;
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn consume(
        &self,
        proposal: &EcsDeploymentProposal,
    ) -> Result<MissionEcsDeploymentResult, ConsumerError> {
        self.ensure_active()?;
        proposal.validate().map_err(|error| match error {
            crate::EcsDeploymentServiceError::EvidenceTampered => ConsumerError::EvidenceTampered,
            _ => ConsumerError::ProposalTampered,
        })?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest
            || proposal.evidence.digests.permission_digest
                != self.scope.permission.permission_digest
            || proposal.evidence.digests.consent_digest != self.scope.consent.consent_digest
            || proposal.operation != proposal.evidence.operation
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.mission != mission_projection(&self.mission) {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.project != project_projection(&self.project) {
            return Err(ConsumerError::StaleProject);
        }
        if proposal.work_product != work_product_projection(&self.work_product) {
            return Err(ConsumerError::StaleWorkProduct);
        }
        Ok(MissionEcsDeploymentResult {
            service_id: AWS_ECS_SERVICE_ID.to_owned(),
            consumer_id: AWS_ECS_CONSUMER_ID.to_owned(),
            operation: proposal.operation,
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            accepted: proposal.state == EvidenceState::Complete,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &EcsDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<EcsDeploymentRecord, ConsumerError> {
        self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        let result = EcsDeploymentRecord::new_for_consumer(proposal, key);
        result
            .validate()
            .map_err(|_| ConsumerError::RecordTampered)?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify_record(
        &self,
        proposal: &EcsDeploymentProposal,
        record: &EcsDeploymentRecord,
    ) -> Result<(), ConsumerError> {
        self.consume(proposal)?;
        record
            .validate()
            .map_err(|_| ConsumerError::RecordTampered)?;
        if record.proposal_digest != proposal.proposal_digest
            || record.registration_digest != self.registration.registration_digest
            || record.scope_digest != self.scope.scope_digest
        {
            return Err(ConsumerError::RecordTampered);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.revoked {
            return Err(ConsumerError::Revoked);
        }
        match self.registration.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Revoked => Err(ConsumerError::RegistrationRevoked),
            RegistrationState::Reversed => Err(ConsumerError::RegistrationReversed),
        }
    }
}

// These aliases make the Mission/Project/Work Product fence types explicit in
// generated API documentation without introducing another mutable authority.
pub type EcsMissionConsumer = MissionEcsDeploymentConsumer;
pub type EcsMissionResult = MissionEcsDeploymentResult;
