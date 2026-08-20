//! Mission-scoped proposal consumption and redacted idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{Digest, GcpOrgPolicyScope, MissionScope, ReadOperation};
use crate::service::{
    GcpOrgPolicyEvidence, GcpOrgPolicyProposal, GcpOrgPolicyRegistration, GcpOrgPolicyServiceError,
};
use crate::{CONSUMER_ID, PROVIDER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("consumer scope or registration mismatch")]
    ScopeMismatch,
    #[error("consumer registration is revoked")]
    Revoked,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("proposal evidence is tampered")]
    TamperedEvidence,
    #[error("consumer idempotency key conflicts with another proposal")]
    RecordingConflict,
    #[error("consumer idempotency key is empty or too long")]
    InvalidIdempotencyKey,
}

impl From<GcpOrgPolicyServiceError> for ConsumerError {
    fn from(error: GcpOrgPolicyServiceError) -> Self {
        match error {
            GcpOrgPolicyServiceError::TamperedEvidence => Self::TamperedEvidence,
            GcpOrgPolicyServiceError::RegistrationRevoked
            | GcpOrgPolicyServiceError::SecretRevoked => Self::Revoked,
            GcpOrgPolicyServiceError::InvalidIdempotencyKey => Self::InvalidIdempotencyKey,
            GcpOrgPolicyServiceError::RecordingConflict => Self::RecordingConflict,
            GcpOrgPolicyServiceError::StaleMission => Self::StaleMission,
            GcpOrgPolicyServiceError::ScopeMismatch
            | GcpOrgPolicyServiceError::ProviderDrift
            | GcpOrgPolicyServiceError::PermissionDrift
            | GcpOrgPolicyServiceError::SecretScopeMismatch
            | GcpOrgPolicyServiceError::Model(_)
            | GcpOrgPolicyServiceError::Provider(_)
            | GcpOrgPolicyServiceError::RegistrationAlreadyTerminal => Self::ScopeMismatch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionGcpOrgPolicyResult {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub project_id: crate::model::ProjectId,
    pub project_revision: crate::model::ProjectRevision,
    pub mission_id: crate::model::MissionId,
    pub mission_revision: crate::model::MissionRevision,
    pub work_product_id: crate::model::WorkProductId,
    pub work_product_revision: crate::model::WorkProductRevision,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub operation: ReadOperation,
    pub evidence: GcpOrgPolicyEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub effective_authorization: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionGcpOrgPolicyResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedMissionGcpOrgPolicyResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub operation: ReadOperation,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedMissionGcpOrgPolicyResult {
    fn new(key_digest: Digest, result: &MissionGcpOrgPolicyResult) -> Self {
        let mut recorded = Self {
            idempotency_key_digest: key_digest,
            proposal_digest: result.proposal_digest.clone(),
            evidence_digest: result.evidence.digests.evidence_digest.clone(),
            operation: result.operation,
            replayed: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-mission-gcp-org-policy-recording"),
        };
        recorded.recording_digest = recorded.digest();
        recorded
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-org-policy-mission-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("operation", format!("{:?}", self.operation)),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), ConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.digest()
        {
            Err(ConsumerError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

pub struct MissionGcpOrgPolicyConsumer {
    scope: GcpOrgPolicyScope,
    registration: GcpOrgPolicyRegistration,
    mission: MissionScope,
    revoked: bool,
    records: BTreeMap<Digest, RecordedMissionGcpOrgPolicyResult>,
}

impl fmt::Debug for MissionGcpOrgPolicyConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpOrgPolicyConsumer")
            .field("scope_digest", &self.scope.scope_digest)
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("mission_digest", &self.mission.digest())
            .field("revoked", &self.revoked)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionGcpOrgPolicyConsumer {
    pub fn new(
        scope: GcpOrgPolicyScope,
        registration: GcpOrgPolicyRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != scope.scope_digest
            || registration.service_id != SERVICE_ID
            || registration.provider_id != PROVIDER_ID
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            mission: scope.mission.clone(),
            scope,
            registration,
            revoked: false,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &GcpOrgPolicyScope {
        &self.scope
    }

    pub fn registration(&self) -> &GcpOrgPolicyRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn replace_mission(&mut self, mission: MissionScope) {
        self.mission = mission;
    }

    pub fn consume(
        &self,
        proposal: &GcpOrgPolicyProposal,
    ) -> Result<MissionGcpOrgPolicyResult, ConsumerError> {
        self.validate_proposal(proposal)?;
        Ok(MissionGcpOrgPolicyResult {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            project_id: self.mission.project_id.clone(),
            project_revision: self.mission.project_revision,
            mission_id: self.mission.mission_id.clone(),
            mission_revision: self.mission.mission_revision,
            work_product_id: self.mission.work_product_id.clone(),
            work_product_revision: self.mission.work_product_revision,
            scope_digest: self.scope.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            operation: proposal.operation,
            evidence: proposal.evidence.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            effective_authorization: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    fn validate_proposal(&self, proposal: &GcpOrgPolicyProposal) -> Result<(), ConsumerError> {
        if self.revoked || !self.registration.is_active() {
            return Err(ConsumerError::Revoked);
        }
        proposal.validate_integrity().map_err(ConsumerError::from)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.mission.digest() != self.mission.digest()
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest
            || proposal.evidence.digests.permission_digest
                != self.scope.permissions.permission_digest
        {
            if proposal.mission.digest() != self.mission.digest() {
                return Err(ConsumerError::StaleMission);
            }
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn record(
        &mut self,
        proposal: &GcpOrgPolicyProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedMissionGcpOrgPolicyResult, ConsumerError> {
        let result = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::model::MAX_IDENTIFIER_BYTES
        {
            return Err(ConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != result.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.digest();
            return Ok(replay);
        }
        let recorded = RecordedMissionGcpOrgPolicyResult::new(key_digest.clone(), &result);
        self.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.revoked {
            Err(ConsumerError::Revoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }
}
