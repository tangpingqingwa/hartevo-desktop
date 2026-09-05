use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{MeltanoPipelineResultError, Result};
use crate::model::{
    Digest, MeltanoEvidenceState, MeltanoPipelineEvidence, MeltanoPipelineRegistration,
    MeltanoPipelineResultProposal, MeltanoPipelineResultScope, MeltanoRecordingReceipt, MissionId,
    ProjectId, WorkProductId,
};
use crate::{CONSUMER_ID, SERVICE_ID};

pub type MissionMeltanoPipelineConsumerError = MeltanoPipelineResultError;
pub type RecordedMeltanoPipelineResult = MeltanoRecordingReceipt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionMeltanoPipelineResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub state: MeltanoEvidenceState,
    pub evidence: MeltanoPipelineEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl MissionMeltanoPipelineResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionMeltanoPipelineConsumer {
    scope: MeltanoPipelineResultScope,
    registration: MeltanoPipelineRegistration,
    records: BTreeMap<Digest, MeltanoRecordingReceipt>,
}

impl fmt::Debug for MissionMeltanoPipelineConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionMeltanoPipelineConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionMeltanoPipelineConsumer {
    pub fn new(
        scope: MeltanoPipelineResultScope,
        registration: MeltanoPipelineRegistration,
    ) -> Result<Self> {
        scope.validate()?;
        registration.validate()?;
        if !registration.is_active() || registration.scope_digest != scope.digest() {
            return Err(MeltanoPipelineResultError::RegistrationInactive);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &MeltanoPipelineRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &MeltanoPipelineResultScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &MeltanoPipelineResultProposal,
    ) -> Result<MissionMeltanoPipelineResult> {
        proposal.validate_integrity(&self.scope)?;
        if !self.registration.is_active()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(MeltanoPipelineResultError::ScopeMismatch);
        }
        Ok(MissionMeltanoPipelineResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            state: proposal.state,
            evidence: proposal.evidence.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &MeltanoPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedMeltanoPipelineResult> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.into();
        if !valid_idempotency_key(&idempotency_key) {
            return Err(MeltanoPipelineResultError::InvalidRequest);
        }
        let idempotency_digest = Digest::from_parts(
            "meltano-consumer-idempotency/v1",
            &[("key", idempotency_key)],
        );
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MeltanoPipelineResultError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let receipt = MeltanoRecordingReceipt::new(
            idempotency_digest.clone(),
            proposal.proposal_digest.clone(),
            proposal.scope_digest.clone(),
            proposal.registration_digest.clone(),
            false,
        );
        receipt.validate()?;
        self.records.insert(idempotency_digest, receipt.clone());
        Ok(receipt)
    }

    pub fn record_proposal(
        &mut self,
        proposal: &MeltanoPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedMeltanoPipelineResult> {
        self.record(proposal, idempotency_key)
    }
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}
