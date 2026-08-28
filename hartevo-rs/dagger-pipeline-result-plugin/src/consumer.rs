use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{DaggerPipelineResultError, Result};
use crate::model::{
    DaggerEvidenceState, DaggerPipelineRegistration, DaggerPipelineResultProposal,
    DaggerPipelineScope, DaggerRecordingReceipt, Digest, MissionId, ProjectId, WorkProductId,
};
use crate::{CONSUMER_ID, SERVICE_ID};

pub type MissionDaggerPipelineConsumerError = DaggerPipelineResultError;
pub type RecordedDaggerPipelineResult = DaggerRecordingReceipt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionDaggerPipelineResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: ProjectId,
    pub mission: MissionId,
    pub work_product: WorkProductId,
    pub state: DaggerEvidenceState,
    pub evidence: crate::model::DaggerPipelineEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

impl MissionDaggerPipelineResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionDaggerPipelineConsumer {
    scope: DaggerPipelineScope,
    registration: DaggerPipelineRegistration,
    records: BTreeMap<Digest, DaggerRecordingReceipt>,
}

impl fmt::Debug for MissionDaggerPipelineConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDaggerPipelineConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionDaggerPipelineConsumer {
    pub fn new(
        scope: DaggerPipelineScope,
        registration: DaggerPipelineRegistration,
    ) -> Result<Self> {
        scope.validate()?;
        registration.validate()?;
        if !registration.is_active() || registration.scope_digest != scope.digest() {
            return Err(DaggerPipelineResultError::RegistrationInactive);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &DaggerPipelineRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &DaggerPipelineScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &DaggerPipelineResultProposal,
    ) -> Result<MissionDaggerPipelineResult> {
        proposal.validate_integrity(&self.scope)?;
        if !self.registration.is_active()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(DaggerPipelineResultError::ScopeMismatch);
        }
        Ok(MissionDaggerPipelineResult {
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
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &DaggerPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedDaggerPipelineResult> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.into();
        if !valid_idempotency_key(&idempotency_key) {
            return Err(DaggerPipelineResultError::InvalidRequest);
        }
        let idempotency_digest = Digest::from_parts(
            "dagger-consumer-idempotency/v1",
            &[("key", idempotency_key)],
        );
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(DaggerPipelineResultError::IdempotencyConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let receipt = DaggerRecordingReceipt::new(
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
        proposal: &DaggerPipelineResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<RecordedDaggerPipelineResult> {
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
