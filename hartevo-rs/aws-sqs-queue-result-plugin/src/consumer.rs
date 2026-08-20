//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsSqsQueueError, Result};
use crate::model::{AwsSqsQueueScope, Digest, TransportProvenance};
use crate::service::{
    AwsSqsQueueProposal, AwsSqsQueueRecord, AwsSqsQueueRegistration, QueueEvidenceState,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSqsResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub queue_digest: Digest,
    pub dead_letter_queue_digest: Option<Digest>,
    pub state: QueueEvidenceState,
    pub queue_attributes: Option<crate::model::QueueAttributesProjection>,
    pub redrive_allow: Option<crate::model::RedriveAllowPosture>,
    pub approximate_counts: Option<crate::model::ApproximateQueueCounts>,
    pub counts_fresh: bool,
    pub evidence: crate::service::AwsSqsQueueEvidence,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub approximate_counts_are_delivery_proof: bool,
}

impl MissionAwsSqsResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A Mission consumer is deliberately below Hartevo Truth, Consent, Effect,
/// Receipt, Verification, Outcome, and Work Product authority.
pub struct MissionAwsSqsConsumer {
    scope: AwsSqsQueueScope,
    registration: AwsSqsQueueRegistration,
    records: BTreeMap<Digest, AwsSqsQueueRecord>,
}

impl fmt::Debug for MissionAwsSqsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsSqsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsSqsConsumer {
    pub fn new(scope: AwsSqsQueueScope, registration: AwsSqsQueueRegistration) -> Result<Self> {
        scope.validate()?;
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsSqsQueueError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest()
            || registration.queue_digest() != &scope.queue_digest()
        {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsSqsQueueScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsSqsQueueRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsSqsQueueProposal) -> Result<MissionAwsSqsResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsSqsQueueError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.queue_digest != self.scope.queue_digest()
        {
            return Err(AwsSqsQueueError::ScopeMismatch);
        }
        Ok(MissionAwsSqsResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            queue_digest: proposal.queue_digest.clone(),
            dead_letter_queue_digest: proposal.dead_letter_queue_digest.clone(),
            state: proposal.state,
            queue_attributes: proposal.queue_attributes.clone(),
            redrive_allow: proposal.redrive_allow.clone(),
            approximate_counts: proposal.approximate_counts.clone(),
            counts_fresh: proposal.counts_fresh,
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            approximate_counts_are_delivery_proof: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsSqsQueueProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<AwsSqsQueueRecord> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsSqsQueueError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsSqsQueueError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = crate::model::Digest::from_parts(
                "aws-sqs-recording/v1",
                &[
                    (
                        "idempotency",
                        replay.idempotency_key_digest.as_str().to_owned(),
                    ),
                    ("proposal", replay.proposal_digest.as_str().to_owned()),
                    ("state", format!("{:?}", replay.state)),
                    (
                        "failure",
                        replay.failure.as_ref().map_or_else(String::new, |value| {
                            crate::model::digest_serialized(value).as_str().to_owned()
                        }),
                    ),
                    ("provenance", replay.provenance.as_str().to_owned()),
                ],
            );
            return Ok(replay);
        }
        let result = AwsSqsQueueRecord::new_for_consumer(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
