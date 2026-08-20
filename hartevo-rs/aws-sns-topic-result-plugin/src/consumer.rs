//! Mission-scoped, review-only consumer and idempotent redacted recording.

use std::{collections::BTreeMap, fmt};

use chrono::{DateTime, Utc};
use serde::Serialize;
use zeroize::Zeroize;

use crate::CONSUMER_ID;
use crate::error::{AwsSnsTopicError, Result};
use crate::model::{AwsSnsTopicScope, Digest};
use crate::service::{
    AwsSnsTopicEvidence, AwsSnsTopicProposal, AwsSnsTopicRegistration, EvidenceState,
    RegistrationStatus,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsSnsResult {
    pub consumer_id: String,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl MissionAwsSnsResult {
    fn from_proposal(proposal: &AwsSnsTopicProposal) -> Self {
        Self {
            consumer_id: CONSUMER_ID.to_owned(),
            state: proposal.state,
            scope_digest: proposal.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            requires_human_review: true,
            safe_to_promote: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsSnsResult {
    pub recording_key_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub recorded_at: DateTime<Utc>,
    pub replayed: bool,
    pub recorded: bool,
    pub raw_provider_payload_retained: bool,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl RecordedAwsSnsResult {
    pub fn validate_integrity(&self) -> Result<()> {
        if self.recording_key_digest == Digest::zero()
            || self.scope_digest == Digest::zero()
            || self.proposal_digest == Digest::zero()
            || self.evidence_digest == Digest::zero()
            || !self.recorded
            || self.raw_provider_payload_retained
            || self.durable_receipt
            || self.connected
            || self.native
            || self.first_party
        {
            Err(AwsSnsTopicError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct MissionAwsSnsConsumer {
    scope: AwsSnsTopicScope,
    registration: AwsSnsTopicRegistration,
    records: BTreeMap<Digest, RecordedAwsSnsResult>,
}

impl MissionAwsSnsConsumer {
    pub fn new(scope: AwsSnsTopicScope, registration: AwsSnsTopicRegistration) -> Result<Self> {
        scope.validate()?;
        registration.validate()?;
        if registration.scope_digest != scope.digest() {
            return Err(AwsSnsTopicError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsSnsTopicScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsSnsTopicRegistration {
        &self.registration
    }

    pub fn consume(&self, proposal: &AwsSnsTopicProposal) -> Result<MissionAwsSnsResult> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.evidence.registration_digest != self.registration.digest() {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        Ok(MissionAwsSnsResult::from_proposal(proposal))
    }

    pub fn record(
        &mut self,
        proposal: &AwsSnsTopicProposal,
        recording_key: impl Into<String>,
    ) -> Result<RecordedAwsSnsResult> {
        self.record_at(proposal, recording_key, Utc::now())
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsSnsTopicProposal,
        recording_key: impl Into<String>,
        recorded_at: DateTime<Utc>,
    ) -> Result<RecordedAwsSnsResult> {
        self.ensure_active()?;
        proposal.validate_integrity(&self.scope)?;
        if proposal.evidence.registration_digest != self.registration.digest() {
            return Err(AwsSnsTopicError::TamperedEvidence);
        }
        let mut recording_key = recording_key.into();
        if recording_key.is_empty() || recording_key.len() > 512 {
            recording_key.zeroize();
            return Err(AwsSnsTopicError::InvalidRequest);
        }
        let key_digest = Digest::from_parts(
            "aws-sns-recording-key/v1",
            &[("key", recording_key.clone())],
        );
        recording_key.zeroize();
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest
                || existing.evidence_digest != proposal.evidence_digest
            {
                return Err(AwsSnsTopicError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        let result = RecordedAwsSnsResult {
            recording_key_digest: key_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            recorded_at,
            replayed: false,
            recorded: true,
            raw_provider_payload_retained: false,
            durable_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        };
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    fn ensure_active(&self) -> Result<()> {
        match self.registration.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => Err(AwsSnsTopicError::RegistrationRevoked),
            RegistrationStatus::Reversed => Err(AwsSnsTopicError::RegistrationReversed),
        }
    }
}

impl fmt::Display for MissionAwsSnsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MissionAwsSnsConsumer({})",
            self.scope.digest().as_str()
        )
    }
}

impl AwsSnsTopicEvidence {
    pub fn mission_result(&self, proposal: &AwsSnsTopicProposal) -> MissionAwsSnsResult {
        MissionAwsSnsResult::from_proposal(proposal)
    }
}
