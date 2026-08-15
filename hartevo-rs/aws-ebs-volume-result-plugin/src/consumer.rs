//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsEbsVolumeError, Result};
use crate::model::{AwsEbsVolumeScope, Digest, EvidenceDigests, TransportProvenance};
use crate::service::{AwsEbsVolumeProposal, AwsEbsVolumeRegistration, EvidenceState};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    CompletedReview,
    NonAdoptableEvidence,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        if value == EvidenceState::Completed {
            Self::CompletedReview
        } else {
            Self::NonAdoptableEvidence
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsEbsResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub accepted_for_review: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsEbsResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub recording_digest: Digest,
    pub replayed: bool,
}

impl RecordedAwsEbsResult {
    fn new(key_digest: Digest, proposal: &AwsEbsVolumeProposal, replayed: bool) -> Self {
        let recording_digest = Digest::from_parts(
            "aws-ebs-recording/v1",
            &[
                ("idempotency", key_digest.as_str().to_owned()),
                ("proposal", proposal.digest().as_str().to_owned()),
                ("state", format!("{:?}", proposal.state)),
                ("provenance", proposal.provenance.as_str().to_owned()),
            ],
        );
        Self {
            idempotency_key_digest: key_digest,
            proposal_digest: proposal.digest().clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            recording_digest,
            replayed,
        }
    }

    fn replay(&self) -> Self {
        let mut replay = self.clone();
        replay.replayed = true;
        replay.recording_digest = Digest::from_parts(
            "aws-ebs-recording-replay/v1",
            &[
                (
                    "idempotency",
                    replay.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", replay.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", replay.state)),
            ],
        );
        replay
    }
}

pub struct MissionAwsEbsConsumer {
    scope: AwsEbsVolumeScope,
    registration: AwsEbsVolumeRegistration,
    records: BTreeMap<Digest, RecordedAwsEbsResult>,
}

impl fmt::Debug for MissionAwsEbsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsEbsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsEbsConsumer {
    pub fn new(scope: AwsEbsVolumeScope, registration: AwsEbsVolumeRegistration) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsEbsVolumeError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsEbsVolumeError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsEbsVolumeRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsEbsVolumeScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsEbsVolumeProposal) -> Result<MissionAwsEbsResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsEbsVolumeError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.volume_allowlist_digest != *self.registration.volume_allowlist_digest()
            || proposal.snapshot_allowlist_digest != *self.registration.snapshot_allowlist_digest()
            || proposal.mission.binding_digest != self.scope.mission().digest()
            || proposal.project.binding_digest != self.scope.project().digest()
            || proposal.work_product.binding_digest != self.scope.work_product().digest()
        {
            return Err(AwsEbsVolumeError::ScopeMismatch);
        }
        Ok(MissionAwsEbsResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.digest().clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance.clone(),
            accepted_for_review: proposal.state == EvidenceState::Completed,
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
        proposal: &AwsEbsVolumeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsEbsResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsEbsVolumeError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != *proposal.digest() {
                return Err(AwsEbsVolumeError::RecordingConflict);
            }
            return Ok(existing.replay());
        }
        let result = RecordedAwsEbsResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
