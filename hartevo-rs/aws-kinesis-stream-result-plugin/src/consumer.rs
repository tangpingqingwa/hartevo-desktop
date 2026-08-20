//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsKinesisStreamResultError, Result};
use crate::model::{
    AwsKinesisStreamScope, ConsumerIdentity, Digest, KinesisEvidenceState, StreamProjection,
    TransportProvenance,
};
use crate::service::{AwsKinesisStreamResultProposal, AwsKinesisStreamResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Creating,
    Active,
    Updating,
    Deleting,
    Partial,
    TokenExpired,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<KinesisEvidenceState> for ProposalDisposition {
    fn from(state: KinesisEvidenceState) -> Self {
        match state {
            KinesisEvidenceState::Creating => Self::Creating,
            KinesisEvidenceState::Active => Self::Active,
            KinesisEvidenceState::Updating => Self::Updating,
            KinesisEvidenceState::Deleting => Self::Deleting,
            KinesisEvidenceState::Partial => Self::Partial,
            KinesisEvidenceState::TokenExpired => Self::TokenExpired,
            KinesisEvidenceState::AccessLost => Self::AccessLoss,
            KinesisEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            KinesisEvidenceState::Tampered => Self::Tampered,
            KinesisEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsKinesisResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: KinesisEvidenceState,
    pub disposition: ProposalDisposition,
    pub stream: Option<StreamProjection>,
    pub evidence: crate::model::EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsKinesisResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsKinesisResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: KinesisEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsKinesisResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsKinesisStreamResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-kinesis-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != recording_digest(self)
        {
            Err(AwsKinesisStreamResultError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

fn recording_digest(result: &RecordedAwsKinesisResult) -> Digest {
    Digest::from_parts(
        "aws-kinesis-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
        ],
    )
}

/// Consumer scoped to one exact Kinesis registration and Mission fence.
pub struct MissionAwsKinesisConsumer {
    scope: AwsKinesisStreamScope,
    registration: AwsKinesisStreamResultRegistration,
    records: BTreeMap<Digest, RecordedAwsKinesisResult>,
}

impl fmt::Debug for MissionAwsKinesisConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsKinesisConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsKinesisConsumer {
    pub fn new(
        scope: AwsKinesisStreamScope,
        registration: AwsKinesisStreamResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsKinesisStreamResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsKinesisStreamResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsKinesisStreamResultRegistration {
        &self.registration
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsKinesisStreamResultProposal,
    ) -> Result<MissionAwsKinesisResult> {
        self.consume_for_mission_revision(proposal, self.scope.mission().revision())
    }

    pub fn consume_for_mission_revision(
        &self,
        proposal: &AwsKinesisStreamResultProposal,
        mission_revision: u64,
    ) -> Result<MissionAwsKinesisResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsKinesisStreamResultError::RegistrationInactive);
        }
        if mission_revision != self.scope.mission().revision()
            || proposal.mission.revision != mission_revision
        {
            return Err(AwsKinesisStreamResultError::StaleMissionRevision);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.stream_digest != self.scope.stream().digest()
            || proposal.stream_version_digest != self.scope.stream_version().digest()
            || proposal.shard_filter_digest != self.scope.shard_filter().digest()
            || proposal.consumer_scope_digest != self.scope.consumer().map(ConsumerIdentity::digest)
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsKinesisStreamResultError::ScopeMismatch);
        }
        if let Some(stream) = &proposal.stream {
            stream.validate(&self.scope)?;
        }
        Ok(MissionAwsKinesisResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            stream: proposal.stream.clone(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsKinesisStreamResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsKinesisResult> {
        self.record_for_mission_revision(proposal, idempotency_key, self.scope.mission().revision())
    }

    pub fn record_for_mission_revision(
        &mut self,
        proposal: &AwsKinesisStreamResultProposal,
        idempotency_key: impl AsRef<str>,
        mission_revision: u64,
    ) -> Result<RecordedAwsKinesisResult> {
        let _ = self.consume_for_mission_revision(proposal, mission_revision)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsKinesisStreamResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsKinesisStreamResultError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedAwsKinesisResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
