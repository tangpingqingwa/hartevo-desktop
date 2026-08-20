//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsEventBridgePipeError, Result};
use crate::model::{
    AwsEventBridgePipeScope, CurrentPipeState, DesiredPipeState, Digest, EvidenceDigests,
    MissionProjection, PipeEvidenceState, ProjectProjection, TransportProvenance,
};
use crate::service::{
    AwsEventBridgePipeEvidence, AwsEventBridgePipeProposal, AwsEventBridgePipeRecord,
    AwsEventBridgePipeRegistration,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Running,
    Stopped,
    Creating,
    Updating,
    Starting,
    Stopping,
    Deleting,
    Failed,
    NotFound,
    Partial,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<PipeEvidenceState> for ProposalDisposition {
    fn from(state: PipeEvidenceState) -> Self {
        match state {
            PipeEvidenceState::Running => Self::Running,
            PipeEvidenceState::Stopped => Self::Stopped,
            PipeEvidenceState::Creating => Self::Creating,
            PipeEvidenceState::Updating => Self::Updating,
            PipeEvidenceState::Starting => Self::Starting,
            PipeEvidenceState::Stopping => Self::Stopping,
            PipeEvidenceState::Deleting => Self::Deleting,
            PipeEvidenceState::Failed => Self::Failed,
            PipeEvidenceState::NotFound => Self::NotFound,
            PipeEvidenceState::Partial => Self::Partial,
            PipeEvidenceState::AccessLoss => Self::AccessLoss,
            PipeEvidenceState::Throttled => Self::Throttled,
            PipeEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            PipeEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsEventBridgePipeResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub state: PipeEvidenceState,
    pub disposition: ProposalDisposition,
    pub current_state: Option<CurrentPipeState>,
    pub desired_state: Option<DesiredPipeState>,
    pub source_arn_digest: Option<Digest>,
    pub target_arn_digest: Option<Digest>,
    pub failure: Option<crate::service::FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub delivery_verified: bool,
}

impl MissionAwsEventBridgePipeResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub type RecordedAwsEventBridgePipeResult = AwsEventBridgePipeRecord;

pub struct MissionAwsEventBridgePipeConsumer {
    scope: AwsEventBridgePipeScope,
    registration: AwsEventBridgePipeRegistration,
    records: BTreeMap<Digest, AwsEventBridgePipeRecord>,
}

impl fmt::Debug for MissionAwsEventBridgePipeConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsEventBridgePipeConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsEventBridgePipeConsumer {
    pub fn new(
        scope: AwsEventBridgePipeScope,
        registration: AwsEventBridgePipeRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsEventBridgePipeError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsEventBridgePipeError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsEventBridgePipeRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsEventBridgePipeProposal,
    ) -> Result<MissionAwsEventBridgePipeResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsEventBridgePipeError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(AwsEventBridgePipeError::ScopeMismatch);
        }
        Ok(MissionAwsEventBridgePipeResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: self.scope.mission().into(),
            project: self.scope.project().into(),
            state: proposal.state,
            disposition: proposal.state.into(),
            current_state: proposal.current_state,
            desired_state: proposal.desired_state,
            source_arn_digest: proposal.source_arn_digest.clone(),
            target_arn_digest: proposal.target_arn_digest.clone(),
            failure: proposal.failure.clone(),
            evidence: proposal.evidence.evidence.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            delivery_verified: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsEventBridgePipeProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsEventBridgePipeResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(AwsEventBridgePipeError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsEventBridgePipeError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.set_recording_digest();
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsEventBridgePipeError::RegistrationInactive);
        }
        let record = AwsEventBridgePipeRecord::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, record.clone());
        Ok(record)
    }
}

// Keep the imported evidence type part of the public module's checked API;
// the consumer never receives or stores any raw provider payload.
#[allow(dead_code)]
fn _evidence_type_is_bounded(_: &AwsEventBridgePipeEvidence) {}
