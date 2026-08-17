//! Mission-scoped proposal consumption and below-kernel recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::model::{
    AwsCodePipelineScope, Digest, EvidenceState, RetryEvidence, TransportProvenance,
};
use crate::service::{AwsCodePipelineRegistration, AwsCodePipelineReleaseProposal};
use crate::{AwsCodePipelineReleaseError, CONSUMER_ID, Result, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Complete,
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Stopped,
    Superseded,
    Canceled,
    Partial,
    Unknown,
    AccessLoss,
    Retryable,
    ExecutionReplaced,
    StageActionReplaced,
    RegistrationRevoked,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Complete => Self::Complete,
            EvidenceState::Queued => Self::Queued,
            EvidenceState::InProgress => Self::InProgress,
            EvidenceState::Succeeded => Self::Succeeded,
            EvidenceState::Failed => Self::Failed,
            EvidenceState::Stopped => Self::Stopped,
            EvidenceState::Superseded => Self::Superseded,
            EvidenceState::Canceled => Self::Canceled,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::Unknown => Self::Unknown,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Retryable => Self::Retryable,
            EvidenceState::ExecutionReplaced => Self::ExecutionReplaced,
            EvidenceState::StageActionReplaced => Self::StageActionReplaced,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCodePipelineResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub retry: RetryEvidence,
    pub provenance: TransportProvenance,
    pub response_truncated: bool,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsCodePipelineResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCodePipelineResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub retry: RetryEvidence,
    pub provenance: TransportProvenance,
    pub response_truncated: bool,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAwsCodePipelineResult {
    fn from_proposal(
        idempotency_key_digest: Digest,
        proposal: &AwsCodePipelineReleaseProposal,
        replayed: bool,
    ) -> Self {
        let mut recorded = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            request_digest: proposal.evidence.request_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            retry: proposal.evidence.retry.clone(),
            provenance: proposal.provenance,
            response_truncated: proposal.response_truncated,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aws-codepipeline-recording"),
        };
        recorded.recording_digest = recorded.calculate_digest();
        recorded
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.idempotency_key_digest.validate().is_err()
            || self.proposal_digest.validate().is_err()
            || self.request_digest.validate().is_err()
            || self.retry.validate(&self.request_digest).is_err()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            Err(AwsCodePipelineReleaseError::InvalidProposal)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-codepipeline-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("disposition", format!("{:?}", self.disposition)),
                (
                    "retry",
                    serde_json::to_string(&self.retry).expect("retry evidence serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("truncated", self.response_truncated.to_string()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct AwsCodePipelineRecordingLog {
    records: BTreeMap<Digest, RecordedAwsCodePipelineResult>,
}

impl AwsCodePipelineRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, key_digest: &Digest) -> Option<&RecordedAwsCodePipelineResult> {
        self.records.get(key_digest)
    }
}

pub type RecordingLog = AwsCodePipelineRecordingLog;

/// Consumer fenced to one exact CodePipeline scope and Mission revision.
pub struct MissionAwsCodePipelineConsumer {
    scope: AwsCodePipelineScope,
    registration: AwsCodePipelineRegistration,
    records: BTreeMap<Digest, RecordedAwsCodePipelineResult>,
}

impl fmt::Debug for MissionAwsCodePipelineConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCodePipelineConsumer")
            .field("scope_digest", self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCodePipelineConsumer {
    pub fn new(
        scope: AwsCodePipelineScope,
        registration: AwsCodePipelineRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCodePipelineReleaseError::RegistrationInactive);
        }
        if registration.scope_digest() != scope.digest() {
            return Err(AwsCodePipelineReleaseError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsCodePipelineScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsCodePipelineRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCodePipelineReleaseProposal,
    ) -> Result<MissionAwsCodePipelineResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsCodePipelineReleaseError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().value.digest()
            || proposal.mission.revision != self.scope.mission().revision
            || proposal.project.id_digest != self.scope.project().value.digest()
            || proposal.project.revision != self.scope.project().revision
            || proposal.work_product.id_digest != self.scope.work_product().value.digest()
            || proposal.work_product.revision != self.scope.work_product().revision
        {
            return Err(AwsCodePipelineReleaseError::ScopeMismatch);
        }
        Ok(MissionAwsCodePipelineResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            retry: proposal.evidence.retry.clone(),
            provenance: proposal.provenance,
            response_truncated: proposal.response_truncated,
            review_only: true,
            connected: false,
            native: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &self,
        log: &mut AwsCodePipelineRecordingLog,
        proposal: &AwsCodePipelineReleaseProposal,
        idempotency_key: &str,
    ) -> Result<RecordedAwsCodePipelineResult> {
        let _ = self.consume(proposal)?;
        if idempotency_key.is_empty() || idempotency_key.trim() != idempotency_key {
            return Err(AwsCodePipelineReleaseError::InvalidProposal);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = log.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCodePipelineReleaseError::ReplayConflict);
            }
            let replay = RecordedAwsCodePipelineResult::from_proposal(key_digest, proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsCodePipelineReleaseError::RegistrationInactive);
        }
        let recorded =
            RecordedAwsCodePipelineResult::from_proposal(key_digest.clone(), proposal, false);
        recorded.validate_integrity()?;
        log.records.insert(key_digest, recorded.clone());
        Ok(recorded)
    }

    pub fn record_local(
        &mut self,
        proposal: &AwsCodePipelineReleaseProposal,
        idempotency_key: &str,
    ) -> Result<RecordedAwsCodePipelineResult> {
        let mut log = AwsCodePipelineRecordingLog {
            records: std::mem::take(&mut self.records),
        };
        let result = self.record(&mut log, proposal, idempotency_key);
        self.records = log.records;
        result
    }
}
