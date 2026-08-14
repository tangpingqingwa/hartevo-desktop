//! Mission-scoped proposal and safe recording below kernel authority.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::{
    Digest, FunctionCallProjection, JobStatus, ModalScope, ProjectionCompleteness,
    TransportProvenance, UsageEvidence,
};
use crate::{
    CONSUMER_ID, CONTRACT_VERSION, ModalJobResultError, Result, SERVICE_ID, validate_text,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    AwaitingPoll,
    Succeeded,
    Failed,
    Canceled,
    Expired,
    ProviderUnknown,
    TruncatedEvidence,
    RedactedEvidence,
}

/// Mission/Project/Work Product-bound job-result proposal. It is a review
/// artifact only and cannot be adopted as an Outcome or kernel fact.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobResultProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub host_digest: Digest,
    pub workspace_digest: Digest,
    pub app_digest: Digest,
    pub function_digest: Digest,
    pub environment_digest: Digest,
    pub call_digest: Digest,
    pub input_digest: Digest,
    pub retry_digest: Digest,
    pub mission_id: String,
    pub mission_revision: u64,
    pub project_id: String,
    pub project_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub status: JobStatus,
    pub disposition: ProposalDisposition,
    pub completeness: ProjectionCompleteness,
    pub result_digest: Option<Digest>,
    pub captured_result_bytes: u64,
    pub reported_result_bytes: Option<u64>,
    pub result_expires_at_epoch_seconds: Option<u64>,
    pub usage: UsageEvidence,
    pub retry_attempt_number: u8,
    pub poll_count: u8,
    pub evidence_digest: Digest,
    pub idempotency_key_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl JobResultProposal {
    fn new(
        scope: &ModalScope,
        projection: &FunctionCallProjection,
        idempotency_key: &str,
    ) -> Result<Self> {
        validate_text(
            idempotency_key,
            "idempotencyKey",
            crate::MAX_IDENTIFIER_BYTES,
        )?;
        scope.validate()?;
        projection.validate_integrity()?;
        if !projection.matches_scope(scope) {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        let idempotency_key_digest = Digest::from_text(idempotency_key);
        let disposition = if projection.status == JobStatus::ProviderUnknown {
            ProposalDisposition::ProviderUnknown
        } else if projection
            .result
            .as_ref()
            .is_some_and(|result| result.truncated)
            || projection.response_truncated
        {
            ProposalDisposition::TruncatedEvidence
        } else if projection
            .result
            .as_ref()
            .is_some_and(|result| result.redacted)
        {
            ProposalDisposition::RedactedEvidence
        } else {
            match projection.status {
                JobStatus::Queued | JobStatus::Running => ProposalDisposition::AwaitingPoll,
                JobStatus::Succeeded => ProposalDisposition::Succeeded,
                JobStatus::Failed => ProposalDisposition::Failed,
                JobStatus::Canceled => ProposalDisposition::Canceled,
                JobStatus::Expired => ProposalDisposition::Expired,
                JobStatus::ProviderUnknown => ProposalDisposition::ProviderUnknown,
            }
        };
        let (result_digest, captured_result_bytes, reported_result_bytes, result_expires_at) =
            projection
                .result
                .as_ref()
                .map_or((None, 0, None, None), |result| {
                    (
                        result.result_digest.clone(),
                        result.captured_bytes,
                        result.reported_bytes,
                        result.expires_at_epoch_seconds,
                    )
                });
        let usage = projection.result.as_ref().map_or_else(
            || UsageEvidence::for_input(&scope.input, projection.poll_count),
            |result| Ok(result.usage),
        )?;
        let mut proposal = Self {
            proposal_version: format!("{CONTRACT_VERSION}/proposal"),
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: scope.digest(),
            host_digest: scope.host.digest(),
            workspace_digest: scope.workspace.digest(),
            app_digest: scope.app.digest(),
            function_digest: scope.function.digest(),
            environment_digest: scope.environment.digest(),
            call_digest: scope.call.digest(),
            input_digest: scope.input.digest(),
            retry_digest: scope.retry.digest(),
            mission_id: scope.mission.id.clone(),
            mission_revision: scope.mission.revision,
            project_id: scope.project.id.clone(),
            project_revision: scope.project.revision,
            work_product_id: scope.work_product.id.clone(),
            work_product_revision: scope.work_product.revision,
            status: projection.status,
            disposition,
            completeness: projection.completeness,
            result_digest,
            captured_result_bytes,
            reported_result_bytes,
            result_expires_at_epoch_seconds: result_expires_at,
            usage,
            retry_attempt_number: projection.attempt_number,
            poll_count: projection.poll_count,
            evidence_digest: projection.evidence_digest.clone(),
            idempotency_key_digest,
            provenance: projection.provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-modal-job-result-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        Ok(proposal)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.scope_digest,
            &self.host_digest,
            &self.workspace_digest,
            &self.app_digest,
            &self.function_digest,
            &self.environment_digest,
            &self.call_digest,
            &self.input_digest,
            &self.retry_digest,
            &self.evidence_digest,
            &self.idempotency_key_digest,
        ] {
            digest.validate()?;
        }
        self.usage.validate()?;
        if self.proposal_version != format!("{CONTRACT_VERSION}/proposal")
            || self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.mission_id.is_empty()
            || self.project_id.is_empty()
            || self.work_product_id.is_empty()
            || self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
            || self.retry_attempt_number == 0
            || self.poll_count > crate::MAX_POLL_ATTEMPTS
            || self.captured_result_bytes > crate::MAX_CAPTURED_RESULT_BYTES
            || self.reported_result_bytes.is_some_and(|value| {
                value > crate::MAX_REPORTED_RESULT_BYTES || value < self.captured_result_bytes
            })
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        if let Some(digest) = &self.result_digest {
            digest.validate()?;
        }
        if self
            .result_expires_at_epoch_seconds
            .is_some_and(|expiry| expiry == 0)
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "modal-job-result-proposal/v1",
            &[
                ("proposal_version", self.proposal_version.clone()),
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("host", self.host_digest.as_str().to_owned()),
                ("workspace", self.workspace_digest.as_str().to_owned()),
                ("app", self.app_digest.as_str().to_owned()),
                ("function", self.function_digest.as_str().to_owned()),
                ("environment", self.environment_digest.as_str().to_owned()),
                ("call", self.call_digest.as_str().to_owned()),
                ("input", self.input_digest.as_str().to_owned()),
                ("retry", self.retry_digest.as_str().to_owned()),
                (
                    "mission",
                    format!("{}@{}", self.mission_id, self.mission_revision),
                ),
                (
                    "project",
                    format!("{}@{}", self.project_id, self.project_revision),
                ),
                (
                    "work_product",
                    format!("{}@{}", self.work_product_id, self.work_product_revision),
                ),
                ("status", self.status.as_str().to_owned()),
                ("disposition", format!("{:?}", self.disposition)),
                ("completeness", format!("{:?}", self.completeness)),
                (
                    "result",
                    self.result_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("captured_bytes", self.captured_result_bytes.to_string()),
                (
                    "reported_bytes",
                    self.reported_result_bytes
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "expires_at",
                    self.result_expires_at_epoch_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "usage",
                    serde_json::to_string(&self.usage).expect("usage evidence"),
                ),
                ("attempt", self.retry_attempt_number.to_string()),
                ("poll", self.poll_count.to_string()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// Safe durable recording result. It contains only bounded status and digest
/// metadata and is not a provider Receipt or Outcome.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedModalJobResult {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub status: JobStatus,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedModalJobResult {
    fn from_proposal(proposal: &JobResultProposal, replayed: bool) -> Self {
        let mut result = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            status: proposal.status,
            disposition: proposal.disposition,
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-modal-job-result-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.proposal_digest.validate()?;
        self.scope_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(ModalJobResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "modal-job-result-recording/v1",
            &[
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("disposition", format!("{:?}", self.disposition)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct ModalJobResultRecordingLog {
    records: BTreeMap<Digest, RecordedModalJobResult>,
}

impl ModalJobResultRecordingLog {
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, idempotency_key_digest: &Digest) -> Option<&RecordedModalJobResult> {
        self.records.get(idempotency_key_digest)
    }
}

/// Mission consumer scoped to one exact Modal registration fence.
#[derive(Clone, Debug)]
pub struct MissionModalJobConsumer {
    scope: ModalScope,
}

impl MissionModalJobConsumer {
    pub fn new(scope: ModalScope) -> Self {
        Self { scope }
    }

    pub fn scope(&self) -> &ModalScope {
        &self.scope
    }

    pub fn compile_proposal(
        &self,
        projection: &FunctionCallProjection,
        idempotency_key: &str,
    ) -> Result<JobResultProposal> {
        self.compile_proposal_at_revision(projection, idempotency_key, self.scope.mission.revision)
    }

    pub fn compile_proposal_at_revision(
        &self,
        projection: &FunctionCallProjection,
        idempotency_key: &str,
        current_mission_revision: u64,
    ) -> Result<JobResultProposal> {
        if current_mission_revision != self.scope.mission.revision {
            return Err(ModalJobResultError::StaleMissionRevision);
        }
        JobResultProposal::new(&self.scope, projection, idempotency_key)
    }

    pub fn record(
        &self,
        proposal: &JobResultProposal,
        log: &mut ModalJobResultRecordingLog,
    ) -> Result<RecordedModalJobResult> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_id != self.scope.mission.id
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.project_id != self.scope.project.id
            || proposal.project_revision != self.scope.project.revision
            || proposal.work_product_id != self.scope.work_product.id
            || proposal.work_product_revision != self.scope.work_product.revision
        {
            return Err(ModalJobResultError::ScopeMismatch);
        }
        if let Some(existing) = log.records.get(&proposal.idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ModalJobResultError::ReplayConflict);
            }
            return Ok(RecordedModalJobResult::from_proposal(proposal, true));
        }
        let recorded = RecordedModalJobResult::from_proposal(proposal, false);
        log.records
            .insert(proposal.idempotency_key_digest.clone(), recorded.clone());
        Ok(recorded)
    }

    pub fn record_with_key(
        &self,
        proposal: &JobResultProposal,
        idempotency_key: &str,
        log: &mut ModalJobResultRecordingLog,
    ) -> Result<RecordedModalJobResult> {
        validate_text(
            idempotency_key,
            "idempotencyKey",
            crate::MAX_IDENTIFIER_BYTES,
        )?;
        if proposal.idempotency_key_digest != Digest::from_text(idempotency_key) {
            return Err(ModalJobResultError::ReplayConflict);
        }
        self.record(proposal, log)
    }
}
