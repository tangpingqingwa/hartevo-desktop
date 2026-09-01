use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ContextAssemblyId, ContextBranchId, ContextCapsuleId, ContextCheckpointId, ContextWorkspaceId,
    MissionId, ProjectId, RuntimeRecoveryAttemptId, RuntimeTurnAttemptId, TenantId, WorkerId,
    WorkerLeaseId,
};

const MAX_TURN_EVIDENCE: usize = 4096;
const MAX_TURN_FAILURES: usize = 32;
const MAX_PRIVATE_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const LEGACY_AGENT_MESSAGE_ITEM_DIGEST: &str =
    "b907287bacf5470d3b3c410ae6e7934f19ee7e0640b289fc41922a441bb88d5b";

/// Why one managed Runtime turn exists. Auxiliary compaction remains part of
/// the recoverable Runtime ledger but can never become a Mission draft.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnPurpose {
    #[default]
    Agent,
    Compaction,
}

impl RuntimeTurnPurpose {
    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "serde skip_serializing_if predicates receive references"
    )]
    fn is_agent(&self) -> bool {
        *self == Self::Agent
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnScope {
    #[serde(default, skip_serializing_if = "RuntimeTurnPurpose::is_agent")]
    pub purpose: RuntimeTurnPurpose,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: ContextWorkspaceId,
    pub capsule_id: ContextCapsuleId,
    pub capsule_revision: u64,
    pub capsule_authority_digest: String,
    pub branch_id: ContextBranchId,
    pub branch_revision: u64,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub worker_lease_id: WorkerLeaseId,
    pub worker_lease_revision: u64,
    pub attachment_epoch: u64,
    pub assembly_id: ContextAssemblyId,
    pub assembly_revision: u64,
    pub assembly_manifest_digest: String,
    pub assembly_input_digest: String,
    pub prompt_digest: String,
    pub checkpoint_id: ContextCheckpointId,
    pub checkpoint_digest: String,
    pub recovery_id: RuntimeRecoveryAttemptId,
    pub recovery_revision: u64,
    pub runtime_instance_digest: String,
    pub runtime_mapping_digest: String,
    pub runtime_thread_id: String,
    pub runtime_thread_id_digest: String,
}

impl RuntimeTurnScope {
    pub fn validate(&self) -> Result<(), RuntimeTurnError> {
        if self.capsule_revision == 0
            || self.branch_revision == 0
            || self.worker_generation == 0
            || self.worker_lease_revision == 0
            || self.attachment_epoch == 0
            || self.assembly_revision == 0
            || self.recovery_revision == 0
            || !is_identifier(&self.runtime_thread_id)
            || !is_digest(&self.capsule_authority_digest)
            || !is_digest(&self.assembly_manifest_digest)
            || !is_digest(&self.assembly_input_digest)
            || !is_digest(&self.prompt_digest)
            || !is_digest(&self.checkpoint_digest)
            || !is_digest(&self.runtime_instance_digest)
            || !is_digest(&self.runtime_mapping_digest)
            || !is_digest(&self.runtime_thread_id_digest)
            || sha256(self.runtime_thread_id.as_bytes()) != self.runtime_thread_id_digest
        {
            return Err(RuntimeTurnError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, RuntimeTurnError> {
        self.validate()?;
        digest_json(self)
    }
}

impl fmt::Debug for RuntimeTurnScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTurnScope")
            .field("purpose", &self.purpose)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("capsule_id", &self.capsule_id)
            .field("capsule_revision", &self.capsule_revision)
            .field("branch_id", &self.branch_id)
            .field("branch_revision", &self.branch_revision)
            .field("worker_id", &self.worker_id)
            .field("worker_generation", &self.worker_generation)
            .field("worker_lease_id", &self.worker_lease_id)
            .field("worker_lease_revision", &self.worker_lease_revision)
            .field("attachment_epoch", &self.attachment_epoch)
            .field("assembly_id", &self.assembly_id)
            .field("assembly_revision", &self.assembly_revision)
            .field("checkpoint_id", &self.checkpoint_id)
            .field("recovery_id", &self.recovery_id)
            .field("recovery_revision", &self.recovery_revision)
            .field("runtime_instance_digest", &self.runtime_instance_digest)
            .field("runtime_mapping_digest", &self.runtime_mapping_digest)
            .field("runtime_thread_id_digest", &self.runtime_thread_id_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnStatus {
    Prepared,
    Dispatching,
    Running,
    WaitingLocalApproval,
    ApprovalResponding,
    InterruptRequested,
    Completed,
    Interrupted,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTurnRestartDisposition {
    FailedBeforeDispatch,
    FrozenUncertain,
    AlreadySafe,
}

impl RuntimeTurnStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Interrupted | Self::Failed)
    }

    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Prepared
                | Self::Dispatching
                | Self::Running
                | Self::WaitingLocalApproval
                | Self::ApprovalResponding
                | Self::InterruptRequested
                | Self::Uncertain
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnFailureClass {
    DispatchRejected,
    DispatchNotSent,
    DispatchUncertain,
    Protocol,
    RuntimeExited,
    EventStream,
    ApprovalResponseUncertain,
    InterruptUncertain,
    RuntimeReportedFailure,
    CoordinatorRestart,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTurnEvidenceKind {
    Prepared,
    DispatchStarted,
    DispatchAccepted,
    TurnStarted,
    ItemStarted,
    AgentMessageDelta,
    ItemCompleted,
    Diagnostic,
    LocalApprovalRequested,
    LocalApprovalResponseStarted,
    LocalApprovalResponseSent,
    InterruptRequested,
    InterruptAccepted,
    Completed,
    Interrupted,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTurnObservedKind {
    TurnStarted,
    ItemStarted,
    AgentMessageDelta,
    ItemCompleted,
    Diagnostic,
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnEvidence {
    pub sequence: u64,
    pub kind: RuntimeTurnEvidenceKind,
    pub evidence_digest: String,
    pub resulting_status: RuntimeTurnStatus,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnFailure {
    pub class: RuntimeTurnFailureClass,
    pub evidence_digest: String,
    pub recorded_at: DateTime<Utc>,
}

/// One private assistant message observed during a Runtime turn.
///
/// The body is intentionally kept out of `RuntimeTurnAttempt`, Domain Events,
/// and Outbox payloads. SQLCipher persistence binds it to the exact durable
/// evidence transition that carried the message so a coordinator crash after
/// turn completion cannot silently discard a user's draft.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnPrivateMessage {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub runtime_turn_attempt_id: RuntimeTurnAttemptId,
    pub evidence_sequence: u64,
    pub worker_generation: u64,
    pub item_id_digest: String,
    pub body: String,
    pub body_digest: String,
    pub event_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for RuntimeTurnPrivateMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTurnPrivateMessage")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("runtime_turn_attempt_id", &self.runtime_turn_attempt_id)
            .field("evidence_sequence", &self.evidence_sequence)
            .field("worker_generation", &self.worker_generation)
            .field("item_id_digest", &self.item_id_digest)
            .field("body_digest", &self.body_digest)
            .field("event_digest", &self.event_digest)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

impl RuntimeTurnPrivateMessage {
    pub fn capture(
        attempt: &RuntimeTurnAttempt,
        body: impl Into<String>,
    ) -> Result<Self, RuntimeTurnError> {
        Self::capture_for_item(attempt, LEGACY_AGENT_MESSAGE_ITEM_DIGEST.to_owned(), body)
    }

    pub fn capture_for_item(
        attempt: &RuntimeTurnAttempt,
        item_id_digest: String,
        body: impl Into<String>,
    ) -> Result<Self, RuntimeTurnError> {
        let body = body.into();
        let evidence = attempt
            .evidence
            .last()
            .ok_or(RuntimeTurnError::InvalidPrivateMessage)?;
        let message = Self {
            tenant_id: attempt.scope.tenant_id.clone(),
            project_id: attempt.scope.project_id.clone(),
            mission_id: attempt.scope.mission_id.clone(),
            runtime_turn_attempt_id: attempt.id.clone(),
            evidence_sequence: evidence.sequence,
            worker_generation: attempt.scope.worker_generation,
            item_id_digest,
            body_digest: sha256(body.as_bytes()),
            body,
            event_digest: evidence.evidence_digest.clone(),
            observed_at: evidence.observed_at,
        };
        message.validate_for(attempt)?;
        Ok(message)
    }

    pub fn validate_for(&self, attempt: &RuntimeTurnAttempt) -> Result<(), RuntimeTurnError> {
        let evidence = attempt
            .evidence
            .iter()
            .find(|evidence| evidence.sequence == self.evidence_sequence)
            .ok_or(RuntimeTurnError::InvalidPrivateMessage)?;
        if self.tenant_id != attempt.scope.tenant_id
            || self.project_id != attempt.scope.project_id
            || self.mission_id != attempt.scope.mission_id
            || self.runtime_turn_attempt_id != attempt.id
            || self.worker_generation != attempt.scope.worker_generation
            || evidence.kind != RuntimeTurnEvidenceKind::ItemCompleted
            || !is_digest(&self.item_id_digest)
            || self.body.trim().is_empty()
            || self.body.len() > MAX_PRIVATE_MESSAGE_BYTES
            || self.body_digest != sha256(self.body.as_bytes())
            || self.event_digest != evidence.evidence_digest
            || self.observed_at != evidence.observed_at
        {
            return Err(RuntimeTurnError::InvalidPrivateMessage);
        }
        Ok(())
    }
}

/// One encrypted assistant text increment, bound to the exact public evidence
/// transition that observed it. `chain_digest` makes omission, reordering, or
/// cross-item splicing detectable when a partial stream is replayed after a
/// coordinator or Desktop restart.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnPrivateTextDelta {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub runtime_turn_attempt_id: RuntimeTurnAttemptId,
    pub evidence_sequence: u64,
    pub stream_sequence: u64,
    pub worker_generation: u64,
    pub item_id_digest: String,
    pub delta: String,
    pub delta_digest: String,
    pub cumulative_byte_count: u64,
    pub chain_digest: String,
    pub event_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl fmt::Debug for RuntimeTurnPrivateTextDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTurnPrivateTextDelta")
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("runtime_turn_attempt_id", &self.runtime_turn_attempt_id)
            .field("evidence_sequence", &self.evidence_sequence)
            .field("stream_sequence", &self.stream_sequence)
            .field("worker_generation", &self.worker_generation)
            .field("item_id_digest", &self.item_id_digest)
            .field("delta_digest", &self.delta_digest)
            .field("cumulative_byte_count", &self.cumulative_byte_count)
            .field("chain_digest", &self.chain_digest)
            .field("event_digest", &self.event_digest)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

impl RuntimeTurnPrivateTextDelta {
    pub fn capture(
        attempt: &RuntimeTurnAttempt,
        item_id_digest: String,
        delta: impl Into<String>,
        previous: Option<&Self>,
    ) -> Result<Self, RuntimeTurnError> {
        let delta = delta.into();
        let evidence = attempt
            .evidence
            .last()
            .ok_or(RuntimeTurnError::InvalidPrivateTextDelta)?;
        let delta_byte_count =
            u64::try_from(delta.len()).map_err(|_| RuntimeTurnError::InvalidPrivateTextDelta)?;
        let (stream_sequence, previous_chain_digest, previous_byte_count) =
            if let Some(previous) = previous {
                (
                    previous
                        .stream_sequence
                        .checked_add(1)
                        .ok_or(RuntimeTurnError::RevisionOverflow)?,
                    previous.chain_digest.as_str(),
                    previous.cumulative_byte_count,
                )
            } else {
                (1, "runtime-text-stream-v1", 0)
            };
        let cumulative_byte_count = previous_byte_count
            .checked_add(delta_byte_count)
            .ok_or(RuntimeTurnError::InvalidPrivateTextDelta)?;
        let delta_digest = sha256(delta.as_bytes());
        let chain_digest = private_text_delta_chain_digest(
            previous_chain_digest,
            &item_id_digest,
            stream_sequence,
            cumulative_byte_count,
            &delta_digest,
            evidence.sequence,
        );
        let record = Self {
            tenant_id: attempt.scope.tenant_id.clone(),
            project_id: attempt.scope.project_id.clone(),
            mission_id: attempt.scope.mission_id.clone(),
            runtime_turn_attempt_id: attempt.id.clone(),
            evidence_sequence: evidence.sequence,
            stream_sequence,
            worker_generation: attempt.scope.worker_generation,
            item_id_digest,
            delta,
            delta_digest,
            cumulative_byte_count,
            chain_digest,
            event_digest: evidence.evidence_digest.clone(),
            observed_at: evidence.observed_at,
        };
        record.validate_for(attempt, previous)?;
        Ok(record)
    }

    pub fn validate_for(
        &self,
        attempt: &RuntimeTurnAttempt,
        previous: Option<&Self>,
    ) -> Result<(), RuntimeTurnError> {
        let evidence = attempt
            .evidence
            .iter()
            .find(|evidence| evidence.sequence == self.evidence_sequence)
            .ok_or(RuntimeTurnError::InvalidPrivateTextDelta)?;
        let delta_byte_count = u64::try_from(self.delta.len())
            .map_err(|_| RuntimeTurnError::InvalidPrivateTextDelta)?;
        let (expected_sequence, previous_chain_digest, previous_byte_count) =
            if let Some(previous) = previous {
                if previous.tenant_id != self.tenant_id
                    || previous.project_id != self.project_id
                    || previous.mission_id != self.mission_id
                    || previous.runtime_turn_attempt_id != self.runtime_turn_attempt_id
                    || previous.worker_generation != self.worker_generation
                    || previous.item_id_digest != self.item_id_digest
                    || previous.evidence_sequence >= self.evidence_sequence
                {
                    return Err(RuntimeTurnError::InvalidPrivateTextDelta);
                }
                (
                    previous
                        .stream_sequence
                        .checked_add(1)
                        .ok_or(RuntimeTurnError::RevisionOverflow)?,
                    previous.chain_digest.as_str(),
                    previous.cumulative_byte_count,
                )
            } else {
                (1, "runtime-text-stream-v1", 0)
            };
        let expected_cumulative = previous_byte_count
            .checked_add(delta_byte_count)
            .ok_or(RuntimeTurnError::InvalidPrivateTextDelta)?;
        let expected_chain = private_text_delta_chain_digest(
            previous_chain_digest,
            &self.item_id_digest,
            self.stream_sequence,
            self.cumulative_byte_count,
            &self.delta_digest,
            self.evidence_sequence,
        );
        if self.tenant_id != attempt.scope.tenant_id
            || self.project_id != attempt.scope.project_id
            || self.mission_id != attempt.scope.mission_id
            || self.runtime_turn_attempt_id != attempt.id
            || self.worker_generation != attempt.scope.worker_generation
            || evidence.kind != RuntimeTurnEvidenceKind::AgentMessageDelta
            || self.stream_sequence != expected_sequence
            || self.delta.is_empty()
            || self.delta.len() > MAX_PRIVATE_MESSAGE_BYTES
            || !is_digest(&self.item_id_digest)
            || self.delta_digest != sha256(self.delta.as_bytes())
            || self.cumulative_byte_count != expected_cumulative
            || self.cumulative_byte_count
                > u64::try_from(MAX_PRIVATE_MESSAGE_BYTES).unwrap_or(u64::MAX)
            || self.chain_digest != expected_chain
            || self.event_digest != evidence.evidence_digest
            || self.observed_at != evidence.observed_at
        {
            return Err(RuntimeTurnError::InvalidPrivateTextDelta);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeTurnAttempt {
    pub id: RuntimeTurnAttemptId,
    pub scope: RuntimeTurnScope,
    pub runtime_turn_id: Option<String>,
    pub runtime_turn_id_digest: Option<String>,
    pub dispatch_request_digest: Option<String>,
    pub dispatch_response_digest: Option<String>,
    pub pending_approval_request_digest: Option<String>,
    pub approval_decision_digest: Option<String>,
    pub interrupt_request_digest: Option<String>,
    pub failures: Vec<RuntimeTurnFailure>,
    pub evidence: Vec<RuntimeTurnEvidence>,
    pub status: RuntimeTurnStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for RuntimeTurnAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTurnAttempt")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("runtime_turn_id_digest", &self.runtime_turn_id_digest)
            .field("dispatch_request_digest", &self.dispatch_request_digest)
            .field("dispatch_response_digest", &self.dispatch_response_digest)
            .field(
                "pending_approval_request_digest",
                &self.pending_approval_request_digest,
            )
            .field("approval_decision_digest", &self.approval_decision_digest)
            .field("interrupt_request_digest", &self.interrupt_request_digest)
            .field("failures", &self.failures)
            .field("evidence_count", &self.evidence.len())
            .field("status", &self.status)
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

impl RuntimeTurnAttempt {
    pub fn prepare(
        id: RuntimeTurnAttemptId,
        scope: RuntimeTurnScope,
        now: DateTime<Utc>,
    ) -> Result<Self, RuntimeTurnError> {
        scope.validate()?;
        let scope_digest = scope.digest()?;
        let mut attempt = Self {
            id,
            scope,
            runtime_turn_id: None,
            runtime_turn_id_digest: None,
            dispatch_request_digest: None,
            dispatch_response_digest: None,
            pending_approval_request_digest: None,
            approval_decision_digest: None,
            interrupt_request_digest: None,
            failures: Vec::new(),
            evidence: Vec::new(),
            status: RuntimeTurnStatus::Prepared,
            revision: 0,
            created_at: now,
            updated_at: now,
        };
        attempt.append_evidence(RuntimeTurnEvidenceKind::Prepared, scope_digest, now)?;
        attempt.validate()?;
        Ok(attempt)
    }

    pub fn begin_dispatch(&mut self, now: DateTime<Utc>) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::Prepared)?;
        self.status = RuntimeTurnStatus::Dispatching;
        let evidence = sha256(
            format!(
                "{}:{}:{}",
                self.scope.assembly_manifest_digest,
                self.scope.runtime_mapping_digest,
                self.revision + 1
            )
            .as_bytes(),
        );
        self.append_evidence(RuntimeTurnEvidenceKind::DispatchStarted, evidence, now)
    }

    /// Closes a prepared attempt when the coordinator can prove that no
    /// Runtime request was sent (for example, after a restart before the
    /// durable dispatch permit existed).
    pub fn fail_without_dispatch(
        &mut self,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::Prepared)?;
        self.record_failure(
            RuntimeTurnFailureClass::DispatchNotSent,
            evidence_digest.clone(),
            now,
        )?;
        self.status = RuntimeTurnStatus::Failed;
        self.append_evidence(RuntimeTurnEvidenceKind::Failed, evidence_digest, now)
    }

    pub fn accept_dispatch(
        &mut self,
        runtime_turn_id: String,
        request_digest: String,
        response_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::Dispatching)?;
        if !is_identifier(&runtime_turn_id)
            || !is_digest(&request_digest)
            || !is_digest(&response_digest)
        {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.runtime_turn_id_digest = Some(sha256(runtime_turn_id.as_bytes()));
        self.runtime_turn_id = Some(runtime_turn_id);
        self.dispatch_request_digest = Some(request_digest);
        self.dispatch_response_digest = Some(response_digest.clone());
        self.status = RuntimeTurnStatus::Running;
        self.append_evidence(
            RuntimeTurnEvidenceKind::DispatchAccepted,
            response_digest,
            now,
        )
    }

    pub fn fail_dispatch(
        &mut self,
        class: RuntimeTurnFailureClass,
        evidence_digest: String,
        definitive: bool,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::Dispatching)?;
        self.record_failure(class, evidence_digest.clone(), now)?;
        self.status = if definitive {
            RuntimeTurnStatus::Failed
        } else {
            RuntimeTurnStatus::Uncertain
        };
        self.append_evidence(
            if definitive {
                RuntimeTurnEvidenceKind::Failed
            } else {
                RuntimeTurnEvidenceKind::Uncertain
            },
            evidence_digest,
            now,
        )
    }

    pub fn observe(
        &mut self,
        kind: RuntimeTurnObservedKind,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        if !is_digest(&evidence_digest) {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        let active_with_identity = self.runtime_turn_id.is_some()
            && matches!(
                self.status,
                RuntimeTurnStatus::Running
                    | RuntimeTurnStatus::WaitingLocalApproval
                    | RuntimeTurnStatus::InterruptRequested
                    | RuntimeTurnStatus::Uncertain
            );
        if !active_with_identity {
            return Err(RuntimeTurnError::InvalidTransition);
        }
        let evidence_kind = match kind {
            RuntimeTurnObservedKind::TurnStarted => RuntimeTurnEvidenceKind::TurnStarted,
            RuntimeTurnObservedKind::ItemStarted => RuntimeTurnEvidenceKind::ItemStarted,
            RuntimeTurnObservedKind::AgentMessageDelta => {
                RuntimeTurnEvidenceKind::AgentMessageDelta
            }
            RuntimeTurnObservedKind::ItemCompleted => RuntimeTurnEvidenceKind::ItemCompleted,
            RuntimeTurnObservedKind::Diagnostic => RuntimeTurnEvidenceKind::Diagnostic,
            RuntimeTurnObservedKind::Completed => {
                self.status = RuntimeTurnStatus::Completed;
                self.pending_approval_request_digest = None;
                RuntimeTurnEvidenceKind::Completed
            }
            RuntimeTurnObservedKind::Interrupted => {
                self.status = RuntimeTurnStatus::Interrupted;
                self.pending_approval_request_digest = None;
                RuntimeTurnEvidenceKind::Interrupted
            }
            RuntimeTurnObservedKind::Failed => {
                self.record_failure(
                    RuntimeTurnFailureClass::RuntimeReportedFailure,
                    evidence_digest.clone(),
                    now,
                )?;
                self.status = RuntimeTurnStatus::Failed;
                self.pending_approval_request_digest = None;
                RuntimeTurnEvidenceKind::Failed
            }
        };
        self.append_evidence(evidence_kind, evidence_digest, now)
    }

    pub fn request_local_approval(
        &mut self,
        request_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::Running)?;
        if !is_digest(&request_digest) || self.pending_approval_request_digest.is_some() {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.pending_approval_request_digest = Some(request_digest.clone());
        self.status = RuntimeTurnStatus::WaitingLocalApproval;
        self.append_evidence(
            RuntimeTurnEvidenceKind::LocalApprovalRequested,
            request_digest,
            now,
        )
    }

    pub fn begin_local_approval_response(
        &mut self,
        request_digest: &str,
        decision_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::WaitingLocalApproval)?;
        if self.pending_approval_request_digest.as_deref() != Some(request_digest)
            || !is_digest(&decision_digest)
        {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.approval_decision_digest = Some(decision_digest.clone());
        self.status = RuntimeTurnStatus::ApprovalResponding;
        self.append_evidence(
            RuntimeTurnEvidenceKind::LocalApprovalResponseStarted,
            decision_digest,
            now,
        )
    }

    pub fn finish_local_approval_response(
        &mut self,
        response_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::ApprovalResponding)?;
        if !is_digest(&response_digest) {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.pending_approval_request_digest = None;
        self.status = RuntimeTurnStatus::Running;
        self.append_evidence(
            RuntimeTurnEvidenceKind::LocalApprovalResponseSent,
            response_digest,
            now,
        )
    }

    pub fn begin_interrupt(&mut self, now: DateTime<Utc>) -> Result<(), RuntimeTurnError> {
        if !matches!(
            self.status,
            RuntimeTurnStatus::Running | RuntimeTurnStatus::WaitingLocalApproval
        ) {
            return Err(RuntimeTurnError::InvalidTransition);
        }
        self.pending_approval_request_digest = None;
        self.status = RuntimeTurnStatus::InterruptRequested;
        let evidence = sha256(format!("{}:interrupt:{}", self.id, self.revision + 1).as_bytes());
        self.append_evidence(RuntimeTurnEvidenceKind::InterruptRequested, evidence, now)
    }

    pub fn confirm_interrupt(
        &mut self,
        request_digest: String,
        response_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        self.require_status(RuntimeTurnStatus::InterruptRequested)?;
        if !is_digest(&request_digest) || !is_digest(&response_digest) {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.interrupt_request_digest = Some(request_digest);
        self.append_evidence(
            RuntimeTurnEvidenceKind::InterruptAccepted,
            response_digest,
            now,
        )
    }

    pub fn freeze_uncertain(
        &mut self,
        class: RuntimeTurnFailureClass,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        if !matches!(
            self.status,
            RuntimeTurnStatus::Running
                | RuntimeTurnStatus::WaitingLocalApproval
                | RuntimeTurnStatus::ApprovalResponding
                | RuntimeTurnStatus::InterruptRequested
                | RuntimeTurnStatus::Dispatching
        ) {
            return Err(RuntimeTurnError::InvalidTransition);
        }
        self.record_failure(class, evidence_digest.clone(), now)?;
        self.status = RuntimeTurnStatus::Uncertain;
        self.append_evidence(RuntimeTurnEvidenceKind::Uncertain, evidence_digest, now)
    }

    pub fn fence_after_coordinator_restart(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<RuntimeTurnRestartDisposition, RuntimeTurnError> {
        match self.status {
            RuntimeTurnStatus::Prepared => {
                self.fail_without_dispatch(
                    sha256(b"runtime-coordinator-restarted-before-dispatch-permit"),
                    now,
                )?;
                Ok(RuntimeTurnRestartDisposition::FailedBeforeDispatch)
            }
            RuntimeTurnStatus::Dispatching
            | RuntimeTurnStatus::Running
            | RuntimeTurnStatus::WaitingLocalApproval
            | RuntimeTurnStatus::ApprovalResponding
            | RuntimeTurnStatus::InterruptRequested => {
                self.freeze_uncertain(
                    RuntimeTurnFailureClass::CoordinatorRestart,
                    sha256(b"runtime-coordinator-restarted-with-live-or-ambiguous-turn"),
                    now,
                )?;
                Ok(RuntimeTurnRestartDisposition::FrozenUncertain)
            }
            RuntimeTurnStatus::Uncertain
            | RuntimeTurnStatus::Completed
            | RuntimeTurnStatus::Interrupted
            | RuntimeTurnStatus::Failed => Ok(RuntimeTurnRestartDisposition::AlreadySafe),
        }
    }

    pub fn validate(&self) -> Result<(), RuntimeTurnError> {
        self.scope.validate()?;
        if self.revision == 0
            || usize::try_from(self.revision).ok() != Some(self.evidence.len())
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_TURN_EVIDENCE
            || self.failures.len() > MAX_TURN_FAILURES
            || self.updated_at < self.created_at
            || self.evidence[0].sequence != 1
            || self.evidence[0].kind != RuntimeTurnEvidenceKind::Prepared
            || self.evidence[0].resulting_status != RuntimeTurnStatus::Prepared
            || self.evidence.last().map(|item| item.resulting_status) != Some(self.status)
        {
            return Err(RuntimeTurnError::InvalidAttempt);
        }
        for (index, evidence) in self.evidence.iter().enumerate() {
            if evidence.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX)
                || !is_digest(&evidence.evidence_digest)
                || evidence.observed_at < self.created_at
                || index > 0 && evidence.observed_at < self.evidence[index - 1].observed_at
                || index > 0
                    && !valid_status_transition(
                        self.evidence[index - 1].resulting_status,
                        evidence.resulting_status,
                        evidence.kind,
                    )
            {
                return Err(RuntimeTurnError::InvalidAttempt);
            }
        }
        if self
            .failures
            .iter()
            .any(|failure| !is_digest(&failure.evidence_digest))
        {
            return Err(RuntimeTurnError::InvalidAttempt);
        }
        match (&self.runtime_turn_id, &self.runtime_turn_id_digest) {
            (Some(turn_id), Some(turn_digest))
                if is_identifier(turn_id) && sha256(turn_id.as_bytes()) == *turn_digest => {}
            (None, None) => {}
            _ => return Err(RuntimeTurnError::InvalidAttempt),
        }
        let dispatch_evidence_present = self.dispatch_request_digest.is_some()
            && self.dispatch_response_digest.is_some()
            && self.runtime_turn_id.is_some();
        if self
            .dispatch_request_digest
            .as_ref()
            .is_some_and(|v| !is_digest(v))
            || self
                .dispatch_response_digest
                .as_ref()
                .is_some_and(|v| !is_digest(v))
            || self
                .pending_approval_request_digest
                .as_ref()
                .is_some_and(|v| !is_digest(v))
            || self
                .approval_decision_digest
                .as_ref()
                .is_some_and(|v| !is_digest(v))
            || self
                .interrupt_request_digest
                .as_ref()
                .is_some_and(|v| !is_digest(v))
            || matches!(
                self.status,
                RuntimeTurnStatus::Running
                    | RuntimeTurnStatus::WaitingLocalApproval
                    | RuntimeTurnStatus::ApprovalResponding
                    | RuntimeTurnStatus::InterruptRequested
                    | RuntimeTurnStatus::Completed
                    | RuntimeTurnStatus::Interrupted
            ) && !dispatch_evidence_present
            || self.status == RuntimeTurnStatus::Prepared && self.revision != 1
            || self.status == RuntimeTurnStatus::Dispatching && self.runtime_turn_id.is_some()
            || self.status == RuntimeTurnStatus::WaitingLocalApproval
                && self.pending_approval_request_digest.is_none()
            || self.status == RuntimeTurnStatus::ApprovalResponding
                && (self.pending_approval_request_digest.is_none()
                    || self.approval_decision_digest.is_none())
            || !matches!(
                self.status,
                RuntimeTurnStatus::WaitingLocalApproval | RuntimeTurnStatus::ApprovalResponding
            ) && self.pending_approval_request_digest.is_some()
        {
            return Err(RuntimeTurnError::InvalidAttempt);
        }
        Ok(())
    }

    pub fn validate_transition_from(
        &self,
        previous: &RuntimeTurnAttempt,
    ) -> Result<(), RuntimeTurnError> {
        self.validate()?;
        previous.validate()?;
        if self.id != previous.id
            || self.scope != previous.scope
            || self.created_at != previous.created_at
            || self.revision != previous.revision + 1
            || self.evidence.len() != previous.evidence.len() + 1
            || !self.evidence.starts_with(&previous.evidence)
            || self.failures.len() < previous.failures.len()
            || self.failures.len() > previous.failures.len() + 1
            || !self.failures.starts_with(&previous.failures)
            || previous
                .runtime_turn_id
                .as_ref()
                .is_some_and(|value| self.runtime_turn_id.as_ref() != Some(value))
            || previous
                .runtime_turn_id_digest
                .as_ref()
                .is_some_and(|value| self.runtime_turn_id_digest.as_ref() != Some(value))
            || previous
                .dispatch_request_digest
                .as_ref()
                .is_some_and(|value| self.dispatch_request_digest.as_ref() != Some(value))
            || previous
                .dispatch_response_digest
                .as_ref()
                .is_some_and(|value| self.dispatch_response_digest.as_ref() != Some(value))
            || previous
                .interrupt_request_digest
                .as_ref()
                .is_some_and(|value| self.interrupt_request_digest.as_ref() != Some(value))
            || !valid_status_transition(
                previous.status,
                self.status,
                self.evidence
                    .last()
                    .ok_or(RuntimeTurnError::InvalidTransition)?
                    .kind,
            )
        {
            return Err(RuntimeTurnError::InvalidTransition);
        }
        Ok(())
    }

    fn require_status(&self, expected: RuntimeTurnStatus) -> Result<(), RuntimeTurnError> {
        if self.status != expected {
            return Err(RuntimeTurnError::InvalidTransition);
        }
        Ok(())
    }

    fn record_failure(
        &mut self,
        class: RuntimeTurnFailureClass,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        if !is_digest(&evidence_digest) || self.failures.len() >= MAX_TURN_FAILURES {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        self.failures.push(RuntimeTurnFailure {
            class,
            evidence_digest,
            recorded_at: now,
        });
        Ok(())
    }

    fn append_evidence(
        &mut self,
        kind: RuntimeTurnEvidenceKind,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), RuntimeTurnError> {
        if !is_digest(&evidence_digest)
            || now < self.updated_at
            || self.evidence.len() >= MAX_TURN_EVIDENCE
        {
            return Err(RuntimeTurnError::InvalidEvidence);
        }
        let sequence = self
            .revision
            .checked_add(1)
            .ok_or(RuntimeTurnError::RevisionOverflow)?;
        self.evidence.push(RuntimeTurnEvidence {
            sequence,
            kind,
            evidence_digest,
            resulting_status: self.status,
            observed_at: now,
        });
        self.revision = sequence;
        self.updated_at = now;
        self.validate()
    }
}

fn valid_status_transition(
    previous: RuntimeTurnStatus,
    current: RuntimeTurnStatus,
    evidence: RuntimeTurnEvidenceKind,
) -> bool {
    match (previous, current, evidence) {
        (
            RuntimeTurnStatus::Prepared,
            RuntimeTurnStatus::Dispatching,
            RuntimeTurnEvidenceKind::DispatchStarted,
        )
        | (
            RuntimeTurnStatus::Prepared | RuntimeTurnStatus::Dispatching,
            RuntimeTurnStatus::Failed,
            RuntimeTurnEvidenceKind::Failed,
        )
        | (
            RuntimeTurnStatus::Dispatching,
            RuntimeTurnStatus::Running,
            RuntimeTurnEvidenceKind::DispatchAccepted,
        )
        | (
            RuntimeTurnStatus::Running,
            RuntimeTurnStatus::WaitingLocalApproval,
            RuntimeTurnEvidenceKind::LocalApprovalRequested,
        )
        | (
            RuntimeTurnStatus::WaitingLocalApproval,
            RuntimeTurnStatus::ApprovalResponding,
            RuntimeTurnEvidenceKind::LocalApprovalResponseStarted,
        )
        | (
            RuntimeTurnStatus::ApprovalResponding,
            RuntimeTurnStatus::Running,
            RuntimeTurnEvidenceKind::LocalApprovalResponseSent,
        )
        | (
            RuntimeTurnStatus::Running | RuntimeTurnStatus::WaitingLocalApproval,
            RuntimeTurnStatus::InterruptRequested,
            RuntimeTurnEvidenceKind::InterruptRequested,
        )
        | (
            RuntimeTurnStatus::InterruptRequested,
            RuntimeTurnStatus::InterruptRequested,
            RuntimeTurnEvidenceKind::InterruptAccepted,
        ) => true,
        (previous, current, RuntimeTurnEvidenceKind::Uncertain) => {
            matches!(
                previous,
                RuntimeTurnStatus::Dispatching
                    | RuntimeTurnStatus::Running
                    | RuntimeTurnStatus::WaitingLocalApproval
                    | RuntimeTurnStatus::ApprovalResponding
                    | RuntimeTurnStatus::InterruptRequested
            ) && current == RuntimeTurnStatus::Uncertain
        }
        (previous, current, evidence) if previous == current => matches!(
            (current, evidence),
            (
                RuntimeTurnStatus::Running
                    | RuntimeTurnStatus::WaitingLocalApproval
                    | RuntimeTurnStatus::InterruptRequested
                    | RuntimeTurnStatus::Uncertain,
                RuntimeTurnEvidenceKind::TurnStarted
                    | RuntimeTurnEvidenceKind::ItemStarted
                    | RuntimeTurnEvidenceKind::AgentMessageDelta
                    | RuntimeTurnEvidenceKind::ItemCompleted
                    | RuntimeTurnEvidenceKind::Diagnostic
            )
        ),
        (previous, current, evidence) => {
            matches!(
                previous,
                RuntimeTurnStatus::Running
                    | RuntimeTurnStatus::WaitingLocalApproval
                    | RuntimeTurnStatus::InterruptRequested
                    | RuntimeTurnStatus::Uncertain
            ) && matches!(
                (current, evidence),
                (
                    RuntimeTurnStatus::Completed,
                    RuntimeTurnEvidenceKind::Completed
                ) | (
                    RuntimeTurnStatus::Interrupted,
                    RuntimeTurnEvidenceKind::Interrupted
                ) | (RuntimeTurnStatus::Failed, RuntimeTurnEvidenceKind::Failed)
            )
        }
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1024 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn private_text_delta_chain_digest(
    previous_chain_digest: &str,
    item_id_digest: &str,
    stream_sequence: u64,
    cumulative_byte_count: u64,
    delta_digest: &str,
    evidence_sequence: u64,
) -> String {
    sha256(
        format!(
            "{previous_chain_digest}:{item_id_digest}:{stream_sequence}:{cumulative_byte_count}:{delta_digest}:{evidence_sequence}"
        )
        .as_bytes(),
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn digest_json(value: &impl Serialize) -> Result<String, RuntimeTurnError> {
    let encoded = serde_json::to_vec(value).map_err(|_| RuntimeTurnError::Serialization)?;
    Ok(sha256(&encoded))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeTurnError {
    #[error("runtime turn scope is invalid")]
    InvalidScope,
    #[error("runtime turn evidence is invalid or exceeds its bound")]
    InvalidEvidence,
    #[error("runtime turn private message is invalid")]
    InvalidPrivateMessage,
    #[error("runtime turn private text delta is invalid")]
    InvalidPrivateTextDelta,
    #[error("runtime turn attempt is internally inconsistent")]
    InvalidAttempt,
    #[error("runtime turn transition is not permitted")]
    InvalidTransition,
    #[error("runtime turn revision overflow")]
    RevisionOverflow,
    #[error("runtime turn digest serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use proptest::prelude::*;

    fn digest(label: &str) -> String {
        sha256(label.as_bytes())
    }

    fn scope() -> RuntimeTurnScope {
        let thread = "runtime-thread-private";
        RuntimeTurnScope {
            purpose: RuntimeTurnPurpose::Agent,
            tenant_id: TenantId::from("tenant-runtime-turn"),
            project_id: ProjectId::from("project-runtime-turn"),
            mission_id: MissionId::from("mission-runtime-turn"),
            workspace_id: ContextWorkspaceId::from("workspace-runtime-turn"),
            capsule_id: ContextCapsuleId::from("capsule-runtime-turn"),
            capsule_revision: 2,
            capsule_authority_digest: digest("capsule-authority"),
            branch_id: ContextBranchId::from("branch-runtime-turn"),
            branch_revision: 3,
            worker_id: WorkerId::from("worker-runtime-turn"),
            worker_generation: 4,
            worker_lease_id: WorkerLeaseId::from("lease-runtime-turn"),
            worker_lease_revision: 5,
            attachment_epoch: 6,
            assembly_id: ContextAssemblyId::from("assembly-runtime-turn"),
            assembly_revision: 1,
            assembly_manifest_digest: digest("assembly-manifest"),
            assembly_input_digest: digest("assembly-input"),
            prompt_digest: digest("prompt"),
            checkpoint_id: ContextCheckpointId::from("checkpoint-runtime-turn"),
            checkpoint_digest: digest("checkpoint"),
            recovery_id: RuntimeRecoveryAttemptId::from("recovery-runtime-turn"),
            recovery_revision: 5,
            runtime_instance_digest: digest("runtime-instance"),
            runtime_mapping_digest: digest("runtime-mapping"),
            runtime_thread_id: thread.into(),
            runtime_thread_id_digest: sha256(thread.as_bytes()),
        }
    }

    #[test]
    fn legacy_runtime_scope_defaults_to_agent_and_compaction_changes_identity() {
        let agent = scope();
        let mut legacy = serde_json::to_value(&agent).expect("scope JSON");
        assert!(legacy.get("purpose").is_none());
        legacy
            .as_object_mut()
            .expect("scope object")
            .remove("purpose");
        let decoded: RuntimeTurnScope = serde_json::from_value(legacy).expect("legacy scope");
        assert_eq!(decoded.purpose, RuntimeTurnPurpose::Agent);
        assert_eq!(decoded.digest().unwrap(), agent.digest().unwrap());

        let mut compaction = agent;
        compaction.purpose = RuntimeTurnPurpose::Compaction;
        assert_eq!(
            serde_json::to_value(&compaction)
                .expect("compaction scope JSON")
                .get("purpose"),
            Some(&serde_json::json!("compaction"))
        );
        assert_ne!(compaction.digest().unwrap(), decoded.digest().unwrap());
    }

    #[test]
    fn dispatch_crash_is_frozen_uncertain_and_never_replays() {
        let now = Utc::now();
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-crash"),
            scope(),
            now,
        )
        .expect("prepare");
        attempt.begin_dispatch(now).expect("dispatch permit");
        attempt
            .freeze_uncertain(
                RuntimeTurnFailureClass::CoordinatorRestart,
                digest("coordinator-crash"),
                now + Duration::milliseconds(1),
            )
            .expect("freeze");
        assert_eq!(attempt.status, RuntimeTurnStatus::Uncertain);
        assert!(matches!(
            attempt.begin_dispatch(now + Duration::milliseconds(2)),
            Err(RuntimeTurnError::InvalidTransition)
        ));
        assert!(matches!(
            attempt.observe(
                RuntimeTurnObservedKind::Completed,
                digest("forged-completion-without-runtime-id"),
                now + Duration::milliseconds(2)
            ),
            Err(RuntimeTurnError::InvalidTransition)
        ));
    }

    #[test]
    fn undispatched_prepared_attempt_can_be_closed_definitively() {
        let now = Utc::now();
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-never-sent"),
            scope(),
            now,
        )
        .expect("prepare");
        attempt
            .fail_without_dispatch(digest("coordinator-restarted-before-permit"), now)
            .expect("definitive failure");
        assert_eq!(attempt.status, RuntimeTurnStatus::Failed);
        assert_eq!(
            attempt.failures[0].class,
            RuntimeTurnFailureClass::DispatchNotSent
        );
        assert!(attempt.validate().is_ok());
    }

    #[test]
    fn coordinator_restart_fails_unsent_freezes_ambiguous_and_is_idempotent_once_safe() {
        let now = Utc::now();
        let mut unsent = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-restart-unsent"),
            scope(),
            now,
        )
        .expect("prepare unsent");
        assert_eq!(
            unsent
                .fence_after_coordinator_restart(now + Duration::milliseconds(1))
                .expect("fence unsent"),
            RuntimeTurnRestartDisposition::FailedBeforeDispatch
        );
        assert_eq!(unsent.status, RuntimeTurnStatus::Failed);
        assert_eq!(
            unsent
                .fence_after_coordinator_restart(now + Duration::milliseconds(2))
                .expect("repeat terminal fence"),
            RuntimeTurnRestartDisposition::AlreadySafe
        );

        let mut ambiguous = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-restart-ambiguous"),
            scope(),
            now,
        )
        .expect("prepare ambiguous");
        ambiguous.begin_dispatch(now).expect("durable permit");
        ambiguous
            .accept_dispatch(
                "runtime-turn-restart-private".into(),
                digest("restart-request"),
                digest("restart-response"),
                now + Duration::milliseconds(1),
            )
            .expect("accepted before crash");
        assert_eq!(
            ambiguous
                .fence_after_coordinator_restart(now + Duration::milliseconds(2))
                .expect("freeze ambiguous"),
            RuntimeTurnRestartDisposition::FrozenUncertain
        );
        assert_eq!(ambiguous.status, RuntimeTurnStatus::Uncertain);
        let revision = ambiguous.revision;
        assert_eq!(
            ambiguous
                .fence_after_coordinator_restart(now + Duration::milliseconds(3))
                .expect("repeat uncertain fence"),
            RuntimeTurnRestartDisposition::AlreadySafe
        );
        assert_eq!(ambiguous.revision, revision);
    }

    #[test]
    fn approval_interrupt_and_terminal_notification_form_one_append_only_history() {
        let now = Utc::now();
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-lifecycle"),
            scope(),
            now,
        )
        .expect("prepare");
        attempt.begin_dispatch(now).expect("dispatch");
        attempt
            .accept_dispatch(
                "runtime-turn-private".into(),
                digest("dispatch-request"),
                digest("dispatch-response"),
                now + Duration::milliseconds(1),
            )
            .expect("accepted");
        attempt
            .request_local_approval(digest("approval-request"), now + Duration::milliseconds(2))
            .expect("approval requested");
        attempt
            .begin_local_approval_response(
                &digest("approval-request"),
                digest("approval-decision"),
                now + Duration::milliseconds(3),
            )
            .expect("approval responding");
        attempt
            .finish_local_approval_response(
                digest("approval-response"),
                now + Duration::milliseconds(4),
            )
            .expect("approval sent");
        attempt
            .begin_interrupt(now + Duration::milliseconds(5))
            .expect("interrupt");
        attempt
            .confirm_interrupt(
                digest("interrupt-request"),
                digest("interrupt-response"),
                now + Duration::milliseconds(6),
            )
            .expect("interrupt accepted");
        attempt
            .observe(
                RuntimeTurnObservedKind::Interrupted,
                digest("terminal-notification"),
                now + Duration::milliseconds(7),
            )
            .expect("terminal");
        assert_eq!(attempt.status, RuntimeTurnStatus::Interrupted);
        assert_eq!(
            usize::try_from(attempt.revision).expect("bounded evidence count"),
            attempt.evidence.len()
        );
        assert!(attempt.validate().is_ok());
        assert!(!format!("{attempt:?}").contains("runtime-turn-private"));
        assert!(!format!("{attempt:?}").contains("runtime-thread-private"));
    }

    #[test]
    fn private_message_is_bound_to_exact_turn_evidence_without_debug_body_leakage() {
        let now = Utc::now();
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-private-message"),
            scope(),
            now,
        )
        .expect("prepare");
        attempt.begin_dispatch(now).expect("dispatch");
        attempt
            .accept_dispatch(
                "runtime-turn-private-message".into(),
                digest("request"),
                digest("response"),
                now + Duration::milliseconds(1),
            )
            .expect("accept");
        attempt
            .observe(
                RuntimeTurnObservedKind::ItemCompleted,
                digest("assistant-message-event"),
                now + Duration::milliseconds(2),
            )
            .expect("message event");
        let body = "PRIVATE-RUNTIME-DRAFT::only SQLCipher may retain this";
        let message = RuntimeTurnPrivateMessage::capture(&attempt, body).expect("capture");
        assert!(message.validate_for(&attempt).is_ok());
        assert_eq!(message.evidence_sequence, attempt.revision);
        assert_eq!(message.event_digest, digest("assistant-message-event"));
        assert!(!format!("{message:?}").contains(body));

        let mut forged = message.clone();
        forged.event_digest = digest("different-event");
        assert_eq!(
            forged.validate_for(&attempt),
            Err(RuntimeTurnError::InvalidPrivateMessage)
        );
    }

    #[test]
    fn private_text_delta_chain_rejects_reordering_splicing_and_content_tamper() {
        let now = Utc::now();
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-private-delta"),
            scope(),
            now,
        )
        .expect("prepare");
        attempt.begin_dispatch(now).expect("dispatch");
        attempt
            .accept_dispatch(
                "runtime-turn-private-delta".into(),
                digest("request"),
                digest("response"),
                now + Duration::milliseconds(1),
            )
            .expect("accept");
        let item_id_digest = digest("assistant-item");
        attempt
            .observe(
                RuntimeTurnObservedKind::AgentMessageDelta,
                digest("delta-event-1"),
                now + Duration::milliseconds(2),
            )
            .expect("first delta event");
        let first = RuntimeTurnPrivateTextDelta::capture(
            &attempt,
            item_id_digest.clone(),
            "PRIVATE-",
            None,
        )
        .expect("first delta");
        attempt
            .observe(
                RuntimeTurnObservedKind::AgentMessageDelta,
                digest("delta-event-2"),
                now + Duration::milliseconds(3),
            )
            .expect("second delta event");
        let second =
            RuntimeTurnPrivateTextDelta::capture(&attempt, item_id_digest, "STREAM", Some(&first))
                .expect("second delta");
        assert_eq!(second.stream_sequence, 2);
        assert_eq!(second.cumulative_byte_count, 14);
        assert!(!format!("{first:?}{second:?}").contains("PRIVATE-STREAM"));

        let mut tampered = second.clone();
        tampered.delta.push('!');
        assert_eq!(
            tampered.validate_for(&attempt, Some(&first)),
            Err(RuntimeTurnError::InvalidPrivateTextDelta)
        );
        assert_eq!(
            second.validate_for(&attempt, None),
            Err(RuntimeTurnError::InvalidPrivateTextDelta)
        );
        let mut cross_item = first.clone();
        cross_item.item_id_digest = digest("different-item");
        assert_eq!(
            second.validate_for(&attempt, Some(&cross_item)),
            Err(RuntimeTurnError::InvalidPrivateTextDelta)
        );
    }

    proptest! {
        #[test]
        fn observed_item_sequences_remain_append_only_and_terminal_fenced(item_count in 0usize..128) {
            let now = Utc::now();
            let mut attempt = RuntimeTurnAttempt::prepare(
                RuntimeTurnAttemptId::from("turn-attempt-property"), scope(), now
            ).expect("prepare");
            attempt.begin_dispatch(now).expect("dispatch");
            attempt.accept_dispatch(
                "runtime-turn-property".into(),
                digest("request"),
                digest("response"),
                now + Duration::milliseconds(1),
            ).expect("accept");
            for index in 0..item_count {
                let previous = attempt.clone();
                attempt.observe(
                    if index % 2 == 0 { RuntimeTurnObservedKind::ItemStarted } else { RuntimeTurnObservedKind::ItemCompleted },
                    digest(&format!("item-{index}")),
                    now + Duration::milliseconds(i64::try_from(index + 2).expect("bounded")),
                ).expect("item");
                prop_assert!(attempt.validate_transition_from(&previous).is_ok());
            }
            attempt.observe(
                RuntimeTurnObservedKind::Completed,
                digest("terminal"),
                now + Duration::milliseconds(i64::try_from(item_count + 2).expect("bounded")),
            ).expect("complete");
            prop_assert!(attempt.status.is_terminal());
            prop_assert!(matches!(
                attempt.observe(
                    RuntimeTurnObservedKind::ItemCompleted,
                    digest("late-item"),
                    now + Duration::milliseconds(i64::try_from(item_count + 3).expect("bounded")),
                ),
                Err(RuntimeTurnError::InvalidTransition)
            ));
        }
    }
}
