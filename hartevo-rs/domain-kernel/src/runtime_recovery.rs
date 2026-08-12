use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContextCheckpoint, ContextError, ContextWorkspaceId, MissionId, ProjectId,
    RuntimeRecoveryAttemptId, TenantId, WorkerHandle, WorkerHandleStatus, WorkerId,
};

const MAX_PROCESS_ATTEMPTS: u32 = 16;
const MAX_RUNTIME_IDENTIFIER_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeResumeStrategy {
    StartNew,
    ResumeExisting,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRecoveryStatus {
    Prepared,
    Spawned,
    Healthy,
    ThreadBound,
    Attached,
    Failed,
}

impl RuntimeRecoveryStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Attached | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRecoveryFailureClass {
    CoordinatorRestart,
    Spawn,
    Health,
    ThreadStart,
    ThreadResume,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRecoveryFailure {
    pub process_attempt: u32,
    pub class: RuntimeRecoveryFailureClass,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRecoveryAttempt {
    pub id: RuntimeRecoveryAttemptId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: ContextWorkspaceId,
    pub worker_id: WorkerId,
    pub worker_generation: u64,
    pub source_attachment_epoch: u64,
    pub target_attachment_epoch: u64,
    pub source_mapping_digest: String,
    pub checkpoint_id: crate::ContextCheckpointId,
    pub checkpoint_digest: String,
    pub runtime_config_digest: String,
    pub initial_strategy: RuntimeResumeStrategy,
    pub requested_thread_id_digest: Option<String>,
    pub max_process_attempts: u32,
    pub process_attempt: u32,
    pub health_digest: Option<String>,
    pub runtime_instance_digest: Option<String>,
    pub runtime_thread_id: Option<String>,
    pub runtime_mapping_digest: Option<String>,
    pub failures: Vec<RuntimeRecoveryFailure>,
    pub status: RuntimeRecoveryStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for RuntimeRecoveryAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeRecoveryAttempt")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("worker_id", &self.worker_id)
            .field("worker_generation", &self.worker_generation)
            .field("source_attachment_epoch", &self.source_attachment_epoch)
            .field("target_attachment_epoch", &self.target_attachment_epoch)
            .field("source_mapping_digest", &self.source_mapping_digest)
            .field("checkpoint_id", &self.checkpoint_id)
            .field("checkpoint_digest", &self.checkpoint_digest)
            .field("runtime_config_digest", &self.runtime_config_digest)
            .field("initial_strategy", &self.initial_strategy)
            .field(
                "requested_thread_id_digest",
                &self.requested_thread_id_digest,
            )
            .field("max_process_attempts", &self.max_process_attempts)
            .field("process_attempt", &self.process_attempt)
            .field("health_digest", &self.health_digest)
            .field("runtime_instance_digest", &self.runtime_instance_digest)
            .field(
                "runtime_thread_id_digest",
                &self
                    .runtime_thread_id
                    .as_ref()
                    .map(|value| digest(value.as_bytes())),
            )
            .field("runtime_mapping_digest", &self.runtime_mapping_digest)
            .field("failures", &self.failures)
            .field("status", &self.status)
            .field("revision", &self.revision)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl RuntimeRecoveryAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        id: RuntimeRecoveryAttemptId,
        attached: &WorkerHandle,
        detached: &WorkerHandle,
        checkpoint: &ContextCheckpoint,
        runtime_config_digest: String,
        initial_strategy: RuntimeResumeStrategy,
        requested_thread_id: Option<&str>,
        max_process_attempts: u32,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        if attached.status != WorkerHandleStatus::Attached
            || detached.status != WorkerHandleStatus::Detached
            || !detached.follows(attached)?
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let source_mapping_digest = attached
            .runtime_mapping_digest
            .clone()
            .ok_or(ContextError::InvalidRuntimeRecovery)?;
        let target_attachment_epoch = attached
            .attachment_epoch
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        let requested_thread_id_digest = match (initial_strategy, requested_thread_id) {
            (RuntimeResumeStrategy::StartNew, None) => None,
            (RuntimeResumeStrategy::ResumeExisting, Some(thread_id))
                if is_runtime_identifier(thread_id) =>
            {
                Some(digest(thread_id.as_bytes()))
            }
            _ => return Err(ContextError::InvalidRuntimeRecovery),
        };
        let value = Self {
            id,
            tenant_id: detached.tenant_id.clone(),
            project_id: detached.project_id.clone(),
            mission_id: detached.mission_id.clone(),
            workspace_id: detached.workspace_id.clone(),
            worker_id: detached.worker_id.clone(),
            worker_generation: detached.generation,
            source_attachment_epoch: attached.attachment_epoch,
            target_attachment_epoch,
            source_mapping_digest,
            checkpoint_id: checkpoint.id.clone(),
            checkpoint_digest: checkpoint.digest()?,
            runtime_config_digest,
            initial_strategy,
            requested_thread_id_digest,
            max_process_attempts,
            process_attempt: 1,
            health_digest: None,
            runtime_instance_digest: None,
            runtime_thread_id: None,
            runtime_mapping_digest: None,
            failures: Vec::new(),
            status: RuntimeRecoveryStatus::Prepared,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_for(detached, checkpoint, now)?;
        Ok(value)
    }

    pub fn confirm_health(
        &mut self,
        health_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != RuntimeRecoveryStatus::Spawned
            || !is_sha256(&health_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.health_digest = Some(health_digest);
        self.status = RuntimeRecoveryStatus::Healthy;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn mark_spawned(
        &mut self,
        runtime_instance_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != RuntimeRecoveryStatus::Prepared
            || !is_sha256(&runtime_instance_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.runtime_instance_digest = Some(runtime_instance_digest);
        self.status = RuntimeRecoveryStatus::Spawned;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn bind_thread(
        &mut self,
        runtime_instance_digest: &str,
        runtime_thread_id: String,
        runtime_mapping_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != RuntimeRecoveryStatus::Healthy
            || self.runtime_instance_digest.as_deref() != Some(runtime_instance_digest)
            || !is_runtime_identifier(&runtime_thread_id)
            || !is_sha256(&runtime_mapping_digest)
            || now < self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.runtime_thread_id = Some(runtime_thread_id);
        self.runtime_mapping_digest = Some(runtime_mapping_digest);
        self.status = RuntimeRecoveryStatus::ThreadBound;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn mark_attached(
        &mut self,
        handle: &WorkerHandle,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status != RuntimeRecoveryStatus::ThreadBound
            || handle.status != WorkerHandleStatus::Attached
            || handle.attachment_epoch != self.target_attachment_epoch
            || handle.runtime_mapping_digest != self.runtime_mapping_digest
            || now < self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.status = RuntimeRecoveryStatus::Attached;
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn record_process_failure(
        &mut self,
        class: RuntimeRecoveryFailureClass,
        evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.status.is_terminal()
            || !is_sha256(&evidence_digest)
            || now < self.updated_at
            || self.failures.len() >= usize::try_from(self.max_process_attempts).unwrap_or(0)
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        let previous = self.clone();
        self.failures.push(RuntimeRecoveryFailure {
            process_attempt: self.process_attempt,
            class,
            evidence_digest,
            observed_at: now,
        });
        self.health_digest = None;
        self.runtime_instance_digest = None;
        self.runtime_thread_id = None;
        self.runtime_mapping_digest = None;
        if self.process_attempt < self.max_process_attempts {
            self.process_attempt = self
                .process_attempt
                .checked_add(1)
                .ok_or(ContextError::RevisionOverflow)?;
            self.status = RuntimeRecoveryStatus::Prepared;
        } else {
            self.status = RuntimeRecoveryStatus::Failed;
        }
        if let Err(error) = self.touch(now) {
            *self = previous;
            return Err(error);
        }
        Ok(())
    }

    /// Validates the immutable scope, retry ledger, lifecycle fields, and
    /// timestamps that are self-contained in this persisted record. This is
    /// deliberately independent of the *current* WorkerHandle so historical
    /// attempts remain verifiable after a later attachment generation moves
    /// the worker forward.
    pub fn validate_record(&self) -> Result<(), ContextError> {
        let target_epoch = self
            .source_attachment_epoch
            .checked_add(1)
            .ok_or(ContextError::InvalidRuntimeRecovery)?;
        let lifecycle_fields_match = match self.status {
            RuntimeRecoveryStatus::Prepared | RuntimeRecoveryStatus::Failed => {
                self.health_digest.is_none()
                    && self.runtime_instance_digest.is_none()
                    && self.runtime_thread_id.is_none()
                    && self.runtime_mapping_digest.is_none()
            }
            RuntimeRecoveryStatus::Spawned => {
                self.health_digest.is_none()
                    && self
                        .runtime_instance_digest
                        .as_ref()
                        .is_some_and(|value| is_sha256(value))
                    && self.runtime_thread_id.is_none()
                    && self.runtime_mapping_digest.is_none()
            }
            RuntimeRecoveryStatus::Healthy => {
                self.health_digest
                    .as_ref()
                    .is_some_and(|value| is_sha256(value))
                    && self
                        .runtime_instance_digest
                        .as_ref()
                        .is_some_and(|value| is_sha256(value))
                    && self.runtime_thread_id.is_none()
                    && self.runtime_mapping_digest.is_none()
            }
            RuntimeRecoveryStatus::ThreadBound | RuntimeRecoveryStatus::Attached => {
                self.health_digest
                    .as_ref()
                    .is_some_and(|value| is_sha256(value))
                    && self
                        .runtime_instance_digest
                        .as_ref()
                        .is_some_and(|value| is_sha256(value))
                    && self
                        .runtime_thread_id
                        .as_ref()
                        .is_some_and(|value| is_runtime_identifier(value))
                    && self
                        .runtime_mapping_digest
                        .as_ref()
                        .is_some_and(|value| is_sha256(value))
            }
        };
        let requested_thread_matches = match self.initial_strategy {
            RuntimeResumeStrategy::StartNew => self.requested_thread_id_digest.is_none(),
            RuntimeResumeStrategy::ResumeExisting => self
                .requested_thread_id_digest
                .as_ref()
                .is_some_and(|value| is_sha256(value)),
        };
        let failure_sequence_matches = self.failures.iter().enumerate().all(|(index, failure)| {
            failure.process_attempt == u32::try_from(index).unwrap_or(u32::MAX) + 1
                && is_sha256(&failure.evidence_digest)
                && failure.observed_at >= self.created_at
                && failure.observed_at <= self.updated_at
        });
        let process_attempt_matches = if self.status == RuntimeRecoveryStatus::Failed {
            self.process_attempt == self.max_process_attempts
                && self.failures.len()
                    == usize::try_from(self.max_process_attempts).unwrap_or(usize::MAX)
        } else {
            usize::try_from(self.process_attempt).ok() == self.failures.len().checked_add(1)
        };
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.workspace_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || self.worker_generation == 0
            || self.source_attachment_epoch == 0
            || self.target_attachment_epoch != target_epoch
            || !is_sha256(&self.source_mapping_digest)
            || self.checkpoint_id.as_str().trim().is_empty()
            || !is_sha256(&self.checkpoint_digest)
            || !is_sha256(&self.runtime_config_digest)
            || !requested_thread_matches
            || !(1..=MAX_PROCESS_ATTEMPTS).contains(&self.max_process_attempts)
            || self.process_attempt == 0
            || !process_attempt_matches
            || !failure_sequence_matches
            || !lifecycle_fields_match
            || self.revision == 0
            || self.created_at > self.updated_at
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the recovery validator keeps checkpoint, handle, retry, and lifecycle fences in one fail-closed predicate"
    )]
    pub fn validate_for(
        &self,
        handle: &WorkerHandle,
        checkpoint: &ContextCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        self.validate_record()?;
        let handle_state_matches = match self.status {
            RuntimeRecoveryStatus::Attached => {
                handle.status == WorkerHandleStatus::Attached
                    && handle.attachment_epoch == self.target_attachment_epoch
                    && handle.runtime_mapping_digest == self.runtime_mapping_digest
            }
            RuntimeRecoveryStatus::Prepared
            | RuntimeRecoveryStatus::Spawned
            | RuntimeRecoveryStatus::Healthy
            | RuntimeRecoveryStatus::ThreadBound
            | RuntimeRecoveryStatus::Failed => {
                handle.status == WorkerHandleStatus::Detached
                    && handle.attachment_epoch == self.source_attachment_epoch
                    && handle.runtime_mapping_digest.is_none()
            }
        };
        if self.tenant_id != handle.tenant_id
            || self.project_id != handle.project_id
            || self.mission_id != handle.mission_id
            || self.workspace_id != handle.workspace_id
            || self.worker_id != handle.worker_id
            || self.worker_generation != handle.generation
            || self.checkpoint_id != checkpoint.id
            || self.checkpoint_digest != checkpoint.digest()?
            || checkpoint.tenant_id != self.tenant_id
            || checkpoint.project_id != self.project_id
            || checkpoint.mission_id != self.mission_id
            || checkpoint.workspace_id != self.workspace_id
            || checkpoint.generation != self.worker_generation
            || !handle_state_matches
            || self.updated_at > now
        {
            return Err(ContextError::InvalidRuntimeRecovery);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        let immutable = self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.workspace_id == previous.workspace_id
            && self.worker_id == previous.worker_id
            && self.worker_generation == previous.worker_generation
            && self.source_attachment_epoch == previous.source_attachment_epoch
            && self.target_attachment_epoch == previous.target_attachment_epoch
            && self.source_mapping_digest == previous.source_mapping_digest
            && self.checkpoint_id == previous.checkpoint_id
            && self.checkpoint_digest == previous.checkpoint_digest
            && self.runtime_config_digest == previous.runtime_config_digest
            && self.initial_strategy == previous.initial_strategy
            && self.requested_thread_id_digest == previous.requested_thread_id_digest
            && self.max_process_attempts == previous.max_process_attempts
            && self.created_at == previous.created_at;
        let spawned = previous.status == RuntimeRecoveryStatus::Prepared
            && self.status == RuntimeRecoveryStatus::Spawned
            && self.process_attempt == previous.process_attempt
            && self.failures == previous.failures
            && self.health_digest.is_none()
            && self.runtime_instance_digest.is_some()
            && self.runtime_thread_id.is_none()
            && self.runtime_mapping_digest.is_none();
        let health = previous.status == RuntimeRecoveryStatus::Spawned
            && self.status == RuntimeRecoveryStatus::Healthy
            && self.process_attempt == previous.process_attempt
            && self.failures == previous.failures
            && self.health_digest.is_some()
            && self.runtime_instance_digest.is_some()
            && self.runtime_thread_id.is_none()
            && self.runtime_mapping_digest.is_none();
        let bound = previous.status == RuntimeRecoveryStatus::Healthy
            && self.status == RuntimeRecoveryStatus::ThreadBound
            && self.process_attempt == previous.process_attempt
            && self.failures == previous.failures
            && self.health_digest == previous.health_digest
            && self.runtime_instance_digest == previous.runtime_instance_digest
            && self.runtime_thread_id.is_some()
            && self.runtime_mapping_digest.is_some();
        let attached = previous.status == RuntimeRecoveryStatus::ThreadBound
            && self.status == RuntimeRecoveryStatus::Attached
            && self.process_attempt == previous.process_attempt
            && self.failures == previous.failures
            && self.health_digest == previous.health_digest
            && self.runtime_instance_digest == previous.runtime_instance_digest
            && self.runtime_thread_id == previous.runtime_thread_id
            && self.runtime_mapping_digest == previous.runtime_mapping_digest;
        let failed_process = !previous.status.is_terminal()
            && matches!(
                self.status,
                RuntimeRecoveryStatus::Prepared | RuntimeRecoveryStatus::Failed
            )
            && self.failures.len() == previous.failures.len() + 1
            && self.failures.starts_with(&previous.failures)
            && self
                .failures
                .last()
                .is_some_and(|failure| failure.process_attempt == previous.process_attempt)
            && self.health_digest.is_none()
            && self.runtime_instance_digest.is_none()
            && self.runtime_thread_id.is_none()
            && self.runtime_mapping_digest.is_none()
            && if self.status == RuntimeRecoveryStatus::Prepared {
                previous.process_attempt.checked_add(1) == Some(self.process_attempt)
            } else {
                self.process_attempt == previous.process_attempt
                    && self.process_attempt == self.max_process_attempts
            };
        Ok(immutable
            && (spawned || health || bound || attached || failed_process)
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at)
    }

    fn touch(&mut self, now: DateTime<Utc>) -> Result<(), ContextError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        Ok(())
    }
}

fn is_runtime_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RUNTIME_IDENTIFIER_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::TimeZone;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        ContextBranchId, ContextBudget, ContextCapsuleId, CurrencyCode, Money, WorkerLeaseId,
        WorkerUsage,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 15, 0, 0)
            .single()
            .expect("valid time")
    }

    fn prepared_attempt(max_process_attempts: u32) -> RuntimeRecoveryAttempt {
        RuntimeRecoveryAttempt {
            id: RuntimeRecoveryAttemptId::from("attempt-runtime-recovery-model"),
            tenant_id: TenantId::from("tenant-runtime-recovery-model"),
            project_id: ProjectId::from("project-runtime-recovery-model"),
            mission_id: MissionId::from("mission-runtime-recovery-model"),
            workspace_id: ContextWorkspaceId::from("workspace-runtime-recovery-model"),
            worker_id: WorkerId::from("worker-runtime-recovery-model"),
            worker_generation: 5,
            source_attachment_epoch: 1,
            target_attachment_epoch: 2,
            source_mapping_digest: "1".repeat(64),
            checkpoint_id: crate::ContextCheckpointId::from("checkpoint-runtime-recovery-model"),
            checkpoint_digest: "2".repeat(64),
            runtime_config_digest: "3".repeat(64),
            initial_strategy: RuntimeResumeStrategy::StartNew,
            requested_thread_id_digest: None,
            max_process_attempts,
            process_attempt: 1,
            health_digest: None,
            runtime_instance_digest: None,
            runtime_thread_id: None,
            runtime_mapping_digest: None,
            failures: Vec::new(),
            status: RuntimeRecoveryStatus::Prepared,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn attached_handle(mapping_digest: String) -> WorkerHandle {
        WorkerHandle {
            tenant_id: TenantId::from("tenant-runtime-recovery-model"),
            project_id: ProjectId::from("project-runtime-recovery-model"),
            mission_id: MissionId::from("mission-runtime-recovery-model"),
            workspace_id: ContextWorkspaceId::from("workspace-runtime-recovery-model"),
            branch_id: ContextBranchId::from("branch-runtime-recovery-model"),
            capsule_id: ContextCapsuleId::from("capsule-runtime-recovery-model"),
            lease_id: WorkerLeaseId::from("lease-runtime-recovery-model"),
            worker_id: WorkerId::from("worker-runtime-recovery-model"),
            parent_worker_id: None,
            generation: 5,
            attachment_epoch: 2,
            runtime_mapping_digest: Some(mapping_digest),
            capabilities: BTreeSet::from(["research.discover".into()]),
            budget: ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + chrono::Duration::hours(1),
                max_depth: 1,
                max_concurrency: 1,
            },
            usage: WorkerUsage {
                tokens: 0,
                cost: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                tool_calls: 0,
                runtime_millis: 0,
            },
            cursor: 0,
            status: WorkerHandleStatus::Attached,
            revision: 3,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[test]
    fn lifecycle_follows_only_the_durable_spawn_health_thread_attach_order() {
        let mut attempt = prepared_attempt(3);
        let before_spawn = attempt.clone();
        attempt.mark_spawned("4".repeat(64), now()).expect("spawn");
        assert!(attempt.follows(&before_spawn).expect("spawn follows"));
        let before_health = attempt.clone();
        attempt
            .confirm_health("5".repeat(64), now())
            .expect("health");
        assert!(attempt.follows(&before_health).expect("health follows"));
        let before_binding = attempt.clone();
        let private_thread = "private-runtime-thread-model";
        attempt
            .bind_thread(
                &"4".repeat(64),
                private_thread.into(),
                "6".repeat(64),
                now(),
            )
            .expect("bind thread");
        assert!(attempt.follows(&before_binding).expect("binding follows"));
        assert!(!format!("{attempt:?}").contains(private_thread));
        let before_attach = attempt.clone();
        attempt
            .mark_attached(&attached_handle("6".repeat(64)), now())
            .expect("attach");
        assert!(attempt.follows(&before_attach).expect("attach follows"));
        assert!(attempt.status.is_terminal());

        let mut forged = before_health;
        forged.runtime_thread_id = Some("forged-out-of-order-thread".into());
        forged.runtime_mapping_digest = Some("7".repeat(64));
        forged.status = RuntimeRecoveryStatus::ThreadBound;
        forged.revision += 1;
        assert!(!forged.follows(&before_spawn).expect("forged comparison"));
    }

    proptest! {
        #[test]
        fn retry_budget_is_exact_append_only_and_never_exceeds_sixteen(
            maximum in 1_u32..=16,
        ) {
            let mut attempt = prepared_attempt(maximum);
            for process_attempt in 1..=maximum {
                let previous = attempt.clone();
                attempt
                    .record_process_failure(
                        RuntimeRecoveryFailureClass::Health,
                        digest(format!("failure-{process_attempt}").as_bytes()),
                        now(),
                    )
                    .expect("failure within exact retry budget");
                prop_assert!(attempt.follows(&previous).expect("failure follows"));
                prop_assert!(attempt.failures.starts_with(&previous.failures));
                prop_assert_eq!(attempt.failures.len(), usize::try_from(process_attempt).expect("usize"));
                if process_attempt < maximum {
                    prop_assert_eq!(attempt.status, RuntimeRecoveryStatus::Prepared);
                    prop_assert_eq!(attempt.process_attempt, process_attempt + 1);
                } else {
                    prop_assert_eq!(attempt.status, RuntimeRecoveryStatus::Failed);
                    prop_assert_eq!(attempt.process_attempt, maximum);
                }
            }
            prop_assert!(attempt.status.is_terminal());
            prop_assert!(attempt
                .record_process_failure(
                    RuntimeRecoveryFailureClass::CoordinatorRestart,
                    "8".repeat(64),
                    now(),
                )
                .is_err());
        }
    }
}
