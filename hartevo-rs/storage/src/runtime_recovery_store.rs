use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ProjectId, RuntimeRecoveryAttempt, RuntimeRecoveryAttemptId, RuntimeRecoveryStatus,
    WorkerHandle, WorkerMailbox,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::context_collaboration_store::{
    project_worker_message_changes, update_worker_handle_row, update_worker_mailbox_row,
};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn begin_runtime_recovery(
        &mut self,
        detached_handle: &WorkerHandle,
        expected_handle_revision: u64,
        attempt: &RuntimeRecoveryAttempt,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() || attempt.revision != 1 {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_worker_handle(
            &detached_handle.project_id,
            &detached_handle.workspace_id,
            &detached_handle.worker_id,
        )?;
        if previous.revision != expected_handle_revision || !detached_handle.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_recovery_worker:{}", detached_handle.worker_id),
                expected_revision: expected_handle_revision,
            });
        }
        self.validate_worker_handle(detached_handle, now)?;
        let checkpoint =
            self.load_context_checkpoint(&attempt.project_id, &attempt.checkpoint_id)?;
        attempt.validate_for(detached_handle, &checkpoint, now)?;

        let transaction = self.connection.transaction()?;
        update_worker_handle_row(&transaction, detached_handle, expected_handle_revision)?;
        insert_runtime_recovery_attempt(&transaction, attempt)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            attempt.tenant_id.as_str(),
            attempt.project_id.as_str(),
            Some(attempt.mission_id.as_str()),
            "runtime_recovery",
            attempt.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: attempt.revision,
        })
    }

    pub fn update_runtime_recovery(
        &mut self,
        attempt: &RuntimeRecoveryAttempt,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_runtime_recovery(&attempt.project_id, &attempt.id)?;
        if previous.revision != expected_revision || !attempt.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_recovery:{}", attempt.id),
                expected_revision,
            });
        }
        let handle = self.load_worker_handle(
            &attempt.project_id,
            &attempt.workspace_id,
            &attempt.worker_id,
        )?;
        let checkpoint =
            self.load_context_checkpoint(&attempt.project_id, &attempt.checkpoint_id)?;
        attempt.validate_for(&handle, &checkpoint, now)?;

        let transaction = self.connection.transaction()?;
        update_runtime_recovery_attempt(&transaction, attempt, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            attempt.tenant_id.as_str(),
            attempt.project_id.as_str(),
            Some(attempt.mission_id.as_str()),
            "runtime_recovery",
            attempt.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: attempt.revision,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the final recovery commit binds handle, optional mailbox requeue, attempt, and audit CAS revisions"
    )]
    pub fn attach_worker_and_finish_runtime_recovery(
        &mut self,
        handle: &WorkerHandle,
        expected_handle_revision: u64,
        mailbox: &WorkerMailbox,
        expected_mailbox_revision: u64,
        attempt: &RuntimeRecoveryAttempt,
        expected_attempt_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() || attempt.status != RuntimeRecoveryStatus::Attached {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_handle =
            self.load_worker_handle(&handle.project_id, &handle.workspace_id, &handle.worker_id)?;
        let previous_mailbox = self.load_worker_mailbox(&mailbox.project_id, &mailbox.id)?;
        let previous_attempt = self.load_runtime_recovery(&attempt.project_id, &attempt.id)?;
        let mailbox_changed = *mailbox != previous_mailbox;
        let mailbox_transition_valid = if mailbox_changed {
            mailbox.follows(&previous_mailbox)?
        } else {
            true
        };
        if previous_handle.revision != expected_handle_revision
            || previous_mailbox.revision != expected_mailbox_revision
            || previous_attempt.revision != expected_attempt_revision
            || !handle.follows(&previous_handle)?
            || !mailbox_transition_valid
            || !attempt.follows(&previous_attempt)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_recovery_attach:{}", attempt.id),
                expected_revision: expected_attempt_revision,
            });
        }
        self.validate_worker_handle(handle, now)?;
        mailbox.validate_for(handle, now)?;
        let checkpoint =
            self.load_context_checkpoint(&attempt.project_id, &attempt.checkpoint_id)?;
        attempt.validate_for(handle, &checkpoint, now)?;

        let transaction = self.connection.transaction()?;
        update_worker_handle_row(&transaction, handle, expected_handle_revision)?;
        if mailbox_changed {
            update_worker_mailbox_row(&transaction, mailbox, expected_mailbox_revision)?;
            project_worker_message_changes(&transaction, &previous_mailbox, mailbox)?;
        }
        update_runtime_recovery_attempt(&transaction, attempt, expected_attempt_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            attempt.tenant_id.as_str(),
            attempt.project_id.as_str(),
            Some(attempt.mission_id.as_str()),
            "runtime_recovery",
            attempt.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: attempt.revision,
        })
    }

    pub fn load_runtime_recovery(
        &self,
        project_id: &ProjectId,
        id: &RuntimeRecoveryAttemptId,
    ) -> Result<RuntimeRecoveryAttempt, StorageError> {
        load_runtime_recovery_record(&self.connection, project_id, id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "runtime recovery",
                project_id: project_id.clone(),
                id: id.to_string(),
            }
        })
    }

    /// Returns every Runtime recovery attempt scoped to one Project. The
    /// Application layer subsequently validates each record against its exact
    /// persisted WorkerHandle and ContextCheckpoint before projecting it.
    pub fn list_runtime_recoveries(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<RuntimeRecoveryAttempt>, StorageError> {
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT id FROM runtime_recovery_attempts
                 WHERE project_id = ?1 ORDER BY updated_at, created_at, id",
            )?;
            statement
                .query_map(params![project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.load_runtime_recovery(project_id, &RuntimeRecoveryAttemptId::from_stable(id))
            })
            .collect()
    }

    pub fn load_active_runtime_recovery_for_worker(
        &self,
        project_id: &ProjectId,
        workspace_id: &hartevo_domain_kernel::ContextWorkspaceId,
        worker_id: &hartevo_domain_kernel::WorkerId,
    ) -> Result<Option<RuntimeRecoveryAttempt>, StorageError> {
        let id = self
            .connection
            .query_row(
                "SELECT id FROM runtime_recovery_attempts
                 WHERE project_id = ?1 AND workspace_id = ?2 AND worker_id = ?3
                   AND status NOT IN ('attached', 'failed')
                 ORDER BY updated_at DESC, revision DESC LIMIT 1",
                params![
                    project_id.as_str(),
                    workspace_id.as_str(),
                    worker_id.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        id.map(|id: String| {
            self.load_runtime_recovery(project_id, &RuntimeRecoveryAttemptId::from_stable(id))
        })
        .transpose()
    }
}

fn load_runtime_recovery_record(
    connection: &Connection,
    project_id: &ProjectId,
    id: &RuntimeRecoveryAttemptId,
) -> Result<Option<RuntimeRecoveryAttempt>, StorageError> {
    let projection = connection
        .query_row(
            "SELECT tenant_id, project_id, id, mission_id, workspace_id, worker_id,
                    worker_generation, source_attachment_epoch, target_attachment_epoch,
                    source_mapping_digest, checkpoint_id, checkpoint_digest,
                    runtime_config_digest, initial_strategy, requested_thread_id_digest,
                    max_process_attempts, process_attempt, health_digest,
                    runtime_instance_digest, runtime_thread_id_digest, runtime_mapping_digest,
                    failure_count, status, revision, created_at, updated_at, record_json
             FROM runtime_recovery_attempts
             WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), id.as_str()],
            |row| {
                (0..27)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
            },
        )
        .optional()?;
    let Some(projection) = projection else {
        return Ok(None);
    };
    let Some(rusqlite::types::Value::Text(record)) = projection.get(26) else {
        return Err(StorageError::DomainDecode(
            "runtime recovery encrypted record projection is invalid".into(),
        ));
    };
    let attempt: RuntimeRecoveryAttempt = serde_json::from_str(record)?;
    attempt.validate_record()?;
    if runtime_recovery_values(&attempt)? != projection {
        return Err(StorageError::DomainDecode(
            "runtime recovery normalized projection mismatch".into(),
        ));
    }
    Ok(Some(attempt))
}

fn insert_runtime_recovery_attempt(
    transaction: &Transaction<'_>,
    attempt: &RuntimeRecoveryAttempt,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_recovery_attempts
           (tenant_id, project_id, id, mission_id, workspace_id, worker_id,
            worker_generation, source_attachment_epoch, target_attachment_epoch,
            source_mapping_digest, checkpoint_id, checkpoint_digest,
            runtime_config_digest, initial_strategy, requested_thread_id_digest,
            max_process_attempts, process_attempt, health_digest,
            runtime_instance_digest, runtime_thread_id_digest, runtime_mapping_digest,
            failure_count, status, revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24,
                 ?25, ?26, ?27)",
        runtime_recovery_params(attempt)?,
    )?;
    Ok(())
}

pub(crate) fn update_runtime_recovery_attempt(
    transaction: &Transaction<'_>,
    attempt: &RuntimeRecoveryAttempt,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE runtime_recovery_attempts
         SET process_attempt = ?1, health_digest = ?2, runtime_instance_digest = ?3,
             runtime_thread_id_digest = ?4, runtime_mapping_digest = ?5,
             failure_count = ?6, status = ?7, revision = ?8, updated_at = ?9,
             record_json = ?10
         WHERE project_id = ?11 AND id = ?12 AND revision = ?13",
        params![
            to_sql_u64(u64::from(attempt.process_attempt))?,
            attempt.health_digest,
            attempt.runtime_instance_digest,
            attempt
                .runtime_thread_id
                .as_ref()
                .map(|value| digest(value.as_bytes())),
            attempt.runtime_mapping_digest,
            to_sql_u64(
                u64::try_from(attempt.failures.len())
                    .map_err(|_| { StorageError::RevisionOverflow(u64::MAX) })?
            )?,
            json_enum(&attempt.status)?,
            to_sql_u64(attempt.revision)?,
            attempt.updated_at.to_rfc3339(),
            serde_json::to_string(attempt)?,
            attempt.project_id.as_str(),
            attempt.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "runtime_recovery",
        &attempt.id.to_string(),
        expected_revision,
    )
}

fn runtime_recovery_params(
    attempt: &RuntimeRecoveryAttempt,
) -> Result<rusqlite::ParamsFromIter<Vec<rusqlite::types::Value>>, StorageError> {
    Ok(rusqlite::params_from_iter(runtime_recovery_values(
        attempt,
    )?))
}

fn runtime_recovery_values(
    attempt: &RuntimeRecoveryAttempt,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    use rusqlite::types::Value;

    let values = vec![
        Value::Text(attempt.tenant_id.to_string()),
        Value::Text(attempt.project_id.to_string()),
        Value::Text(attempt.id.to_string()),
        Value::Text(attempt.mission_id.to_string()),
        Value::Text(attempt.workspace_id.to_string()),
        Value::Text(attempt.worker_id.to_string()),
        Value::Integer(to_sql_u64(attempt.worker_generation)?),
        Value::Integer(to_sql_u64(attempt.source_attachment_epoch)?),
        Value::Integer(to_sql_u64(attempt.target_attachment_epoch)?),
        Value::Text(attempt.source_mapping_digest.clone()),
        Value::Text(attempt.checkpoint_id.to_string()),
        Value::Text(attempt.checkpoint_digest.clone()),
        Value::Text(attempt.runtime_config_digest.clone()),
        Value::Text(json_enum(&attempt.initial_strategy)?),
        attempt
            .requested_thread_id_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        Value::Integer(to_sql_u64(u64::from(attempt.max_process_attempts))?),
        Value::Integer(to_sql_u64(u64::from(attempt.process_attempt))?),
        attempt
            .health_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        attempt
            .runtime_instance_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        attempt
            .runtime_thread_id
            .as_ref()
            .map(|value| digest(value.as_bytes()))
            .map_or(Value::Null, Value::Text),
        attempt
            .runtime_mapping_digest
            .clone()
            .map_or(Value::Null, Value::Text),
        Value::Integer(to_sql_u64(
            u64::try_from(attempt.failures.len())
                .map_err(|_| StorageError::RevisionOverflow(u64::MAX))?,
        )?),
        Value::Text(json_enum(&attempt.status)?),
        Value::Integer(to_sql_u64(attempt.revision)?),
        Value::Text(attempt.created_at.to_rfc3339()),
        Value::Text(attempt.updated_at.to_rfc3339()),
        Value::Text(serde_json::to_string(attempt)?),
    ];
    Ok(values)
}

pub(crate) fn require_one(
    changed: usize,
    aggregate: &str,
    id: &str,
    expected_revision: u64,
) -> Result<(), StorageError> {
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("{aggregate}:{id}"),
            expected_revision,
        });
    }
    Ok(())
}

pub(crate) fn json_enum(value: &impl serde::Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as string".into()))
}

pub(crate) fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ContextBranch, ContextBranchId, ContextBudget, ContextCapsule, ContextCapsuleId,
        ContextCheckpoint, ContextCheckpointId, ContextCompactionRecord, ContextCompactionRecordId,
        ContextContinuationLedgerId, ContextDataPolicy, ContextInputRefs, ContextMergePolicy,
        ContextReturnContract, ContextWorkerMailboxId, ContextWorkerMessageId,
        ContextWorkerMessageKind, ContextWorkerMessageStatus, ContextWorkingSet,
        ContextWorkingSetId, ContextWorkspace, ContextWorkspaceId, ContinuationLedger,
        CurrencyCode, Mission, MissionId, Money, OperatingContract, Project, RuntimeProcessClaim,
        RuntimeProcessCleanupDisposition, RuntimeProcessIdentity, RuntimeRecoveryFailureClass,
        RuntimeResumeStrategy, StorageMode, Task, TaskId, TaskStatus, TenantId, WorkerHandleStatus,
        WorkerId, WorkerLease, WorkerLeaseId, WorkerMailbox,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 14, 0, 0)
            .single()
            .expect("valid time")
    }

    struct RecoveryStoreFixture {
        store: ProjectStore,
        project: Project,
        mission: Mission,
        workspace: ContextWorkspace,
        checkpoint: ContextCheckpoint,
        attached: WorkerHandle,
        mailbox: WorkerMailbox,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture builds the exact persisted checkpoint, worker, capsule, and in-flight mailbox graph used by the transaction proof"
    )]
    fn fixture() -> RecoveryStoreFixture {
        let tenant_id = TenantId::from("tenant-runtime-recovery-store");
        let project = Project::create_local(
            tenant_id.clone(),
            ProjectId::from("project-runtime-recovery-store"),
            "Runtime recovery store",
            "",
            "/tmp/runtime-recovery-store",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut mission = Mission::compile(
            tenant_id,
            MissionId::from("mission-runtime-recovery-store"),
            project.id.clone(),
            "Runtime recovery store",
            OperatingContract::bootstrap(
                "Recover one bounded worker",
                ["research.discover".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let task_id = TaskId::from("task-runtime-recovery-store");
        mission
            .start_research(
                [Task {
                    id: task_id.clone(),
                    title: "Research".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("task");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-runtime-recovery-store"),
            &mission,
            3,
            "context-policy/v1",
            BTreeSet::from(["research.discover".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::days(1),
                max_depth: 2,
                max_concurrency: 1,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-runtime-recovery-store"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation-runtime-recovery-store"),
            &workspace,
            now(),
        )
        .expect("continuation");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-runtime-recovery-store"),
            &workspace,
            &mission,
            &[],
            None,
            1,
            10,
            "1".repeat(64),
            1_000,
            9,
            format!("cas://{}", "2".repeat(64)),
            "3".repeat(64),
            512,
            100,
            BTreeSet::new(),
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            now() + Duration::seconds(1),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-runtime-recovery-store"),
            &workspace,
            &mission,
            &[],
            &working_set,
            &continuation,
            &compaction,
            None,
            "7".repeat(64),
            "8".repeat(64),
            10,
            now() + Duration::seconds(2),
        )
        .expect("checkpoint");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-runtime-recovery-store"),
            &workspace,
            None,
            "bounded runtime",
            "9".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-runtime-recovery-store"),
            &workspace,
            &branch,
            WorkerId::from("worker-runtime-recovery-store"),
            workspace.generation,
            "a".repeat(64),
            Some("b".repeat(64)),
            now() + Duration::hours(2),
            now(),
        )
        .expect("lease");
        let mut capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-runtime-recovery-store"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Return one typed result",
            task_id,
            BTreeSet::new(),
            &[],
            BTreeSet::from(["research.discover".into()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::minutes(90),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.runtime-result".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["finding".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::hours(1),
            now(),
        )
        .expect("capsule");
        let attached = WorkerHandle::create(&workspace, &branch, &lease, &capsule, None, now())
            .expect("handle");
        let mut mailbox = WorkerMailbox::create(
            ContextWorkerMailboxId::from("mailbox-runtime-recovery-store"),
            &attached,
            2,
            now(),
        )
        .expect("mailbox");

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("persist project");
        store.save_mission(&mission).expect("persist mission");
        store
            .create_context_workspace(
                &workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.workspace_created",
                    serde_json::json!({"workspaceId": workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist workspace");
        store
            .append_context_compaction_checkpoint(
                &compaction,
                &checkpoint,
                &[PendingEvent::new(
                    "context.checkpoint_recorded",
                    serde_json::json!({"checkpointId": checkpoint.id}),
                    now() + Duration::seconds(2),
                )],
                now() + Duration::seconds(2),
            )
            .expect("persist checkpoint");
        store
            .issue_context_capsule_bundle(
                &workspace,
                std::slice::from_ref(&branch),
                &lease,
                &capsule,
                &attached,
                &mailbox,
                &[],
                &[PendingEvent::new(
                    "context.capsule_issued",
                    serde_json::json!({"capsuleId": capsule.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist worker graph");
        capsule
            .claim(workspace.generation, now() + Duration::seconds(3))
            .expect("claim capsule");
        store
            .update_context_capsule(
                &capsule,
                1,
                &[PendingEvent::new(
                    "context.capsule_claimed",
                    serde_json::json!({"capsuleId": capsule.id}),
                    now() + Duration::seconds(3),
                )],
                now() + Duration::seconds(3),
            )
            .expect("persist claim");
        let message = mailbox
            .enqueue(
                &attached,
                ContextWorkerMessageId::from("message-runtime-recovery-store"),
                None,
                ContextWorkerMessageKind::Steer,
                format!("cas://{}", "c".repeat(64)),
                "d".repeat(64),
                now() + Duration::seconds(4),
            )
            .expect("enqueue");
        store
            .update_worker_mailbox(
                &mailbox,
                1,
                &[PendingEvent::new(
                    "context.worker_message_enqueued",
                    serde_json::json!({"messageId": message.id}),
                    now() + Duration::seconds(4),
                )],
                now() + Duration::seconds(4),
            )
            .expect("persist enqueue");
        mailbox
            .claim_next(&attached, &capsule, 1, now() + Duration::seconds(5))
            .expect("claim mailbox message")
            .expect("message available");
        store
            .update_worker_mailbox(
                &mailbox,
                2,
                &[PendingEvent::new(
                    "context.worker_message_claimed",
                    serde_json::json!({"messageId": message.id}),
                    now() + Duration::seconds(5),
                )],
                now() + Duration::seconds(5),
            )
            .expect("persist in-flight message");

        RecoveryStoreFixture {
            store,
            project,
            mission,
            workspace,
            checkpoint,
            attached,
            mailbox,
        }
    }

    fn assert_failed_recovery_is_inactive_and_tamper_is_detected(
        store: &ProjectStore,
        project_id: &ProjectId,
        detached: &WorkerHandle,
        attempt: &RuntimeRecoveryAttempt,
    ) {
        assert!(
            store
                .load_active_runtime_recovery_for_worker(
                    project_id,
                    &detached.workspace_id,
                    &detached.worker_id,
                )
                .expect("active lookup")
                .is_none()
        );
        store
            .connection
            .execute(
                "UPDATE runtime_recovery_attempts SET status = 'prepared'
                 WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), attempt.id.as_str()],
            )
            .expect("tamper normalized recovery projection");
        assert!(matches!(
            store.load_runtime_recovery(project_id, &attempt.id),
            Err(StorageError::DomainDecode(message))
                if message == "runtime recovery normalized projection mismatch"
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the fault-injection test proves one complete private Claim/Recovery transaction, rollback, cleanup, redaction, and projection-tamper sequence"
    )]
    fn runtime_process_claim_and_recovery_spawn_are_atomic_private_and_tamper_evident() {
        let RecoveryStoreFixture {
            mut store,
            project,
            checkpoint,
            attached,
            ..
        } = fixture();
        let mut detached = attached.clone();
        detached
            .detach(attached.attachment_epoch, now() + Duration::seconds(6))
            .expect("detach");
        let mut recovery = RuntimeRecoveryAttempt::prepare(
            RuntimeRecoveryAttemptId::from("attempt-runtime-process-claim-store"),
            &attached,
            &detached,
            &checkpoint,
            "e".repeat(64),
            RuntimeResumeStrategy::StartNew,
            None,
            3,
            now() + Duration::seconds(6),
        )
        .expect("prepare recovery");
        store
            .begin_runtime_recovery(
                &detached,
                attached.revision,
                &recovery,
                &[PendingEvent::new(
                    "context.runtime_recovery_prepared",
                    serde_json::json!({"recoveryId": recovery.id}),
                    now() + Duration::seconds(6),
                )],
                now() + Duration::seconds(6),
            )
            .expect("persist recovery");
        let launch_token = "1".repeat(64);
        let launch_path = format!("/tmp/{}/interpreter", digest(launch_token.as_bytes()));
        let mut claim = RuntimeProcessClaim::prepare(
            &recovery,
            "2".repeat(64),
            launch_token.clone(),
            launch_path.clone(),
            digest(launch_path.as_bytes()),
            now() + Duration::seconds(7),
        )
        .expect("prepare process claim");
        store
            .prepare_runtime_process_claim(
                &claim,
                &[PendingEvent::new(
                    "context.runtime_process_launch_prepared",
                    serde_json::json!({
                        "runtimeRecoveryId": recovery.id,
                        "launchTokenDigest": claim.launch_token_digest,
                        "launchExecutablePathDigest": claim.launch_executable_path_digest,
                    }),
                    now() + Duration::seconds(7),
                )],
                now() + Duration::seconds(7),
            )
            .expect("persist claim");
        let expected_recovery_revision = recovery.revision;
        let expected_claim_revision = claim.revision;
        recovery
            .mark_spawned("3".repeat(64), now() + Duration::seconds(8))
            .expect("spawn recovery");
        claim
            .mark_spawned(
                RuntimeProcessIdentity {
                    process_id: 42,
                    started_at_epoch_seconds: 1_786_492_800,
                    executable_path_digest: "4".repeat(64),
                    runtime_instance_digest: "3".repeat(64),
                },
                now() + Duration::seconds(8),
            )
            .expect("spawn claim");
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER abort_runtime_process_claim_spawn
                 BEFORE UPDATE ON runtime_process_claims
                 BEGIN SELECT RAISE(ABORT, 'injected runtime process claim failure'); END;",
            )
            .expect("install trigger");
        assert!(
            store
                .mark_runtime_process_spawned(
                    &recovery,
                    expected_recovery_revision,
                    &claim,
                    expected_claim_revision,
                    &[PendingEvent::new(
                        "context.runtime_recovery_spawned",
                        serde_json::json!({"runtimeRecoveryId": recovery.id}),
                        now() + Duration::seconds(8),
                    )],
                    now() + Duration::seconds(8),
                )
                .is_err()
        );
        assert_eq!(
            store
                .load_runtime_recovery(&project.id, &recovery.id)
                .expect("rolled back recovery")
                .status,
            RuntimeRecoveryStatus::Prepared
        );
        assert_eq!(
            store
                .load_runtime_process_claim(&project.id, &recovery.id, 1)
                .expect("rolled back claim")
                .status,
            hartevo_domain_kernel::RuntimeProcessClaimStatus::Prepared
        );
        store
            .connection
            .execute_batch("DROP TRIGGER abort_runtime_process_claim_spawn;")
            .expect("drop trigger");
        store
            .mark_runtime_process_spawned(
                &recovery,
                expected_recovery_revision,
                &claim,
                expected_claim_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_spawned",
                    serde_json::json!({"runtimeRecoveryId": recovery.id}),
                    now() + Duration::seconds(8),
                )],
                now() + Duration::seconds(8),
            )
            .expect("atomic spawn");
        let spawned = store
            .load_runtime_process_claim(&project.id, &recovery.id, 1)
            .expect("spawned claim");
        assert_eq!(spawned, claim);
        assert!(!format!("{spawned:?}").contains(&launch_token));
        assert!(!format!("{spawned:?}").contains(&launch_path));

        let expected_revision = claim.revision;
        claim
            .record_cleanup(
                RuntimeProcessCleanupDisposition::AlreadyExited,
                "5".repeat(64),
                now() + Duration::seconds(9),
            )
            .expect("cleanup");
        store
            .update_runtime_process_claim(
                &claim,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_process_reconciled",
                    serde_json::json!({
                        "runtimeRecoveryId": recovery.id,
                        "cleanupEvidenceDigest": "5".repeat(64),
                    }),
                    now() + Duration::seconds(9),
                )],
                now() + Duration::seconds(9),
            )
            .expect("persist cleanup");
        assert!(
            store
                .list_active_runtime_process_claims()
                .expect("active claims")
                .is_empty()
        );
        let events = serde_json::to_string(
            &store
                .events_for_mission(&project.id, &recovery.mission_id)
                .expect("events"),
        )
        .expect("events json");
        assert!(!events.contains(&launch_token));
        assert!(!events.contains(&launch_path));

        store
            .connection
            .execute(
                "UPDATE runtime_process_claims SET launch_token_digest = ?1
                 WHERE project_id = ?2 AND recovery_id = ?3 AND process_attempt = 1",
                params!["6".repeat(64), project.id.as_str(), recovery.id.as_str()],
            )
            .expect("tamper projection");
        assert!(matches!(
            store.load_runtime_process_claim(&project.id, &recovery.id, 1),
            Err(StorageError::DomainDecode(message))
                if message == "runtime process claim normalized projection mismatch"
        ));
    }

    #[test]
    fn migration_v39_creates_runtime_process_claim_ledger_idempotently() {
        let RecoveryStoreFixture { mut store, .. } = fixture();
        crate::downgrade_identity_bootstrap_schema_for_test(&store.connection);
        store
            .connection
            .execute_batch(
                "DROP TABLE runtime_process_claims;
                 DELETE FROM schema_migrations WHERE version >= 39;",
            )
            .expect("construct v38 schema");
        store.migrate().expect("migrate v38 to v39");
        assert_eq!(
            store.schema_version().expect("schema"),
            crate::STORAGE_SCHEMA_VERSION
        );
        let table_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'runtime_process_claims'",
                [],
                |row| row.get(0),
            )
            .expect("runtime process claim table");
        assert_eq!(table_count, 1);
        store.migrate().expect("idempotent v39 migration");
        assert_eq!(
            store.schema_version().expect("schema replay"),
            crate::STORAGE_SCHEMA_VERSION
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the failure-injection proof keeps every pre-commit projection and post-rollback assertion in one atomic transaction narrative"
    )]
    fn final_runtime_attach_rolls_back_handle_mailbox_attempt_messages_and_event() {
        let RecoveryStoreFixture {
            mut store,
            project,
            mission,
            workspace,
            checkpoint,
            attached,
            mailbox,
        } = fixture();
        let mut detached = attached.clone();
        detached
            .detach(attached.attachment_epoch, now() + Duration::seconds(6))
            .expect("detach");
        let mut attempt = RuntimeRecoveryAttempt::prepare(
            RuntimeRecoveryAttemptId::from("attempt-runtime-recovery-store"),
            &attached,
            &detached,
            &checkpoint,
            "e".repeat(64),
            RuntimeResumeStrategy::StartNew,
            None,
            3,
            now() + Duration::seconds(6),
        )
        .expect("prepare recovery");
        store
            .begin_runtime_recovery(
                &detached,
                attached.revision,
                &attempt,
                &[PendingEvent::new(
                    "context.runtime_recovery_prepared",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(6),
                )],
                now() + Duration::seconds(6),
            )
            .expect("persist recovery start");
        let expected_revision = attempt.revision;
        attempt
            .mark_spawned("f".repeat(64), now() + Duration::seconds(7))
            .expect("spawned");
        store
            .update_runtime_recovery(
                &attempt,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_spawned",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(7),
                )],
                now() + Duration::seconds(7),
            )
            .expect("persist spawned");
        let expected_revision = attempt.revision;
        attempt
            .confirm_health("1".repeat(64), now() + Duration::seconds(8))
            .expect("healthy");
        store
            .update_runtime_recovery(
                &attempt,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_healthy",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(8),
                )],
                now() + Duration::seconds(8),
            )
            .expect("persist healthy");
        let expected_revision = attempt.revision;
        attempt
            .bind_thread(
                &"f".repeat(64),
                "private-thread-runtime-recovery-store".into(),
                "2".repeat(64),
                now() + Duration::seconds(9),
            )
            .expect("thread bound");
        store
            .update_runtime_recovery(
                &attempt,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_thread_bound",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(9),
                )],
                now() + Duration::seconds(9),
            )
            .expect("persist thread binding");

        let mut reattached = detached.clone();
        reattached
            .reattach(
                detached.attachment_epoch,
                "2".repeat(64),
                now() + Duration::seconds(10),
            )
            .expect("reattach projection");
        let mut requeued = mailbox.clone();
        assert!(
            requeued
                .recover_after_reattach(&reattached, now() + Duration::seconds(10))
                .expect("requeue old epoch")
        );
        let expected_attempt_revision = attempt.revision;
        attempt
            .mark_attached(&reattached, now() + Duration::seconds(10))
            .expect("finish attempt projection");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_runtime_recovery_attach_failure
                 BEFORE UPDATE OF status ON runtime_recovery_attempts
                 WHEN NEW.status = 'attached'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected runtime recovery attach failure');
                 END;",
            )
            .expect("failure trigger");
        let event_count_before: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row.get(0))
            .expect("event count");
        assert!(
            store
                .attach_worker_and_finish_runtime_recovery(
                    &reattached,
                    detached.revision,
                    &requeued,
                    mailbox.revision,
                    &attempt,
                    expected_attempt_revision,
                    &[PendingEvent::new(
                        "context.runtime_recovery_attached",
                        serde_json::json!({"recoveryId": attempt.id}),
                        now() + Duration::seconds(10),
                    )],
                    now() + Duration::seconds(10),
                )
                .is_err()
        );
        assert_eq!(
            store
                .load_worker_handle(&project.id, &workspace.id, &detached.worker_id)
                .expect("rolled-back handle"),
            detached
        );
        let rolled_back_mailbox = store
            .load_worker_mailbox(&project.id, &mailbox.id)
            .expect("rolled-back mailbox");
        assert_eq!(rolled_back_mailbox, mailbox);
        assert_eq!(
            rolled_back_mailbox.messages[0].status,
            ContextWorkerMessageStatus::InFlight
        );
        assert_eq!(
            store
                .load_runtime_recovery(&project.id, &attempt.id)
                .expect("rolled-back attempt")
                .status,
            RuntimeRecoveryStatus::ThreadBound
        );
        let event_count_after: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row.get(0))
            .expect("event count after rollback");
        assert_eq!(event_count_after, event_count_before);

        store
            .connection
            .execute_batch("DROP TRIGGER inject_runtime_recovery_attach_failure;")
            .expect("remove trigger");
        store
            .attach_worker_and_finish_runtime_recovery(
                &reattached,
                detached.revision,
                &requeued,
                mailbox.revision,
                &attempt,
                expected_attempt_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_attached",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(10),
                )],
                now() + Duration::seconds(10),
            )
            .expect("retry exact atomic finalization");
        assert_eq!(
            store
                .load_worker_handle(&project.id, &workspace.id, &reattached.worker_id)
                .expect("attached handle")
                .status,
            WorkerHandleStatus::Attached
        );
        assert_eq!(
            store
                .load_worker_mailbox(&project.id, &requeued.id)
                .expect("requeued mailbox")
                .messages[0]
                .status,
            ContextWorkerMessageStatus::Pending
        );
        assert_eq!(
            store
                .load_runtime_recovery(&project.id, &attempt.id)
                .expect("attached attempt")
                .status,
            RuntimeRecoveryStatus::Attached
        );
        let serialized_events = serde_json::to_string(
            &store
                .events_for_mission(&project.id, &mission.id)
                .expect("events"),
        )
        .expect("events serialize");
        assert!(!serialized_events.contains("private-thread-runtime-recovery-store"));
    }

    #[test]
    fn recovery_failure_ledger_is_append_only_and_retry_bounded() {
        let RecoveryStoreFixture {
            mut store,
            project,
            checkpoint,
            attached,
            ..
        } = fixture();
        let mut detached = attached.clone();
        detached
            .detach(attached.attachment_epoch, now() + Duration::seconds(6))
            .expect("detach");
        let mut attempt = RuntimeRecoveryAttempt::prepare(
            RuntimeRecoveryAttemptId::from("attempt-runtime-recovery-failures"),
            &attached,
            &detached,
            &checkpoint,
            "3".repeat(64),
            RuntimeResumeStrategy::StartNew,
            None,
            2,
            now() + Duration::seconds(6),
        )
        .expect("attempt");
        store
            .begin_runtime_recovery(
                &detached,
                attached.revision,
                &attempt,
                &[PendingEvent::new(
                    "context.runtime_recovery_prepared",
                    serde_json::json!({"recoveryId": attempt.id}),
                    now() + Duration::seconds(6),
                )],
                now() + Duration::seconds(6),
            )
            .expect("begin");
        let expected_revision = attempt.revision;
        attempt
            .record_process_failure(
                RuntimeRecoveryFailureClass::Spawn,
                "4".repeat(64),
                now() + Duration::seconds(7),
            )
            .expect("retryable failure");
        store
            .update_runtime_recovery(
                &attempt,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_retry_scheduled",
                    serde_json::json!({"failureEvidenceDigest": "4".repeat(64)}),
                    now() + Duration::seconds(7),
                )],
                now() + Duration::seconds(7),
            )
            .expect("persist first failure");
        let first = attempt.clone();
        let expected_revision = attempt.revision;
        attempt
            .record_process_failure(
                RuntimeRecoveryFailureClass::Health,
                "5".repeat(64),
                now() + Duration::seconds(8),
            )
            .expect("terminal failure");
        store
            .update_runtime_recovery(
                &attempt,
                expected_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_failed",
                    serde_json::json!({"failureEvidenceDigest": "5".repeat(64)}),
                    now() + Duration::seconds(8),
                )],
                now() + Duration::seconds(8),
            )
            .expect("persist terminal failure");
        assert_eq!(attempt.status, RuntimeRecoveryStatus::Failed);
        assert!(attempt.failures.starts_with(&first.failures));
        assert!(
            attempt
                .record_process_failure(
                    RuntimeRecoveryFailureClass::CoordinatorRestart,
                    "6".repeat(64),
                    now() + Duration::seconds(9),
                )
                .is_err()
        );
        assert_failed_recovery_is_inactive_and_tamper_is_detected(
            &store,
            &project.id,
            &detached,
            &attempt,
        );
    }
}
