//! Same-Mission restart fences built from the existing SQLCipher v47 rows.
//!
//! This module deliberately adds no table.  A restart checkpoint is a typed
//! read of the already durable Project, Mission, Conversation, Context
//! Foundation, Worker Handle, Runtime Turn, Event and Outbox rows.  Recovery
//! may only replay an exact snapshot; a stale cursor/epoch or a partial graph
//! is rejected before any caller can construct a new request.

use chrono::{DateTime, Utc};
use hartevo_context_fabric::{
    MissionControlClaim, MissionControlEvidence, MissionControlGate, MissionControlGateStatus,
    MissionControlHandoff, MissionControlObjective, MissionControlQuota, MissionControlSnapshot,
    MissionControlTodo, MissionControlTodoStatus, MissionControlWriteback,
    MissionRestartCheckpoint, MissionRestartError, MissionRestartPhase, MissionRestartSnapshot,
    MissionRestartSnapshotParts,
};
use hartevo_domain_kernel::{
    ContextFoundationSnapshot, Mission, MissionCheckpointStatus, MissionConversation, MissionId,
    Project, ProjectId, TaskStatus, WorkerHandle, WorkerLease, WorkerLeaseStatus,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Reads the Mission Control board from authoritative Mission/Context
    /// rows.  The returned snapshot is content-free and can be compared after
    /// a process restart without creating a second board or task authority.
    pub fn capture_mission_control_snapshot(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<MissionControlSnapshot, StorageError> {
        let inputs = self.load_restart_inputs(project_id, mission_id, now)?;
        build_mission_control_snapshot(
            &inputs.mission,
            &inputs.foundation,
            &inputs.handle,
            &inputs.lease,
            now,
        )
    }

    /// Reopens Mission Control only when every typed board digest is exactly
    /// unchanged.  There is no repair or best-effort merge path here: callers
    /// must replay the authoritative Mission transaction or fail closed.
    pub fn validate_mission_control_snapshot(
        &self,
        snapshot: &MissionControlSnapshot,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        snapshot.validate(now)?;
        let project_id = ProjectId::from_stable(snapshot.project_id.clone());
        let mission_id = MissionId::from_stable(snapshot.mission_id.clone());
        let current = self.capture_mission_control_snapshot(&project_id, &mission_id, now)?;
        if current != *snapshot {
            return Err(StorageError::MissionRestart(
                MissionRestartError::StaleSnapshot,
            ));
        }
        Ok(())
    }

    /// Captures a content-free restart checkpoint at one of the three
    /// user-visible boundaries.  Every field is read from the same SQLite
    /// connection and is digest-bound before it is returned.
    pub fn capture_mission_restart_checkpoint(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        phase: MissionRestartPhase,
        now: DateTime<Utc>,
    ) -> Result<MissionRestartCheckpoint, StorageError> {
        let inputs = self.load_restart_inputs(project_id, mission_id, now)?;
        let checkpoint = inputs.foundation.checkpoint.clone();
        let runtime = load_latest_runtime_turn(&self.connection, project_id, mission_id)?;
        let pack = load_latest_pack_manifest(
            self,
            project_id,
            mission_id,
            inputs
                .mission
                .definition
                .as_ref()
                .map(|definition| &definition.required_artifact_types),
        )?;
        let mission_control = build_mission_control_snapshot(
            &inputs.mission,
            &inputs.foundation,
            &inputs.handle,
            &inputs.lease,
            now,
        )?;
        let delta_count = runtime
            .as_ref()
            .map(|row| runtime_delta_count(&self.connection, project_id, &row.id))
            .transpose()?
            .unwrap_or(0);
        validate_phase(
            phase,
            &inputs.mission,
            runtime.as_ref(),
            delta_count,
            pack.is_some(),
        )?;
        if phase == MissionRestartPhase::BeforeHumanDecision && pack.is_none() {
            return Err(StorageError::MissionRestart(
                MissionRestartError::MissingAuthority,
            ));
        }

        let cursor_digest = digest_json(&(
            checkpoint.resume_cursor_digest.as_str(),
            runtime.as_ref().map(|row| {
                (
                    row.id.as_str(),
                    row.record_digest.as_str(),
                    row.runtime_turn_id_digest.as_deref(),
                    row.evidence_count,
                )
            }),
            delta_count,
        ))?;
        let event_log_digest = digest_event_rows(&self.connection, project_id, mission_id)?;
        let outbox_digest = digest_outbox_rows(&self.connection, project_id, mission_id)?;
        let snapshot = MissionRestartSnapshot::from_parts(MissionRestartSnapshotParts {
            tenant_id: inputs.project.tenant_id.clone(),
            project_id: inputs.project.id.clone(),
            mission_id: inputs.mission.id.clone(),
            conversation_id: inputs.conversation.id.clone(),
            checkpoint_id: checkpoint.id.clone(),
            project_digest: digest_json(&inputs.project)?,
            mission_digest: digest_json(&inputs.mission)?,
            contract_digest: digest_json(&inputs.mission.contract)?,
            conversation_digest: digest_json(&inputs.conversation)?,
            mission_control_digest: mission_control.digest()?,
            pack_digest: pack.as_ref().map(|value| value.manifest_digest.clone()),
            pack_revision: pack.as_ref().map(|value| value.version),
            mission_revision: inputs.mission.revision,
            conversation_revision: inputs.conversation.revision,
            cursor_digest,
            generation: inputs.handle.generation,
            attachment_epoch: inputs.handle.attachment_epoch,
            idempotency_digest: digest_idempotency_rows(
                &self.connection,
                project_id,
                mission_id,
                &inputs.conversation,
            )?,
            event_log_digest,
            outbox_digest,
        })?;
        MissionRestartCheckpoint::new(phase, snapshot).map_err(StorageError::MissionRestart)
    }

    /// Re-reads the same durable graph and returns `ExactReplay` only when no
    /// row, cursor, epoch, identity or idempotency digest has changed.
    pub fn validate_mission_restart_checkpoint(
        &self,
        checkpoint: &MissionRestartCheckpoint,
        now: DateTime<Utc>,
    ) -> Result<hartevo_context_fabric::MissionRestartDisposition, StorageError> {
        checkpoint
            .validate()
            .map_err(StorageError::MissionRestart)?;
        let current = self.capture_mission_restart_checkpoint(
            &checkpoint.snapshot.project_id,
            &checkpoint.snapshot.mission_id,
            checkpoint.phase,
            now,
        )?;
        checkpoint
            .validate_reopen(&current)
            .map_err(StorageError::MissionRestart)
    }

    fn load_restart_inputs(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        now: DateTime<Utc>,
    ) -> Result<RestartInputs, StorageError> {
        let project = self.load_project(project_id)?;
        let mission = self.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id || mission.tenant_id != project.tenant_id {
            return Err(StorageError::TenantScopeMismatch);
        }
        let conversation = self.load_mission_conversation(project_id, mission_id)?;
        if conversation.project_id != *project_id
            || conversation.mission_id != *mission_id
            || conversation.tenant_id != project.tenant_id
        {
            return Err(StorageError::MissionRestart(
                MissionRestartError::CrossProject,
            ));
        }
        let workspace_id = self
            .connection
            .query_row(
                "SELECT id FROM context_workspaces
                 WHERE project_id = ?1 AND mission_id = ?2
                 ORDER BY generation DESC, revision DESC, id DESC LIMIT 1",
                params![project_id.as_str(), mission_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(StorageError::MissionRestart(
                MissionRestartError::MissingAuthority,
            ))?;
        let workspace_id = hartevo_domain_kernel::ContextWorkspaceId::from_stable(workspace_id);
        let foundation =
            self.load_context_foundation_snapshot(project_id, &workspace_id, 1, now)?;
        let handle = load_latest_worker_handle(&self.connection, project_id, mission_id)?.ok_or(
            StorageError::MissionRestart(MissionRestartError::MissingAuthority),
        )?;
        if handle.project_id != *project_id
            || handle.mission_id != *mission_id
            || handle.tenant_id != project.tenant_id
            || handle.generation != foundation.workspace.generation
        {
            return Err(StorageError::MissionRestart(
                MissionRestartError::CrossProject,
            ));
        }
        let lease = self.load_worker_lease(project_id, &handle.lease_id)?;
        Ok(RestartInputs {
            project,
            mission,
            conversation,
            foundation,
            handle,
            lease,
        })
    }
}

struct RestartInputs {
    project: Project,
    mission: Mission,
    conversation: MissionConversation,
    foundation: ContextFoundationSnapshot,
    handle: WorkerHandle,
    lease: WorkerLease,
}

fn build_mission_control_snapshot(
    mission: &Mission,
    foundation: &ContextFoundationSnapshot,
    handle: &WorkerHandle,
    lease: &hartevo_domain_kernel::WorkerLease,
    now: DateTime<Utc>,
) -> Result<MissionControlSnapshot, StorageError> {
    let objective = MissionControlObjective {
        objective_digest: digest_bytes(mission.contract.goal.as_bytes()),
        contract_digest: digest_json(&mission.contract)?,
        revision: mission.revision,
    };
    let gates = mission_control_gates(mission)?;
    let todos = mission_control_todos(mission);
    let evidence = mission_control_evidence(mission)?;
    let quota = MissionControlQuota {
        token_limit: foundation.workspace.budget.token_limit,
        token_spent: handle.usage.tokens,
        cost_limit_minor: foundation.workspace.budget.cost_limit.amount_minor,
        cost_spent_minor: handle.usage.cost.amount_minor,
        deadline_at: foundation.workspace.budget.deadline_at,
    };
    let claim = mission_control_claim(handle, lease, now);
    let accepted_writebacks = mission_control_writebacks(mission);
    let control = MissionControlSnapshot {
        tenant_id: mission.tenant_id.to_string(),
        project_id: mission.project_id.to_string(),
        mission_id: mission.id.to_string(),
        objective,
        gates,
        todos,
        evidence,
        quota,
        claim,
        handoff: None::<MissionControlHandoff>,
        worker_graph_digest: digest_json(&(&foundation.workspace, handle, lease))?,
        accepted_writebacks,
        mission_revision: mission.revision,
    };
    control.validate(now)?;
    Ok(control)
}

fn mission_control_gates(mission: &Mission) -> Result<Vec<MissionControlGate>, StorageError> {
    mission
        .definition
        .as_ref()
        .map(|definition| {
            definition
                .checkpoints
                .iter()
                .map(|checkpoint| {
                    let status = match checkpoint.status {
                        MissionCheckpointStatus::Pending => MissionControlGateStatus::Pending,
                        MissionCheckpointStatus::Ready => MissionControlGateStatus::Ready,
                        MissionCheckpointStatus::Running | MissionCheckpointStatus::Verifying => {
                            MissionControlGateStatus::Running
                        }
                        MissionCheckpointStatus::Blocked => MissionControlGateStatus::Blocked,
                        MissionCheckpointStatus::WaitingUser
                        | MissionCheckpointStatus::WaitingApproval => {
                            MissionControlGateStatus::WaitingHuman
                        }
                        MissionCheckpointStatus::Completed | MissionCheckpointStatus::Skipped => {
                            MissionControlGateStatus::Completed
                        }
                    };
                    Ok(MissionControlGate {
                        gate_id: checkpoint.id.clone(),
                        status,
                        required_evidence_digest: checkpoint
                            .completion
                            .as_ref()
                            .map(digest_json)
                            .transpose()?,
                        revision: checkpoint.revision,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn mission_control_todos(mission: &Mission) -> Vec<MissionControlTodo> {
    mission
        .tasks
        .iter()
        .map(|task| MissionControlTodo {
            todo_id: task.id.to_string(),
            status: match task.status {
                TaskStatus::Ready => MissionControlTodoStatus::Pending,
                TaskStatus::Running => MissionControlTodoStatus::Claimed,
                TaskStatus::Blocked => MissionControlTodoStatus::Blocked,
                TaskStatus::Completed => MissionControlTodoStatus::Completed,
                TaskStatus::Cancelled => MissionControlTodoStatus::Cancelled,
            },
            idempotency_digest: digest_bytes(task.id.as_str().as_bytes()),
            revision: mission.revision,
        })
        .collect()
}

fn mission_control_evidence(
    mission: &Mission,
) -> Result<Vec<MissionControlEvidence>, StorageError> {
    mission
        .evidence
        .iter()
        .map(|item| {
            Ok(MissionControlEvidence {
                evidence_digest: digest_json(item)?,
                source_digest: digest_bytes(item.source_uri.as_bytes()),
                revision: mission.revision,
            })
        })
        .collect()
}

fn mission_control_claim(
    handle: &WorkerHandle,
    lease: &WorkerLease,
    now: DateTime<Utc>,
) -> Option<MissionControlClaim> {
    (lease.effective_status(now) == WorkerLeaseStatus::Active && lease.expires_at > now).then(
        || MissionControlClaim {
            owner_digest: digest_bytes(handle.worker_id.as_str().as_bytes()),
            generation: handle.generation,
            attachment_epoch: handle.attachment_epoch,
            lease_expires_at: lease.expires_at,
        },
    )
}

fn mission_control_writebacks(mission: &Mission) -> Vec<MissionControlWriteback> {
    mission
        .effects
        .iter()
        .map(|effect| MissionControlWriteback {
            idempotency_digest: digest_bytes(effect.idempotency_key.as_bytes()),
            payload_digest: effect.payload_digest.clone(),
        })
        .collect()
}

#[derive(Clone, Debug)]
struct RuntimeTurnRow {
    id: String,
    status: String,
    record_digest: String,
    runtime_turn_id_digest: Option<String>,
    evidence_count: i64,
}

fn load_latest_runtime_turn(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Option<RuntimeTurnRow>, StorageError> {
    connection
        .query_row(
            "SELECT id, status, record_digest, runtime_turn_id_digest, evidence_count
             FROM runtime_turn_attempts
             WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY updated_at DESC, revision DESC, id DESC LIMIT 1",
            params![project_id.as_str(), mission_id.as_str()],
            |row| {
                Ok(RuntimeTurnRow {
                    id: row.get(0)?,
                    status: row.get(1)?,
                    record_digest: row.get(2)?,
                    runtime_turn_id_digest: row.get(3)?,
                    evidence_count: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(StorageError::from)
}

fn load_latest_worker_handle(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Option<hartevo_domain_kernel::WorkerHandle>, StorageError> {
    let row = connection
        .query_row(
            "SELECT workspace_id, worker_id
             FROM context_worker_handles
             WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY generation DESC, attachment_epoch DESC, revision DESC, worker_id DESC
             LIMIT 1",
            params![project_id.as_str(), mission_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    row.map(|(workspace_id, worker_id)| {
        let workspace_id = hartevo_domain_kernel::ContextWorkspaceId::from_stable(workspace_id);
        let worker_id = hartevo_domain_kernel::WorkerId::from_stable(worker_id);
        let handle = connection.query_row(
            "SELECT record_json FROM context_worker_handles
             WHERE project_id = ?1 AND workspace_id = ?2 AND worker_id = ?3",
            params![
                project_id.as_str(),
                workspace_id.as_str(),
                worker_id.as_str()
            ],
            |row| row.get::<_, String>(0),
        )?;
        serde_json::from_str(&handle).map_err(StorageError::from)
    })
    .transpose()
}

fn runtime_delta_count(
    connection: &Connection,
    project_id: &ProjectId,
    runtime_turn_id: &str,
) -> Result<i64, StorageError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_turn_evidence
             WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2
               AND evidence_kind = 'agent_message_delta'",
            params![project_id.as_str(), runtime_turn_id],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
}

fn validate_phase(
    phase: MissionRestartPhase,
    mission: &Mission,
    runtime: Option<&RuntimeTurnRow>,
    delta_count: i64,
    pack_present: bool,
) -> Result<(), StorageError> {
    match phase {
        MissionRestartPhase::BeforeFirstDelta if delta_count != 0 => {
            Err(StorageError::MissionRestart(MissionRestartError::StaleSnapshot))
        }
        MissionRestartPhase::DuringStreaming
            if runtime.is_none_or(|row| {
                delta_count == 0
                    || !matches!(
                        row.status.as_str(),
                        "dispatching"
                            | "running"
                            | "waiting_local_approval"
                            | "approval_responding"
                            | "interrupt_requested"
                    )
            }) => Err(StorageError::MissionRestart(
            MissionRestartError::MissingAuthority,
        )),
        MissionRestartPhase::BeforeHumanDecision
            if !pack_present
                || !mission.definition.as_ref().is_some_and(|definition| {
                    definition.current_checkpoint().is_some_and(|checkpoint| {
                        checkpoint.route.as_ref().is_some_and(|route| {
                            route.executor == hartevo_domain_kernel::MissionCheckpointExecutor::Human
                                && route.completion_policy
                                    == Some(
                                        hartevo_domain_kernel::MissionCheckpointCompletionPolicy::HumanConfirmation,
                                    )
                        })
                    })
                }) => Err(StorageError::MissionRestart(
            MissionRestartError::MissingAuthority,
        )),
        _ => Ok(()),
    }
}

fn load_latest_pack_manifest(
    store: &ProjectStore,
    project_id: &ProjectId,
    mission_id: &MissionId,
    required_artifact_types: Option<&std::collections::BTreeSet<String>>,
) -> Result<Option<hartevo_domain_kernel::WorkProductManifest>, StorageError> {
    let mut statement = store.connection.prepare(
        "SELECT work_product_id, work_product_type FROM work_product_manifests
         WHERE project_id = ?1 AND mission_id = ?2
         ORDER BY version DESC, updated_at DESC, work_product_id DESC",
    )?;
    let rows = statement.query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (id, product_type) = row?;
        if required_artifact_types
            .is_none_or(|types| types.is_empty() || types.contains(&product_type))
        {
            return store
                .load_work_product_manifest(
                    project_id,
                    &hartevo_domain_kernel::WorkProductId::from_stable(id),
                )
                .map(Some);
        }
    }
    Ok(None)
}

fn digest_idempotency_rows(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
    conversation: &hartevo_domain_kernel::MissionConversation,
) -> Result<String, StorageError> {
    let effects = connection
        .prepare(
            "SELECT idempotency_key, effect_id, status, updated_at
             FROM effect_idempotency WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY idempotency_key, effect_id",
        )?
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    digest_json(&(
        conversation
            .messages
            .iter()
            .map(|message| {
                (
                    message.sequence,
                    message.idempotency_key.as_str(),
                    message.content_digest.as_str(),
                )
            })
            .collect::<Vec<_>>(),
        effects,
    ))
}

fn digest_event_rows(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<String, StorageError> {
    let rows = connection
        .prepare(
            "SELECT sequence, event_type, payload_json, recorded_at
             FROM domain_events WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY sequence",
        )?
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            let payload: String = row.get(2)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                digest_bytes(payload.as_bytes()),
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    digest_json(&rows)
}

fn digest_outbox_rows(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<String, StorageError> {
    let rows = connection
        .prepare(
            "SELECT sequence, event_type, payload_json, status, attempts, created_at,
                    published_at
             FROM outbox_messages WHERE project_id = ?1 AND mission_id = ?2
             ORDER BY sequence",
        )?
        .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
            let payload: String = row.get(2)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                digest_bytes(payload.as_bytes()),
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    digest_json(&rows)
}

fn digest_json(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(digest_bytes(&serde_json::to_vec(value)?))
}

fn digest_bytes(value: &[u8]) -> String {
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
        ContextReturnContract, ContextWorkingSet, ContextWorkingSetId, ContextWorkspace,
        ContextWorkspaceId, ContinuationLedger, Mission, MissionContract, MissionConversation,
        MissionConversationId, MissionConversationMessageId, MissionDefinition, MissionId, Money,
        OperatingMode, Project, ProjectId, StorageMode, Task, TaskId, TaskStatus, TenantId,
        WorkerHandle, WorkerLease, WorkerLeaseId, WorkerMailbox,
    };

    use super::*;
    use crate::PendingEvent;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn recovery_domain() -> (Project, Mission, MissionConversation) {
        let project = Project::create_local(
            TenantId::from("tenant-restart-fixture"),
            ProjectId::from("project-restart-fixture"),
            "Restart fixture",
            "",
            "/tmp/project-restart-fixture",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let contract = MissionContract::bootstrap(
            "Preserve one Mission across restart",
            ["research.discover".into()],
            now(),
        );
        let definition = MissionDefinition::from_linear_manifest(
            "VM-07",
            1,
            "a".repeat(64),
            OperatingMode::BuildOnce,
            ["research.discover".into()],
            ["evidence_pack".into()],
            ["market_truth".into()],
            ["research".into()],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            project.tenant_id.clone(),
            MissionId::from("mission-restart-fixture"),
            project.id.clone(),
            "Restart fixture mission",
            contract,
            definition,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-restart-fixture"),
                    title: "Preserve restart state".into(),
                    status: TaskStatus::Ready,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("task");
        let conversation = MissionConversation::start(
            MissionConversationId::from("conversation-restart-fixture"),
            MissionConversationMessageId::from("message-restart-goal"),
            &mission,
            mission.contract.goal.clone(),
            "restart:goal",
            now(),
        )
        .expect("conversation");
        (project, mission, conversation)
    }

    fn recovery_workspace(
        mission: &Mission,
    ) -> (
        ContextWorkspace,
        ContextWorkingSet,
        ContinuationLedger,
        ContextBranch,
        WorkerLease,
    ) {
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-restart-fixture"),
            mission,
            1,
            "context-policy/v1",
            BTreeSet::from(["research.discover".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::zero(hartevo_domain_kernel::CurrencyCode::parse("USD").unwrap()),
                deadline_at: now() + Duration::hours(1),
                max_depth: 2,
                max_concurrency: 1,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-set-restart-fixture"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation-restart-fixture"),
            &workspace,
            now(),
        )
        .expect("continuation");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-restart-fixture"),
            &workspace,
            None,
            "restart worker",
            "b".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-restart-fixture"),
            &workspace,
            &branch,
            hartevo_domain_kernel::WorkerId::from("worker-restart-fixture"),
            1,
            "c".repeat(64),
            Some("d".repeat(64)),
            now() + Duration::minutes(30),
            now(),
        )
        .expect("lease");
        (workspace, working_set, continuation, branch, lease)
    }

    fn recovery_worker(
        mission: &Mission,
        workspace: &ContextWorkspace,
        branch: &ContextBranch,
        lease: &WorkerLease,
    ) -> (ContextCapsule, WorkerHandle, WorkerMailbox) {
        let capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-restart-fixture"),
            workspace,
            branch,
            lease,
            mission,
            "Return one bounded finding",
            TaskId::from("task-restart-fixture"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["research.discover".into()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::zero(hartevo_domain_kernel::CurrencyCode::parse("USD").unwrap()),
                deadline_at: now() + Duration::minutes(20),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.finding".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["finding".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::minutes(20),
            now(),
        )
        .expect("capsule");
        let handle = WorkerHandle::create(workspace, branch, lease, &capsule, None, now())
            .expect("worker handle");
        let mailbox = WorkerMailbox::create(
            hartevo_domain_kernel::ContextWorkerMailboxId::from("mailbox-restart-fixture"),
            &handle,
            2,
            now(),
        )
        .expect("mailbox");
        (capsule, handle, mailbox)
    }

    fn persist_recovery_context(
        store: &mut ProjectStore,
        mission: &Mission,
        workspace: &ContextWorkspace,
        working_set: &ContextWorkingSet,
        continuation: &ContinuationLedger,
    ) {
        store
            .create_context_workspace(
                workspace,
                working_set,
                continuation,
                &[PendingEvent::new(
                    "context.restart_fixture_created",
                    serde_json::json!({"workspaceId": workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("context foundation persistence");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-restart-fixture"),
            workspace,
            mission,
            &[],
            None,
            1,
            1,
            "e".repeat(64),
            100,
            1,
            "cas://".to_owned() + &"f".repeat(64),
            "1".repeat(64),
            256,
            10,
            BTreeSet::new(),
            "2".repeat(64),
            "3".repeat(64),
            "4".repeat(64),
            now(),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-restart-fixture"),
            workspace,
            mission,
            &[],
            working_set,
            continuation,
            &compaction,
            None,
            "5".repeat(64),
            "6".repeat(64),
            1,
            now(),
        )
        .expect("checkpoint");
        store
            .append_context_compaction_checkpoint(
                &compaction,
                &checkpoint,
                &[PendingEvent::new(
                    "context.restart_checkpoint_created",
                    serde_json::json!({"checkpointId": checkpoint.id}),
                    now(),
                )],
                now(),
            )
            .expect("checkpoint persistence");
    }

    fn recovery_fixture() -> (ProjectStore, ProjectId, MissionId, MissionRestartCheckpoint) {
        let (project, mission, conversation) = recovery_domain();
        let (workspace, working_set, continuation, branch, lease) = recovery_workspace(&mission);
        let (capsule, handle, mailbox) = recovery_worker(&mission, &workspace, &branch, &lease);

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("project persistence");
        store
            .create_catalog_mission_with_conversation_atomic(
                &mission,
                &conversation,
                &[PendingEvent::new(
                    "mission.restart_fixture_created",
                    serde_json::json!({"missionId": mission.id}),
                    now(),
                )],
            )
            .expect("mission and conversation persistence");
        persist_recovery_context(
            &mut store,
            &mission,
            &workspace,
            &working_set,
            &continuation,
        );
        store
            .issue_context_capsule_bundle(
                &workspace,
                std::slice::from_ref(&branch),
                &lease,
                &capsule,
                &handle,
                &mailbox,
                &[],
                &[PendingEvent::new(
                    "context.restart_worker_attached",
                    serde_json::json!({"workerId": handle.worker_id}),
                    now(),
                )],
                now(),
            )
            .expect("worker persistence");
        let checkpoint = store
            .capture_mission_restart_checkpoint(
                &project.id,
                &mission.id,
                MissionRestartPhase::BeforeFirstDelta,
                now(),
            )
            .expect("restart checkpoint");
        let control = store
            .capture_mission_control_snapshot(&project.id, &mission.id, now())
            .expect("mission control snapshot");
        assert_eq!(
            checkpoint.snapshot.mission_control_digest,
            control.digest().expect("control digest")
        );
        (store, project.id, mission.id, checkpoint)
    }

    #[test]
    fn same_mission_restart_checkpoint_reopens_exactly_and_rejects_snapshot_drift() {
        let (store, project_id, mission_id, checkpoint) = recovery_fixture();
        assert_eq!(
            store
                .validate_mission_restart_checkpoint(&checkpoint, now())
                .expect("exact replay"),
            hartevo_context_fabric::MissionRestartDisposition::ExactReplay
        );
        let control = store
            .capture_mission_control_snapshot(&project_id, &mission_id, now())
            .expect("control snapshot");
        store
            .validate_mission_control_snapshot(&control, now())
            .expect("exact control replay");
        let mut stale_control = control;
        stale_control.objective.objective_digest = "b".repeat(64);
        assert!(matches!(
            store.validate_mission_control_snapshot(&stale_control, now()),
            Err(StorageError::MissionRestart(
                MissionRestartError::StaleSnapshot
            ))
        ));

        let mut stale_snapshot = checkpoint.snapshot.clone();
        stale_snapshot.event_log_digest = "a".repeat(64);
        let stale = MissionRestartCheckpoint::new(checkpoint.phase, stale_snapshot)
            .expect("well-formed but stale checkpoint");
        assert!(matches!(
            store.validate_mission_restart_checkpoint(&stale, now()),
            Err(StorageError::MissionRestart(
                MissionRestartError::StaleSnapshot
            ))
        ));

        assert_eq!(
            store
                .load_mission(&project_id, &mission_id)
                .expect("mission remains exact")
                .revision,
            checkpoint.snapshot.mission_revision
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| row
                    .get::<_, i64>(0))
                .expect("outbox remains unchanged"),
            4
        );
    }

    #[test]
    fn restart_phase_fences_distinguish_pre_delta_from_active_streaming() {
        let (store, project_id, mission_id, _) = recovery_fixture();
        let mission = store
            .load_mission(&project_id, &mission_id)
            .expect("mission");
        assert!(
            validate_phase(
                MissionRestartPhase::BeforeFirstDelta,
                &mission,
                None,
                0,
                false,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_phase(
                MissionRestartPhase::BeforeFirstDelta,
                &mission,
                None,
                1,
                false,
            ),
            Err(StorageError::MissionRestart(
                MissionRestartError::StaleSnapshot
            ))
        ));
        let runtime = RuntimeTurnRow {
            id: "runtime-turn".into(),
            status: "running".into(),
            record_digest: "a".repeat(64),
            runtime_turn_id_digest: None,
            evidence_count: 2,
        };
        assert!(
            validate_phase(
                MissionRestartPhase::DuringStreaming,
                &mission,
                Some(&runtime),
                1,
                false,
            )
            .is_ok()
        );
        let mut completed = runtime;
        completed.status = "completed".into();
        assert!(matches!(
            validate_phase(
                MissionRestartPhase::DuringStreaming,
                &mission,
                Some(&completed),
                1,
                false,
            ),
            Err(StorageError::MissionRestart(
                MissionRestartError::MissingAuthority
            ))
        ));
    }
}
