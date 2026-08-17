//! Durable Worker Graph projection over the existing Context/Cell rows.
//!
//! This module deliberately does not add a second persistence table.  Worker
//! identity, lease fencing, return contracts, usage, branches and capsules
//! already live in the encrypted Context rows.  The graph is rebuilt from
//! those rows in one read transaction, so reopening a SQLCipher store cannot
//! invent a second source of truth or replay a writeback.

use chrono::{DateTime, Utc};
use hartevo_context_fabric::worker_graph::{
    ReturnContract, UsageAccount, WorkerClaim, WorkerClaimState, WorkerGraph, WorkerGraphError,
    WorkerKind, WorkerLease, WorkerLeaseState, WorkerSpec, WorkerState,
};
use hartevo_domain_kernel::{
    ContextBranch, ContextCapsule, ContextWorkspace, ContextWorkspaceId, Mission, MissionId,
    ProjectId, WorkerHandle, WorkerHandleStatus, WorkerLease as DomainWorkerLease,
    WorkerLeaseStatus,
};
use rusqlite::{Connection, params};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ProjectStore, StorageError};

#[derive(Debug, Error)]
pub enum ContextWorkerGraphError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Graph(#[from] WorkerGraphError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextWorkerGraphSnapshot {
    pub graph: WorkerGraph,
    pub graph_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerGraphStoreDisposition {
    ExactReplay,
}

impl ProjectStore {
    /// Rebuilds the Worker Graph from the current encrypted Context rows.
    /// Every linked row is decoded and scope-checked before a graph is
    /// returned; no caller-supplied worker or lease data is trusted.
    pub fn load_worker_graph(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        workspace_id: &ContextWorkspaceId,
        now: DateTime<Utc>,
    ) -> Result<ContextWorkerGraphSnapshot, ContextWorkerGraphError> {
        let workspace = self.load_context_workspace(project_id, workspace_id)?;
        if workspace.mission_id != *mission_id {
            return Err(ContextWorkerGraphError::Storage(
                StorageError::TenantScopeMismatch,
            ));
        }
        let handles = load_worker_handles(&self.connection, project_id, mission_id, workspace_id)?;
        if handles.is_empty() {
            return Err(ContextWorkerGraphError::Storage(
                StorageError::DomainDecode("worker graph has no durable worker handles".into()),
            ));
        }
        let mission = self.load_mission(project_id, mission_id)?;
        let mut projections = Vec::with_capacity(handles.len());
        let mut source_rows = Vec::with_capacity(handles.len() * 4 + 1);
        source_rows.push(serde_json::to_value(&workspace).map_err(StorageError::from)?);
        let scope = GraphLoadScope {
            store: self,
            workspace: &workspace,
            mission: &mission,
            project_id,
            mission_id,
            workspace_id,
            now,
        };

        for handle in &handles {
            let projection = project_worker_row(&scope, handle)?;
            source_rows.extend(projection.source_rows.clone());
            projections.push(projection);
        }

        let graph = WorkerGraph {
            schema_version: hartevo_context_fabric::worker_graph::WORKER_GRAPH_SCHEMA_VERSION,
            tenant_digest: digest(workspace.tenant_id.as_str().as_bytes()),
            project_digest: digest(project_id.as_str().as_bytes()),
            mission_digest: digest(mission_id.as_str().as_bytes()),
            workspace_digest: digest(workspace_id.as_str().as_bytes()),
            source_revision: workspace.revision,
            source_digest: digest(&serde_json::to_vec(&source_rows).map_err(StorageError::from)?),
            graph_revision: projections
                .iter()
                .map(|projection| projection.graph_revision)
                .max()
                .unwrap_or(workspace.revision),
            workers: projections
                .iter()
                .map(|projection| projection.worker.clone())
                .collect(),
            claims: projections
                .iter()
                .map(|projection| projection.claim.clone())
                .collect(),
            leases: projections
                .iter()
                .map(|projection| projection.lease.clone())
                .collect(),
            usage: projections
                .iter()
                .map(|projection| {
                    (
                        projection.worker_id_digest.clone(),
                        projection.usage.clone(),
                    )
                })
                .collect(),
            handoffs: Vec::new(),
            returns: Vec::new(),
            merges: Vec::new(),
        };
        graph.validate(now)?;
        let graph_digest = graph.digest()?;
        Ok(ContextWorkerGraphSnapshot {
            graph,
            graph_digest,
        })
    }

    /// Reopens the graph from SQLCipher and accepts only a byte-for-byte
    /// durable projection.  A stale, cross-project, or partially persisted
    /// snapshot is rejected before any write path can be selected.
    pub fn validate_worker_graph_restart(
        &self,
        snapshot: &ContextWorkerGraphSnapshot,
        project_id: &ProjectId,
        mission_id: &MissionId,
        workspace_id: &ContextWorkspaceId,
        now: DateTime<Utc>,
    ) -> Result<WorkerGraphStoreDisposition, ContextWorkerGraphError> {
        if snapshot.graph_digest != snapshot.graph.digest()? {
            return Err(ContextWorkerGraphError::Graph(
                WorkerGraphError::StaleSnapshot,
            ));
        }
        let current = self.load_worker_graph(project_id, mission_id, workspace_id, now)?;
        snapshot.graph.validate_restart(&current.graph, now)?;
        if snapshot.graph_digest != current.graph_digest {
            return Err(ContextWorkerGraphError::Graph(
                WorkerGraphError::StaleSnapshot,
            ));
        }
        Ok(WorkerGraphStoreDisposition::ExactReplay)
    }
}

struct WorkerRowProjection {
    worker_id_digest: String,
    worker: WorkerSpec,
    claim: WorkerClaim,
    lease: WorkerLease,
    usage: UsageAccount,
    graph_revision: u64,
    source_rows: Vec<serde_json::Value>,
}

struct GraphLoadScope<'a> {
    store: &'a ProjectStore,
    workspace: &'a ContextWorkspace,
    mission: &'a Mission,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
    workspace_id: &'a ContextWorkspaceId,
    now: DateTime<Utc>,
}

fn project_worker_row(
    scope: &GraphLoadScope<'_>,
    handle: &WorkerHandle,
) -> Result<WorkerRowProjection, ContextWorkerGraphError> {
    validate_handle_scope(
        handle,
        scope.project_id,
        scope.mission_id,
        scope.workspace_id,
    )?;
    let (branch, lease, capsule) = load_linked_rows(scope, handle)?;
    let worker_id_digest = digest(handle.worker_id.as_str().as_bytes());
    let source_rows = vec![
        serde_json::to_value(handle).map_err(StorageError::from)?,
        serde_json::to_value(&branch).map_err(StorageError::from)?,
        serde_json::to_value(&lease).map_err(StorageError::from)?,
        serde_json::to_value(&capsule).map_err(StorageError::from)?,
    ];
    let owner_digest = handle.runtime_mapping_digest.as_ref().map_or_else(
        || digest(handle.worker_id.as_str().as_bytes()),
        |value| digest(value.as_bytes()),
    );
    let claim_state = match handle.status {
        WorkerHandleStatus::Attached
            if lease.status == WorkerLeaseStatus::Active && lease.expires_at > scope.now =>
        {
            WorkerClaimState::Active
        }
        WorkerHandleStatus::Detached => WorkerClaimState::Detached,
        _ => WorkerClaimState::Released,
    };
    let worker = build_worker_spec(handle, &branch, &capsule)?;
    Ok(WorkerRowProjection {
        worker_id_digest: worker_id_digest.clone(),
        worker,
        claim: WorkerClaim {
            worker_id_digest: worker_id_digest.clone(),
            owner_digest,
            generation: handle.generation,
            attachment_epoch: handle.attachment_epoch,
            lease_expires_at: lease.expires_at,
            state: claim_state,
        },
        lease: WorkerLease {
            worker_id_digest,
            generation: lease.generation,
            attachment_epoch: handle.attachment_epoch,
            lease_token_digest: lease.lease_token_digest,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            state: lease_state(lease.status),
        },
        usage: UsageAccount {
            token_spent: handle.usage.tokens,
            cost_spent_minor: handle.usage.cost.amount_minor,
            tool_calls: handle.usage.tool_calls,
            runtime_millis: handle.usage.runtime_millis,
        },
        graph_revision: scope
            .workspace
            .revision
            .max(handle.revision)
            .max(branch.revision)
            .max(lease.revision)
            .max(capsule.revision),
        source_rows,
    })
}

fn load_linked_rows(
    scope: &GraphLoadScope<'_>,
    handle: &WorkerHandle,
) -> Result<(ContextBranch, DomainWorkerLease, ContextCapsule), ContextWorkerGraphError> {
    let branch = scope
        .store
        .load_context_branch(scope.project_id, &handle.branch_id)?;
    let lease = scope
        .store
        .load_worker_lease(scope.project_id, &handle.lease_id)?;
    let capsule = scope
        .store
        .load_context_capsule(scope.project_id, &handle.capsule_id)?;
    let parent = handle
        .parent_worker_id
        .as_ref()
        .map(|worker_id| {
            scope
                .store
                .load_worker_handle(scope.project_id, scope.workspace_id, worker_id)
        })
        .transpose()?;
    let facts = scope
        .store
        .load_context_capsule_facts(scope.project_id, &capsule.id)?;
    handle
        .validate_for(
            scope.workspace,
            &branch,
            &lease,
            &capsule,
            parent.as_ref(),
            scope.now,
        )
        .map_err(StorageError::from)?;
    capsule
        .validate_for(
            scope.workspace,
            &branch,
            &lease,
            scope.mission,
            &facts,
            scope.now,
        )
        .map_err(StorageError::from)?;
    lease
        .validate_for(scope.workspace, &branch, scope.now)
        .map_err(StorageError::from)?;
    Ok((branch, lease, capsule))
}

fn build_worker_spec(
    handle: &WorkerHandle,
    branch: &ContextBranch,
    capsule: &ContextCapsule,
) -> Result<WorkerSpec, ContextWorkerGraphError> {
    Ok(WorkerSpec {
        worker_id_digest: digest(handle.worker_id.as_str().as_bytes()),
        parent_worker_id_digest: handle
            .parent_worker_id
            .as_ref()
            .map(|worker_id| digest(worker_id.as_str().as_bytes())),
        kind: if handle.parent_worker_id.is_some() {
            WorkerKind::ReadOnly
        } else {
            WorkerKind::Runtime
        },
        branch_digest: digest(branch.id.as_str().as_bytes()),
        capability_digest: digest(
            &serde_json::to_vec(&handle.capabilities).map_err(StorageError::from)?,
        ),
        return_contract: ReturnContract {
            schema_digest: digest(
                &serde_json::to_vec(&capsule.return_contract).map_err(StorageError::from)?,
            ),
            required_evidence: capsule.return_contract.evidence_required,
            max_result_bytes: capsule.return_contract.max_result_bytes,
            max_tokens: handle.budget.token_limit,
            max_cost_minor: handle.budget.cost_limit.amount_minor,
        },
        generation: handle.generation,
        revision: handle.revision,
        state: worker_state(handle.status),
    })
}

fn load_worker_handles(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
    workspace_id: &ContextWorkspaceId,
) -> Result<Vec<WorkerHandle>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT record_json FROM context_worker_handles
         WHERE project_id = ?1 AND mission_id = ?2 AND workspace_id = ?3
         ORDER BY generation, worker_id",
    )?;
    let rows = statement.query_map(
        params![
            project_id.as_str(),
            mission_id.as_str(),
            workspace_id.as_str()
        ],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| {
        row.map_err(StorageError::from)
            .and_then(|json| decode_record(&json))
    })
    .collect()
}

fn decode_record<T: DeserializeOwned>(json: &str) -> Result<T, StorageError> {
    serde_json::from_str(json).map_err(StorageError::from)
}

fn validate_handle_scope(
    handle: &WorkerHandle,
    project_id: &ProjectId,
    mission_id: &MissionId,
    workspace_id: &ContextWorkspaceId,
) -> Result<(), StorageError> {
    if handle.project_id != *project_id
        || handle.mission_id != *mission_id
        || handle.workspace_id != *workspace_id
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn worker_state(status: WorkerHandleStatus) -> WorkerState {
    match status {
        WorkerHandleStatus::Attached => WorkerState::Claimed,
        WorkerHandleStatus::Detached => WorkerState::Detached,
        WorkerHandleStatus::Completed => WorkerState::Returned,
        WorkerHandleStatus::Failed => WorkerState::Rejected,
        WorkerHandleStatus::Cancelled => WorkerState::Abandoned,
    }
}

fn lease_state(status: WorkerLeaseStatus) -> WorkerLeaseState {
    match status {
        WorkerLeaseStatus::Active => WorkerLeaseState::Active,
        WorkerLeaseStatus::Released => WorkerLeaseState::Released,
        WorkerLeaseStatus::Revoked => WorkerLeaseState::Revoked,
        WorkerLeaseStatus::Expired => WorkerLeaseState::Expired,
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ContextBranch, ContextBranchId, ContextBudget, ContextCapsule, ContextCapsuleId,
        ContextContinuationLedgerId, ContextDataPolicy, ContextInputRefs, ContextMergePolicy,
        ContextWorkerMailboxId, ContextWorkspace, ContextWorkspaceId, ContinuationLedger,
        CurrencyCode, Mission, MissionContract, MissionId, Money, Project, ProjectId, StorageMode,
        Task, TaskId, TaskStatus, TenantId, WorkerId, WorkerLeaseId, WorkerMailbox,
    };
    use tempfile::NamedTempFile;

    use crate::{PendingEvent, ProjectStore};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 13, 0, 0)
            .single()
            .expect("fixture time")
    }

    fn fixture() -> (Project, Mission, ContextWorkspace, ContextWorkspaceId) {
        let project_id = ProjectId::from("ctx02-worker-graph-project");
        let mission_id = MissionId::from("ctx02-worker-graph-mission");
        let project = Project::create_local(
            TenantId::from("ctx02-tenant"),
            project_id.clone(),
            "Worker graph",
            "",
            std::env::temp_dir(),
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut mission = Mission::compile(
            TenantId::from("ctx02-tenant"),
            mission_id,
            project_id,
            "Worker graph mission",
            MissionContract::bootstrap("Durable worker graph", ["worker.runtime".into()], now()),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("ctx02-worker-graph-task"),
                    title: "Worker graph task".into(),
                    status: TaskStatus::Ready,
                    capability: "worker.runtime".into(),
                }],
                now(),
            )
            .expect("task");
        let budget = ContextBudget {
            token_limit: 10_000,
            cost_limit: Money::new(0, CurrencyCode::parse("USD").expect("currency")),
            deadline_at: now() + Duration::minutes(30),
            max_depth: 2,
            max_concurrency: 2,
        };
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("ctx02-worker-graph-workspace"),
            &mission,
            1,
            "ctx02",
            BTreeSet::from(["worker.runtime".into()]),
            budget,
            ContextDataPolicy::PublicOnly,
            now(),
        )
        .expect("workspace");
        let workspace_id = workspace.id.clone();
        (project, mission, workspace, workspace_id)
    }

    struct DurableFixture {
        project: Project,
        mission: Mission,
        workspace: ContextWorkspace,
        branch: ContextBranch,
        lease: hartevo_domain_kernel::WorkerLease,
        capsule: ContextCapsule,
        handle: WorkerHandle,
        mailbox: WorkerMailbox,
    }

    fn durable_fixture() -> DurableFixture {
        let (project, mission, workspace, _) = fixture();
        let branch = ContextBranch::create(
            ContextBranchId::from("ctx02-worker-graph-branch"),
            &workspace,
            None,
            "runtime branch",
            "1".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = hartevo_domain_kernel::WorkerLease::issue(
            WorkerLeaseId::from("ctx02-worker-graph-lease"),
            &workspace,
            &branch,
            WorkerId::from("ctx02-worker-graph-worker"),
            1,
            "2".repeat(64),
            Some("3".repeat(64)),
            now() + Duration::minutes(30),
            now(),
        )
        .expect("lease");
        let capsule = ContextCapsule::issue(
            ContextCapsuleId::from("ctx02-worker-graph-capsule"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Run durable worker graph",
            TaskId::from("ctx02-worker-graph-task"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["worker.runtime".into()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::new(0, CurrencyCode::parse("USD").expect("currency")),
                deadline_at: now() + Duration::minutes(20),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            hartevo_domain_kernel::ContextReturnContract {
                schema_id: "ctx02.return".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["result".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::minutes(20),
            now(),
        )
        .expect("capsule");
        let handle = WorkerHandle::create(&workspace, &branch, &lease, &capsule, None, now())
            .expect("handle");
        let mailbox = WorkerMailbox::create(
            ContextWorkerMailboxId::from("ctx02-worker-graph-mailbox"),
            &handle,
            2,
            now(),
        )
        .expect("mailbox");
        DurableFixture {
            project,
            mission,
            workspace,
            branch,
            lease,
            capsule,
            handle,
            mailbox,
        }
    }

    fn persist_fixture(
        fixture: &DurableFixture,
        database: &NamedTempFile,
        key: &crate::DatabaseKey,
    ) {
        let mut store = ProjectStore::open(database.path(), key).expect("store");
        store.save_project(&fixture.project).expect("project");
        store.save_mission(&fixture.mission).expect("mission");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("ctx02-worker-graph-continuation"),
            &fixture.workspace,
            now(),
        )
        .expect("continuation");
        let working_set = hartevo_domain_kernel::ContextWorkingSet::create(
            hartevo_domain_kernel::ContextWorkingSetId::from("ctx02-worker-graph-working"),
            &fixture.workspace,
            now(),
        )
        .expect("working set");
        store
            .create_context_workspace(
                &fixture.workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.worker_graph.created",
                    serde_json::json!({"workspace": fixture.workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("workspace");
        store
            .issue_context_capsule_bundle(
                &fixture.workspace,
                std::slice::from_ref(&fixture.branch),
                &fixture.lease,
                &fixture.capsule,
                &fixture.handle,
                &fixture.mailbox,
                &[],
                &[PendingEvent::new(
                    "context.worker_graph.claimed",
                    serde_json::json!({"worker": fixture.handle.worker_id}),
                    now(),
                )],
                now(),
            )
            .expect("worker bundle");
    }

    #[test]
    fn local_sqlcipher_restart_rebuilds_worker_graph_without_duplicate_writeback() {
        let fixture = durable_fixture();
        let database = NamedTempFile::new().expect("database");
        let key = crate::DatabaseKey::new([7; 32]).expect("key");
        persist_fixture(&fixture, &database, &key);
        let store = ProjectStore::open(database.path(), &key).expect("store");
        let before = store
            .load_worker_graph(
                &fixture.project.id,
                &fixture.mission.id,
                &fixture.workspace.id,
                now(),
            )
            .expect("graph before restart");
        drop(store);
        let reopened = ProjectStore::open(database.path(), &key).expect("reopen");
        let disposition = reopened
            .validate_worker_graph_restart(
                &before,
                &fixture.project.id,
                &fixture.mission.id,
                &fixture.workspace.id,
                now(),
            )
            .expect("exact restart");
        assert_eq!(disposition, WorkerGraphStoreDisposition::ExactReplay);
        assert_eq!(before.graph.workers.len(), 1);
        assert_eq!(before.graph.claims.len(), 1);
        assert_eq!(before.graph.leases.len(), 1);
        assert_eq!(before.graph.usage.len(), 1);
        assert_eq!(
            before.graph_digest,
            reopened
                .load_worker_graph(
                    &fixture.project.id,
                    &fixture.mission.id,
                    &fixture.workspace.id,
                    now(),
                )
                .expect("graph after restart")
                .graph_digest
        );
        let mut changed_handle = fixture.handle.clone();
        changed_handle.updated_at = now() + Duration::seconds(1);
        reopened
            .connection
            .execute(
                "UPDATE context_worker_handles SET updated_at = ?1, record_json = ?2
                 WHERE project_id = ?3 AND workspace_id = ?4 AND worker_id = ?5",
                rusqlite::params![
                    changed_handle.updated_at.to_rfc3339(),
                    serde_json::to_string(&changed_handle).expect("changed handle"),
                    fixture.project.id.as_str(),
                    fixture.workspace.id.as_str(),
                    fixture.handle.worker_id.as_str(),
                ],
            )
            .expect("tamper handle revision");
        assert!(matches!(
            reopened.validate_worker_graph_restart(
                &before,
                &fixture.project.id,
                &fixture.mission.id,
                &fixture.workspace.id,
                now() + Duration::seconds(1),
            ),
            Err(ContextWorkerGraphError::Graph(
                WorkerGraphError::StaleSnapshot
            ))
        ));
    }
}
