use super::*;
use crate::DatabaseKey;
use chrono::{Duration, TimeZone};
use hartevo_domain_kernel::mission_loop::{
    LoopAction, LoopActor, LoopContinuation, LoopHost, LoopMode, LoopPeer, LoopTodoSpec,
    LoopTurnResult, LoopWorkKind,
};
use hartevo_domain_kernel::{
    ActorId, Evidence, EvidenceId, EvidenceStatus, MissionContract, Project, StorageMode, Task,
    TaskId, TaskStatus, TenantId,
};
use std::collections::BTreeSet;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 7, 8, 0, 0).unwrap()
}
fn hash(value: &str) -> String {
    loop_digest(&value).unwrap()
}
fn key() -> DatabaseKey {
    DatabaseKey::new([19; 32]).unwrap()
}
fn operator() -> LoopActor {
    LoopActor::Operator(ActorId::from("operator"))
}
fn agent() -> LoopActor {
    LoopActor::Agent("worker".into())
}
fn host() -> LoopHost {
    LoopHost {
        agent_id: "worker".into(),
        available_capabilities: BTreeSet::from(["research.discover".into()]),
        workspace_digest: hash("workspace"),
    }
}
fn policy() -> LoopPolicy {
    LoopPolicy {
        operator_id: ActorId::from("operator"),
        max_slots: 10,
        max_parallel: 2,
        lease_seconds: 60,
        stall_limit: 3,
    }
}
fn event() -> PendingEvent {
    PendingEvent::new("test.evidence", serde_json::json!({"fixture": true}), now())
}
fn command(
    store: &ProjectStore,
    mission: &Mission,
    actor: LoopActor,
    action: LoopAction,
) -> LoopCommand {
    let snapshot = store
        .mission_loop_snapshot(&mission.project_id, &mission.id, now())
        .unwrap()
        .unwrap();
    LoopCommand {
        operation_id: format!("operation-{}", snapshot.state.revision()),
        expected_revision: snapshot.state.revision(),
        expected_mission_revision: snapshot.mission.revision,
        actor,
        action,
    }
}
fn apply(
    store: &mut ProjectStore,
    mission: &Mission,
    actor: LoopActor,
    action: LoopAction,
) -> LoopReceipt {
    let command = command(store, mission, actor, action);
    store
        .apply_mission_loop_command(&mission.project_id, &mission.id, &command, now())
        .unwrap()
}
fn seed(store: &mut ProjectStore) -> Mission {
    let project = Project::create_local(
        TenantId::from("tenant"),
        ProjectId::from("project"),
        "Project",
        "",
        "/workspace",
        StorageMode::LocalExisting,
    )
    .unwrap();
    store.create_project_atomic(&project, &[event()]).unwrap();
    let mut mission = Mission::compile(
        project.tenant_id,
        MissionId::from("mission"),
        project.id,
        "Research",
        MissionContract::bootstrap(
            "Private mission objective",
            ["research.discover".into()],
            now(),
        ),
        now(),
    )
    .unwrap();
    mission
        .start_research(
            [Task {
                id: TaskId::from("task"),
                title: "Task".into(),
                status: TaskStatus::Running,
                capability: "research.discover".into(),
            }],
            now(),
        )
        .unwrap();
    store.create_mission_atomic(&mission, &[event()]).unwrap();
    store
        .create_mission_loop(
            &mission.project_id,
            &mission.id,
            policy(),
            mission.revision,
            now(),
        )
        .unwrap();
    apply(
        store,
        &mission,
        operator(),
        LoopAction::RegisterPeer {
            peer: LoopPeer {
                id: "worker".into(),
                capabilities: host().available_capabilities,
                workspace_digest: hash("workspace"),
            },
        },
    );
    apply(
        store,
        &mission,
        operator(),
        LoopAction::AddTodo {
            todo: LoopTodoSpec {
                id: "slice".into(),
                title: "PRIVATE bounded action".into(),
                task_id: Some(TaskId::from("task")),
                capability: Some("research.discover".into()),
                kind: LoopWorkKind::Advancement,
                priority: 0,
                depends_on: BTreeSet::new(),
                eligible_agents: BTreeSet::new(),
                required_decisions: BTreeSet::new(),
                workspace_digest: hash("workspace"),
                write_scopes: BTreeSet::new(),
                monitor: None,
            },
        },
    );
    mission
}
fn count(store: &ProjectStore, table: &str) -> i64 {
    let sql = match table {
        "operations" => "SELECT count(*) FROM mission_loop_operations",
        "events" => "SELECT count(*) FROM domain_events",
        _ => "SELECT count(*) FROM outbox_messages",
    };
    store
        .connection
        .query_row(sql, [], |row| row.get(0))
        .unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one crash-boundary test retains encrypted reopen, exact replay, conflicting replay and public projection evidence"
)]
fn mission_loop_settlement_reopens_encrypted_and_replays_without_double_spend() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("loop.sqlite3");
    let mut store = ProjectStore::open(&path, &key()).unwrap();
    let mut mission = seed(&mut store);
    let claim = apply(
        &mut store,
        &mission,
        agent(),
        LoopAction::Claim {
            host: host(),
            todo_id: "slice".into(),
            token_digest: hash("token"),
        },
    )
    .claim
    .unwrap();
    apply(
        &mut store,
        &mission,
        agent(),
        LoopAction::BeginExecution {
            claim: claim.clone(),
            host: host(),
        },
    );
    let previous = mission.revision;
    mission
        .record_evidence(
            Evidence {
                id: EvidenceId::from("evidence"),
                title: "Evidence".into(),
                source_uri: "test://oracle".into(),
                observed_at: now(),
                confidence: 1.0,
                status: EvidenceStatus::Confirmed,
                content_digest: hash("verified"),
            },
            now(),
        )
        .unwrap();
    store
        .update_mission_atomic(&mission, previous, &[event()])
        .unwrap();
    let settle = command(
        &store,
        &mission,
        agent(),
        LoopAction::Settle {
            claim,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([EvidenceId::from("evidence")]),
                continuation: LoopContinuation::NoFollowup,
            },
        },
    );
    let receipt = store
        .apply_mission_loop_command(&mission.project_id, &mission.id, &settle, now())
        .unwrap();
    assert!(!receipt.replayed);
    let counts = (
        count(&store, "operations"),
        count(&store, "events"),
        count(&store, "outbox"),
    );
    drop(store);
    let mut reopened = ProjectStore::open(&path, &key()).unwrap();
    let replayed = reopened
        .apply_mission_loop_command(
            &mission.project_id,
            &mission.id,
            &settle,
            now() + Duration::hours(1),
        )
        .unwrap();
    assert!(replayed.replayed);
    let snapshot = reopened
        .mission_loop_snapshot(&mission.project_id, &mission.id, now())
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.state.spent_slots(), 1);
    assert_eq!(
        counts,
        (
            count(&reopened, "operations"),
            count(&reopened, "events"),
            count(&reopened, "outbox")
        )
    );
    let mut conflicting = settle;
    conflicting.action = LoopAction::Pause { paused: true };
    assert!(matches!(
        reopened.apply_mission_loop_command(&mission.project_id, &mission.id, &conflicting, now()),
        Err(StorageError::MissionLoopReplayConflict)
    ));
    let file = std::fs::read(&path).unwrap();
    assert!(
        !file
            .windows(b"Private mission objective".len())
            .any(|bytes| bytes == b"Private mission objective")
    );
    let events = serde_json::to_string(
        &reopened
            .events_for_mission(&mission.project_id, &mission.id)
            .unwrap(),
    )
    .unwrap();
    for private in [
        "PRIVATE bounded action",
        "Private mission objective",
        "operation-",
        "token",
    ] {
        assert!(!events.contains(private));
    }
}

#[test]
fn mission_loop_operation_failure_rolls_back_state_receipt_and_outbox() {
    let mut store = ProjectStore::in_memory().unwrap();
    let mission = seed(&mut store);
    let before = store
        .mission_loop_snapshot(&mission.project_id, &mission.id, now())
        .unwrap()
        .unwrap();
    let counts = (
        count(&store, "operations"),
        count(&store, "events"),
        count(&store, "outbox"),
    );
    let claim = command(
        &store,
        &mission,
        agent(),
        LoopAction::Claim {
            host: host(),
            todo_id: "slice".into(),
            token_digest: hash("token"),
        },
    );
    store.connection.execute_batch("CREATE TRIGGER fail_loop_operation BEFORE INSERT ON mission_loop_operations BEGIN SELECT RAISE(ABORT, 'injected failure'); END").unwrap();
    assert!(
        store
            .apply_mission_loop_command(&mission.project_id, &mission.id, &claim, now())
            .is_err()
    );
    assert_eq!(
        before.state,
        store
            .mission_loop_snapshot(&mission.project_id, &mission.id, now())
            .unwrap()
            .unwrap()
            .state
    );
    assert_eq!(
        counts,
        (
            count(&store, "operations"),
            count(&store, "events"),
            count(&store, "outbox")
        )
    );
    store
        .connection
        .execute_batch("DROP TRIGGER fail_loop_operation")
        .unwrap();
    assert!(
        store
            .apply_mission_loop_command(&mission.project_id, &mission.id, &claim, now())
            .is_ok()
    );
}

#[test]
fn mission_loop_two_connections_cannot_claim_the_same_revision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("race.sqlite3");
    let mut first = ProjectStore::open(&path, &key()).unwrap();
    let mission = seed(&mut first);
    let mut second = ProjectStore::open(&path, &key()).unwrap();
    let one = command(
        &first,
        &mission,
        agent(),
        LoopAction::Claim {
            host: host(),
            todo_id: "slice".into(),
            token_digest: hash("one"),
        },
    );
    let mut two = one.clone();
    two.operation_id = "different-operation".into();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let scope = (mission.project_id.clone(), mission.id.clone());
    let other_scope = scope.clone();
    let other_barrier = barrier.clone();
    let other = std::thread::spawn(move || {
        other_barrier.wait();
        second
            .apply_mission_loop_command(&other_scope.0, &other_scope.1, &two, now())
            .is_ok()
    });
    barrier.wait();
    let first_won = first
        .apply_mission_loop_command(&scope.0, &scope.1, &one, now())
        .is_ok();
    assert_ne!(first_won, other.join().unwrap());
    let snapshot = first
        .mission_loop_snapshot(&scope.0, &scope.1, now())
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot
            .state
            .todos()
            .values()
            .filter(|todo| todo.claim.is_some())
            .count(),
        1
    );
}

#[test]
fn mission_loop_migration_v51_preserves_mission_and_is_transactional_on_collision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("migration.sqlite3");
    let mut store = ProjectStore::open(&path, &key()).unwrap();
    let mission = seed(&mut store);
    store.connection.execute_batch("DROP TABLE mission_loop_operations; DROP TABLE mission_loops; DELETE FROM schema_migrations WHERE version = 52; CREATE TABLE mission_loop_operations (collision TEXT)").unwrap();
    drop(store);
    assert!(ProjectStore::open(&path, &key()).is_err());
    let connection = Connection::open(&path).unwrap();
    crate::apply_database_key(&connection, &key()).unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM schema_migrations WHERE version = 52",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name = 'mission_loops'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    connection
        .execute_batch("DROP TABLE mission_loop_operations")
        .unwrap();
    drop(connection);
    let reopened = ProjectStore::open(&path, &key()).unwrap();
    assert_eq!(reopened.schema_version().unwrap(), 52);
    assert_eq!(
        reopened
            .load_mission(&mission.project_id, &mission.id)
            .unwrap(),
        mission
    );
    assert!(
        reopened
            .mission_loop_snapshot(&mission.project_id, &mission.id, now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn mission_loop_scope_record_and_schema_tampering_fail_closed() {
    let mut store = ProjectStore::in_memory().unwrap();
    let mission = seed(&mut store);
    assert!(
        store
            .mission_loop_snapshot(&ProjectId::from("other"), &mission.id, now())
            .is_err()
    );
    store
        .connection
        .execute("UPDATE mission_loops SET revision = revision + 1", [])
        .unwrap();
    assert!(matches!(
        store.mission_loop_snapshot(&mission.project_id, &mission.id, now()),
        Err(StorageError::MissionLoop(LoopError::InvalidState))
    ));
    store
        .connection
        .execute_batch(
            "DROP TABLE mission_loop_operations; CREATE TABLE mission_loop_operations (fake TEXT)",
        )
        .unwrap();
    assert!(verify_schema(&store.connection).is_err());
}

#[test]
fn mission_loop_reopen_keeps_ambiguous_claim_and_rejects_reinitialization() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("crash.sqlite3");
    let mut store = ProjectStore::open(&path, &key()).unwrap();
    let mission = seed(&mut store);
    apply(
        &mut store,
        &mission,
        agent(),
        LoopAction::Claim {
            host: host(),
            todo_id: "slice".into(),
            token_digest: hash("token"),
        },
    );
    drop(store);
    let mut reopened = ProjectStore::open(&path, &key()).unwrap();
    let later = now() + Duration::seconds(61);
    let snapshot = reopened
        .mission_loop_snapshot(&mission.project_id, &mission.id, later)
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot
            .state
            .should_run(snapshot.facts(), &host(), later)
            .unwrap()
            .mode,
        LoopMode::ReconcileRequired
    );
    assert_eq!(
        reopened
            .create_mission_loop(
                &mission.project_id,
                &mission.id,
                policy(),
                mission.revision,
                later
            )
            .unwrap(),
        snapshot.state
    );
    let mut replacement = policy();
    replacement.max_slots += 1;
    assert!(matches!(
        reopened.create_mission_loop(
            &mission.project_id,
            &mission.id,
            replacement,
            mission.revision,
            later
        ),
        Err(StorageError::MissionLoopReplayConflict)
    ));
}

#[test]
fn mission_loop_crash_after_evidence_writeback_recovers_settlement_without_host_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("writeback-crash.sqlite3");
    let mut store = ProjectStore::open(&path, &key()).unwrap();
    let mut mission = seed(&mut store);
    let claim = apply(
        &mut store,
        &mission,
        agent(),
        LoopAction::Claim {
            host: host(),
            todo_id: "slice".into(),
            token_digest: hash("token"),
        },
    )
    .claim
    .unwrap();
    apply(
        &mut store,
        &mission,
        agent(),
        LoopAction::BeginExecution {
            claim: claim.clone(),
            host: host(),
        },
    );
    let previous = mission.revision;
    mission
        .record_evidence(
            Evidence {
                id: EvidenceId::from("crash-evidence"),
                title: "Durable oracle result".into(),
                source_uri: "test://readback".into(),
                observed_at: now(),
                confidence: 1.0,
                status: EvidenceStatus::Confirmed,
                content_digest: hash("persisted before crash"),
            },
            now(),
        )
        .unwrap();
    store
        .update_mission_atomic(&mission, previous, &[event()])
        .unwrap();
    drop(store);
    let mut reopened = ProjectStore::open(&path, &key()).unwrap();
    let later = now() + Duration::hours(1);
    let snapshot = reopened
        .mission_loop_snapshot(&mission.project_id, &mission.id, later)
        .unwrap()
        .unwrap();
    let recover = LoopCommand {
        operation_id: "recover-original-writeback".into(),
        expected_revision: snapshot.state.revision(),
        expected_mission_revision: mission.revision,
        actor: operator(),
        action: LoopAction::ReconcileSettlement {
            claim,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([EvidenceId::from("crash-evidence")]),
                continuation: LoopContinuation::NoFollowup,
            },
            readback_digest: hash("independent readback matches original evidence"),
        },
    };
    assert!(
        reopened
            .apply_mission_loop_command(&mission.project_id, &mission.id, &recover, later)
            .unwrap()
            .run
            .unwrap()
            .spent_slot
    );
    assert!(
        reopened
            .apply_mission_loop_command(&mission.project_id, &mission.id, &recover, later)
            .unwrap()
            .replayed
    );
    let recovered = reopened
        .mission_loop_snapshot(&mission.project_id, &mission.id, later)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.state.spent_slots(), 1);
    assert_eq!(recovered.mission.evidence.len(), 1);
    assert_eq!(recovered.state.recent_runs().len(), 1);
    assert_eq!(
        recovered.state.todos()["slice"].status,
        hartevo_domain_kernel::mission_loop::LoopTodoStatus::Completed
    );
}
