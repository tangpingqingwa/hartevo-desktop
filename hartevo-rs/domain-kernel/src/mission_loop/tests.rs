use super::*;
use crate::{Evidence, EvidenceStatus, MissionContract, MissionStage, Task, TaskStatus};
use chrono::{Duration, TimeZone};

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 7, 8, 0, 0).unwrap()
}
fn hash(value: &str) -> String {
    loop_digest(&value).unwrap()
}
fn operator() -> LoopActor {
    LoopActor::Operator(ActorId::from("operator"))
}
fn agent(id: &str) -> LoopActor {
    LoopActor::Agent(id.into())
}
fn host(id: &str) -> LoopHost {
    LoopHost {
        agent_id: id.into(),
        available_capabilities: BTreeSet::from(["research.discover".into()]),
        workspace_digest: hash("workspace"),
    }
}
fn facts(mission: &Mission) -> LoopMissionFacts<'_> {
    LoopMissionFacts {
        mission,
        steering_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }
}
fn command(
    state: &MissionLoop,
    mission: &Mission,
    actor: LoopActor,
    action: LoopAction,
) -> LoopCommand {
    LoopCommand {
        operation_id: format!("operation-{}", state.revision()),
        expected_revision: state.revision(),
        expected_mission_revision: mission.revision,
        actor,
        action,
    }
}
fn apply(
    state: &mut MissionLoop,
    mission: &Mission,
    actor: LoopActor,
    action: LoopAction,
    at: DateTime<Utc>,
) -> LoopReceipt {
    state
        .apply(facts(mission), &command(state, mission, actor, action), at)
        .unwrap()
}
fn fixture() -> (MissionLoop, Mission) {
    let mut mission = Mission::compile(
        TenantId::from("tenant"),
        MissionId::from("mission"),
        ProjectId::from("project"),
        "Research",
        MissionContract::bootstrap("Verify the objective", ["research.discover".into()], now()),
        now(),
    )
    .unwrap();
    mission
        .start_research(
            [Task {
                id: TaskId::from("task"),
                title: "Research".into(),
                status: TaskStatus::Running,
                capability: "research.discover".into(),
            }],
            now(),
        )
        .unwrap();
    let policy = LoopPolicy {
        operator_id: ActorId::from("operator"),
        max_slots: 4,
        max_parallel: 2,
        lease_seconds: 60,
        stall_limit: 2,
    };
    let mut state = MissionLoop::new(&mission, policy, now()).unwrap();
    for id in ["alice", "bob"] {
        apply(
            &mut state,
            &mission,
            operator(),
            LoopAction::RegisterPeer {
                peer: LoopPeer {
                    id: id.into(),
                    capabilities: host(id).available_capabilities,
                    workspace_digest: hash("workspace"),
                },
            },
            now(),
        );
    }
    (state, mission)
}
fn todo(id: &str) -> LoopTodoSpec {
    LoopTodoSpec {
        id: id.into(),
        title: format!("Private work: {id}"),
        task_id: Some(TaskId::from("task")),
        capability: Some("research.discover".into()),
        kind: LoopWorkKind::Advancement,
        priority: 1,
        depends_on: BTreeSet::new(),
        eligible_agents: BTreeSet::new(),
        required_decisions: BTreeSet::new(),
        workspace_digest: hash("workspace"),
        write_scopes: BTreeSet::new(),
        monitor: None,
    }
}
fn add(state: &mut MissionLoop, mission: &Mission, spec: LoopTodoSpec) {
    apply(
        state,
        mission,
        operator(),
        LoopAction::AddTodo { todo: spec },
        now(),
    );
}
fn claim(
    state: &mut MissionLoop,
    mission: &Mission,
    id: &str,
    peer: &str,
    at: DateTime<Utc>,
) -> LoopClaim {
    apply(
        state,
        mission,
        agent(peer),
        LoopAction::Claim {
            host: host(peer),
            todo_id: id.into(),
            token_digest: hash(&format!("{id}-{peer}")),
        },
        at,
    )
    .claim
    .unwrap()
}
fn begin(
    state: &mut MissionLoop,
    mission: &Mission,
    id: &str,
    peer: &str,
    at: DateTime<Utc>,
) -> LoopClaim {
    let claim = claim(state, mission, id, peer, at);
    apply(
        state,
        mission,
        agent(peer),
        LoopAction::BeginExecution {
            claim: claim.clone(),
            host: host(peer),
        },
        at,
    );
    claim
}
fn evidence(mission: &mut Mission, id: &str, at: DateTime<Utc>) -> EvidenceId {
    let id = EvidenceId::from_stable(id);
    mission
        .record_evidence(
            Evidence {
                id: id.clone(),
                title: "Verified observation".into(),
                source_uri: "test://oracle".into(),
                observed_at: at,
                confidence: 1.0,
                status: EvidenceStatus::Confirmed,
                content_digest: hash(id.as_str()),
            },
            at,
        )
        .unwrap();
    id
}

#[test]
fn decision_is_read_only_and_empty_checklist_does_not_complete_mission() {
    let (state, mut mission) = fixture();
    let before = state.clone();
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .mode,
        LoopMode::Replan
    );
    assert_eq!(state, before);
    mission.stage = MissionStage::Completed;
    let decision = state
        .should_run(facts(&mission), &host("alice"), now())
        .unwrap();
    assert_eq!(decision.mode, LoopMode::Terminal);
    assert_eq!(decision.wake, LoopWake::Stop);
}

#[test]
fn scoped_human_gate_allows_independent_peer_and_action() {
    let (mut state, mission) = fixture();
    let mut blocked = todo("blocked");
    blocked
        .required_decisions
        .insert("direction:experiment:target".into());
    add(&mut state, &mission, blocked);
    add(&mut state, &mission, todo("independent"));
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::OpenGate {
            gate: LoopUserGate {
                id: "choose-target".into(),
                question: "Which target should this experiment use?".into(),
                scope: LoopGateScope::Decision("direction:experiment".into()),
            },
        },
        now(),
    );
    let decision = state
        .should_run(facts(&mission), &host("alice"), now())
        .unwrap();
    assert_eq!(decision.selected_todo.as_deref(), Some("independent"));
    assert!(decision.user.notify);
    apply(
        &mut state,
        &mission,
        agent("alice"),
        LoopAction::AcknowledgeNotice {
            notification_digest: decision.user.notification_digest.unwrap(),
        },
        now(),
    );
    assert!(
        !state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .user
            .notify
    );
    let before = state.clone();
    let cmd = command(
        &state,
        &mission,
        agent("alice"),
        LoopAction::ResolveGate {
            gate_id: "choose-target".into(),
            decision_digest: hash("pick"),
        },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::OperatorRequired)
    );
    assert_eq!(state, before);
}

#[test]
fn scoped_notices_stay_acknowledged_when_another_peer_answers_its_question() {
    let (mut state, mission) = fixture();
    for peer in ["alice", "bob"] {
        apply(
            &mut state,
            &mission,
            operator(),
            LoopAction::OpenGate {
                gate: LoopUserGate {
                    id: format!("{peer}-gate"),
                    question: format!("Choose {peer}'s direction"),
                    scope: LoopGateScope::Agent(peer.into()),
                },
            },
            now(),
        );
    }
    for peer in ["alice", "bob"] {
        let notice = state.user_channel(peer).unwrap();
        assert!(notice.notify);
        apply(
            &mut state,
            &mission,
            agent(peer),
            LoopAction::AcknowledgeNotice {
                notification_digest: notice.notification_digest.unwrap(),
            },
            now(),
        );
    }
    assert!(!state.user_channel("alice").unwrap().notify);
    assert!(!state.user_channel("bob").unwrap().notify);
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::ResolveGate {
            gate_id: "alice-gate".into(),
            decision_digest: hash("answer Alice"),
        },
        now(),
    );
    assert!(!state.user_channel("bob").unwrap().notify);
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::OpenGate {
            gate: LoopUserGate {
                id: "alice-gate".into(),
                question: "Choose alice's direction".into(),
                scope: LoopGateScope::Agent("alice".into()),
            },
        },
        now(),
    );
    assert!(state.user_channel("alice").unwrap().notify);
    assert!(!state.user_channel("bob").unwrap().notify);
}

#[test]
fn agent_gate_does_not_stop_other_registered_peer() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("work"));
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::OpenGate {
            gate: LoopUserGate {
                id: "alice-gate".into(),
                question: "Choose Alice's direction".into(),
                scope: LoopGateScope::Agent("alice".into()),
            },
        },
        now(),
    );
    assert!(
        !state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .should_run()
    );
    assert!(
        state
            .should_run(facts(&mission), &host("bob"), now())
            .unwrap()
            .should_run()
    );
}

#[test]
fn capability_and_workspace_are_rechecked_on_selected_work() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("work"));
    let mut unavailable = host("alice");
    unavailable.available_capabilities.clear();
    assert_eq!(
        state
            .should_run(facts(&mission), &unavailable, now())
            .unwrap()
            .mode,
        LoopMode::CapabilityUnavailable
    );
    unavailable = host("alice");
    unavailable.workspace_digest = hash("wrong");
    assert_eq!(
        state
            .should_run(facts(&mission), &unavailable, now())
            .unwrap()
            .mode,
        LoopMode::WorkspaceMismatch
    );
    assert_eq!(
        state.should_run(facts(&mission), &host("unknown"), now()),
        Err(LoopError::UnknownAgent)
    );
}

#[test]
fn peers_reserve_quota_and_conflicting_paths_cannot_run_together() {
    let (mut state, mission) = fixture();
    let mut first = todo("first");
    first.write_scopes.insert("src".into());
    let mut second = todo("second");
    second.write_scopes.insert("src/lib.rs".into());
    add(&mut state, &mission, first);
    add(&mut state, &mission, second);
    add(&mut state, &mission, todo("third"));
    claim(&mut state, &mission, "first", "alice", now());
    assert!(
        !state
            .decision_for_todo(facts(&mission), &host("bob"), "second", now())
            .unwrap()
            .should_run()
    );
    assert_eq!(
        state
            .should_run(facts(&mission), &host("bob"), now())
            .unwrap()
            .selected_todo
            .as_deref(),
        Some("third")
    );
    let (mut budget, mission) = fixture();
    add(&mut budget, &mission, todo("first"));
    add(&mut budget, &mission, todo("second"));
    apply(
        &mut budget,
        &mission,
        operator(),
        LoopAction::SetQuota { max_slots: 1 },
        now(),
    );
    claim(&mut budget, &mission, "first", "alice", now());
    assert_eq!(
        budget
            .should_run(facts(&mission), &host("bob"), now())
            .unwrap()
            .mode,
        LoopMode::QuotaExhausted
    );
    assert_eq!(budget.spent_slots(), 0);
}

#[test]
fn priority_is_advisory_and_actor_cannot_impersonate_a_peer() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("first"));
    let mut last = todo("last");
    last.priority = 99;
    add(&mut state, &mission, last);
    assert!(
        state
            .decision_for_todo(facts(&mission), &host("alice"), "last", now())
            .unwrap()
            .should_run()
    );
    let cmd = command(
        &state,
        &mission,
        agent("alice"),
        LoopAction::Claim {
            host: host("bob"),
            todo_id: "last".into(),
            token_digest: hash("secret"),
        },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::ActorMismatch)
    );
    claim(&mut state, &mission, "last", "alice", now());
}

#[test]
fn expired_claim_is_not_automatically_reexecuted() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("work"));
    let old = begin(&mut state, &mission, "work", "alice", now());
    let later = now() + Duration::seconds(61);
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), later)
            .unwrap()
            .mode,
        LoopMode::ReconcileRequired
    );
    assert_eq!(
        state.require_claim(facts(&mission), &old, later),
        Err(LoopError::ClaimLost)
    );
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::ReconcileRetry {
            todo_id: "work".into(),
            evidence_digest: hash("independent readback: absent"),
        },
        later,
    );
    let new = claim(&mut state, &mission, "work", "bob", later);
    assert!(new.generation > old.generation);
    assert_eq!(
        state.require_claim(facts(&mission), &old, later),
        Err(LoopError::ClaimLost)
    );
}

#[test]
fn steering_and_pause_revoke_in_flight_claims_without_spend() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("work"));
    let active = begin(&mut state, &mission, "work", "alice", now());
    let changed = hash("new user correction");
    assert_eq!(
        state.require_claim(
            LoopMissionFacts {
                mission: &mission,
                steering_digest: &changed
            },
            &active,
            now()
        ),
        Err(LoopError::ClaimLost)
    );
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::Pause { paused: true },
        now(),
    );
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .mode,
        LoopMode::Paused
    );
    apply(
        &mut state,
        &mission,
        operator(),
        LoopAction::Pause { paused: false },
        now(),
    );
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .mode,
        LoopMode::ReconcileRequired
    );
    assert_eq!(state.spent_slots(), 0);
}

#[test]
fn model_steps_stop_when_the_bound_task_advances_but_finished_work_can_settle() {
    let (mut state, mut mission) = fixture();
    add(&mut state, &mission, todo("work"));
    let active = begin(&mut state, &mission, "work", "alice", now());
    assert!(
        state
            .require_execution(facts(&mission), &active, now())
            .is_ok()
    );
    for status in [TaskStatus::Completed, TaskStatus::Cancelled] {
        mission.tasks[0].status = status;
        assert_eq!(
            state.require_execution(facts(&mission), &active, now()),
            Err(LoopError::ClaimLost)
        );
    }
    let id = evidence(&mut mission, "already-finished-work", now());
    let receipt = apply(
        &mut state,
        &mission,
        agent("alice"),
        LoopAction::Settle {
            claim: active,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([id]),
                continuation: LoopContinuation::Replan,
            },
        },
        now(),
    );
    assert!(receipt.run.unwrap().spent_slot);
}

#[test]
fn begin_execution_is_single_use_and_settlement_requires_fresh_confirmed_evidence() {
    let (mut state, mut mission) = fixture();
    add(&mut state, &mission, todo("work"));
    let active = begin(&mut state, &mission, "work", "alice", now());
    let cmd = command(
        &state,
        &mission,
        agent("alice"),
        LoopAction::BeginExecution {
            claim: active.clone(),
            host: host("alice"),
        },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::ExecutionAlreadyStarted)
    );
    let before = state.clone();
    let cmd = command(
        &state,
        &mission,
        agent("alice"),
        LoopAction::Settle {
            claim: active.clone(),
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::new(),
                continuation: LoopContinuation::NoFollowup,
            },
        },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::EvidenceRequired)
    );
    assert_eq!(state, before);
    let id = evidence(&mut mission, "new-evidence", now());
    let receipt = apply(
        &mut state,
        &mission,
        agent("alice"),
        LoopAction::Settle {
            claim: active,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([id]),
                continuation: LoopContinuation::NoFollowup,
            },
        },
        now(),
    );
    assert!(receipt.run.unwrap().spent_slot);
    assert_eq!(state.spent_slots(), 1);
    assert_eq!(mission.stage, MissionStage::Running);
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .mode,
        LoopMode::Replan
    );
}

#[test]
fn evidence_cannot_be_reused_to_spend_another_slot() {
    let (mut state, mut mission) = fixture();
    add(&mut state, &mission, todo("a"));
    add(&mut state, &mission, todo("b"));
    let first = begin(&mut state, &mission, "a", "alice", now());
    let id = evidence(&mut mission, "evidence", now());
    apply(
        &mut state,
        &mission,
        agent("alice"),
        LoopAction::Settle {
            claim: first,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([id.clone()]),
                continuation: LoopContinuation::NextTodo("b".into()),
            },
        },
        now(),
    );
    let second = begin(&mut state, &mission, "b", "alice", now());
    let cmd = command(
        &state,
        &mission,
        agent("alice"),
        LoopAction::Settle {
            claim: second,
            result: LoopTurnResult::Progress {
                evidence_ids: BTreeSet::from([id]),
                continuation: LoopContinuation::NoFollowup,
            },
        },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::EvidenceRequired)
    );
    assert_eq!(state.spent_slots(), 1);
}

#[test]
fn no_progress_requires_repair_instead_of_endless_model_turns() {
    let (mut state, mission) = fixture();
    add(&mut state, &mission, todo("work"));
    for _ in 0..2 {
        let active = begin(&mut state, &mission, "work", "alice", now());
        apply(
            &mut state,
            &mission,
            agent("alice"),
            LoopAction::Settle {
                claim: active,
                result: LoopTurnResult::NoProgress {
                    reason_digest: hash("nothing changed"),
                },
            },
            now(),
        );
    }
    let decision = state
        .should_run(facts(&mission), &host("alice"), now())
        .unwrap();
    assert_eq!(decision.mode, LoopMode::Repair);
    assert!(!decision.should_run());
    assert_eq!(state.spent_slots(), 0);
    let mut repair = todo("repair");
    repair.kind = LoopWorkKind::Repair;
    repair.task_id = None;
    repair.capability = None;
    add(&mut state, &mission, repair);
    assert_eq!(
        state
            .should_run(facts(&mission), &host("alice"), now())
            .unwrap()
            .selected_todo
            .as_deref(),
        Some("repair")
    );
}

#[test]
fn repair_and_replan_stop_after_their_own_bounded_unproductive_attempts() {
    for kind in [LoopWorkKind::Repair, LoopWorkKind::Replan] {
        for result in [
            LoopTurnResult::NoProgress {
                reason_digest: hash("nothing changed"),
            },
            LoopTurnResult::Failed {
                evidence_digest: hash("known failure"),
                uncertain: false,
            },
        ] {
            let (mut state, mission) = fixture();
            let mut spec = todo("bounded-recovery");
            spec.kind = kind;
            spec.task_id = None;
            spec.capability = None;
            add(&mut state, &mission, spec.clone());
            for _ in 0..state.policy().stall_limit {
                let active = begin(&mut state, &mission, &spec.id, "alice", now());
                apply(
                    &mut state,
                    &mission,
                    agent("alice"),
                    LoopAction::Settle {
                        claim: active,
                        result: result.clone(),
                    },
                    now(),
                );
            }
            let decision = state
                .should_run(facts(&mission), &host("alice"), now())
                .unwrap();
            assert!(!decision.should_run());
            assert_eq!(decision.mode, LoopMode::Replan);
            assert_eq!(decision.wake, LoopWake::OnStateChange);
            assert_eq!(state.spent_slots(), 0);
            spec.id = "new-recovery-plan".into();
            add(&mut state, &mission, spec);
            assert_eq!(
                state
                    .should_run(facts(&mission), &host("alice"), now())
                    .unwrap()
                    .selected_todo
                    .as_deref(),
                Some("new-recovery-plan")
            );
        }
    }
}

#[test]
fn monitor_coalesces_missed_ticks_and_notifies_only_on_change_without_spending() {
    let (mut state, mission) = fixture();
    let mut monitor = todo("monitor");
    monitor.kind = LoopWorkKind::Monitor;
    monitor.monitor = Some(LoopMonitor {
        target_digest: hash("ci-checks"),
        next_due_at: now(),
        interval_seconds: 30,
        expires_at: now() + Duration::minutes(10),
    });
    add(&mut state, &mission, monitor);
    for (seconds, value, changed) in [
        (0, "pending", false),
        (95, "pending", false),
        (120, "passed", true),
    ] {
        let at = now() + Duration::seconds(seconds);
        let active = begin(&mut state, &mission, "monitor", "alice", at);
        let receipt = apply(
            &mut state,
            &mission,
            agent("alice"),
            LoopAction::Settle {
                claim: active,
                result: LoopTurnResult::MonitorObservation {
                    observation_digest: hash(value),
                },
            },
            at,
        );
        let run = receipt.run.unwrap();
        assert_eq!(run.notify, changed);
        assert!(!run.spent_slot);
        assert!(
            !state
                .should_run(facts(&mission), &host("alice"), at)
                .unwrap()
                .should_run()
        );
    }
    assert_eq!(
        state.todos()["monitor"]
            .spec
            .monitor
            .as_ref()
            .unwrap()
            .next_due_at,
        now() + Duration::seconds(150)
    );
    assert_eq!(state.spent_slots(), 0);
    assert!(
        !state
            .should_run(
                facts(&mission),
                &host("alice"),
                now() + Duration::minutes(11)
            )
            .unwrap()
            .should_run()
    );
}

#[test]
fn malformed_scope_dependency_or_clock_is_rejected_without_partial_mutation() {
    let (mut state, mission) = fixture();
    for path in ["../secret", "/absolute", "a/../b", "a//b", "a\\b"] {
        let mut spec = todo("bad");
        spec.write_scopes.insert(path.into());
        let before = state.clone();
        let cmd = command(
            &state,
            &mission,
            operator(),
            LoopAction::AddTodo { todo: spec },
        );
        assert_eq!(
            state.apply(facts(&mission), &cmd, now()),
            Err(LoopError::InvalidTodo)
        );
        assert_eq!(state, before);
    }
    let mut spec = todo("bad");
    spec.depends_on.insert("missing".into());
    let cmd = command(
        &state,
        &mission,
        operator(),
        LoopAction::AddTodo { todo: spec },
    );
    assert_eq!(
        state.apply(facts(&mission), &cmd, now()),
        Err(LoopError::InvalidTodo)
    );
    assert_eq!(
        state.should_run(
            facts(&mission),
            &host("alice"),
            now() - Duration::seconds(1)
        ),
        Err(LoopError::ClockRegression)
    );
    assert!(!format!("{:?}", todo("hidden-title")).contains("hidden-title"));
}
