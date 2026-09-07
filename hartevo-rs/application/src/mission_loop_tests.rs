use super::*;
use crate::{CreateProject, EvidenceInput, ResearchPacket, StartMission};
use chrono::{Duration, TimeZone};
use hartevo_domain_kernel::mission_loop::{
    LoopContinuation, LoopGateScope, LoopMode, LoopPeer, LoopTodoStatus, LoopWorkKind,
};
use hartevo_domain_kernel::{ActorId, EvidenceId, StorageMode, TaskId, TenantId, WorkProductId};
use hartevo_storage::ProjectStore;
use std::cell::Cell;
use std::collections::BTreeSet;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 7, 8, 0, 0).unwrap()
}
fn hash(value: &str) -> String {
    loop_digest(&value).unwrap()
}
fn request() -> RunMissionLoopSlice {
    RunMissionLoopSlice {
        project_id: ProjectId::from("project"),
        mission_id: MissionId::from("mission"),
        operation_id: "bounded-run-1".into(),
        host: LoopHost {
            agent_id: "desktop".into(),
            available_capabilities: BTreeSet::from(["research.discover".into()]),
            workspace_digest: hash("workspace"),
        },
        todo_id: Some("research-slice".into()),
    }
}
fn operate(service: &mut ApplicationService, action: LoopAction) -> LoopReceipt {
    operate_at(service, action, now())
}
fn operate_at(
    service: &mut ApplicationService,
    action: LoopAction,
    at: DateTime<Utc>,
) -> LoopReceipt {
    let request = request();
    let snapshot = service
        .require_loop_snapshot(&request.project_id, &request.mission_id, at)
        .unwrap();
    service
        .apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &LoopCommand {
                operation_id: format!("operator-{}", snapshot.state.revision()),
                expected_revision: snapshot.state.revision(),
                expected_mission_revision: snapshot.mission.revision,
                actor: LoopActor::Operator(ActorId::from("operator")),
                action,
            },
            at,
        )
        .unwrap()
}
fn setup() -> ApplicationService {
    setup_with(ProjectStore::in_memory().unwrap())
}

fn setup_with(store: ProjectStore) -> ApplicationService {
    let mut service = ApplicationService::new(store);
    let request = request();
    service
        .create_project(
            CreateProject {
                tenant_id: TenantId::from("tenant"),
                id: request.project_id.clone(),
                name: "Project".into(),
                description: String::new(),
                workspace_root: "/workspace".into(),
                storage_mode: StorageMode::LocalExisting,
            },
            now(),
        )
        .unwrap();
    let mission = service
        .start_mission(
            StartMission {
                id: request.mission_id.clone(),
                research_task_id: TaskId::from("research-task"),
                project_id: request.project_id.clone(),
                title: Some("Research".into()),
                prompt: "Find source-backed evidence".into(),
            },
            now(),
        )
        .unwrap();
    service
        .configure_mission_loop(
            &request.project_id,
            &request.mission_id,
            LoopPolicy {
                operator_id: ActorId::from("operator"),
                max_slots: 5,
                max_parallel: 2,
                lease_seconds: 120,
                stall_limit: 2,
            },
            mission.revision,
            now(),
        )
        .unwrap();
    operate(
        &mut service,
        LoopAction::RegisterPeer {
            peer: LoopPeer {
                id: "desktop".into(),
                capabilities: request.host.available_capabilities,
                workspace_digest: hash("workspace"),
            },
        },
    );
    operate(
        &mut service,
        LoopAction::AddTodo {
            todo: LoopTodoSpec {
                id: "research-slice".into(),
                title: "Verify one evidence packet".into(),
                task_id: Some(TaskId::from("research-task")),
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
    service
}

#[test]
fn mission_loop_application_runs_one_slice_through_existing_evidence_and_work_product_commands() {
    let mut service = setup();
    let request = request();
    let calls = Cell::new(0);
    let clock = Cell::new(now());
    let receipt = service
        .run_mission_loop_slice(
            &request,
            || clock.get(),
            |application, handoff| {
                calls.set(calls.get() + 1);
                assert_eq!(handoff.objective, "Find source-backed evidence");
                assert!(!format!("{handoff:?}").contains(&handoff.objective));
                clock.set(now() + Duration::seconds(30));
                let snapshot = application
                    .require_loop_snapshot(&request.project_id, &request.mission_id, clock.get())
                    .unwrap();
                application
                    .apply_mission_loop_command(
                        &request.project_id,
                        &request.mission_id,
                        &LoopCommand {
                            operation_id: "renew-running-slice".into(),
                            expected_revision: snapshot.state.revision(),
                            expected_mission_revision: snapshot.mission.revision,
                            actor: LoopActor::Agent("desktop".into()),
                            action: LoopAction::Heartbeat {
                                claim: handoff.claim.clone(),
                            },
                        },
                        clock.get(),
                    )
                    .unwrap();
                // Finish after the original lease, inside the persisted renewal.
                clock.set(now() + Duration::seconds(130));
                application
                    .record_research(
                        &handoff.project_id,
                        &handoff.mission_id,
                        ResearchPacket {
                            work_product_id: WorkProductId::from("research-result"),
                            title: "Evidence packet".into(),
                            body: "A verified bounded finding".into(),
                            work_product_type: "document.evidence_pack".into(),
                            fact_ids: BTreeSet::new(),
                            task_ids: BTreeSet::from([TaskId::from("research-task")]),
                            file_digest: None,
                            preview_media_type: "text/markdown".into(),
                            preview: "A verified bounded finding".into(),
                            editable_scopes: BTreeSet::from(["/content".into()]),
                            evidence: vec![EvidenceInput {
                                id: EvidenceId::from("evidence"),
                                title: "Oracle observation".into(),
                                source_uri: "test://independent-oracle".into(),
                                confidence: 1.0,
                                content: "the observed result".into(),
                            }],
                        },
                        clock.get(),
                    )
                    .unwrap();
                Ok(LoopTurnResult::Progress {
                    evidence_ids: BTreeSet::from([EvidenceId::from("evidence")]),
                    continuation: LoopContinuation::NoFollowup,
                })
            },
        )
        .unwrap();
    assert!(receipt.run.unwrap().spent_slot);
    assert_eq!(calls.get(), 1);
    let snapshot = service
        .require_loop_snapshot(&request.project_id, &request.mission_id, clock.get())
        .unwrap();
    assert_eq!(snapshot.state.spent_slots(), 1);
    assert_eq!(snapshot.mission.work_products.len(), 1);
    assert!(snapshot.mission.effects.is_empty());
    assert!(!snapshot.mission.stage.is_terminal());
    assert!(
        service
            .run_mission_loop_slice(
                &request,
                || clock.get(),
                |_, _| {
                    calls.set(calls.get() + 1);
                    Ok(LoopTurnResult::NoProgress {
                        reason_digest: hash("should not run"),
                    })
                }
            )
            .is_err()
    );
    assert_eq!(calls.get(), 1);
}

#[test]
fn mission_loop_application_wait_does_not_invoke_runtime_or_spend() {
    let mut service = setup();
    let request = request();
    operate(
        &mut service,
        LoopAction::OpenGate {
            gate: LoopUserGate {
                id: "owner-question".into(),
                question: "Select the evidence source".into(),
                scope: LoopGateScope::Mission,
            },
        },
    );
    let calls = Cell::new(0);
    let outcome = service.run_mission_loop_slice(&request, now, |_, _| {
        calls.set(calls.get() + 1);
        Ok(LoopTurnResult::NoProgress {
            reason_digest: hash("unused"),
        })
    });
    assert!(
        matches!(outcome, Err(MissionLoopApplicationError::Deferred(decision)) if decision.mode == LoopMode::UserActionRequired)
    );
    assert_eq!(calls.get(), 0);
    assert_eq!(
        service
            .require_loop_snapshot(&request.project_id, &request.mission_id, now())
            .unwrap()
            .state
            .spent_slots(),
        0
    );
}

#[test]
fn mission_loop_application_rechecks_task_after_durable_dispatch_before_callback() {
    use hartevo_domain_kernel::TaskStatus;
    use hartevo_storage::DatabaseKey;
    use std::cell::RefCell;

    for status in [TaskStatus::Completed, TaskStatus::Cancelled] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("task-close-race.sqlite3");
        let key = DatabaseKey::new([72; 32]).unwrap();
        let mut service = setup_with(ProjectStore::open(&path, &key).unwrap());
        let writer = RefCell::new(ProjectStore::open(&path, &key).unwrap());
        let request = request();
        let task_closed = Cell::new(false);
        let calls = Cell::new(0);
        let result = service.run_mission_loop_slice(
            &request,
            || {
                let mut writer = writer.borrow_mut();
                let snapshot = writer
                    .mission_loop_snapshot(&request.project_id, &request.mission_id, now())
                    .unwrap()
                    .unwrap();
                if snapshot.state.todos()["research-slice"].execution_started
                    && !task_closed.replace(true)
                {
                    let mut mission = snapshot.mission;
                    mission.tasks[0].status = status.clone();
                    mission.revision += 1;
                    writer.save_mission(&mission).unwrap();
                }
                now()
            },
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(LoopTurnResult::NoProgress {
                    reason_digest: hash("must not run"),
                })
            },
        );
        assert!(task_closed.get());
        assert_eq!(calls.get(), 0);
        assert!(matches!(
            result,
            Err(MissionLoopApplicationError::Domain(LoopError::ClaimLost))
        ));
        let snapshot = service
            .require_loop_snapshot(&request.project_id, &request.mission_id, now())
            .unwrap();
        assert_eq!(snapshot.state.spent_slots(), 0);
        assert!(snapshot.state.todos()["research-slice"].execution_started);
    }
}

#[test]
fn mission_loop_application_runtime_failure_is_durable_and_does_not_retry_automatically() {
    let mut service = setup();
    let request = request();
    let receipt = service
        .run_mission_loop_slice(&request, now, |_, _| {
            Err(MissionLoopRunnerFailure {
                code: "provider_connection_lost",
            })
        })
        .unwrap();
    assert!(!receipt.run.unwrap().spent_slot);
    let snapshot = service
        .require_loop_snapshot(&request.project_id, &request.mission_id, now())
        .unwrap();
    assert_eq!(
        snapshot.state.todos()["research-slice"].status,
        LoopTodoStatus::Uncertain
    );
    assert_eq!(
        service
            .mission_loop_decision(
                &request.project_id,
                &request.mission_id,
                &request.host,
                now() + Duration::minutes(5)
            )
            .unwrap()
            .mode,
        LoopMode::ReconcileRequired
    );
    assert!(
        service
            .run_mission_loop_slice(&request, now, |_, _| panic!(
                "must not invoke a second time"
            ))
            .is_err()
    );
}

#[test]
fn mission_loop_application_rejects_unpersisted_progress_and_keeps_dispatch_reserved() {
    let mut service = setup();
    let request = request();
    let result = service.run_mission_loop_slice(&request, now, |_, _| {
        Ok(LoopTurnResult::Progress {
            evidence_ids: BTreeSet::from([EvidenceId::from("model-invented-evidence")]),
            continuation: LoopContinuation::NoFollowup,
        })
    });
    assert!(matches!(
        result,
        Err(MissionLoopApplicationError::Storage(
            StorageError::MissionLoop(LoopError::EvidenceRequired)
        ))
    ));
    let snapshot = service
        .require_loop_snapshot(&request.project_id, &request.mission_id, now())
        .unwrap();
    assert_eq!(snapshot.state.spent_slots(), 0);
    assert!(snapshot.state.todos()["research-slice"].execution_started);
    assert!(
        !service
            .mission_loop_decision(
                &request.project_id,
                &request.mission_id,
                &request.host,
                now()
            )
            .unwrap()
            .should_run()
    );
}

#[test]
fn mission_loop_application_steering_during_execution_cannot_write_stale_progress() {
    let mut service = setup();
    let request = request();
    let result = service.run_mission_loop_slice(&request, now, |application, _| {
        operate(
            application,
            LoopAction::Steer {
                rationale_digest: hash("operator changed direction"),
            },
        );
        Ok(LoopTurnResult::NoProgress {
            reason_digest: hash("old work"),
        })
    });
    assert!(matches!(
        result,
        Err(MissionLoopApplicationError::Storage(
            StorageError::MissionLoop(LoopError::ClaimLost)
        ))
    ));
    assert_eq!(
        service
            .mission_loop_decision(
                &request.project_id,
                &request.mission_id,
                &request.host,
                now()
            )
            .unwrap()
            .mode,
        LoopMode::ReconcileRequired
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "prove Cordis admission, busy reader, live pause and peer isolation against the same encrypted database"
)]
fn mission_loop_cordis_guard_reads_current_database_before_each_model_step() {
    use hartevo_cordis::{
        AgentInboxTarget, AgentPreStepDecision, CordisHost, SessionContentBlock, SessionId,
        SessionMessage, SessionMessageRole, SessionMessageSource, SessionStore, admit_agent_step,
    };
    use hartevo_storage::DatabaseKey;
    use std::sync::{Arc, Mutex};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cordis-loop.sqlite3");
    let key = DatabaseKey::new([71; 32]).unwrap();
    let mut service = setup_with(ProjectStore::open(&path, &key).unwrap());
    let request = request();
    let snapshot = service
        .require_loop_snapshot(&request.project_id, &request.mission_id, now())
        .unwrap();
    let claim_command = LoopCommand {
        operation_id: "claim-for-cordis".into(),
        expected_revision: snapshot.state.revision(),
        expected_mission_revision: snapshot.mission.revision,
        actor: LoopActor::Agent("desktop".into()),
        action: LoopAction::Claim {
            host: request.host.clone(),
            todo_id: "research-slice".into(),
            token_digest: hash("cordis-token"),
        },
    };
    let receipt = service
        .apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &claim_command,
            now(),
        )
        .unwrap();
    let claim = receipt.claim.unwrap();
    service
        .apply_mission_loop_command(
            &request.project_id,
            &request.mission_id,
            &LoopCommand {
                operation_id: "dispatch-for-cordis".into(),
                expected_revision: receipt.revision,
                expected_mission_revision: snapshot.mission.revision,
                actor: LoopActor::Agent("desktop".into()),
                action: LoopAction::BeginExecution {
                    claim: claim.clone(),
                    host: request.host,
                },
            },
            now(),
        )
        .unwrap();
    let reader = Arc::new(Mutex::new(ProjectStore::open(&path, &key).unwrap()));
    let binding = MissionLoopCordisBinding {
        project_id: request.project_id,
        mission_id: request.mission_id,
        runtime_agent_id: "cordis-session".into(),
        claim,
    };

    let preflight = |session_name: &str, at: DateTime<Utc>, proof: &LoopClaim| {
        let mut host = CordisHost::boot(false).unwrap();
        let mut binding = binding.clone();
        binding.claim = proof.clone();
        bind_cordis_mission_loop_guard(host.context_mut(), binding, reader.clone(), move || at)
            .unwrap();
        let session = host
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .create(SessionId::new(session_name).unwrap())
            .unwrap();
        session
            .inbox()
            .append_next_turn(SessionMessage {
                id: "user-input".into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::Text {
                    text: "Continue the bounded slice".into(),
                }],
                source: SessionMessageSource::User,
            })
            .unwrap();
        let turn = session.start_turn().unwrap();
        admit_agent_step(
            host.context_mut(),
            session.id(),
            AgentInboxTarget::NextTurn,
            turn,
            1,
        )
        .unwrap()
        .into_decision()
    };
    assert!(matches!(
        preflight("cordis-session", now(), &binding.claim),
        AgentPreStepDecision::Enter { .. }
    ));
    let mut invalid_proof = binding.claim.clone();
    invalid_proof.token_digest = hash("different-execution");
    assert_eq!(
        preflight("cordis-session", now(), &invalid_proof),
        AgentPreStepDecision::Reject
    );
    {
        let _busy = reader.lock().unwrap();
        assert_eq!(
            preflight("cordis-session", now(), &binding.claim),
            AgentPreStepDecision::Reject
        );
    }
    let renewal_at = now() + Duration::seconds(30);
    let snapshot = service
        .require_loop_snapshot(&binding.project_id, &binding.mission_id, renewal_at)
        .unwrap();
    service
        .apply_mission_loop_command(
            &binding.project_id,
            &binding.mission_id,
            &LoopCommand {
                operation_id: "renew-cordis-execution".into(),
                expected_revision: snapshot.state.revision(),
                expected_mission_revision: snapshot.mission.revision,
                actor: LoopActor::Agent("desktop".into()),
                action: LoopAction::Heartbeat {
                    claim: binding.claim.clone(),
                },
            },
            renewal_at,
        )
        .unwrap();
    let after_original_expiry = now() + Duration::seconds(130);
    assert!(matches!(
        preflight("cordis-session", after_original_expiry, &binding.claim),
        AgentPreStepDecision::Enter { .. }
    ));
    assert_eq!(
        preflight(
            "cordis-session",
            now() + Duration::seconds(150),
            &binding.claim
        ),
        AgentPreStepDecision::Reject
    );
    operate_at(
        &mut service,
        LoopAction::Pause { paused: true },
        after_original_expiry,
    );
    assert_eq!(
        preflight("cordis-session", after_original_expiry, &binding.claim),
        AgentPreStepDecision::Reject
    );
    assert!(matches!(
        preflight("unrelated-session", after_original_expiry, &binding.claim),
        AgentPreStepDecision::Enter { .. }
    ));
}
