use std::fmt;
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    AgentRef, ApprovalError, ApprovalOutcome, ApprovalPolicy, ApprovalPolicySource,
    ApprovalRequest, ApprovalRequestId, BailOutcome, CordisHost, LifecycleCancellation, NonBail,
    SessionApprovalAsked, SessionApprovalDecided, SessionEvent, SessionEventKind, SessionHandle,
    SessionHeader, SessionId, SessionLog, SessionStore, TurnEndReason, approval_events,
    register_agent, request_approval, session_events, set_approval_policy,
};

#[derive(Debug)]
struct TestError(&'static str);

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for TestError {}

fn live_session(host: &mut CordisHost, id: &str) -> (AgentRef, SessionHandle) {
    let agent = AgentRef::new(id);
    register_agent(host.context_mut(), agent.clone()).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions.create(SessionId::new(id).unwrap()).unwrap();
    session.start_turn().unwrap();
    (agent, session)
}

fn request(agent: AgentRef, cancellation: LifecycleCancellation) -> ApprovalRequest {
    ApprovalRequest::new(agent, "filesystem.write", cancellation)
        .unwrap()
        .with_call_id("call-1")
        .unwrap()
        .with_reason("requires one explicit write grant")
        .unwrap()
}

#[tokio::test]
async fn missing_answerer_fails_closed_and_keeps_a_balanced_non_surface_audit() {
    let mut host = CordisHost::boot(false).unwrap();
    let (agent, session) = live_session(&mut host, "approval-missing");

    let outcome = request_approval(
        host.context_mut(),
        &session,
        request(agent, LifecycleCancellation::default()),
    )
    .await
    .unwrap();

    assert_eq!(outcome, ApprovalOutcome::Unavailable);
    let events = session.events().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.kind.event_type())
            .collect::<Vec<_>>(),
        ["turn/start", "approval/asked", "approval/decided"]
    );
    let SessionEventKind::ApprovalAsked { approval: asked } = &events[1].kind else {
        unreachable!();
    };
    let SessionEventKind::ApprovalDecided { approval: decided } = &events[2].kind else {
        unreachable!();
    };
    assert_eq!(asked.id(), decided.id());
    assert_eq!(asked.tool_name(), "filesystem.write");
    assert_eq!(asked.call_id(), Some("call-1"));
    assert_eq!(decided.outcome(), ApprovalOutcome::Unavailable);
    assert!(session.derive_messages().unwrap().is_empty());
    assert!(session.surface().unwrap().nodes.is_empty());
    session.finish_turn(1, TurnEndReason::Completed).unwrap();
}

#[tokio::test]
async fn asked_is_flushed_before_answer_and_decided_is_flushed_before_return() {
    let mut host = CordisHost::boot(false).unwrap();
    let (agent, session) = live_session(&mut host, "approval-durable");
    let checkpoints = Arc::new(Mutex::new(Vec::<Vec<&'static str>>::new()));
    {
        let checkpoints = Arc::clone(&checkpoints);
        host.context_mut()
            .on_parallel(session_events::SESSION_FLUSH, move |checkpoint| {
                let checkpoints = Arc::clone(&checkpoints);
                async move {
                    checkpoints.lock().unwrap().push(
                        checkpoint
                            .events
                            .iter()
                            .map(|event| event.kind.event_type())
                            .collect(),
                    );
                    Ok::<(), TestError>(())
                }
            })
            .unwrap();
    }
    {
        let checkpoints = Arc::clone(&checkpoints);
        host.context_mut()
            .on_serial(approval_events::APPROVAL_REQUEST, move |prompt| {
                let checkpoints = Arc::clone(&checkpoints);
                async move {
                    assert_eq!(prompt.tool_name(), "filesystem.write");
                    assert_eq!(
                        checkpoints
                            .lock()
                            .unwrap()
                            .last()
                            .and_then(|events| events.last())
                            .copied(),
                        Some("approval/asked")
                    );
                    Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
                }
            })
            .unwrap();
    }

    assert_eq!(
        request_approval(
            host.context_mut(),
            &session,
            request(agent, LifecycleCancellation::default()),
        )
        .await
        .unwrap(),
        ApprovalOutcome::AllowedOnce
    );
    let checkpoints = checkpoints.lock().unwrap();
    assert_eq!(checkpoints.len(), 2);
    assert_eq!(checkpoints[0].last(), Some(&"approval/asked"));
    assert_eq!(checkpoints[1].last(), Some(&"approval/decided"));
}

#[tokio::test]
async fn never_policy_is_durable_and_bypasses_answerers() {
    let mut host = CordisHost::boot(false).unwrap();
    let (agent, session) = live_session(&mut host, "approval-never");
    let calls = Arc::new(Mutex::new(0_u64));
    {
        let calls = Arc::clone(&calls);
        host.context_mut()
            .on_serial(approval_events::APPROVAL_REQUEST, move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    *calls.lock().unwrap() += 1;
                    Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
                }
            })
            .unwrap();
    }

    assert!(
        set_approval_policy(
            host.context(),
            &session,
            ApprovalPolicy::Never,
            Some(ApprovalPolicySource::Delegation),
        )
        .await
        .unwrap()
    );
    assert!(
        !set_approval_policy(
            host.context(),
            &session,
            ApprovalPolicy::Never,
            Some(ApprovalPolicySource::Delegation),
        )
        .await
        .unwrap()
    );
    assert_eq!(
        request_approval(
            host.context_mut(),
            &session,
            request(agent, LifecycleCancellation::default()),
        )
        .await
        .unwrap(),
        ApprovalOutcome::Rejected
    );
    assert_eq!(*calls.lock().unwrap(), 0);

    let restored =
        SessionLog::restore(session.header().unwrap(), session.events().unwrap()).unwrap();
    assert_eq!(restored.approval_policy(), ApprovalPolicy::Never);
}

#[tokio::test]
async fn listener_error_panic_and_mid_answer_cancellation_all_fail_closed() {
    let mut error_host = CordisHost::boot(false).unwrap();
    let (error_agent, error_session) = live_session(&mut error_host, "approval-error");
    error_host
        .context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, |_| async {
            Err::<BailOutcome<ApprovalOutcome>, _>(TestError("answerer failed"))
        })
        .unwrap();
    assert_eq!(
        request_approval(
            error_host.context_mut(),
            &error_session,
            request(error_agent, LifecycleCancellation::default()),
        )
        .await
        .unwrap(),
        ApprovalOutcome::Unavailable
    );

    let mut panic_host = CordisHost::boot(false).unwrap();
    let (panic_agent, panic_session) = live_session(&mut panic_host, "approval-panic");
    panic_host
        .context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, |_| async {
            panic!("answerer panicked");
            #[allow(unreachable_code)]
            Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
        })
        .unwrap();
    assert_eq!(
        request_approval(
            panic_host.context_mut(),
            &panic_session,
            request(panic_agent, LifecycleCancellation::default()),
        )
        .await
        .unwrap(),
        ApprovalOutcome::Unavailable
    );

    let mut cancel_host = CordisHost::boot(false).unwrap();
    let (cancel_agent, cancel_session) = live_session(&mut cancel_host, "approval-cancel");
    let cancellation = LifecycleCancellation::default();
    let listener_cancellation = cancellation.clone();
    cancel_host
        .context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, move |_| {
            let cancellation = listener_cancellation.clone();
            async move {
                cancellation.cancel();
                Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
            }
        })
        .unwrap();
    assert_eq!(
        request_approval(
            cancel_host.context_mut(),
            &cancel_session,
            request(cancel_agent, cancellation),
        )
        .await
        .unwrap(),
        ApprovalOutcome::Cancelled
    );
}

#[tokio::test]
async fn exact_live_agent_identity_is_required_before_an_audit_is_opened() {
    let mut host = CordisHost::boot(false).unwrap();
    let (_agent, session) = live_session(&mut host, "approval-identity");
    let imposter = AgentRef::new("approval-identity");
    let error = request_approval(
        host.context_mut(),
        &session,
        request(imposter, LifecycleCancellation::default()),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error,
        ApprovalError::AgentUnavailable {
            agent_id: "approval-identity".into(),
        }
    );
    assert_eq!(session.events().unwrap().len(), 1);
}

#[tokio::test]
async fn explicit_live_agent_may_answer_for_a_different_exact_session_id() {
    let mut host = CordisHost::boot(false).unwrap();
    let agent = AgentRef::new("runtime-agent");
    register_agent(host.context_mut(), agent.clone()).unwrap();
    let session = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("mission-session").unwrap())
        .unwrap();
    session.start_turn().unwrap();
    host.context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, |prompt| async move {
            assert_eq!(prompt.agent().id, "runtime-agent");
            assert_eq!(prompt.session_id().as_str(), "mission-session");
            Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
        })
        .unwrap();
    let request = ApprovalRequest::for_session(
        agent,
        session.id().clone(),
        "filesystem.write",
        LifecycleCancellation::default(),
    )
    .unwrap();

    assert_eq!(
        request_approval(host.context_mut(), &session, request)
            .await
            .unwrap(),
        ApprovalOutcome::AllowedOnce
    );
}

#[test]
fn replay_rejects_unpaired_audits_and_repair_cancels_a_pending_request() {
    let header = SessionHeader::new_at(SessionId::new("approval-replay").unwrap(), 1).unwrap();
    let id = ApprovalRequestId::new("approval-replay:approval:1").unwrap();
    let asked = SessionApprovalAsked::new(
        id.clone(),
        "filesystem.write".into(),
        Some("call-1".into()),
        None,
    )
    .unwrap();
    let turn = SessionEvent {
        seq: 0,
        time_ms: 1,
        kind: SessionEventKind::TurnStart { turn: 1 },
    };
    let asked_event = SessionEvent {
        seq: 1,
        time_ms: 1,
        kind: SessionEventKind::ApprovalAsked {
            approval: asked.clone(),
        },
    };

    let mut outside_turn = asked_event.clone();
    outside_turn.seq = 0;
    assert!(matches!(
        SessionLog::restore(header.clone(), vec![outside_turn]),
        Err(hartevo_cordis::SessionError::NoOpenTurn)
    ));

    let mut duplicate = asked_event.clone();
    duplicate.seq = 2;
    assert!(matches!(
        SessionLog::restore(
            header.clone(),
            vec![turn.clone(), asked_event.clone(), duplicate]
        ),
        Err(hartevo_cordis::SessionError::DuplicatePendingApproval { .. })
    ));
    assert!(matches!(
        SessionLog::restore(
            header.clone(),
            vec![
                turn.clone(),
                SessionEvent {
                    seq: 1,
                    time_ms: 1,
                    kind: SessionEventKind::ApprovalDecided {
                        approval: SessionApprovalDecided::new(
                            id.clone(),
                            ApprovalOutcome::Rejected,
                        ),
                    },
                },
            ],
        ),
        Err(hartevo_cordis::SessionError::ApprovalDecisionWithoutRequest { .. })
    ));

    let mut interrupted =
        SessionLog::restore(header, vec![turn, asked_event]).expect("pending audit restores");
    assert!(interrupted.repair_interrupted_tail().unwrap());
    assert_eq!(
        interrupted
            .events()
            .iter()
            .map(|event| event.kind.event_type())
            .collect::<Vec<_>>(),
        [
            "turn/start",
            "approval/asked",
            "approval/decided",
            "turn/end",
        ]
    );
    let SessionEventKind::ApprovalDecided { approval } = &interrupted.events()[2].kind else {
        unreachable!();
    };
    assert_eq!(approval.id(), &id);
    assert_eq!(approval.outcome(), ApprovalOutcome::Cancelled);
    assert_eq!(interrupted.open_turn(), None);
}

#[tokio::test]
async fn serial_answerers_continue_until_the_first_explicit_bail() {
    let mut host = CordisHost::boot(false).unwrap();
    let (agent, session) = live_session(&mut host, "approval-serial");
    let calls = Arc::new(Mutex::new(Vec::new()));
    {
        let calls = Arc::clone(&calls);
        host.context_mut()
            .on_serial(approval_events::APPROVAL_REQUEST, move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.lock().unwrap().push("continue");
                    Ok::<_, TestError>(BailOutcome::Continue(NonBail::Undefined))
                }
            })
            .unwrap();
    }
    {
        let calls = Arc::clone(&calls);
        host.context_mut()
            .on_serial(approval_events::APPROVAL_REQUEST, move |_| {
                let calls = Arc::clone(&calls);
                async move {
                    calls.lock().unwrap().push("bail");
                    Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
                }
            })
            .unwrap();
    }
    assert_eq!(
        request_approval(
            host.context_mut(),
            &session,
            request(agent, LifecycleCancellation::default()),
        )
        .await
        .unwrap(),
        ApprovalOutcome::AllowedOnce
    );
    assert_eq!(*calls.lock().unwrap(), ["continue", "bail"]);
}
