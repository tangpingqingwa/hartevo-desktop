use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, CordisError, CordisHost, DispatchMode, KernelApproval, KernelApprovalDecision,
    KernelConsentState, SessionContentBlock, SessionError, SessionEvent, SessionEventKind,
    SessionHeader, SessionId, SessionLog, SessionMessage, SessionMessageRole, SessionMessageSource,
    SessionStore, TurnEndReason, invariant_missing, session_events,
};

#[derive(Debug)]
struct PersistenceTestError(&'static str);

impl fmt::Display for PersistenceTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for PersistenceTestError {}

fn approved_host() -> CordisHost {
    let now = Utc.with_ymd_and_hms(2026, 8, 31, 1, 0, 0).unwrap();
    let mut host = CordisHost::boot(false).unwrap();
    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: now + Duration::minutes(5),
        }),
        now,
    )
    .unwrap();
    host
}

fn user_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn assistant_message(id: &str, content: Vec<SessionContentBlock>) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::Assistant,
        content,
        source: SessionMessageSource::Model {
            provider: "mock".into(),
            model: "mock".into(),
        },
    }
}

fn tool_result_message(id: &str, call_id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::ToolResult {
            tool_call_id: call_id.into(),
            content: vec![SessionContentBlock::Text { text: text.into() }],
            is_error: false,
        }],
        source: SessionMessageSource::Tool {
            call_id: call_id.into(),
        },
    }
}

#[test]
fn boundary_log_is_contiguous_and_restores_exactly() {
    let id = SessionId::new("session-1").unwrap();
    let mut log = SessionLog::new_at(id.clone(), 1).unwrap();
    let turn = log.start_turn().unwrap();
    let step = log.start_step(turn).unwrap();
    log.finish_step(turn, step).unwrap();
    log.finish_turn(turn, TurnEndReason::Completed).unwrap();

    assert_eq!(
        log.events()
            .iter()
            .map(|event| (event.seq, event.kind.event_type()))
            .collect::<Vec<_>>(),
        [
            (0, "turn/start"),
            (1, "step/start"),
            (2, "step/end"),
            (3, "turn/end"),
        ]
    );
    assert_eq!(log.open_turn(), None);
    assert_eq!(log.open_step(), None);

    let restored = SessionLog::restore(log.header().clone(), log.events().to_vec()).unwrap();
    assert_eq!(restored, log);
    assert_eq!(restored.header().id, id);
}

#[test]
fn message_history_derives_replays_and_detaches_from_the_log() {
    let mut log = SessionLog::new_at(SessionId::new("message-history").unwrap(), 1).unwrap();
    let turn = log.start_turn().unwrap();
    let user = user_message("user-1", "hello");
    log.append_user_message(user.clone()).unwrap();
    let step = log.start_step(turn).unwrap();
    let assistant = assistant_message(
        "assistant-1",
        vec![
            SessionContentBlock::Text {
                text: "let me check".into(),
            },
            SessionContentBlock::ToolCall {
                id: "call-1".into(),
                name: "echo".into(),
                arguments: "{}".into(),
            },
        ],
    );
    log.append_assistant_message(turn, step, assistant.clone())
        .unwrap();
    let tool = tool_result_message("tool-1", "call-1", "ok");
    log.append_tool_result(turn, step, tool.clone()).unwrap();
    log.finish_step(turn, step).unwrap();
    log.finish_turn(turn, TurnEndReason::Completed).unwrap();

    let expected = vec![user, assistant, tool];
    assert_eq!(log.derive_messages(), expected);
    assert_eq!(
        log.events()
            .iter()
            .map(|event| event.kind.event_type())
            .collect::<Vec<_>>(),
        [
            "turn/start",
            "user/message",
            "step/start",
            "assistant/message",
            "tool/result",
            "step/end",
            "turn/end",
        ]
    );

    let restored = SessionLog::restore(log.header().clone(), log.events().to_vec()).unwrap();
    assert_eq!(restored.derive_messages(), expected);

    let mut detached = restored.derive_messages();
    let SessionContentBlock::Text { text } = &mut detached[0].content[0] else {
        panic!("first message must retain its text block");
    };
    *text = "mutated copy".into();
    assert_eq!(
        restored.derive_messages()[0].content[0],
        expected[0].content[0]
    );
}

#[test]
fn empty_assistant_message_is_durable_but_absent_from_history() {
    let mut log = SessionLog::new_at(SessionId::new("empty-assistant").unwrap(), 1).unwrap();
    let turn = log.start_turn().unwrap();
    let step = log.start_step(turn).unwrap();
    log.append_assistant_message(turn, step, assistant_message("usage-only", vec![]))
        .unwrap();
    log.finish_step(turn, step).unwrap();
    log.finish_turn(turn, TurnEndReason::MaxTokens).unwrap();

    assert_eq!(log.events()[2].kind.event_type(), "assistant/message");
    assert!(log.derive_messages().is_empty());
}

#[test]
fn malformed_message_replay_fails_closed() {
    let mut log = SessionLog::new_at(SessionId::new("message-validation").unwrap(), 1).unwrap();
    let turn = log.start_turn().unwrap();
    log.append_user_message(user_message("user-1", "hello"))
        .unwrap();
    let step = log.start_step(turn).unwrap();
    log.append_tool_result(turn, step, tool_result_message("tool-1", "call-1", "ok"))
        .unwrap();

    let mut empty_id = log.events().to_vec();
    let SessionEventKind::UserMessage { message } = &mut empty_id[1].kind else {
        panic!("fixture must contain a user message");
    };
    message.id.clear();
    assert_eq!(
        SessionLog::restore(log.header().clone(), empty_id).unwrap_err(),
        SessionError::EmptyMessageId {
            event_type: "user/message"
        }
    );

    let mut wrong_role = log.events().to_vec();
    let SessionEventKind::UserMessage { message } = &mut wrong_role[1].kind else {
        panic!("fixture must contain a user message");
    };
    message.role = SessionMessageRole::Assistant;
    assert!(matches!(
        SessionLog::restore(log.header().clone(), wrong_role),
        Err(SessionError::UnexpectedMessageRole {
            event_type: "user/message",
            ..
        })
    ));

    let mut mismatched_call = log.events().to_vec();
    let SessionEventKind::ToolResult { message, .. } = &mut mismatched_call[3].kind else {
        panic!("fixture must contain a tool result");
    };
    message.source = SessionMessageSource::Tool {
        call_id: "other-call".into(),
    };
    assert_eq!(
        SessionLog::restore(log.header().clone(), mismatched_call).unwrap_err(),
        SessionError::MismatchedToolCallIds
    );
}

#[test]
fn invalid_transition_or_corrupt_replay_is_rejected_before_mutation() {
    let mut log = SessionLog::new_at(SessionId::new("session-invalid").unwrap(), 1).unwrap();
    assert_eq!(
        log.finish_turn(1, TurnEndReason::Completed).unwrap_err(),
        SessionError::NoOpenTurn
    );
    assert!(log.events().is_empty());

    let turn = log.start_turn().unwrap();
    let step = log.start_step(turn).unwrap();
    assert_eq!(
        log.finish_turn(turn, TurnEndReason::Completed).unwrap_err(),
        SessionError::StepStillOpen { turn, step }
    );
    assert_eq!(log.events().len(), 2);

    log.finish_step(turn, step).unwrap();
    log.finish_turn(turn, TurnEndReason::Completed).unwrap();
    let mut corrupt = log.events().to_vec();
    corrupt[2].seq = 9;
    assert_eq!(
        SessionLog::restore(log.header().clone(), corrupt).unwrap_err(),
        SessionError::UnexpectedEventSequence {
            expected: 2,
            actual: 9,
        }
    );
}

#[test]
fn interrupted_tail_repair_is_deterministic_idempotent_and_resumable() {
    let header = SessionHeader::new_at(SessionId::new("crashed-step").unwrap(), 1).unwrap();
    let mut log = SessionLog::restore(
        header,
        vec![
            SessionEvent {
                seq: 0,
                time_ms: 10,
                kind: SessionEventKind::TurnStart { turn: 1 },
            },
            SessionEvent {
                seq: 1,
                time_ms: 20,
                kind: SessionEventKind::StepStart { turn: 1, step: 1 },
            },
        ],
    )
    .unwrap();

    assert!(log.repair_interrupted_tail().unwrap());
    assert_eq!(
        &log.events()[2..],
        [
            SessionEvent {
                seq: 2,
                time_ms: 20,
                kind: SessionEventKind::StepEnd { turn: 1, step: 1 },
            },
            SessionEvent {
                seq: 3,
                time_ms: 20,
                kind: SessionEventKind::TurnEnd {
                    turn: 1,
                    reason: TurnEndReason::Interrupted,
                },
            },
        ]
    );
    let repaired = log.events().to_vec();
    assert!(!log.repair_interrupted_tail().unwrap());
    assert_eq!(log.events(), repaired);
    assert_eq!(log.start_turn().unwrap(), 2);

    let header = SessionHeader::new_at(SessionId::new("crashed-turn").unwrap(), 1).unwrap();
    let mut turn_only = SessionLog::restore(
        header,
        vec![SessionEvent {
            seq: 0,
            time_ms: 30,
            kind: SessionEventKind::TurnStart { turn: 1 },
        }],
    )
    .unwrap();
    assert!(turn_only.repair_interrupted_tail().unwrap());
    assert_eq!(
        turn_only.events()[1],
        SessionEvent {
            seq: 1,
            time_ms: 30,
            kind: SessionEventKind::TurnEnd {
                turn: 1,
                reason: TurnEndReason::Interrupted,
            },
        }
    );

    let mut balanced = SessionLog::new_at(SessionId::new("balanced").unwrap(), 1).unwrap();
    let turn = balanced.start_turn().unwrap();
    balanced
        .finish_turn(turn, TurnEndReason::Completed)
        .unwrap();
    let unchanged = balanced.events().to_vec();
    assert!(!balanced.repair_interrupted_tail().unwrap());
    assert_eq!(balanced.events(), unchanged);
}

#[test]
fn agent_step_records_completed_turn_and_read_only_restore() {
    let mut host = approved_host();
    host.step(AgentStep::new("mission-session", "plan"))
        .unwrap();
    host.step(AgentStep::new("mission-session", "plan again"))
        .unwrap();

    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let id = SessionId::new("mission-session").unwrap();
    let live = sessions.get(&id).unwrap().unwrap();
    let header = live.header().unwrap();
    let events = live.events().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.kind.clone())
            .collect::<Vec<_>>(),
        [
            SessionEventKind::TurnStart { turn: 1 },
            SessionEventKind::StepStart { turn: 1, step: 1 },
            SessionEventKind::StepEnd { turn: 1, step: 1 },
            SessionEventKind::TurnEnd {
                turn: 1,
                reason: TurnEndReason::Completed,
            },
            SessionEventKind::TurnStart { turn: 2 },
            SessionEventKind::StepStart { turn: 2, step: 1 },
            SessionEventKind::StepEnd { turn: 2, step: 1 },
            SessionEventKind::TurnEnd {
                turn: 2,
                reason: TurnEndReason::Completed,
            },
        ]
    );

    let agents_before = host
        .context()
        .agents::<hartevo_cordis::AgentsSurface>()
        .unwrap()
        .list();
    let restored_store = SessionStore::new();
    let restored = restored_store.restore(header, events.clone()).unwrap();
    assert_eq!(restored.events().unwrap(), events);
    assert_eq!(
        host.context()
            .agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list(),
        agents_before,
        "restoring a Session must not execute an agent or provider"
    );
}

#[test]
fn blocked_turn_closes_without_step_or_agent_execution() {
    let mut host = CordisHost::boot(false).unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-blocked", "plan"))
            .unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let id = SessionId::new("mission-blocked").unwrap();
    let events = sessions.get(&id).unwrap().unwrap().events().unwrap();
    assert_eq!(
        events
            .iter()
            .map(|event| event.kind.clone())
            .collect::<Vec<_>>(),
        [
            SessionEventKind::TurnStart { turn: 1 },
            SessionEventKind::TurnEnd {
                turn: 1,
                reason: TurnEndReason::Blocked,
            },
        ]
    );
    assert!(
        host.context()
            .agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list()
            .is_empty()
    );
}

#[test]
fn committed_session_events_publish_post_append_and_reject_reentry() {
    let mut host = approved_host();
    assert_eq!(
        host.context().event_mode(session_events::SESSION_EVENT),
        Some(DispatchMode::Emit)
    );
    assert_eq!(
        host.context().event_mode(session_events::SESSION_FLUSH),
        Some(DispatchMode::Parallel)
    );

    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let id = SessionId::new("session-feed").unwrap();
    let session = sessions.create(id.clone()).unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let reentry_errors = Arc::new(Mutex::new(Vec::new()));

    let callback_session = session.clone();
    let callback_observed = Arc::clone(&observed);
    let callback_errors = Arc::clone(&reentry_errors);
    host.context_mut()
        .on_emit(session_events::SESSION_EVENT, move |record| {
            let committed = callback_session.events().unwrap();
            assert_eq!(committed.last(), Some(&record.event));
            callback_observed.lock().unwrap().push(record.clone());
            callback_errors
                .lock()
                .unwrap()
                .push(callback_session.start_turn().unwrap_err());
        })
        .unwrap();
    host.context_mut()
        .try_on_emit(session_events::SESSION_EVENT, |_| {
            Err::<(), _>(PersistenceTestError("write-behind failed"))
        })
        .unwrap();
    let reached_after_failure = Arc::new(Mutex::new(0_u64));
    let callback_reached = Arc::clone(&reached_after_failure);
    host.context_mut()
        .on_emit(session_events::SESSION_EVENT, move |_| {
            *callback_reached.lock().unwrap() += 1;
        })
        .unwrap();

    let turn = session.start_turn().unwrap();
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();

    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].header.id, id);
    assert_eq!(observed[0].event.kind, SessionEventKind::TurnStart { turn });
    assert_eq!(
        observed[1].event.kind,
        SessionEventKind::TurnEnd {
            turn,
            reason: TurnEndReason::Completed,
        }
    );
    assert_eq!(
        *reentry_errors.lock().unwrap(),
        [
            SessionError::AppendInProgress {
                id: SessionId::new("session-feed").unwrap(),
            },
            SessionError::AppendInProgress {
                id: SessionId::new("session-feed").unwrap(),
            },
        ]
    );
    assert_eq!(*reached_after_failure.lock().unwrap(), 2);
}

#[tokio::test]
async fn flush_awaits_exact_checkpoint_and_contains_listener_failures() {
    let mut host = approved_host();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("session-flush").unwrap())
        .unwrap();
    let turn = session.start_turn().unwrap();
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();

    let checkpoints = Arc::new(Mutex::new(Vec::new()));
    let callback_checkpoints = Arc::clone(&checkpoints);
    host.context_mut()
        .on_parallel(session_events::SESSION_FLUSH, move |checkpoint| {
            let callback_checkpoints = Arc::clone(&callback_checkpoints);
            async move {
                tokio::task::yield_now().await;
                callback_checkpoints.lock().unwrap().push(checkpoint);
                Ok::<(), PersistenceTestError>(())
            }
        })
        .unwrap();

    assert!(sessions.flush(&session).await.unwrap());
    let first = checkpoints.lock().unwrap().pop().unwrap();
    assert_eq!(first.header.id, *session.id());
    assert_eq!(first.through_seq(), Some(1));
    assert_eq!(first.events, session.events().unwrap());

    host.context_mut()
        .on_parallel(session_events::SESSION_FLUSH, |_| async {
            Err::<(), _>(PersistenceTestError("disk unavailable"))
        })
        .unwrap();
    let error = sessions.flush(&session).await.unwrap_err();
    assert!(matches!(
        error,
        SessionError::FlushFailed { ref message } if message.contains("disk unavailable")
    ));
    assert_eq!(checkpoints.lock().unwrap().len(), 1);

    let standalone = SessionStore::new();
    let standalone_session = standalone
        .create(SessionId::new("standalone").unwrap())
        .unwrap();
    assert!(!standalone.flush(&standalone_session).await.unwrap());
    assert_eq!(
        standalone.flush(&session).await.unwrap_err(),
        SessionError::SessionNotLive {
            id: SessionId::new("session-flush").unwrap(),
        }
    );
}

#[test]
fn fork_detaches_empty_and_latest_closed_seeds_with_lineage() {
    let store = SessionStore::new();
    let empty_parent_id = SessionId::new("empty-parent").unwrap();
    store.create(empty_parent_id.clone()).unwrap();
    let empty_child = store
        .fork(
            &empty_parent_id,
            None,
            SessionId::new("empty-child").unwrap(),
        )
        .unwrap();
    assert!(empty_child.events().unwrap().is_empty());
    assert_eq!(
        empty_child.header().unwrap().parent_session,
        Some(empty_parent_id)
    );
    assert_eq!(empty_child.header().unwrap().seed_length, Some(0));

    let parent_id = SessionId::new("fork-parent").unwrap();
    let parent = store.create(parent_id.clone()).unwrap();
    let turn = parent.start_turn().unwrap();
    let step = parent.start_step(turn).unwrap();
    parent.finish_step(turn, step).unwrap();
    parent.finish_turn(turn, TurnEndReason::Completed).unwrap();
    let inherited = parent.events().unwrap();

    let child = store
        .fork(&parent_id, None, SessionId::new("fork-child").unwrap())
        .unwrap();
    assert_eq!(child.events().unwrap(), inherited);
    assert_eq!(child.header().unwrap().parent_session, Some(parent_id));
    assert_eq!(child.header().unwrap().seed_length, Some(4));

    let parent_turn = parent.start_turn().unwrap();
    parent
        .finish_turn(parent_turn, TurnEndReason::Blocked)
        .unwrap();
    assert_eq!(child.events().unwrap(), inherited);

    let child_turn = child.start_turn().unwrap();
    child
        .finish_turn(child_turn, TurnEndReason::Completed)
        .unwrap();
    assert_eq!(parent.events().unwrap().len(), 6);
    assert_eq!(child.events().unwrap().len(), 6);
}

#[test]
fn fork_accepts_an_earlier_closed_boundary_from_an_open_tail() {
    let store = SessionStore::new();
    let parent_id = SessionId::new("earlier-parent").unwrap();
    let parent = store.create(parent_id.clone()).unwrap();

    let first_turn = parent.start_turn().unwrap();
    let first_step = parent.start_step(first_turn).unwrap();
    parent.finish_step(first_turn, first_step).unwrap();
    parent
        .finish_turn(first_turn, TurnEndReason::Completed)
        .unwrap();
    let first_boundary = 3;

    let second_turn = parent.start_turn().unwrap();
    parent
        .finish_turn(second_turn, TurnEndReason::Completed)
        .unwrap();
    let open_turn = parent.start_turn().unwrap();

    let child = store
        .fork(
            &parent_id,
            Some(first_boundary),
            SessionId::new("earlier-child").unwrap(),
        )
        .unwrap();
    assert_eq!(child.events().unwrap().len(), 4);
    assert_eq!(child.header().unwrap().seed_length, Some(4));
    assert_eq!(
        parent.events().unwrap().last().unwrap().kind,
        SessionEventKind::TurnStart { turn: open_turn }
    );

    let child_turn = child.start_turn().unwrap();
    assert_eq!(child_turn, 2);
    child
        .finish_turn(child_turn, TurnEndReason::Completed)
        .unwrap();
}

#[test]
fn fork_rejects_missing_duplicate_invalid_and_open_sources_before_publish() {
    let store = SessionStore::new();
    let missing = SessionId::new("missing").unwrap();
    let missing_child = SessionId::new("missing-child").unwrap();
    assert_eq!(
        store
            .fork(&missing, None, missing_child.clone())
            .unwrap_err(),
        SessionError::SessionNotFound { id: missing }
    );
    assert!(store.get(&missing_child).unwrap().is_none());

    let parent_id = SessionId::new("open-parent").unwrap();
    let parent = store.create(parent_id.clone()).unwrap();
    let turn = parent.start_turn().unwrap();
    let open_child = SessionId::new("open-child").unwrap();
    assert_eq!(
        store
            .fork(&parent_id, None, open_child.clone())
            .unwrap_err(),
        SessionError::ForkInsideOpenTurn {
            id: parent_id.clone(),
            boundary: 0,
            turn,
        }
    );
    assert!(store.get(&open_child).unwrap().is_none());

    let invalid_child = SessionId::new("invalid-child").unwrap();
    assert_eq!(
        store
            .fork(&parent_id, Some(9), invalid_child.clone())
            .unwrap_err(),
        SessionError::ForkBoundaryDoesNotExist {
            id: parent_id.clone(),
            boundary: 9,
            last_seq: Some(0),
        }
    );
    assert!(store.get(&invalid_child).unwrap().is_none());

    let duplicate_id = SessionId::new("duplicate-child").unwrap();
    store.create(duplicate_id.clone()).unwrap();
    assert_eq!(
        store
            .fork(&parent_id, None, duplicate_id.clone())
            .unwrap_err(),
        SessionError::SessionAlreadyExists { id: duplicate_id }
    );
}
