use hartevo_cordis::{
    CompactionCheckpoint, CompactionId, CompactionSummaryDraft, SessionContentBlock, SessionError,
    SessionEventKind, SessionId, SessionLog, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionStore, SessionSurfaceIntent, TurnEndReason,
    is_compact_checkpoint_source, tool_pairing_balanced_after, tool_pairing_balanced_before,
};

fn user_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn assistant_tool_call(id: &str, call_id: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::Assistant,
        content: vec![SessionContentBlock::ToolCall {
            id: call_id.into(),
            name: "echo".into(),
            arguments: "{}".into(),
        }],
        source: SessionMessageSource::Model {
            provider: "mock".into(),
            model: "mock".into(),
        },
    }
}

fn tool_result(id: &str, call_id: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::ToolResult {
            tool_call_id: call_id.into(),
            content: vec![SessionContentBlock::Text { text: "ok".into() }],
            is_error: false,
        }],
        source: SessionMessageSource::Tool {
            call_id: call_id.into(),
        },
    }
}

fn summary(text: &str) -> CompactionSummaryDraft {
    CompactionSummaryDraft {
        summary: vec![SessionContentBlock::Text { text: text.into() }],
        shadowed_token_count: 42,
        provider: "mock".into(),
        model: "summary-model".into(),
        max_tokens: Some(256),
        usage: None,
        raw_output: Some(vec![SessionContentBlock::Text { text: text.into() }]),
        llm_stream_call: true,
    }
}

fn checkpoint(id: &str, text: &str) -> CompactionCheckpoint {
    CompactionCheckpoint {
        message_id: id.into(),
        content: vec![SessionContentBlock::Text { text: text.into() }],
    }
}

#[test]
fn compaction_replaces_one_balanced_surface_region_and_restores_exactly() {
    let sessions = SessionStore::new();
    let session = sessions
        .create(SessionId::new("compact-success").unwrap())
        .unwrap();
    let turn = session.start_turn().unwrap();
    session
        .append_user_message(user_message("user-1", "question"))
        .unwrap();
    let step = session.start_step(turn).unwrap();
    session
        .append_assistant_message(turn, step, assistant_tool_call("assistant-1", "call-1"))
        .unwrap();
    session
        .append_tool_call(turn, step, "call-1", "echo", "{}")
        .unwrap();
    session
        .append_tool_result(turn, step, tool_result("tool-1", "call-1"))
        .unwrap();

    let nodes = session.surface().unwrap().nodes;
    assert_eq!(nodes, vec![1, 3, 5]);
    assert!(tool_pairing_balanced_before(&session, nodes[0]).unwrap());
    assert!(tool_pairing_balanced_after(&session, nodes[2]).unwrap());
    assert!(!tool_pairing_balanced_after(&session, nodes[1]).unwrap());
    assert!(!tool_pairing_balanced_before(&session, nodes[2]).unwrap());

    let lease = session
        .begin_compaction(
            CompactionId::new("compact-1").unwrap(),
            Some("command-1".into()),
            Some(turn),
            nodes[0],
            nodes[2],
        )
        .unwrap();
    let result = session
        .complete_compaction(
            &lease,
            summary("raw summary"),
            checkpoint(
                "checkpoint-1",
                "<compacted-summary>safe</compacted-summary>",
            ),
        )
        .unwrap();

    assert_eq!(result.start_seq, lease.start_seq());
    assert_eq!(result.shadowed_seqs, nodes);
    assert_eq!(result.shadowed_range.start, 1);
    assert_eq!(result.shadowed_range.end, 5);
    assert_eq!(
        session
            .events()
            .unwrap()
            .iter()
            .map(|event| event.kind.event_type())
            .rev()
            .take(4)
            .collect::<Vec<_>>(),
        [
            "compaction/end",
            "user/message",
            "compaction/summary",
            "compaction/start",
        ]
    );
    let surface = session.surface().unwrap();
    assert_eq!(surface.nodes, vec![result.summary_seq + 1]);
    assert_eq!(surface.replace_generation, 1);
    let derived = session.derive_messages().unwrap();
    assert_eq!(derived.len(), 1);
    assert!(is_compact_checkpoint_source(&derived[0].source));
    let encoded = derived[0].to_json_value().unwrap();
    assert_eq!(
        encoded["source"]["plugin"]["plugin"],
        hartevo_cordis::COMPACTION_CHECKPOINT_PLUGIN
    );
    assert_eq!(
        encoded["source"]["plugin"]["compactionId"],
        result.compaction_id.as_str()
    );
    assert_eq!(encoded["source"]["plugin"]["sourceCommandId"], "command-1");

    let restored =
        SessionLog::restore(session.header().unwrap(), session.events().unwrap()).unwrap();
    assert_eq!(restored.surface(), surface);
    assert_eq!(restored.derive_messages(), derived);
}

#[test]
fn unsafe_or_changed_regions_fail_without_partial_summary_events() {
    let sessions = SessionStore::new();
    let session = sessions
        .create(SessionId::new("compact-atomic").unwrap())
        .unwrap();
    let turn = session.start_turn().unwrap();
    session
        .append_user_message(user_message("user-1", "question"))
        .unwrap();
    let step = session.start_step(turn).unwrap();
    session
        .append_assistant_message(turn, step, assistant_tool_call("assistant-1", "call-1"))
        .unwrap();
    session
        .append_tool_call(turn, step, "call-1", "echo", "{}")
        .unwrap();
    session
        .append_tool_result(turn, step, tool_result("tool-1", "call-1"))
        .unwrap();
    session
        .append_user_message(user_message("user-2", "tail"))
        .unwrap();
    let nodes = session.surface().unwrap().nodes;

    let before = session.events().unwrap();
    assert_eq!(
        session
            .begin_compaction(
                CompactionId::new("unsafe").unwrap(),
                None,
                Some(turn),
                nodes[1],
                nodes[1],
            )
            .unwrap_err(),
        SessionError::CompactionRangeUnbalanced {
            edge: "end",
            seq: nodes[1],
        }
    );
    assert_eq!(session.events().unwrap(), before);

    let lease = session
        .begin_compaction(
            CompactionId::new("changed").unwrap(),
            None,
            Some(turn),
            nodes[0],
            nodes[2],
        )
        .unwrap();
    session
        .append_user_message_with_surface(
            user_message("tail-replacement", "new tail"),
            SessionSurfaceIntent::replace(nodes[3], nodes[3], vec![nodes[3]]),
        )
        .unwrap();
    let before_complete = session.events().unwrap();
    assert_eq!(
        session
            .complete_compaction(
                &lease,
                summary("must not land"),
                checkpoint("checkpoint", "must not land"),
            )
            .unwrap_err(),
        SessionError::CompactionRegionChanged
    );
    assert_eq!(session.events().unwrap(), before_complete);
    session.fail_compaction(&lease, "surface changed").unwrap();
}

#[test]
fn complete_compaction_is_atomic_when_checkpoint_is_invalid() {
    let sessions = SessionStore::new();
    let session = sessions
        .create(SessionId::new("compact-invalid-checkpoint").unwrap())
        .unwrap();
    session
        .append_user_message(user_message("user-1", "first"))
        .unwrap();
    session
        .append_user_message(user_message("user-2", "second"))
        .unwrap();
    let nodes = session.surface().unwrap().nodes;
    let lease = session
        .begin_compaction(
            CompactionId::new("atomic").unwrap(),
            None,
            None,
            nodes[0],
            nodes[1],
        )
        .unwrap();
    let before = session.events().unwrap();

    let other = sessions
        .create(SessionId::new("compact-other").unwrap())
        .unwrap();
    assert!(matches!(
        other
            .complete_compaction(
                &lease,
                summary("wrong session"),
                checkpoint("wrong-session", "replacement"),
            )
            .unwrap_err(),
        SessionError::CompactionLeaseSessionMismatch { .. }
    ));
    assert!(other.events().unwrap().is_empty());

    assert_eq!(
        session
            .complete_compaction(&lease, summary("summary"), checkpoint("", "replacement"))
            .unwrap_err(),
        SessionError::EmptyMessageId {
            event_type: "user/message",
        }
    );
    assert_eq!(session.events().unwrap(), before);
    session
        .fail_compaction(&lease, "invalid checkpoint")
        .unwrap();
}

#[test]
fn surface_position_ranges_allow_numeric_start_greater_than_end() {
    let sessions = SessionStore::new();
    let session = sessions
        .create(SessionId::new("compact-position-order").unwrap())
        .unwrap();
    session
        .append_user_message(user_message("user-1", "first"))
        .unwrap();
    session
        .append_user_message(user_message("user-2", "second"))
        .unwrap();
    session
        .append_user_message(user_message("user-3", "third"))
        .unwrap();
    session
        .append_user_message_with_surface(
            user_message("replacement", "first two"),
            SessionSurfaceIntent::replace(0, 1, vec![0, 1]),
        )
        .unwrap();
    assert_eq!(session.surface().unwrap().nodes, vec![3, 2]);

    let lease = session
        .begin_compaction(
            CompactionId::new("non-monotonic").unwrap(),
            None,
            None,
            3,
            2,
        )
        .unwrap();
    assert_eq!(lease.region().shadowed_seqs, vec![3, 2]);
    session.fail_compaction(&lease, "fixture complete").unwrap();
}

#[test]
fn replay_rejects_identity_drift_and_turn_crossing() {
    let sessions = SessionStore::new();
    let session = sessions
        .create(SessionId::new("compact-replay").unwrap())
        .unwrap();
    let turn = session.start_turn().unwrap();
    session
        .append_user_message(user_message("user-1", "first"))
        .unwrap();
    let node = session.surface().unwrap().nodes[0];
    let lease = session
        .begin_compaction(
            CompactionId::new("replay").unwrap(),
            None,
            Some(turn),
            node,
            node,
        )
        .unwrap();

    assert_eq!(
        session
            .finish_turn(turn, TurnEndReason::Completed)
            .unwrap_err(),
        SessionError::CompactionCrossesTurnBoundary
    );
    assert!(matches!(
        session
            .begin_compaction(
                CompactionId::new("second").unwrap(),
                None,
                Some(turn),
                node,
                node,
            )
            .unwrap_err(),
        SessionError::CompactionAlreadyOpen { .. }
    ));

    session
        .complete_compaction(
            &lease,
            summary("summary"),
            checkpoint("checkpoint", "replacement"),
        )
        .unwrap();
    let header = session.header().unwrap();
    let mut events = session.events().unwrap();
    let mut changed_region = events.clone();
    let SessionEventKind::CompactionSummary { compaction } =
        &mut changed_region[usize::try_from(lease.start_seq() + 1).unwrap()].kind
    else {
        panic!("summary must immediately follow start in this fixture");
    };
    compaction.shadowed_seqs.push(compaction.shadowed_range.end);
    assert_eq!(
        SessionLog::restore(header.clone(), changed_region).unwrap_err(),
        SessionError::CompactionRegionChanged
    );

    let SessionEventKind::CompactionSummary { compaction } =
        &mut events[usize::try_from(lease.start_seq() + 1).unwrap()].kind
    else {
        panic!("summary must immediately follow start in this fixture");
    };
    compaction.compaction_id = CompactionId::new("drift").unwrap();
    assert!(matches!(
        SessionLog::restore(header, events).unwrap_err(),
        SessionError::CompactionIdMismatch { .. }
    ));
}
