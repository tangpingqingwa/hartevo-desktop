use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    AgentInboxOutcome, AgentInboxTarget, CordisHost, SessionContentBlock, SessionError,
    SessionEvent, SessionEventKind, SessionHeader, SessionId, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionStore, TurnEndReason, session_events,
};

fn user_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

#[test]
fn prepend_replace_and_remove_preserve_order_identity_and_durability() {
    let host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("inbox-controls").unwrap())
        .unwrap();
    let inbox = session.inbox();
    let turn_tail = user_message("turn-tail", "turn tail");
    let turn_head = user_message("turn-head", "turn head");
    let step_tail = user_message("step-tail", "step tail");
    let step_head = user_message("step-head", "step head");
    inbox.append_next_turn(turn_tail.clone()).unwrap();
    inbox.prepend_next_turn(turn_head.clone()).unwrap();
    inbox.append_next_step(step_tail.clone()).unwrap();
    inbox.prepend_next_step(step_head.clone()).unwrap();
    assert_eq!(
        inbox.next_turn().unwrap(),
        [turn_head.clone(), turn_tail.clone()]
    );
    assert_eq!(
        inbox.next_step().unwrap(),
        [step_head.clone(), step_tail.clone()]
    );

    let replacement = user_message("turn-replacement", "replacement");
    let before_missing = session.events().unwrap().len();
    assert!(!inbox.replace("missing", replacement.clone()).unwrap());
    assert!(!inbox.remove("missing").unwrap());
    assert_eq!(session.events().unwrap().len(), before_missing);

    assert!(inbox.replace(&turn_tail.id, replacement.clone()).unwrap());
    assert_eq!(
        inbox.next_turn().unwrap(),
        [turn_head.clone(), replacement.clone()]
    );
    assert!(matches!(
        &session.events().unwrap().last().unwrap().kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 1,
            removed_count: Some(1),
            inserted,
            outcome: Some(AgentInboxOutcome::Canceled),
        } if inserted.as_slice() == std::slice::from_ref(&replacement)
    ));

    let before_duplicate = session.events().unwrap().len();
    assert_eq!(
        inbox.replace(&step_head.id, replacement.clone()),
        Err(SessionError::DuplicatePendingMessage {
            id: replacement.id.clone(),
        })
    );
    assert_eq!(session.events().unwrap().len(), before_duplicate);
    assert_eq!(
        inbox.next_step().unwrap(),
        [step_head.clone(), step_tail.clone()]
    );

    assert!(inbox.remove(&turn_head.id).unwrap());
    assert_eq!(
        inbox.next_turn().unwrap().as_slice(),
        std::slice::from_ref(&replacement)
    );
    assert!(matches!(
        &session.events().unwrap().last().unwrap().kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 0,
            removed_count: Some(1),
            inserted,
            outcome: Some(AgentInboxOutcome::Canceled),
        } if inserted.is_empty()
    ));

    let restored = SessionStore::new()
        .restore(session.header().unwrap(), session.events().unwrap())
        .unwrap();
    assert_eq!(restored.inbox().next_turn().unwrap(), [replacement]);
    assert_eq!(
        restored.inbox().next_step().unwrap(),
        [step_head, step_tail]
    );
    assert!(restored.derive_messages().unwrap().is_empty());
}

#[test]
fn clear_cancels_next_step_before_next_turn_and_contains_reentry() {
    let mut host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("inbox-clear").unwrap())
        .unwrap();
    let inbox = session.inbox();
    let turn = user_message("clear-turn", "turn");
    let step = user_message("clear-step", "step");
    inbox.append_next_turn(turn.clone()).unwrap();
    inbox.append_next_step(step.clone()).unwrap();

    let observed = Arc::new(Mutex::new(Vec::new()));
    let reentry_errors = Arc::new(Mutex::new(Vec::new()));
    let callback_inbox = inbox.clone();
    let callback_observed = Arc::clone(&observed);
    let callback_errors = Arc::clone(&reentry_errors);
    host.context_mut()
        .on_emit(session_events::SESSION_EVENT, move |record| {
            let SessionEventKind::AgentInboxSpliced {
                target,
                outcome: Some(AgentInboxOutcome::Canceled),
                ..
            } = record.event.kind
            else {
                return;
            };
            callback_observed.lock().unwrap().push((
                target,
                callback_inbox.next_turn().unwrap(),
                callback_inbox.next_step().unwrap(),
            ));
            callback_errors
                .lock()
                .unwrap()
                .push(callback_inbox.clear().unwrap_err());
        })
        .unwrap();

    let before_clear = session.events().unwrap().len();
    inbox.clear().unwrap();
    assert!(!inbox.has_pending().unwrap());
    assert_eq!(
        *observed.lock().unwrap(),
        [
            (
                AgentInboxTarget::NextStep,
                vec![turn.clone()],
                vec![step.clone()],
            ),
            (AgentInboxTarget::NextTurn, vec![turn], Vec::new()),
        ]
    );
    assert_eq!(
        *reentry_errors.lock().unwrap(),
        [
            SessionError::InboxMutationInProgress {
                id: SessionId::new("inbox-clear").unwrap(),
            },
            SessionError::InboxMutationInProgress {
                id: SessionId::new("inbox-clear").unwrap(),
            },
        ]
    );
    let events = session.events().unwrap();
    assert!(matches!(
        &events[before_clear].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextStep,
            start: 0,
            removed_count: Some(1),
            inserted,
            outcome: Some(AgentInboxOutcome::Canceled),
        } if inserted.is_empty()
    ));
    assert!(matches!(
        &events[before_clear + 1].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 0,
            removed_count: Some(1),
            inserted,
            outcome: Some(AgentInboxOutcome::Canceled),
        } if inserted.is_empty()
    ));
    assert_eq!(events.len(), before_clear + 2);
    inbox.clear().unwrap();
    assert_eq!(session.events().unwrap().len(), before_clear + 2);

    let restored = SessionStore::new()
        .restore(session.header().unwrap(), session.events().unwrap())
        .unwrap();
    assert!(!restored.inbox().has_pending().unwrap());
}

#[test]
fn append_commits_before_projection_and_contains_reentrant_mutation() {
    let mut host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("inbox-order").unwrap())
        .unwrap();
    let inbox = session.inbox();
    let shared = session.clone().inbox();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let reentry_errors = Arc::new(Mutex::new(Vec::new()));

    let callback_inbox = inbox.clone();
    let callback_observed = Arc::clone(&observed);
    let callback_errors = Arc::clone(&reentry_errors);
    host.context_mut()
        .on_emit(session_events::SESSION_EVENT, move |record| {
            if !matches!(
                record.event.kind,
                SessionEventKind::AgentInboxSpliced { .. }
            ) {
                return;
            }
            callback_observed
                .lock()
                .unwrap()
                .push(callback_inbox.next_turn().unwrap());
            callback_errors.lock().unwrap().push(
                callback_inbox
                    .append_next_turn(user_message("nested", "nested"))
                    .unwrap_err(),
            );
        })
        .unwrap();

    let outer = user_message("outer", "outer");
    inbox.append_next_turn(outer.clone()).unwrap();

    assert_eq!(*observed.lock().unwrap(), [Vec::<SessionMessage>::new()]);
    assert_eq!(
        shared.next_turn().unwrap().as_slice(),
        std::slice::from_ref(&outer)
    );
    assert_eq!(
        *reentry_errors.lock().unwrap(),
        [SessionError::InboxMutationInProgress {
            id: SessionId::new("inbox-order").unwrap(),
        }]
    );
    assert_eq!(session.events().unwrap().len(), 1);
    assert_eq!(session.derive_messages().unwrap(), []);
    assert!(matches!(
        inbox.append_next_step(outer.clone()),
        Err(SessionError::DuplicatePendingMessage { id }) if id == outer.id
    ));
    assert_eq!(session.events().unwrap().len(), 1);
    assert!(matches!(
        &session.events().unwrap()[0].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 0,
            removed_count: None,
            inserted,
            outcome: None,
        } if inserted == &[outer]
    ));

    let invalid = SessionMessage {
        id: "assistant".into(),
        role: SessionMessageRole::Assistant,
        content: vec![],
        source: SessionMessageSource::Model {
            provider: "mock".into(),
            model: "mock".into(),
        },
    };
    assert!(matches!(
        inbox.append_next_turn(invalid),
        Err(SessionError::UnexpectedMessageRole {
            event_type: "agent/inbox/spliced",
            ..
        })
    ));
    assert_eq!(session.events().unwrap().len(), 1);
}

#[test]
fn next_step_claim_requires_the_exact_turn_and_drains_fifo_before_projection() {
    let mut host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("inbox-step-claim").unwrap())
        .unwrap();
    let inbox = session.inbox();
    let queued_turn = user_message("turn", "turn");
    let first = user_message("step-first", "first");
    let second = user_message("step-second", "second");
    inbox.append_next_turn(queued_turn.clone()).unwrap();
    inbox.append_next_step(first.clone()).unwrap();
    inbox.append_next_step(second.clone()).unwrap();

    assert_eq!(inbox.claim_next_step(1), Err(SessionError::NoOpenTurn));
    let turn = session.start_turn().unwrap();
    assert_eq!(
        inbox.claim_next_step(turn + 1),
        Err(SessionError::TurnMismatch {
            expected: turn,
            actual: turn + 1,
        })
    );

    let observed = Arc::new(Mutex::new(Vec::new()));
    let reentry_errors = Arc::new(Mutex::new(Vec::new()));
    let callback_inbox = inbox.clone();
    let callback_observed = Arc::clone(&observed);
    let callback_errors = Arc::clone(&reentry_errors);
    host.context_mut()
        .on_emit(session_events::SESSION_EVENT, move |record| {
            if !matches!(
                record.event.kind,
                SessionEventKind::AgentInboxSpliced {
                    target: AgentInboxTarget::NextStep,
                    removed_count: Some(_),
                    ..
                }
            ) {
                return;
            }
            callback_observed
                .lock()
                .unwrap()
                .push(callback_inbox.next_step().unwrap());
            callback_errors.lock().unwrap().push(
                callback_inbox
                    .append_next_step(user_message("nested-step", "nested"))
                    .unwrap_err(),
            );
        })
        .unwrap();

    assert_eq!(
        inbox.claim_next_step(turn).unwrap(),
        [first.clone(), second.clone()]
    );
    assert_eq!(*observed.lock().unwrap(), [vec![first, second]]);
    assert_eq!(
        *reentry_errors.lock().unwrap(),
        [SessionError::InboxMutationInProgress {
            id: SessionId::new("inbox-step-claim").unwrap(),
        }]
    );
    assert!(inbox.next_step().unwrap().is_empty());
    assert_eq!(inbox.next_turn().unwrap(), [queued_turn]);
    assert!(matches!(
        &session.events().unwrap().last().unwrap().kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextStep,
            start: 0,
            removed_count: Some(2),
            inserted,
            outcome: None,
        } if inserted.is_empty()
    ));

    let event_count = session.events().unwrap().len();
    assert!(inbox.claim_next_step(turn).unwrap().is_empty());
    assert_eq!(session.events().unwrap().len(), event_count);
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
    assert_eq!(inbox.claim_next_step(turn), Err(SessionError::NoOpenTurn));
}

#[test]
fn claim_requires_the_exact_open_turn_and_removes_only_the_first_message() {
    let host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("inbox-claim").unwrap())
        .unwrap();
    let inbox = session.inbox();
    let first = user_message("first", "first");
    let second = user_message("second", "second");
    inbox.append_next_turn(first.clone()).unwrap();
    inbox.append_next_turn(second.clone()).unwrap();

    assert_eq!(inbox.claim_next_turn(1), Err(SessionError::NoOpenTurn));
    let turn = session.start_turn().unwrap();
    assert_eq!(
        inbox.claim_next_turn(turn + 1),
        Err(SessionError::TurnMismatch {
            expected: turn,
            actual: turn + 1,
        })
    );
    assert_eq!(
        session.clone().inbox().claim_next_turn(turn).unwrap(),
        Some(first)
    );
    assert_eq!(
        inbox.next_turn().unwrap().as_slice(),
        std::slice::from_ref(&second)
    );
    assert!(matches!(
        &session.events().unwrap().last().unwrap().kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 0,
            removed_count: Some(1),
            inserted,
            outcome: None,
        } if inserted.is_empty()
    ));

    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
    assert_eq!(inbox.claim_next_turn(turn), Err(SessionError::NoOpenTurn));
    let turn = session.start_turn().unwrap();
    assert_eq!(inbox.claim_next_turn(turn).unwrap(), Some(second));
    let event_count = session.events().unwrap().len();
    assert_eq!(inbox.claim_next_turn(turn).unwrap(), None);
    assert_eq!(session.events().unwrap().len(), event_count);
    assert!(!inbox.has_pending().unwrap());
}

#[test]
fn restore_rejects_invalid_splices_and_forks_start_with_an_empty_owned_suffix() {
    let store = SessionStore::new();
    let parent = store
        .create(SessionId::new("inbox-parent").unwrap())
        .unwrap();
    let parent_message = user_message("parent", "parent");
    parent
        .inbox()
        .append_next_turn(parent_message.clone())
        .unwrap();
    let parent_step = user_message("parent-step", "parent step");
    parent
        .inbox()
        .append_next_step(parent_step.clone())
        .unwrap();

    let restored = SessionStore::new()
        .restore(parent.header().unwrap(), parent.events().unwrap())
        .unwrap();
    assert_eq!(
        restored.inbox().next_turn().unwrap().as_slice(),
        std::slice::from_ref(&parent_message)
    );
    assert_eq!(restored.inbox().next_step().unwrap(), [parent_step]);

    let child = store
        .fork(parent.id(), None, SessionId::new("inbox-child").unwrap())
        .unwrap();
    assert_eq!(child.header().unwrap().seed_length, Some(2));
    assert!(child.inbox().next_turn().unwrap().is_empty());
    assert!(child.inbox().next_step().unwrap().is_empty());
    let child_message = user_message("child", "child");
    let child_step = user_message("child-step", "child step");
    child
        .inbox()
        .append_next_turn(child_message.clone())
        .unwrap();
    child.inbox().append_next_step(child_step.clone()).unwrap();
    let cold_child = SessionStore::new()
        .restore(child.header().unwrap(), child.events().unwrap())
        .unwrap();
    assert_eq!(cold_child.inbox().next_turn().unwrap(), [child_message]);
    assert_eq!(cold_child.inbox().next_step().unwrap(), [child_step]);

    let invalid_header =
        SessionHeader::new_at(SessionId::new("invalid-splice").unwrap(), 1).unwrap();
    let invalid = vec![SessionEvent {
        seq: 0,
        time_ms: 1,
        kind: SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            start: 1,
            removed_count: None,
            inserted: vec![user_message("invalid", "invalid")],
            outcome: None,
        },
    }];
    assert!(matches!(
        SessionStore::new().restore(invalid_header, invalid),
        Err(SessionError::InvalidPersistedInboxSplice { seq: 0 })
    ));

    let duplicate_header =
        SessionHeader::new_at(SessionId::new("duplicate-splice").unwrap(), 1).unwrap();
    let duplicate = user_message("duplicate", "duplicate");
    let duplicate_events = vec![
        SessionEvent {
            seq: 0,
            time_ms: 1,
            kind: SessionEventKind::AgentInboxSpliced {
                target: AgentInboxTarget::NextTurn,
                start: 0,
                removed_count: None,
                inserted: vec![duplicate.clone()],
                outcome: None,
            },
        },
        SessionEvent {
            seq: 1,
            time_ms: 2,
            kind: SessionEventKind::AgentInboxSpliced {
                target: AgentInboxTarget::NextTurn,
                start: 1,
                removed_count: None,
                inserted: vec![duplicate],
                outcome: None,
            },
        },
    ];
    assert!(matches!(
        SessionStore::new().restore(duplicate_header, duplicate_events),
        Err(SessionError::InvalidPersistedInboxSplice { seq: 1 })
    ));
}
