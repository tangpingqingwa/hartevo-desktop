use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, CordisError, CordisHost, KernelApproval, KernelApprovalDecision, KernelConsentState,
    SessionError, SessionEventKind, SessionId, SessionLog, SessionStore, TurnEndReason,
    invariant_missing,
};

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
