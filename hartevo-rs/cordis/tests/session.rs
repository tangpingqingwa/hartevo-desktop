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
