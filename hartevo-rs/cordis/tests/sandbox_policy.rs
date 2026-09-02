use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    ApprovalOutcome, ApprovalPolicy, ApprovalPolicySource, BailOutcome, CordisHost,
    LifecycleCancellation, SANDBOX_ESCALATION_TARGETS, SANDBOX_MODES, SandboxError,
    SandboxEscalationApproval, SandboxEscalationRequest, SandboxMode, SandboxModeSource,
    SandboxPolicyRequest, SandboxPolicyService, SessionEventKind, SessionId, SessionLog,
    SessionSandboxMode, SessionStore, approval_events, approve_sandbox_escalation,
    bind_sandbox_workspace, register_agent, resolve_sandbox_policy, session_events,
    set_approval_policy, set_sandbox_mode, validate_sandbox_escalation_args,
};

#[derive(Debug)]
struct TestError;

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("test error")
    }
}

impl std::error::Error for TestError {}

#[test]
fn vocabulary_defaults_roots_and_widening_are_closed() {
    assert_eq!(
        SANDBOX_MODES,
        [
            SandboxMode::ReadOnly,
            SandboxMode::WorkspaceWrite,
            SandboxMode::DangerFullAccess,
        ]
    );
    assert_eq!(
        SANDBOX_ESCALATION_TARGETS,
        [SandboxMode::WorkspaceWrite, SandboxMode::DangerFullAccess,]
    );
    assert!(SandboxMode::WorkspaceWrite.is_strictly_wider_than(SandboxMode::ReadOnly));
    assert!(SandboxMode::DangerFullAccess.is_strictly_wider_than(SandboxMode::ReadOnly));
    assert!(SandboxMode::DangerFullAccess.is_strictly_wider_than(SandboxMode::WorkspaceWrite));
    assert!(!SandboxMode::ReadOnly.is_strictly_wider_than(SandboxMode::ReadOnly));
    assert!(!SandboxMode::WorkspaceWrite.is_strictly_wider_than(SandboxMode::DangerFullAccess));

    let service = SandboxPolicyService::new(
        SandboxMode::WorkspaceWrite,
        "sandbox-tests/../sandbox-tests",
    )
    .unwrap();
    assert_eq!(service.default_mode(), SandboxMode::WorkspaceWrite);
    assert!(service.workspace_root().is_absolute());
    assert!(service.workspace_root().ends_with("sandbox-tests"));
}

#[tokio::test]
async fn session_switch_is_flushed_non_surface_and_replayed_from_the_last_event() {
    let mut host = CordisHost::boot(false).unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("sandbox-durable").unwrap())
        .unwrap();
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

    set_sandbox_mode(
        host.context(),
        &session,
        SandboxMode::WorkspaceWrite,
        Some(SandboxModeSource::Delegation),
    )
    .await
    .unwrap();
    set_sandbox_mode(host.context(), &session, SandboxMode::ReadOnly, None)
        .await
        .unwrap();

    assert_eq!(session.sandbox_mode().unwrap(), Some(SandboxMode::ReadOnly));
    assert_eq!(
        *checkpoints.lock().unwrap(),
        [vec!["sandbox/mode"], vec!["sandbox/mode", "sandbox/mode"]]
    );
    let events = session.events().unwrap();
    let SessionEventKind::SandboxMode { sandbox: first } = events[0].kind else {
        unreachable!();
    };
    assert_eq!(first.mode(), SandboxMode::WorkspaceWrite);
    assert_eq!(first.source(), Some(SandboxModeSource::Delegation));
    let restored = SessionLog::restore(session.header().unwrap(), events).unwrap();
    assert_eq!(restored.sandbox_mode(), Some(SandboxMode::ReadOnly));
    assert!(restored.derive_messages().is_empty());
    assert!(restored.surface().nodes.is_empty());
    let child = sessions
        .fork(
            session.id(),
            None,
            SessionId::new("sandbox-durable-child").unwrap(),
        )
        .unwrap();
    assert_eq!(child.sandbox_mode().unwrap(), Some(SandboxMode::ReadOnly));
    assert_eq!(child.events().unwrap().len(), 2);
}

#[tokio::test]
async fn resolution_uses_grant_then_session_then_deployment_without_changing_approval() {
    let host = CordisHost::boot(false).unwrap();
    let policy = host
        .context()
        .sandbox_policy::<SandboxPolicyService>()
        .unwrap();
    assert_eq!(policy.default_mode(), SandboxMode::ReadOnly);
    assert!(policy.workspace_root().is_absolute());
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions
        .create(SessionId::new("sandbox-resolve").unwrap())
        .unwrap();

    let deployment =
        resolve_sandbox_policy(host.context(), SandboxPolicyRequest::default()).unwrap();
    assert_eq!(deployment.mode(), SandboxMode::ReadOnly);
    assert!(deployment.session_id().is_none());

    set_sandbox_mode(host.context(), &session, SandboxMode::WorkspaceWrite, None)
        .await
        .unwrap();
    let resolved = resolve_sandbox_policy(
        host.context(),
        SandboxPolicyRequest::for_session(&session)
            .with_call_id("call-standing")
            .unwrap()
            .with_workspace_root("sandbox-session/../sandbox-session"),
    )
    .unwrap();
    assert_eq!(resolved.mode(), SandboxMode::WorkspaceWrite);
    assert_eq!(resolved.session_id(), Some(session.id()));
    assert_eq!(resolved.call_id(), Some("call-standing"));
    assert!(resolved.workspace_root().is_absolute());
    assert!(resolved.workspace_root().ends_with("sandbox-session"));
    assert_eq!(session.approval_policy().unwrap(), ApprovalPolicy::Ask);
}

#[test]
fn live_session_workspace_binding_is_exact_precedence_ordered_and_drop_scoped() {
    let host = CordisHost::boot(false).unwrap();
    let policy = host
        .context()
        .sandbox_policy::<SandboxPolicyService>()
        .unwrap();
    let session = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("sandbox-workspace-binding").unwrap())
        .unwrap();
    let bound_root = std::fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap();
    let explicit_root = std::fs::canonicalize(bound_root.join("src")).unwrap();

    let binding = bind_sandbox_workspace(host.context(), &session, &bound_root).unwrap();
    let resolved =
        resolve_sandbox_policy(host.context(), SandboxPolicyRequest::for_session(&session))
            .unwrap();
    assert_eq!(resolved.workspace_root(), bound_root);
    let explicit = resolve_sandbox_policy(
        host.context(),
        SandboxPolicyRequest::for_session(&session).with_workspace_root(&explicit_root),
    )
    .unwrap();
    assert_eq!(explicit.workspace_root(), explicit_root);
    assert!(matches!(
        bind_sandbox_workspace(host.context(), &session, &bound_root),
        Err(SandboxError::WorkspaceBindingUnavailable { .. })
    ));

    drop(binding);
    let restored =
        resolve_sandbox_policy(host.context(), SandboxPolicyRequest::for_session(&session))
            .unwrap();
    assert_eq!(restored.workspace_root(), policy.workspace_root());
    assert!(matches!(
        bind_sandbox_workspace(
            host.context(),
            &session,
            bound_root.join("missing-n92-workspace")
        ),
        Err(SandboxError::WorkspaceBindingUnavailable { .. })
    ));
}

#[tokio::test]
async fn foreign_session_handle_is_rejected_before_resolution_or_write() {
    let first = CordisHost::boot(false).unwrap();
    let second = CordisHost::boot(false).unwrap();
    let first_session = first
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("same-session-id").unwrap())
        .unwrap();
    let foreign = second
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("same-session-id").unwrap())
        .unwrap();

    assert!(matches!(
        resolve_sandbox_policy(first.context(), SandboxPolicyRequest::for_session(&foreign)),
        Err(SandboxError::Session(
            hartevo_cordis::SessionError::SessionNotLive { .. }
        ))
    ));
    assert!(matches!(
        bind_sandbox_workspace(first.context(), &foreign, std::env::current_dir().unwrap()),
        Err(SandboxError::Session(
            hartevo_cordis::SessionError::SessionNotLive { .. }
        ))
    ));
    assert!(matches!(
        set_sandbox_mode(
            first.context(),
            &foreign,
            SandboxMode::DangerFullAccess,
            None
        )
        .await,
        Err(SandboxError::Session(
            hartevo_cordis::SessionError::SessionNotLive { .. }
        ))
    ));
    assert_eq!(first_session.sandbox_mode().unwrap(), None);
    assert!(first_session.events().unwrap().is_empty());
}

#[test]
fn escalation_argument_pairing_and_persisted_encoding_fail_closed() {
    assert!(validate_sandbox_escalation_args(None, None).is_ok());
    assert!(
        validate_sandbox_escalation_args(
            Some(SandboxMode::WorkspaceWrite),
            Some("write requested")
        )
        .is_ok()
    );
    assert_eq!(
        validate_sandbox_escalation_args(Some(SandboxMode::WorkspaceWrite), None),
        Err(SandboxError::MissingJustification)
    );
    assert_eq!(
        validate_sandbox_escalation_args(None, Some("orphan")),
        Err(SandboxError::OrphanJustification)
    );
    assert_eq!(
        validate_sandbox_escalation_args(Some(SandboxMode::WorkspaceWrite), Some("   ")),
        Err(SandboxError::BlankJustification)
    );
    assert!(
        SessionSandboxMode::from_json_value(&serde_json::json!({
            "mode": "host-root"
        }))
        .is_err()
    );
    assert!(
        SessionSandboxMode::from_json_value(&serde_json::json!({
            "mode": "read-only",
            "extra": true
        }))
        .is_err()
    );
}

fn escalation(
    agent: hartevo_cordis::AgentRef,
    session_id: SessionId,
    requested_mode: SandboxMode,
    effective_mode: SandboxMode,
) -> SandboxEscalationRequest {
    SandboxEscalationRequest::new(
        requested_mode,
        effective_mode,
        "the requested operation needs a wider file boundary",
        "command",
        std::env::current_dir().unwrap(),
        SandboxEscalationApproval::new(
            agent,
            session_id,
            "bash",
            "call-escalate",
            LifecycleCancellation::default(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn allowed_once_grant_is_exact_consumed_and_does_not_persist_a_wider_mode() {
    let mut host = CordisHost::boot(false).unwrap();
    let agent = hartevo_cordis::AgentRef::new("sandbox-agent");
    register_agent(host.context_mut(), agent.clone()).unwrap();
    let session = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("sandbox-session").unwrap())
        .unwrap();
    session.start_turn().unwrap();
    host.context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, |prompt| async move {
            assert_eq!(prompt.session_id().as_str(), "sandbox-session");
            assert_eq!(prompt.call_id(), Some("call-escalate"));
            assert_eq!(
                prompt.reason(),
                Some(
                    "escalate sandbox to workspace-write: the requested operation needs a wider file boundary"
                )
            );
            Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
        })
        .unwrap();

    let grant = approve_sandbox_escalation(
        host.context_mut(),
        &session,
        escalation(
            agent.clone(),
            session.id().clone(),
            SandboxMode::WorkspaceWrite,
            SandboxMode::ReadOnly,
        ),
    )
    .await
    .unwrap();
    assert_eq!(grant.mode(), SandboxMode::WorkspaceWrite);
    let resolved = resolve_sandbox_policy(
        host.context(),
        SandboxPolicyRequest::for_session(&session)
            .with_call_id("call-escalate")
            .unwrap()
            .with_escalation(grant),
    )
    .unwrap();
    assert_eq!(resolved.mode(), SandboxMode::WorkspaceWrite);
    assert_eq!(session.sandbox_mode().unwrap(), None);
    assert_eq!(session.approval_policy().unwrap(), ApprovalPolicy::Ask);
    assert_eq!(
        session
            .events()
            .unwrap()
            .iter()
            .map(|event| event.kind.event_type())
            .collect::<Vec<_>>(),
        ["turn/start", "approval/asked", "approval/decided"]
    );
}

#[tokio::test]
async fn non_widening_never_prompts_and_a_policy_change_stales_a_grant() {
    let mut host = CordisHost::boot(false).unwrap();
    let agent = hartevo_cordis::AgentRef::new("sandbox-stale-agent");
    register_agent(host.context_mut(), agent.clone()).unwrap();
    let session = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("sandbox-stale-session").unwrap())
        .unwrap();
    session.start_turn().unwrap();

    assert!(matches!(
        approve_sandbox_escalation(
            host.context_mut(),
            &session,
            escalation(
                agent.clone(),
                session.id().clone(),
                SandboxMode::ReadOnly,
                SandboxMode::ReadOnly,
            )
        )
        .await,
        Err(SandboxError::NotStrictlyWider { .. })
    ));
    assert_eq!(session.events().unwrap().len(), 1);

    host.context_mut()
        .on_serial(approval_events::APPROVAL_REQUEST, |_| async {
            Ok::<_, TestError>(BailOutcome::Bail(ApprovalOutcome::AllowedOnce))
        })
        .unwrap();
    let grant = approve_sandbox_escalation(
        host.context_mut(),
        &session,
        escalation(
            agent.clone(),
            session.id().clone(),
            SandboxMode::WorkspaceWrite,
            SandboxMode::ReadOnly,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        resolve_sandbox_policy(
            host.context(),
            SandboxPolicyRequest::for_session(&session)
                .with_call_id("call-escalate")
                .unwrap()
                .with_workspace_root(std::env::current_dir().unwrap().join("different-root"))
                .with_escalation(grant)
        ),
        Err(SandboxError::EscalationGrantMismatch)
    );
    let grant = approve_sandbox_escalation(
        host.context_mut(),
        &session,
        escalation(
            agent,
            session.id().clone(),
            SandboxMode::WorkspaceWrite,
            SandboxMode::ReadOnly,
        ),
    )
    .await
    .unwrap();
    set_sandbox_mode(host.context(), &session, SandboxMode::WorkspaceWrite, None)
        .await
        .unwrap();
    assert_eq!(
        resolve_sandbox_policy(
            host.context(),
            SandboxPolicyRequest::for_session(&session)
                .with_call_id("call-escalate")
                .unwrap()
                .with_escalation(grant)
        ),
        Err(SandboxError::EscalationGrantMismatch)
    );
}

#[tokio::test]
async fn non_grant_outcomes_fail_closed_and_the_two_policy_knobs_remain_independent() {
    for (index, outcome) in [
        ApprovalOutcome::Rejected,
        ApprovalOutcome::Cancelled,
        ApprovalOutcome::Unavailable,
    ]
    .into_iter()
    .enumerate()
    {
        let mut host = CordisHost::boot(false).unwrap();
        let agent = hartevo_cordis::AgentRef::new(format!("sandbox-denied-agent-{index}"));
        register_agent(host.context_mut(), agent.clone()).unwrap();
        let session = host
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .create(SessionId::new(format!("sandbox-denied-session-{index}")).unwrap())
            .unwrap();
        session.start_turn().unwrap();
        host.context_mut()
            .on_serial(approval_events::APPROVAL_REQUEST, move |_| async move {
                Ok::<_, TestError>(BailOutcome::Bail(outcome))
            })
            .unwrap();

        let error = approve_sandbox_escalation(
            host.context_mut(),
            &session,
            escalation(
                agent,
                session.id().clone(),
                SandboxMode::WorkspaceWrite,
                SandboxMode::ReadOnly,
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            (outcome, error),
            (
                ApprovalOutcome::Rejected,
                SandboxError::EscalationRejected { .. }
            ) | (
                ApprovalOutcome::Cancelled,
                SandboxError::EscalationCancelled { .. }
            ) | (
                ApprovalOutcome::Unavailable,
                SandboxError::EscalationUnavailable { .. }
            )
        ));
        assert_eq!(session.sandbox_mode().unwrap(), None);
    }

    let host = CordisHost::boot(false).unwrap();
    let session = host
        .context()
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("sandbox-independent").unwrap())
        .unwrap();
    set_approval_policy(
        host.context(),
        &session,
        ApprovalPolicy::Never,
        Some(ApprovalPolicySource::Delegation),
    )
    .await
    .unwrap();
    set_sandbox_mode(
        host.context(),
        &session,
        SandboxMode::DangerFullAccess,
        Some(SandboxModeSource::Delegation),
    )
    .await
    .unwrap();
    assert_eq!(session.approval_policy().unwrap(), ApprovalPolicy::Never);
    assert_eq!(
        session.sandbox_mode().unwrap(),
        Some(SandboxMode::DangerFullAccess)
    );
}
