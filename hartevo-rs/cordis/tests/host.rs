use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentRef, AgentStatus, AgentStatusChange, AgentStep, AgentTurnStopping, AgentsSurface,
    AuthorityScope, BailOutcome, BrowserReadBinding, CordisError, CordisHost, DomainCommandBinding,
    DomainCommandKind, DomainSurface, EffectBrokerSurface, EffectExecutionBinding,
    EffectReconciliationBinding, EnvironmentOverlay, HOST_PLUGIN_IDS, InvariantGate,
    KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, LifecycleCancellation, LoaderContext, NonBail, OPENINTERPRETER,
    OPENINTERPRETER_PLUGIN_ID, PluginId, RuntimeBinding, RuntimeSurface, SessionCallConfig,
    SessionContentBlock, SessionFinishReason, SessionId, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionStore, SessionStreamChunk, SurfaceOwner, ToolCall, TurnEndReason,
    enforce_invariants, events, host_is_cordis_loop, host_plugin_ids, invariant_missing, keys,
    register_agent,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
}

fn live_approval() -> KernelApproval {
    KernelApproval {
        decision: KernelApprovalDecision::Approved,
        valid_until: now() + Duration::minutes(5),
    }
}

fn granted_record(valid_until: chrono::DateTime<Utc>) -> KernelConsentRecord {
    KernelConsentRecord {
        status: KernelConsentStatus::Granted,
        granted_at: Some(now()),
        valid_until: Some(valid_until),
        withdrawn_at: None,
    }
}

fn bind_confirmed_approved(host: &mut CordisHost) {
    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
}

fn runtime_scope(
    project: &str,
    mission: &str,
    mission_revision: u64,
    generation: u64,
    digest_byte: char,
) -> AuthorityScope {
    AuthorityScope::new("tenant-a", project, mission, mission_revision)
        .unwrap()
        .with_runtime(
            RuntimeBinding::new(generation, None, None, digest_byte.to_string().repeat(64))
                .unwrap(),
        )
}

fn domain_scope(project: &str, mission: &str, mission_revision: u64) -> AuthorityScope {
    AuthorityScope::new("tenant-a", project, mission, mission_revision).unwrap()
}

fn approval_command(effect: &str, digest_byte: char) -> DomainCommandBinding {
    DomainCommandBinding::approve_proposed_effect(effect, digest_byte.to_string().repeat(64))
        .unwrap()
}

fn proposal_command(effect: &str, digest_byte: char) -> DomainCommandBinding {
    DomainCommandBinding::propose_effect(effect, digest_byte.to_string().repeat(64)).unwrap()
}

fn browser_read(workspace: &str) -> BrowserReadBinding {
    BrowserReadBinding::new(
        workspace,
        5,
        7,
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
    )
    .unwrap()
}

fn effect_execution(
    effect: &str,
    scope_byte: char,
    authorization_byte: char,
) -> EffectExecutionBinding {
    EffectExecutionBinding::new(
        effect,
        scope_byte.to_string().repeat(64),
        authorization_byte.to_string().repeat(64),
    )
    .unwrap()
}

fn effect_reconciliation(
    effect: &str,
    scope_byte: char,
    authorization_byte: char,
) -> EffectReconciliationBinding {
    EffectReconciliationBinding::new(
        effect,
        scope_byte.to_string().repeat(64),
        authorization_byte.to_string().repeat(64),
    )
    .unwrap()
}

#[test]
fn effect_proposal_command_is_exact_and_domain_only() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();

    let proposal_digest = "c".repeat(64);
    let command = proposal_command("effect-a", 'c');
    let permit = host
        .authorize_domain_command(&scope, command.clone())
        .unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(permit.command(), &command);
    assert_eq!(permit.command().kind(), DomainCommandKind::ProposeEffect);
    assert_eq!(permit.command().effect_id(), "effect-a");
    assert_eq!(
        permit.command().proposal_digest(),
        Some(proposal_digest.as_str())
    );
    assert_eq!(permit.command().approval_scope_digest(), None);
    assert!(scope.runtime().is_none());
    assert!(host.active_runtime_scope().is_none());

    host.finish_domain_command(permit).unwrap();
    assert_eq!(host.active_domain_command_scope(), None);
    assert!(host.active_runtime_scope().is_none());
}

#[test]
fn domain_command_requires_and_preserves_exact_bound_scope() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    let command = approval_command("effect-a", 'a');
    assert_eq!(
        host.authorize_domain_command(&scope, command.clone())
            .unwrap_err(),
        CordisError::AuthorityScopeUnbound
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();
    let other = domain_scope("project-a", "mission-b", 3);
    assert_eq!(
        host.authorize_domain_command(&other, command.clone())
            .unwrap_err(),
        CordisError::AuthorityScopeMismatch
    );

    let permit = host
        .authorize_domain_command(&scope, command.clone())
        .unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(permit.command(), &command);
    assert_eq!(
        permit.command().kind(),
        DomainCommandKind::ApproveProposedEffect
    );
    assert_eq!(host.active_domain_command_scope(), Some(&scope));
    assert_eq!(
        host.authorize_domain_command(&scope, command.clone())
            .unwrap_err(),
        CordisError::DomainCommandDispatchBusy
    );
    assert_eq!(
        host.authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'a', 'b'),)
            .unwrap_err(),
        CordisError::DomainCommandDispatchBusy
    );
    assert_eq!(
        host.bind_domain_kernel_scope(
            scope.clone(),
            KernelConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap_err(),
        CordisError::DomainCommandDispatchBusy
    );
    host.finish_domain_command(permit).unwrap();
    assert_eq!(host.bound_scope(), Some(&scope));
    assert_eq!(host.active_domain_command_scope(), None);
}

#[test]
fn domain_command_excludes_runtime_authority_and_runtime_bound_scopes() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    assert_eq!(
        host.authorize_domain_command(&scope, approval_command("effect-a", 'a'))
            .unwrap_err(),
        CordisError::DomainCommandRuntimeBound
    );

    let permit = host.authorize_runtime(&scope).unwrap();
    assert_eq!(
        host.authorize_domain_command(&scope, approval_command("effect-a", 'a'))
            .unwrap_err(),
        CordisError::RuntimeDispatchBusy
    );
    assert_eq!(
        host.authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'a', 'b'),)
            .unwrap_err(),
        CordisError::RuntimeDispatchBusy
    );
    host.finish_runtime(permit).unwrap();
}

#[test]
fn abandoned_domain_command_permit_releases_active_slot() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_domain_command(&scope, approval_command("effect-a", 'a'))
        .unwrap();
    assert_eq!(host.active_domain_command_scope(), Some(&scope));
    drop(permit);
    assert_eq!(host.active_domain_command_scope(), None);

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_domain_command(&scope, approval_command("effect-a", 'a'))
        .unwrap();
    host.finish_domain_command(permit).unwrap();
}

#[test]
fn browser_read_is_exact_mutually_exclusive_drop_safe_and_teardown_revoked() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    assert_eq!(
        host.authorize_browser_read(&scope, browser_read("workspace-a"))
            .unwrap_err(),
        CordisError::AuthorityScopeUnbound
    );
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();
    let other = domain_scope("project-a", "mission-b", 3);
    assert_eq!(
        host.authorize_browser_read(&other, browser_read("workspace-a"))
            .unwrap_err(),
        CordisError::AuthorityScopeMismatch
    );

    let binding = browser_read("workspace-a");
    let permit = host
        .authorize_browser_read(&scope, binding.clone())
        .unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(permit.binding(), &binding);
    assert_eq!(host.active_browser_read_scope(), Some(&scope));
    assert_eq!(
        host.authorize_browser_read(&scope, binding.clone())
            .unwrap_err(),
        CordisError::BrowserReadDispatchBusy
    );
    assert_eq!(
        host.authorize_domain_command(&scope, approval_command("effect-a", 'd'))
            .unwrap_err(),
        CordisError::BrowserReadDispatchBusy
    );
    assert_eq!(
        host.authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'd', 'e'),)
            .unwrap_err(),
        CordisError::BrowserReadDispatchBusy
    );
    assert_eq!(
        host.bind_domain_kernel_scope(
            scope.clone(),
            KernelConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap_err(),
        CordisError::BrowserReadDispatchBusy
    );
    drop(permit);
    assert_eq!(host.active_browser_read_scope(), None);

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();
    let permit = host.authorize_browser_read(&scope, binding).unwrap();
    host.teardown();
    assert_eq!(host.active_browser_read_scope(), None);
    assert_eq!(host.bound_scope(), None);
    assert_eq!(
        host.finish_browser_read(permit).unwrap_err(),
        CordisError::BrowserReadPermitMismatch
    );

    let runtime = runtime_scope("project-a", "mission-a", 4, 2, 'f');
    let mut runtime_host = CordisHost::boot(false).unwrap();
    runtime_host
        .bind_domain_kernel_scope(
            runtime.clone(),
            KernelConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap();
    assert_eq!(
        runtime_host
            .authorize_browser_read(&runtime, browser_read("workspace-a"))
            .unwrap_err(),
        CordisError::BrowserReadRuntimeBound
    );
}

#[test]
fn effect_execution_requires_exact_approved_domain_scope() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    let binding = effect_execution("effect-a", 'a', 'b');
    assert_eq!(
        host.authorize_effect_execution(&scope, binding.clone())
            .unwrap_err(),
        CordisError::AuthorityScopeUnbound
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        None,
        now(),
    )
    .unwrap();
    assert_eq!(
        host.authorize_effect_execution(&scope, binding.clone())
            .unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    let other = domain_scope("project-a", "mission-b", 3);
    assert_eq!(
        host.authorize_effect_execution(&other, binding.clone())
            .unwrap_err(),
        CordisError::AuthorityScopeMismatch
    );

    let permit = host
        .authorize_effect_execution(&scope, binding.clone())
        .unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(permit.binding(), &binding);
    assert_eq!(permit.binding().effect_id(), "effect-a");
    assert_eq!(permit.binding().approval_scope_digest(), "a".repeat(64));
    assert_eq!(
        permit.binding().broker_authorization_digest(),
        "b".repeat(64)
    );
    assert_eq!(host.active_effect_execution_scope(), Some(&scope));
    assert_eq!(
        host.authorize_effect_execution(&scope, binding.clone())
            .unwrap_err(),
        CordisError::EffectExecutionDispatchBusy
    );
    assert_eq!(
        host.authorize_domain_command(&scope, approval_command("effect-a", 'a'))
            .unwrap_err(),
        CordisError::EffectExecutionDispatchBusy
    );
    assert_eq!(
        host.authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'a', 'b'),)
            .unwrap_err(),
        CordisError::EffectExecutionDispatchBusy
    );
    assert_eq!(
        host.bind_domain_kernel_scope(
            scope.clone(),
            KernelConsentState::Confirmed,
            None,
            Some(live_approval()),
            now(),
        )
        .unwrap_err(),
        CordisError::EffectExecutionDispatchBusy
    );
    host.finish_effect_execution(permit).unwrap();
    assert_eq!(host.active_effect_execution_scope(), None);
    assert_eq!(host.bound_scope(), Some(&scope));
}

#[test]
fn effect_execution_is_disjoint_from_runtime_and_domain_command_authority() {
    let mut host = CordisHost::boot(false).unwrap();
    let runtime = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        runtime.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    assert_eq!(
        host.authorize_effect_execution(&runtime, effect_execution("effect-a", 'a', 'b'))
            .unwrap_err(),
        CordisError::EffectExecutionRuntimeBound
    );
    let runtime_permit = host.authorize_runtime(&runtime).unwrap();
    assert_eq!(
        host.authorize_effect_execution(&runtime, effect_execution("effect-a", 'a', 'b'))
            .unwrap_err(),
        CordisError::RuntimeDispatchBusy
    );
    host.finish_runtime(runtime_permit).unwrap();

    let scope = domain_scope("project-a", "mission-a", 4);
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    let command_permit = host
        .authorize_domain_command(&scope, approval_command("effect-a", 'a'))
        .unwrap();
    assert_eq!(
        host.authorize_effect_execution(&scope, effect_execution("effect-a", 'a', 'b'))
            .unwrap_err(),
        CordisError::DomainCommandDispatchBusy
    );
    host.finish_domain_command(command_permit).unwrap();
}

#[test]
fn abandoned_effect_execution_permit_releases_slot_and_teardown_revokes_it() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 3);
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_effect_execution(&scope, effect_execution("effect-a", 'a', 'b'))
        .unwrap();
    assert_eq!(host.active_effect_execution_scope(), Some(&scope));
    drop(permit);
    assert_eq!(host.active_effect_execution_scope(), None);

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_effect_execution(&scope, effect_execution("effect-a", 'a', 'b'))
        .unwrap();
    host.teardown();
    assert_eq!(host.active_effect_execution_scope(), None);
    assert_eq!(host.bound_scope(), None);
    assert_eq!(
        host.finish_effect_execution(permit).unwrap_err(),
        CordisError::EffectExecutionPermitMismatch
    );
}

#[test]
fn effect_execution_binding_rejects_noncanonical_or_content_like_inputs() {
    assert_eq!(
        EffectExecutionBinding::new(" effect-a", "a".repeat(64), "b".repeat(64)).unwrap_err(),
        CordisError::InvalidAuthorityScope {
            field: "effect_execution_effect_id"
        }
    );
    assert_eq!(
        EffectExecutionBinding::new("effect-a", "A".repeat(64), "b".repeat(64)).unwrap_err(),
        CordisError::InvalidAuthorityDigest {
            field: "effect_execution_approval_scope_digest"
        }
    );
    assert_eq!(
        EffectExecutionBinding::new("effect-a", "a".repeat(64), "provider-token").unwrap_err(),
        CordisError::InvalidAuthorityDigest {
            field: "effect_execution_broker_authorization_digest"
        }
    );
}

#[test]
fn effect_reconciliation_is_exact_read_only_and_does_not_require_live_approval() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 7);
    let binding = EffectReconciliationBinding::new_observation_bound(
        "effect-a",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
    )
    .unwrap();
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();

    let permit = host
        .authorize_effect_reconciliation(&scope, binding.clone())
        .unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(permit.binding(), &binding);
    assert_eq!(permit.binding().effect_id(), "effect-a");
    assert_eq!(permit.binding().approval_scope_digest(), "a".repeat(64));
    assert_eq!(
        permit.binding().broker_authorization_digest(),
        "b".repeat(64)
    );
    assert_eq!(
        permit.binding().observation_authority_digest(),
        Some("c".repeat(64).as_str())
    );
    assert_eq!(host.active_effect_reconciliation_scope(), Some(&scope));
    assert!(host.active_effect_execution_scope().is_none());
    assert!(host.active_domain_command_scope().is_none());
    assert!(host.active_runtime_scope().is_none());

    host.finish_effect_reconciliation(permit).unwrap();
    assert!(host.active_effect_reconciliation_scope().is_none());
}

#[test]
fn effect_reconciliation_is_mutually_exclusive_drop_safe_and_teardown_revoked() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = domain_scope("project-a", "mission-a", 7);
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Confirmed,
        None,
        Some(live_approval()),
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'a', 'b'))
        .unwrap();
    assert_eq!(
        host.authorize_effect_execution(&scope, effect_execution("effect-a", 'a', 'b'))
            .unwrap_err(),
        CordisError::EffectReconciliationDispatchBusy
    );
    assert_eq!(
        host.authorize_domain_command(&scope, approval_command("effect-a", 'a'))
            .unwrap_err(),
        CordisError::EffectReconciliationDispatchBusy
    );
    assert_eq!(
        host.authorize_runtime(&scope).unwrap_err(),
        CordisError::EffectReconciliationDispatchBusy
    );
    drop(permit);
    assert!(host.active_effect_reconciliation_scope().is_none());

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();
    let permit = host
        .authorize_effect_reconciliation(&scope, effect_reconciliation("effect-a", 'a', 'b'))
        .unwrap();
    host.teardown();
    assert!(host.active_effect_reconciliation_scope().is_none());
    assert_eq!(
        host.finish_effect_reconciliation(permit).unwrap_err(),
        CordisError::EffectReconciliationPermitMismatch
    );

    let runtime = runtime_scope("project-a", "mission-a", 8, 2, 'c');
    let mut runtime_host = CordisHost::boot(false).unwrap();
    runtime_host
        .bind_domain_kernel_scope(
            runtime.clone(),
            KernelConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap();
    assert_eq!(
        runtime_host
            .authorize_effect_reconciliation(&runtime, effect_reconciliation("effect-a", 'a', 'b'),)
            .unwrap_err(),
        CordisError::EffectReconciliationRuntimeBound
    );
}

#[test]
fn effect_reconciliation_binding_is_distinct_redacted_and_canonical() {
    let binding = effect_reconciliation("effect-a", 'a', 'b');
    assert!(binding.observation_authority_digest().is_none());
    let debug = format!("{binding:?}");
    assert!(debug.contains("effect-a"));
    assert!(!debug.contains(&"a".repeat(64)));
    assert!(!debug.contains(&"b".repeat(64)));
    let bounded = EffectReconciliationBinding::new_observation_bound(
        "effect-a",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64),
    )
    .unwrap();
    assert_eq!(
        bounded.observation_authority_digest(),
        Some("c".repeat(64).as_str())
    );
    assert!(!format!("{bounded:?}").contains(&"c".repeat(64)));
    assert_eq!(
        EffectReconciliationBinding::new(" effect-a", "a".repeat(64), "b".repeat(64)).unwrap_err(),
        CordisError::InvalidAuthorityScope {
            field: "effect_reconciliation_effect_id"
        }
    );
    assert_eq!(
        EffectReconciliationBinding::new("effect-a", "A".repeat(64), "b".repeat(64)).unwrap_err(),
        CordisError::InvalidAuthorityDigest {
            field: "effect_reconciliation_approval_scope_digest"
        }
    );
    assert_eq!(
        EffectReconciliationBinding::new("effect-a", "a".repeat(64), "provider-token").unwrap_err(),
        CordisError::InvalidAuthorityDigest {
            field: "effect_reconciliation_broker_authorization_digest"
        }
    );
    assert_eq!(
        EffectReconciliationBinding::new_observation_bound(
            "effect-a",
            "a".repeat(64),
            "b".repeat(64),
            "Provider-GID",
        )
        .unwrap_err(),
        CordisError::InvalidAuthorityDigest {
            field: "effect_reconciliation_observation_authority_digest"
        }
    );
}

#[test]
fn runtime_dispatch_requires_and_preserves_exact_bound_scope() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    assert_eq!(
        host.authorize_runtime(&scope).unwrap_err(),
        CordisError::AuthorityScopeUnbound
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::Missing,
        None,
        None,
        now(),
    )
    .unwrap();
    let other = runtime_scope("project-a", "mission-b", 3, 2, 'a');
    assert_eq!(
        host.authorize_runtime(&other).unwrap_err(),
        CordisError::AuthorityScopeMismatch
    );

    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let started_agents = std::sync::Arc::clone(&agents);
    host.on_runtime_started(move |agent| {
        assert_eq!(agent.status(), AgentStatus::Running);
        assert_eq!(
            started_agents.list().as_slice(),
            std::slice::from_ref(agent)
        );
    })
    .unwrap();

    let mut permit = host.authorize_runtime(&scope).unwrap();
    assert_eq!(permit.scope(), &scope);
    assert_eq!(host.active_runtime_scope(), Some(&scope));
    assert_eq!(
        host.authorize_runtime(&scope).unwrap_err(),
        CordisError::RuntimeDispatchBusy
    );
    assert_eq!(
        host.bind_domain_kernel_scope(
            scope.clone(),
            KernelConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap_err(),
        CordisError::RuntimeDispatchBusy
    );
    assert!(agents.list().is_empty(), "authorization stays unpublished");
    permit.announce_started().unwrap();
    let agent = agents.list().into_iter().next().unwrap();
    host.finish_runtime(permit).unwrap().announce().unwrap();
    assert_eq!(host.bound_scope(), Some(&scope));
    assert_eq!(host.active_runtime_scope(), None);
    assert_eq!(agent.status(), AgentStatus::Idle);
    assert_eq!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .as_slice(),
        std::slice::from_ref(&agent),
        "the Mission Agent remains published while its Host is alive"
    );
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[test]
fn runtime_status_events_are_ordered_visible_and_non_vetoing() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));

    {
        let agents = std::sync::Arc::clone(&agents);
        let order = std::sync::Arc::clone(&order);
        host.context_mut()
            .on_emit(events::AGENT_CREATED, move |agent| {
                assert_eq!(agent.status(), AgentStatus::Running);
                assert_eq!(agents.list().as_slice(), std::slice::from_ref(agent));
                order.lock().unwrap().push("created".to_string());
            })
            .unwrap();
    }
    host.context_mut()
        .try_on_emit(events::AGENT_STATUS, |_: &AgentStatusChange| {
            Err(std::io::Error::other("contained status listener"))
        })
        .unwrap();
    host.context_mut()
        .on_emit(events::AGENT_STATUS, |_: &AgentStatusChange| {
            panic!("contained status listener panic");
        })
        .unwrap();
    {
        let agents = std::sync::Arc::clone(&agents);
        let order = std::sync::Arc::clone(&order);
        host.context_mut()
            .on_emit(events::AGENT_STATUS, move |change| {
                assert_eq!(change.agent().status(), change.status());
                assert_eq!(
                    agents.list().as_slice(),
                    std::slice::from_ref(change.agent())
                );
                order
                    .lock()
                    .unwrap()
                    .push(format!("status:{}", change.status().as_str()));
            })
            .unwrap();
    }
    {
        let agents = std::sync::Arc::clone(&agents);
        let order = std::sync::Arc::clone(&order);
        host.context_mut()
            .on_emit(events::AGENT_DISPOSED, move |agent| {
                assert_eq!(agent.status(), AgentStatus::Idle);
                assert!(agents.list().is_empty());
                order.lock().unwrap().push("disposed".to_string());
            })
            .unwrap();
    }

    let mut permit = host.authorize_runtime(&scope).unwrap();
    assert!(order.lock().unwrap().is_empty());
    permit.announce_started().unwrap();
    let agent = agents.list().into_iter().next().unwrap();
    assert_eq!(*order.lock().unwrap(), ["created", "status:running"]);

    let completion = host.finish_runtime(permit).unwrap();
    assert!(host.active_runtime_scope().is_none());
    assert_eq!(agent.status(), AgentStatus::Idle);
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    completion.announce().unwrap();

    assert_eq!(agent.status(), AgentStatus::Idle);
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    assert_eq!(
        *order.lock().unwrap(),
        ["created", "status:running", "status:idle"]
    );

    let teardown = host.teardown();
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    teardown.announce();
    assert!(agents.list().is_empty());
    assert_eq!(
        *order.lock().unwrap(),
        ["created", "status:running", "status:idle", "disposed"]
    );
}

#[test]
fn same_mission_reuses_exact_agent_after_authority_revalidation() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let created = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let created = std::sync::Arc::clone(&created);
        host.on_runtime_started(move |_| {
            created.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .unwrap();
    }
    let mut first = host.authorize_runtime(&scope).unwrap();
    first.announce_started().unwrap();
    let agent = first.agent().clone();
    host.finish_runtime(first).unwrap().announce().unwrap();

    let next_scope = runtime_scope("project-a", "mission-a", 4, 3, 'b');
    assert_eq!(
        host.authorize_runtime(&next_scope).unwrap_err(),
        CordisError::AuthorityScopeMismatch,
        "every permit still requires the currently bound exact authority"
    );
    host.bind_domain_kernel_scope(
        next_scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let mut next = host.authorize_runtime(&next_scope).unwrap();
    assert!(next.agent().is_same_lifecycle(&agent));
    next.announce_started().unwrap();
    host.finish_runtime(next).unwrap().announce().unwrap();

    assert_eq!(agent.status(), AgentStatus::Idle);
    assert_eq!(created.load(std::sync::atomic::Ordering::SeqCst), 1);
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[test]
fn distinct_missions_retain_distinct_agents_until_host_teardown() {
    let mut host = CordisHost::boot(false).unwrap();
    let first_scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        first_scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let mut first = host.authorize_runtime(&first_scope).unwrap();
    first.announce_started().unwrap();
    let first_agent = first.agent().clone();
    host.finish_runtime(first).unwrap().announce().unwrap();

    let second_scope = runtime_scope("project-a", "mission-b", 1, 1, 'b');
    host.bind_domain_kernel_scope(
        second_scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let mut second = host.authorize_runtime(&second_scope).unwrap();
    second.announce_started().unwrap();
    assert!(!second.agent().is_same_lifecycle(&first_agent));
    host.finish_runtime(second).unwrap().announce().unwrap();
    assert_eq!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .len(),
        2
    );

    let agents = host.context().agents::<AgentsSurface>().unwrap();
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[tokio::test]
async fn runtime_agent_status_and_when_idle_follow_the_exact_permit() {
    let idle = AgentRef::new("not-yet-published");
    assert_eq!(idle.status(), AgentStatus::Idle);
    idle.when_idle().await;

    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let mut permit = host.authorize_runtime(&scope).unwrap();
    assert!(agents.list().is_empty());

    permit.announce_started().unwrap();
    let agent = agents.list().into_iter().next().unwrap();
    assert_eq!(agent.status(), AgentStatus::Running);
    let waiter = tokio::spawn({
        let agent = agent.clone();
        async move {
            agent.when_idle().await;
            agent.status()
        }
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    let completion = host.finish_runtime(permit).unwrap();
    assert_eq!(agent.status(), AgentStatus::Idle);
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    assert_eq!(waiter.await.unwrap(), AgentStatus::Idle);
    completion.announce().unwrap();
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one journey keeps permit publication, exact Agent callbacks, explicit Session routing, and settlement together"
)]
async fn permit_bound_turn_uses_one_live_agent_and_an_explicit_session_identity() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();

    let session_id = SessionId::new("mission-a").unwrap();
    let sessions = host.context().sessions::<SessionStore>().unwrap();
    let session = sessions.create(session_id.clone()).unwrap();
    session
        .inbox()
        .append_next_turn(SessionMessage {
            id: "runtime-input-a".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "run the exact live agent".into(),
            }],
            source: SessionMessageSource::User,
        })
        .unwrap();

    let expected = std::sync::Arc::new(std::sync::Mutex::new(None::<AgentRef>));
    let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::<AgentRef>::new()));
    let agents = host.context().agents::<AgentsSurface>().unwrap();

    {
        let expected = std::sync::Arc::clone(&expected);
        let observed = std::sync::Arc::clone(&observed);
        let agents = std::sync::Arc::clone(&agents);
        host.context_mut()
            .on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
                let expected = expected.lock().unwrap().clone().unwrap();
                assert!(proposal.agent().is_same_lifecycle(&expected));
                assert_eq!(proposal.agent().status(), AgentStatus::Running);
                assert!(
                    agents
                        .list()
                        .iter()
                        .any(|agent| agent.is_same_lifecycle(proposal.agent()))
                );
                observed.lock().unwrap().push(proposal.agent().clone());
                next(proposal)
            })
            .unwrap();
    }
    {
        let expected = std::sync::Arc::clone(&expected);
        let observed = std::sync::Arc::clone(&observed);
        let agents = std::sync::Arc::clone(&agents);
        host.context_mut()
            .on_waterfall(events::AGENT_REQUEST, move |request, next| {
                let expected = expected.lock().unwrap().clone().unwrap();
                assert!(request.agent().is_same_lifecycle(&expected));
                assert_eq!(request.agent().status(), AgentStatus::Running);
                assert!(
                    agents
                        .list()
                        .iter()
                        .any(|agent| agent.is_same_lifecycle(request.agent()))
                );
                observed.lock().unwrap().push(request.agent().clone());
                next(request)
            })
            .unwrap();
    }
    {
        let expected = std::sync::Arc::clone(&expected);
        let observed = std::sync::Arc::clone(&observed);
        let agents = std::sync::Arc::clone(&agents);
        host.context_mut()
            .on_serial(
                events::AGENT_TURN_STOPPING,
                move |stopping: std::sync::Arc<AgentTurnStopping>| {
                    let expected = expected.lock().unwrap().clone().unwrap();
                    assert!(stopping.agent().is_same_lifecycle(&expected));
                    assert_eq!(stopping.agent().status(), AgentStatus::Running);
                    assert!(
                        agents
                            .list()
                            .iter()
                            .any(|agent| agent.is_same_lifecycle(stopping.agent()))
                    );
                    observed.lock().unwrap().push(stopping.agent().clone());
                    std::future::ready(Ok::<_, std::convert::Infallible>(BailOutcome::Continue(
                        NonBail::Undefined,
                    )))
                },
            )
            .unwrap();
    }
    {
        let session_id = session_id.clone();
        host.context_mut()
            .on_waterfall(events::LLM_STREAM, move |stream, _next| {
                assert_eq!(
                    stream.request().and_then(|request| request.session_id()),
                    Some(&session_id)
                );
                stream.with_chunk_stream(Box::pin(futures_util::stream::iter([
                    SessionStreamChunk::Finish {
                        reason: SessionFinishReason::Stop,
                        replay_state: None,
                    },
                ])))
            })
            .unwrap();
    }

    let mut permit = host.authorize_runtime(&scope).unwrap();
    assert_ne!(permit.agent().id, session_id.as_str());
    *expected.lock().unwrap() = Some(permit.agent().clone());
    assert_eq!(
        host.run_authorized_runtime_agent_turn(
            &permit,
            &session_id,
            SessionCallConfig {
                provider: "mock".into(),
                model: "model".into(),
                reasoning_effort: None,
                temperature: None,
                max_tokens: None,
                stop: None,
            },
            &LifecycleCancellation::default(),
        )
        .await,
        Err(CordisError::RuntimePermitMismatch)
    );

    permit.announce_started().unwrap();
    let published = agents.list().into_iter().next().unwrap();
    assert!(published.is_same_lifecycle(permit.agent()));
    let outcome = host
        .run_authorized_runtime_agent_turn(
            &permit,
            &session_id,
            SessionCallConfig {
                provider: "mock".into(),
                model: "model".into(),
                reasoning_effort: None,
                temperature: None,
                max_tokens: None,
                stop: None,
            },
            &LifecycleCancellation::default(),
        )
        .await
        .unwrap();

    assert_eq!(outcome.reason(), TurnEndReason::Completed);
    assert_eq!(outcome.steps(), 1);
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 3);
    assert!(
        observed
            .iter()
            .all(|agent| agent.is_same_lifecycle(permit.agent()))
    );
    drop(observed);

    host.finish_runtime(permit).unwrap().announce().unwrap();
    assert_eq!(agents.list().len(), 1);
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[tokio::test]
async fn runtime_teardown_revokes_publication_while_the_permit_is_retained() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let statuses = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    host.context_mut()
        .on_emit(events::AGENT_STATUS, |change: &AgentStatusChange| {
            assert_ne!(
                change.status(),
                AgentStatus::Idle,
                "contained teardown status listener"
            );
        })
        .unwrap();
    {
        let statuses = std::sync::Arc::clone(&statuses);
        host.context_mut()
            .on_emit(events::AGENT_STATUS, move |change: &AgentStatusChange| {
                statuses.lock().unwrap().push(change.status());
            })
            .unwrap();
    }
    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();
    let agent = agents.list().into_iter().next().unwrap();
    assert_eq!(agent.status(), AgentStatus::Running);

    let teardown = host.teardown();
    assert_eq!(agent.status(), AgentStatus::Idle);
    agent.when_idle().await;
    assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
    assert!(host.active_runtime_scope().is_none());
    assert_eq!(*statuses.lock().unwrap(), [AgentStatus::Running]);
    teardown.announce();
    assert!(agents.list().is_empty());
    assert_eq!(
        *statuses.lock().unwrap(),
        [AgentStatus::Running, AgentStatus::Idle]
    );

    let replacement = AgentRef::new(agent.id.clone());
    agents.register(replacement.clone());
    drop(permit);
    let published = agents.list();
    assert_eq!(published.as_slice(), std::slice::from_ref(&replacement));
}

#[test]
fn runtime_agent_publication_collision_never_replaces_or_disposes_the_live_identity() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let agent = AgentRef::new("project-a:mission-a:2:1");
    register_agent(host.context_mut(), agent.clone()).unwrap();
    let disposed_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let status_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let disposed_calls = std::sync::Arc::clone(&disposed_calls);
        host.on_runtime_finished(move |_| {
            disposed_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .unwrap();
    }
    {
        let status_calls = std::sync::Arc::clone(&status_calls);
        host.context_mut()
            .on_emit(events::AGENT_STATUS, move |_| {
                status_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .unwrap();
    }

    let mut permit = host.authorize_runtime(&scope).unwrap();
    let first = permit.announce_started().unwrap_err();
    let second = permit.announce_started().unwrap_err();
    assert_eq!(first, second);
    assert_eq!(
        first,
        CordisError::AgentAlreadyPublished {
            id: agent.id.clone()
        }
    );
    let published = host.context().agents::<AgentsSurface>().unwrap().list();
    assert_eq!(published.as_slice(), std::slice::from_ref(&agent));
    assert_eq!(agent.status(), AgentStatus::Idle);

    host.finish_runtime(permit).unwrap().announce().unwrap();
    assert_eq!(disposed_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(status_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(host.active_runtime_scope().is_none());
}

#[test]
fn runtime_agent_publication_panic_rolls_back_before_the_caller_recovers() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let status_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    {
        let status_calls = std::sync::Arc::clone(&status_calls);
        host.context_mut()
            .on_emit(events::AGENT_STATUS, move |_| {
                status_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
            .unwrap();
    }
    let observed_agent = std::sync::Arc::clone(&observed);
    host.on_runtime_started(move |agent| {
        assert_eq!(agent.status(), AgentStatus::Running);
        *observed_agent.lock().unwrap() = Some(agent.clone());
        panic!("publication listener panic");
    })
    .unwrap();

    let mut permit = host.authorize_runtime(&scope).unwrap();
    let panicked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| permit.announce_started()));
    assert!(panicked.is_err());
    assert!(agents.list().is_empty());
    assert_eq!(
        observed.lock().unwrap().as_ref().unwrap().status(),
        AgentStatus::Idle
    );
    assert_eq!(status_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    host.finish_runtime(permit).unwrap().announce().unwrap();
    assert!(host.active_runtime_scope().is_none());
}

#[test]
fn runtime_dispatch_rejects_missing_and_stale_durable_bindings() {
    let mut host = CordisHost::boot(true).unwrap();
    let base = AuthorityScope::new("tenant-a", "project-a", "mission-a", 3).unwrap();
    host.bind_domain_kernel_scope(
        base.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();

    assert_eq!(
        host.authorize_runtime(&base).unwrap_err(),
        CordisError::RuntimeAuthorityUnbound
    );
    let bound = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        bound.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    for stale in [
        runtime_scope("project-a", "mission-a", 2, 2, 'a'),
        runtime_scope("project-a", "mission-a", 3, 1, 'a'),
        runtime_scope("project-a", "mission-a", 3, 2, 'b'),
    ] {
        assert_eq!(
            host.authorize_runtime(&stale).unwrap_err(),
            CordisError::AuthorityScopeMismatch
        );
    }
    let permit = host.authorize_runtime(&bound).unwrap();
    host.finish_runtime(permit).unwrap();
    assert!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .is_empty()
    );
    assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
}

#[test]
fn abandoned_runtime_permit_releases_active_slot_and_keeps_idle_agent() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope("project-a", "mission-a", 3, 2, 'a');
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let permit = host.authorize_runtime(&scope).unwrap();
    assert_eq!(host.active_runtime_scope(), Some(&scope));
    drop(permit);
    assert_eq!(host.active_runtime_scope(), None);
    assert!(host.take_deferred_runtime_status().is_empty());
    assert!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .is_empty()
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let statuses = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let statuses = std::sync::Arc::clone(&statuses);
        host.context_mut()
            .on_emit(events::AGENT_STATUS, move |change: &AgentStatusChange| {
                statuses.lock().unwrap().push(change.status());
            })
            .unwrap();
    }
    let mut permit = host.authorize_runtime(&scope).unwrap();
    permit.announce_started().unwrap();
    let abandoned = host
        .context()
        .agents::<AgentsSurface>()
        .unwrap()
        .list()
        .into_iter()
        .next()
        .unwrap();
    assert_eq!(abandoned.status(), AgentStatus::Running);
    drop(permit);
    assert_eq!(abandoned.status(), AgentStatus::Idle);
    assert!(host.active_runtime_scope().is_none());
    assert_eq!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .as_slice(),
        std::slice::from_ref(&abandoned)
    );
    assert_eq!(*statuses.lock().unwrap(), [AgentStatus::Running]);
    let deferred = host.take_deferred_runtime_status();
    assert_eq!(deferred.len(), 1);
    for status in deferred {
        status.announce();
    }
    assert_eq!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .as_slice(),
        std::slice::from_ref(&abandoned)
    );
    assert_eq!(
        *statuses.lock().unwrap(),
        [AgentStatus::Running, AgentStatus::Idle]
    );

    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        now(),
    )
    .unwrap();
    let mut permit = host.authorize_runtime(&scope).unwrap();
    assert!(permit.agent().is_same_lifecycle(&abandoned));
    permit.announce_started().unwrap();
    host.finish_runtime(permit).unwrap().announce().unwrap();
    assert_eq!(abandoned.status(), AgentStatus::Idle);
    let agents = host.context().agents::<AgentsSurface>().unwrap();
    host.teardown().announce();
    assert!(agents.list().is_empty());
}

#[test]
fn production_desktop_surfaces_do_not_pre_grant_consent_or_approval() {
    for openinterpreter in [false, true] {
        let host = CordisHost::boot(openinterpreter).unwrap();
        let domain = host.context().domain::<DomainSurface>().unwrap();
        let broker = host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap();
        assert!(!domain.consent());
        assert!(!domain.approved());
        assert_eq!(domain.as_ref(), &DomainSurface::default());
        assert!(!broker.receipt_is_verification());
        assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
        assert_eq!(broker.owner(), SurfaceOwner::Hartevo);
        assert_eq!(
            host.runtime_plugin(),
            openinterpreter.then_some(OPENINTERPRETER)
        );
    }
}

#[test]
fn boot_mounts_surfaces_loop_and_gate() {
    let mut host = CordisHost::boot(false).unwrap();
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(
        enforce_invariants(host.context()).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    for key in host.mounted_keys() {
        assert!(host.context().has(key), "{key} must be mounted");
    }
    assert_eq!(host.runtime_plugin(), None);
    let domain = host.context().domain::<DomainSurface>().unwrap();
    assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
    assert!(!domain.consent());
    assert!(!domain.approved());
    assert!(domain.local_first());
    assert!(domain.sqlcipher());
    assert!(domain.eval_gate());
    assert_eq!(
        host.context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .owner(),
        SurfaceOwner::Hartevo
    );
    assert!(
        !host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification()
    );
    assert!(host.context().get::<String>(OPENINTERPRETER).is_none());

    bind_confirmed_approved(&mut host);
    let out = host.step(AgentStep::new("mission-host", "plan")).unwrap();
    assert_eq!(out.id, "mission-host");
    host.apply_effect().unwrap();
}

#[test]
fn boot_keeps_openinterpreter_as_optional_runtime_plugin() {
    let mut host = CordisHost::boot(true).unwrap();
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
    assert_eq!(
        host.context().runtime::<RuntimeSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        host.context().domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        host.step(AgentStep::new("mission-oi", "plan")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    bind_confirmed_approved(&mut host);
    let out = host.step(AgentStep::new("mission-oi", "plan")).unwrap();
    assert_eq!(out.id, "mission-oi");
    host.apply_effect().unwrap();
}

#[test]
fn step_fails_closed_without_consent_or_approval() {
    let mut host = CordisHost::boot(false).unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    host.teardown();
    let mut host = CordisHost::boot(false).unwrap();
    host.bind_domain_kernel(KernelConsentState::Confirmed, None, None, now())
        .unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );
}

#[test]
fn receipt_is_not_verification_on_host_effect() {
    let mut host = CordisHost::boot(false).unwrap();
    assert!(
        !host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification()
    );
    bind_confirmed_approved(&mut host);
    host_is_cordis_loop(&host).unwrap();
    host.apply_effect().unwrap();
}

#[test]
fn overlay_boot_starts_five_host_plugins_and_can_disable_openinterpreter() {
    let overlay = EnvironmentOverlay::new("macos-r0");
    let loader = LoaderContext::new();
    let (mut host, report) = CordisHost::boot_overlay(&overlay, &loader, false).unwrap();

    assert_eq!(report.started, host_plugin_ids());
    assert_eq!(report.disabled, [PluginId::new(OPENINTERPRETER_PLUGIN_ID)]);
    assert_eq!(
        HOST_PLUGIN_IDS,
        [
            "surfaces",
            "compaction-basic",
            "agent-loop",
            "subagent-spawn-in-process",
            "invariants"
        ]
    );
    assert!(host.context().get::<&str>(OPENINTERPRETER).is_none());
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-overlay", "plan"))
            .unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    bind_confirmed_approved(&mut host);
    let out = host
        .step(
            AgentStep::new("mission-overlay", "plan")
                .with_tool(ToolCall::new("search", "q=growth", "allow")),
        )
        .unwrap();
    assert_eq!(out.id, "mission-overlay");
}

#[test]
fn overlay_boot_may_start_openinterpreter_adapter_without_owning_domain() {
    let overlay = EnvironmentOverlay::new("macos-r0");
    let loader = LoaderContext::new();
    let (mut host, report) = CordisHost::boot_overlay(&overlay, &loader, true).unwrap();

    assert_eq!(
        report.started,
        [
            PluginId::new("surfaces"),
            PluginId::new("compaction-basic"),
            PluginId::new("agent-loop"),
            PluginId::new("subagent-spawn-in-process"),
            PluginId::new("invariants"),
            PluginId::new(OPENINTERPRETER_PLUGIN_ID),
        ]
    );
    assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
    assert_eq!(
        host.context().get::<&str>(OPENINTERPRETER).as_deref(),
        Some(&"adapter")
    );
    assert_eq!(
        host.context().domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    bind_confirmed_approved(&mut host);
    host.apply_effect().unwrap();
    let out = host
        .step(AgentStep::new("mission-adapter", "plan"))
        .unwrap();
    assert_eq!(out.id, "mission-adapter");
}

#[test]
fn boot_without_surfaces_cannot_mount_gate() {
    assert_eq!(
        {
            let mut ctx = hartevo_cordis::Context::new();
            ctx.mount(InvariantGate)
        }
        .unwrap_err(),
        CordisError::MissingDependencies(vec![
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
        ])
    );
}

#[test]
fn boot_time_host_check_requires_local_first_sqlcipher_eval_and_hartevo_ownership() {
    for openinterpreter in [false, true] {
        let host = CordisHost::boot(openinterpreter).unwrap();
        host_is_cordis_loop(&host).unwrap();
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
        assert!(domain.local_first() && domain.sqlcipher() && domain.eval_gate());
        assert_eq!(
            host.context()
                .effect_broker::<EffectBrokerSurface>()
                .unwrap()
                .owner(),
            SurfaceOwner::Hartevo
        );
        assert_eq!(
            host.runtime_plugin(),
            openinterpreter.then_some(OPENINTERPRETER)
        );
    }
}

#[test]
fn kernel_facts_fail_closed_without_live_consent() {
    let mut host = CordisHost::boot(false).unwrap();
    host_is_cordis_loop(&host).unwrap();

    host.bind_domain_kernel(KernelConsentState::Confirmed, None, None, now())
        .unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );

    for (state, record, at) in [
        (KernelConsentState::Missing, None, now()),
        (
            KernelConsentState::Withdrawn,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Withdrawn,
                granted_at: Some(now()),
                valid_until: Some(now() + Duration::days(30)),
                withdrawn_at: Some(now() + Duration::hours(1)),
            }),
            now() + Duration::hours(2),
        ),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Denied,
                granted_at: None,
                valid_until: None,
                withdrawn_at: None,
            }),
            now(),
        ),
        (
            KernelConsentState::NotRequired,
            Some(KernelConsentRecord {
                status: KernelConsentStatus::Expired,
                granted_at: Some(now() - Duration::days(2)),
                valid_until: Some(now() - Duration::days(1)),
                withdrawn_at: None,
            }),
            now(),
        ),
    ] {
        host.bind_domain_kernel(state, record, Some(live_approval()), at)
            .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }
}

#[test]
fn kernel_facts_bind_live_consent_and_in_window_approval() {
    let mut host = CordisHost::boot(false).unwrap();
    host_is_cordis_loop(&host).unwrap();

    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: now(),
        }),
        now(),
    )
    .unwrap();
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );

    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Rejected,
            valid_until: now() + Duration::minutes(5),
        }),
        now(),
    )
    .unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );

    let later = now() + Duration::hours(1);
    host.bind_domain_kernel(
        KernelConsentState::NotRequired,
        Some(granted_record(now() + Duration::days(30))),
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: later + Duration::minutes(5),
        }),
        later,
    )
    .unwrap();
    host.step(AgentStep::new("mission-granted-record", "grow"))
        .unwrap();

    bind_confirmed_approved(&mut host);
    host.step(AgentStep::new("mission-confirmed", "grow"))
        .unwrap();
    let domain = host.context().domain::<DomainSurface>().unwrap();
    assert!(domain.consent());
    assert!(domain.approved());
    assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
    assert!(domain.local_first() && domain.sqlcipher() && domain.eval_gate());
}

#[test]
fn teardown_reverses_host_mounts() {
    let mut host = CordisHost::boot(true).unwrap();
    bind_confirmed_approved(&mut host);
    host.step(AgentStep::new("mission-1", "grow")).unwrap();
    host.teardown();
    for key in [
        keys::TOOLS,
        keys::LLM,
        keys::SESSIONS,
        keys::AGENTS,
        keys::DOMAIN,
        keys::EFFECT_BROKER,
        keys::RUNTIME,
        keys::DESKTOP,
    ] {
        assert!(!host.context().has(key), "{key} must reverse on teardown");
    }
    assert_eq!(host.runtime_plugin(), None);
}
