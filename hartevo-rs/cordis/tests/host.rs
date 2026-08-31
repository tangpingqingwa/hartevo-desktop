use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, AgentsSurface, AuthorityScope, CordisError, CordisHost, DomainCommandBinding,
    DomainCommandKind, DomainSurface, EffectBrokerSurface, EffectExecutionBinding,
    EffectReconciliationBinding, EnvironmentOverlay, HOST_PLUGIN_IDS, InvariantGate,
    KernelApproval, KernelApprovalDecision, KernelConsentRecord, KernelConsentState,
    KernelConsentStatus, LoaderContext, OPENINTERPRETER, OPENINTERPRETER_PLUGIN_ID, PluginId,
    RuntimeBinding, RuntimeSurface, SurfaceOwner, ToolCall, enforce_invariants,
    host_is_cordis_loop, host_plugin_ids, invariant_missing, keys,
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

    let permit = host.authorize_runtime(&scope).unwrap();
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
    assert_eq!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .len(),
        1
    );
    host.finish_runtime(permit).unwrap();
    assert_eq!(host.bound_scope(), Some(&scope));
    assert_eq!(host.active_runtime_scope(), None);
    assert!(
        host.context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .is_empty(),
        "the scoped runtime agent must be disposed after the adapter returns"
    );
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
fn abandoned_runtime_permit_releases_agent_and_active_slot() {
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
    let permit = host.authorize_runtime(&scope).unwrap();
    host.finish_runtime(permit).unwrap();
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
fn overlay_boot_starts_three_host_plugins_and_can_disable_openinterpreter() {
    let overlay = EnvironmentOverlay::new("macos-r0");
    let loader = LoaderContext::new();
    let (mut host, report) = CordisHost::boot_overlay(&overlay, &loader, false).unwrap();

    assert_eq!(report.started, host_plugin_ids());
    assert_eq!(report.disabled, [PluginId::new(OPENINTERPRETER_PLUGIN_ID)]);
    assert_eq!(HOST_PLUGIN_IDS, ["surfaces", "agent-loop", "invariants"]);
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
            PluginId::new("agent-loop"),
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
