use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, AgentsSurface, AuthorityScope, CordisError, CordisHost, DomainSurface,
    EffectBrokerSurface, EnvironmentOverlay, HOST_PLUGIN_IDS, InvariantGate, KernelApproval,
    KernelApprovalDecision, KernelConsentRecord, KernelConsentState, KernelConsentStatus,
    LoaderContext, OPENINTERPRETER, OPENINTERPRETER_PLUGIN_ID, PluginId, RuntimeBinding,
    RuntimeSurface, SurfaceOwner, ToolCall, enforce_invariants, host_is_cordis_loop,
    host_plugin_ids, invariant_missing, keys,
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
