use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, CordisError, CordisHost, DomainSurface, EffectBrokerSurface, EnvironmentOverlay,
    HOST_PLUGIN_IDS, HartevoSurfaces, InvariantGate, KernelApproval, KernelApprovalDecision,
    KernelConsentRecord, KernelConsentState, KernelConsentStatus, LoaderContext, OPENINTERPRETER,
    OPENINTERPRETER_PLUGIN_ID, PluginId, RuntimeSurface, SurfaceOwner, ToolCall, desktop_surfaces,
    enforce_invariants, host_is_cordis_loop, host_plugin_ids, invariant_missing, keys,
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

#[test]
fn production_desktop_surfaces_do_not_pre_grant_consent_or_approval() {
    for openinterpreter in [false, true] {
        let surfaces = desktop_surfaces(openinterpreter);
        assert!(!surfaces.domain.consent);
        assert!(!surfaces.domain.approved);
        assert_eq!(surfaces.domain, DomainSurface::default());
        assert!(!surfaces.effect_broker.receipt_is_verification);
        assert_eq!(surfaces.domain.owner, SurfaceOwner::Hartevo);
        assert_eq!(surfaces.effect_broker.owner, SurfaceOwner::Hartevo);
        assert_eq!(
            surfaces.runtime.plugin,
            openinterpreter.then_some(OPENINTERPRETER)
        );
    }
}

#[test]
fn boot_mounts_surfaces_loop_and_gate() {
    let mut host = CordisHost::boot(desktop_surfaces(false)).unwrap();
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
    assert_eq!(domain.owner, SurfaceOwner::Hartevo);
    assert!(!domain.consent);
    assert!(!domain.approved);
    assert!(domain.local_first);
    assert!(domain.sqlcipher);
    assert!(domain.eval_gate);
    assert_eq!(
        host.context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .owner,
        SurfaceOwner::Hartevo
    );
    assert!(
        !host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification
    );
    assert!(host.context().get::<String>(OPENINTERPRETER).is_none());

    bind_confirmed_approved(&mut host);
    let out = host.step(AgentStep::new("mission-host", "plan")).unwrap();
    assert_eq!(out.id, "mission-host");
    host.apply_effect().unwrap();
}

#[test]
fn boot_keeps_openinterpreter_as_optional_runtime_plugin() {
    let mut host = CordisHost::boot(desktop_surfaces(true)).unwrap();
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
    assert_eq!(
        host.context().runtime::<RuntimeSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        host.context().domain::<DomainSurface>().unwrap().owner,
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
    let mut host = CordisHost::boot(HartevoSurfaces::default()).unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    host.teardown();
    let mut host = CordisHost::boot(HartevoSurfaces {
        domain: DomainSurface {
            consent: true,
            approved: false,
            ..DomainSurface::default()
        },
        ..HartevoSurfaces::default()
    })
    .unwrap();
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );
}

#[test]
fn receipt_is_not_verification_on_host_effect() {
    let host = CordisHost::boot(HartevoSurfaces {
        domain: DomainSurface {
            consent: true,
            approved: true,
            ..DomainSurface::default()
        },
        effect_broker: EffectBrokerSurface {
            receipt_is_verification: true,
            ..EffectBrokerSurface::default()
        },
        ..HartevoSurfaces::default()
    })
    .unwrap();
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::VERIFICATION.to_string()])
    );
    assert_eq!(
        host_is_cordis_loop(&host).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::VERIFICATION.to_string()])
    );
}

#[test]
fn overlay_boot_starts_three_host_plugins_and_can_disable_openinterpreter() {
    let overlay = EnvironmentOverlay::new("macos-r0");
    let loader = LoaderContext::new();
    let (mut host, report) =
        CordisHost::boot_overlay(&overlay, &loader, &desktop_surfaces(false), false).unwrap();

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
    let (mut host, report) =
        CordisHost::boot_overlay(&overlay, &loader, &desktop_surfaces(true), true).unwrap();

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
        host.context().domain::<DomainSurface>().unwrap().owner,
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
    for (domain, missing) in [
        (
            DomainSurface {
                local_first: false,
                ..DomainSurface::default()
            },
            invariant_missing::LOCAL_FIRST,
        ),
        (
            DomainSurface {
                sqlcipher: false,
                ..DomainSurface::default()
            },
            invariant_missing::SQLCIPHER,
        ),
        (
            DomainSurface {
                eval_gate: false,
                ..DomainSurface::default()
            },
            invariant_missing::EVAL,
        ),
    ] {
        let host = CordisHost::boot(HartevoSurfaces {
            domain,
            ..HartevoSurfaces::default()
        })
        .unwrap();
        assert_eq!(
            host_is_cordis_loop(&host).unwrap_err(),
            CordisError::MissingDependencies(vec![missing.to_string()])
        );
    }

    let host = CordisHost::boot(HartevoSurfaces {
        domain: DomainSurface {
            owner: SurfaceOwner::Hartevo,
            consent: false,
            approved: false,
            ..DomainSurface::default()
        },
        effect_broker: EffectBrokerSurface {
            owner: SurfaceOwner::Hartevo,
            receipt_is_verification: false,
        },
        runtime: RuntimeSurface {
            owner: SurfaceOwner::Hartevo,
            plugin: Some(OPENINTERPRETER),
        },
        ..HartevoSurfaces::default()
    })
    .unwrap();
    host_is_cordis_loop(&host).unwrap();
    assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
    assert_eq!(
        host.context().domain::<DomainSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        host.context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .owner,
        SurfaceOwner::Hartevo
    );
}

#[test]
fn kernel_facts_fail_closed_without_live_consent() {
    let mut host = CordisHost::boot(desktop_surfaces(false)).unwrap();
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
    let mut host = CordisHost::boot(desktop_surfaces(false)).unwrap();
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
    assert!(domain.consent);
    assert!(domain.approved);
    assert_eq!(domain.owner, SurfaceOwner::Hartevo);
    assert!(domain.local_first && domain.sqlcipher && domain.eval_gate);
}

#[test]
fn teardown_reverses_host_mounts() {
    let mut host = CordisHost::boot(desktop_surfaces(true)).unwrap();
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
