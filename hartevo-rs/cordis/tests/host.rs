use hartevo_cordis::{
    AgentStep, CordisError, CordisHost, DomainSurface, EffectBrokerSurface, EnvironmentOverlay,
    HOST_PLUGIN_IDS, HartevoSurfaces, InvariantGate, LoaderContext, OPENINTERPRETER,
    OPENINTERPRETER_PLUGIN_ID, PluginId, RuntimeSurface, SurfaceOwner, ToolCall, desktop_surfaces,
    enforce_invariants, host_is_cordis_loop, host_plugin_ids, invariant_missing, keys,
};

#[test]
fn boot_mounts_surfaces_loop_and_gate() {
    let mut host = CordisHost::boot(desktop_surfaces(false)).unwrap();
    host_is_cordis_loop(&host).unwrap();
    enforce_invariants(host.context()).unwrap();
    host.apply_effect().unwrap();

    for key in host.mounted_keys() {
        assert!(host.context().has(key), "{key} must be mounted");
    }
    assert_eq!(host.runtime_plugin(), None);
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
    assert!(
        !host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification
    );
    assert!(host.context().get::<String>(OPENINTERPRETER).is_none());

    let out = host.step(AgentStep::new("mission-host", "plan")).unwrap();
    assert_eq!(out.id, "mission-host");
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
fn teardown_reverses_host_mounts() {
    let mut host = CordisHost::boot(desktop_surfaces(true)).unwrap();
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
