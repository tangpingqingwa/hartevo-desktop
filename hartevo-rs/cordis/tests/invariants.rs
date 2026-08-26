use hartevo_cordis::{
    AgentLoop, AgentStep, Context, CordisError, DomainSurface, EffectBrokerSurface,
    HartevoSurfaces, InvariantGate, OPENINTERPRETER, RuntimeSurface, SurfaceMapping, SurfaceOwner,
    apply_effect, enforce_invariants, invariant_missing, keys, map_surfaces, run_agent_step,
};

fn consented_domain() -> DomainSurface {
    DomainSurface {
        consent: true,
        approved: true,
        ..DomainSurface::default()
    }
}

fn mapped_consented() -> Context {
    let mut ctx = Context::new();
    map_surfaces(
        &mut ctx,
        HartevoSurfaces {
            domain: consented_domain(),
            ..HartevoSurfaces::default()
        },
    )
    .unwrap();
    ctx.mount(InvariantGate).unwrap();
    ctx.mount(AgentLoop).unwrap();
    ctx
}

#[test]
fn happy_path_enforces_and_applies_and_runs_a_step() {
    let mut ctx = mapped_consented();
    enforce_invariants(&ctx).unwrap();
    apply_effect(&ctx).unwrap();
    let out = run_agent_step(&mut ctx, AgentStep::new("mission-ok", "plan")).unwrap();
    assert_eq!(out.id, "mission-ok");
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert!(
        !ctx.effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification
    );
}

#[test]
fn missing_consent_or_approval_fails_closed() {
    let mut ctx = Context::new();
    map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap();
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        apply_effect(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        run_agent_step(&mut ctx, AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    ctx.teardown();
    map_surfaces(
        &mut ctx,
        HartevoSurfaces {
            domain: DomainSurface {
                consent: true,
                approved: false,
                ..DomainSurface::default()
            },
            ..HartevoSurfaces::default()
        },
    )
    .unwrap();
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );
}

#[test]
fn receipt_is_not_verification() {
    let mut ctx = Context::new();
    map_surfaces(
        &mut ctx,
        HartevoSurfaces {
            domain: consented_domain(),
            effect_broker: EffectBrokerSurface {
                receipt_is_verification: true,
                ..EffectBrokerSurface::default()
            },
            ..HartevoSurfaces::default()
        },
    )
    .unwrap();
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::VERIFICATION.to_string()])
    );
    assert_eq!(
        apply_effect(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::VERIFICATION.to_string()])
    );
}

#[test]
fn openinterpreter_runtime_plugin_does_not_own_domain_or_effect() {
    let mut ctx = Context::new();
    map_surfaces(
        &mut ctx,
        HartevoSurfaces {
            domain: consented_domain(),
            runtime: RuntimeSurface {
                owner: SurfaceOwner::Hartevo,
                plugin: Some("openinterpreter"),
            },
            ..HartevoSurfaces::default()
        },
    )
    .unwrap();
    ctx.provide(OPENINTERPRETER, "adapter");
    ctx.mount(InvariantGate).unwrap();
    enforce_invariants(&ctx).unwrap();
    apply_effect(&ctx).unwrap();
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().plugin,
        Some("openinterpreter")
    );
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
}

#[test]
fn openinterpreter_cannot_own_domain_without_map_surfaces_panic() {
    let mut ctx = Context::new();
    ctx.provide(
        keys::DOMAIN,
        DomainSurface {
            owner: SurfaceOwner::OpenInterpreter,
            consent: true,
            approved: true,
            ..DomainSurface::default()
        },
    );
    ctx.provide(keys::EFFECT_BROKER, EffectBrokerSurface::default());
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
    );
    assert_eq!(
        apply_effect(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
    );
}

#[test]
fn openinterpreter_cannot_be_the_write_path() {
    let mut ctx = mapped_consented();
    ctx.provide(OPENINTERPRETER, consented_domain());
    enforce_invariants(&ctx).unwrap();
    assert_eq!(
        apply_effect(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
    );
}

#[test]
fn local_first_sqlcipher_and_eval_stay_required() {
    for (domain, missing) in [
        (
            DomainSurface {
                local_first: false,
                ..consented_domain()
            },
            invariant_missing::LOCAL_FIRST,
        ),
        (
            DomainSurface {
                sqlcipher: false,
                ..consented_domain()
            },
            invariant_missing::SQLCIPHER,
        ),
        (
            DomainSurface {
                eval_gate: false,
                ..consented_domain()
            },
            invariant_missing::EVAL,
        ),
    ] {
        let mut ctx = Context::new();
        map_surfaces(
            &mut ctx,
            HartevoSurfaces {
                domain,
                ..HartevoSurfaces::default()
            },
        )
        .unwrap();
        assert_eq!(
            enforce_invariants(&ctx).unwrap_err(),
            CordisError::MissingDependencies(vec![missing.to_string()])
        );
    }
}

#[test]
fn missing_domain_or_effect_broker_is_missing_dependencies() {
    let mut ctx = Context::new();
    assert_eq!(
        ctx.mount(InvariantGate).unwrap_err(),
        CordisError::MissingDependencies(vec![
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
        ])
    );
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
    );
    ctx.provide(keys::DOMAIN, consented_domain());
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::EFFECT_BROKER.to_string()])
    );
}

#[test]
fn teardown_reverses_provides() {
    let mut ctx = mapped_consented();
    run_agent_step(&mut ctx, AgentStep::new("mission-1", "grow")).unwrap();
    assert!(ctx.has(keys::DOMAIN));
    assert!(ctx.has(keys::EFFECT_BROKER));
    ctx.teardown();
    for key in [
        keys::TOOLS,
        keys::LLM,
        keys::AGENTS,
        keys::DOMAIN,
        keys::EFFECT_BROKER,
        keys::RUNTIME,
        keys::DESKTOP,
    ] {
        assert!(!ctx.has(key), "{key} must reverse on teardown");
    }
    ctx.mount(SurfaceMapping {
        surfaces: HartevoSurfaces {
            domain: consented_domain(),
            ..HartevoSurfaces::default()
        },
    })
    .unwrap();
    ctx.mount(InvariantGate).unwrap();
    enforce_invariants(&ctx).unwrap();
    apply_effect(&ctx).unwrap();
}
