use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentStep, Context, CordisError, CordisHost, DomainSurface, EffectBrokerSurface, InvariantGate,
    KernelApproval, KernelApprovalDecision, KernelConsentState, OPENINTERPRETER, RuntimeSurface,
    SurfaceOwner, apply_effect, enforce_invariants, invariant_missing, keys, run_agent_step,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
}

fn consented_host(openinterpreter: bool) -> CordisHost {
    let mut host = CordisHost::boot(openinterpreter).unwrap();
    host.bind_domain_kernel(
        KernelConsentState::Confirmed,
        None,
        Some(KernelApproval {
            decision: KernelApprovalDecision::Approved,
            valid_until: now() + Duration::minutes(5),
        }),
        now(),
    )
    .unwrap();
    host
}

fn mapped_consented() -> Context {
    let mut host = consented_host(false);
    std::mem::take(host.context_mut())
}

#[test]
fn happy_path_enforces_and_applies_and_runs_a_step() {
    let mut ctx = mapped_consented();
    enforce_invariants(&ctx).unwrap();
    apply_effect(&ctx).unwrap();
    let out = run_agent_step(&mut ctx, AgentStep::new("mission-ok", "plan")).unwrap();
    assert_eq!(out.id, "mission-ok");
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert!(
        !ctx.effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification()
    );
}

#[test]
fn missing_consent_or_approval_fails_closed() {
    let mut host = CordisHost::boot(false).unwrap();
    assert_eq!(
        enforce_invariants(host.context()).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        host.apply_effect().unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );
    assert_eq!(
        host.step(AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
    );

    host.bind_domain_kernel(KernelConsentState::Confirmed, None, None, now())
        .unwrap();
    assert_eq!(
        enforce_invariants(host.context()).unwrap_err(),
        CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
    );
}

#[test]
fn receipt_is_not_verification() {
    let host = consented_host(false);
    assert!(
        !host
            .context()
            .effect_broker::<EffectBrokerSurface>()
            .unwrap()
            .receipt_is_verification()
    );
    enforce_invariants(host.context()).unwrap();
    host.apply_effect().unwrap();
}

#[test]
fn openinterpreter_runtime_plugin_does_not_own_domain_or_effect() {
    let host = consented_host(true);
    let ctx = host.context();
    enforce_invariants(ctx).unwrap();
    apply_effect(ctx).unwrap();
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().plugin(),
        Some("openinterpreter")
    );
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
}

#[test]
fn ordinary_provider_cannot_claim_domain_or_effect_authority() {
    let mut ctx = Context::new();
    assert!(matches!(
        ctx.provide(keys::DOMAIN, "forged-domain"),
        Err(CordisError::ReservedServiceKey { key }) if key == keys::DOMAIN
    ));
    assert!(matches!(
        ctx.provide(keys::EFFECT_BROKER, EffectBrokerSurface::default()),
        Err(CordisError::ReservedServiceKey { key }) if key == keys::EFFECT_BROKER
    ));
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
    ctx.provide(OPENINTERPRETER, DomainSurface::default())
        .unwrap();
    enforce_invariants(&ctx).unwrap();
    assert_eq!(
        apply_effect(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
    );
}

#[test]
fn sealed_host_keeps_local_first_sqlcipher_and_eval_required() {
    let mut host = CordisHost::boot(false).unwrap();
    let domain = host.context().domain::<DomainSurface>().unwrap();
    assert!(domain.local_first());
    assert!(domain.sqlcipher());
    assert!(domain.eval_gate());
    for key in [keys::DOMAIN, keys::EFFECT_BROKER] {
        assert!(matches!(
            host.context_mut().provide(key, "forged-gates"),
            Err(CordisError::ReservedServiceKey { .. })
        ));
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
    assert_eq!(
        enforce_invariants(&ctx).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::DOMAIN.to_string()])
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
    let reloaded = consented_host(false);
    enforce_invariants(reloaded.context()).unwrap();
    reloaded.apply_effect().unwrap();
}
