use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    AgentLoopError, AgentTurn, AgentsSurface, Context, CordisError, DispatchMode, DomainSurface,
    EffectBrokerSurface, EnvironmentOverlay, LlmStream, LoaderContext, OpenInterpreterPresence,
    OverlayLayer, PluginId, PluginSpec, RuntimeSurface, Service, SurfaceOwner, ToolCall, events,
    expected_loop_mode, install_agent_loop, keys, load_plugins, loop_events, map_surfaces,
    openinterpreter_runtime_plugin, register_llm_stream, register_tool, run_agent_turn,
    surface_mapping_plugin, surface_mapping_with_openinterpreter_slot,
};

fn hosted() -> Context {
    let mut ctx = Context::new();
    install_agent_loop(&mut ctx).unwrap();
    register_tool(&mut ctx, "search").unwrap();
    register_llm_stream(&mut ctx, "hartevo-local").unwrap();
    ctx
}

fn sample_turn() -> AgentTurn {
    AgentTurn::new(
        "mission-1",
        "compare german buyers",
        "hartevo-local",
        "search",
        "q=growth",
    )
}

#[tokio::test]
async fn hosted_loop_uses_mapped_surfaces_not_openinterpreter() {
    let mut ctx = hosted();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(events::LLM_STREAM, move |mut stream: LlmStream, next| {
            seen.lock()
                .expect("seen")
                .push(format!("llm:{}", stream.model));
            stream.body = format!("decide:{}", stream.prompt);
            next(stream)
        })
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(events::TOOLS_EXECUTE, move |mut call: ToolCall, next| {
            seen.lock()
                .expect("seen")
                .push(format!("tool:{}", call.name));
            call.result = format!("ran:{}", call.arguments);
            next(call)
        })
        .unwrap();
    }

    let turn = run_agent_turn(&mut ctx, sample_turn()).await.unwrap();
    assert_eq!(turn.observed, "domain:mission-1");
    assert_eq!(turn.decision, "decide:compare german buyers");
    assert_eq!(turn.action, "ran:q=growth");
    assert_eq!(turn.effect, "broker:mission-1:search");
    assert_eq!(turn.owner, SurfaceOwner::Hartevo);
    assert!(ctx.get::<String>("openinterpreter").is_none());
    assert_eq!(
        *seen.lock().expect("seen"),
        ["llm:hartevo-local".to_string(), "tool:search".to_string()]
    );
}

#[tokio::test]
async fn loop_events_lock_exactly_one_mode_each() {
    let ctx = hosted();
    for name in [
        loop_events::AGENT_OBSERVE,
        loop_events::AGENT_DECIDE,
        loop_events::AGENT_ACT,
        loop_events::AGENT_TURN,
    ] {
        assert_eq!(ctx.event_mode(name), expected_loop_mode(name));
    }
    let mut ctx = ctx;
    let conflict = ctx
        .on_emit(loop_events::AGENT_OBSERVE, |_: &AgentTurn| {})
        .unwrap_err();
    assert_eq!(
        conflict,
        CordisError::ModeConflict {
            name: loop_events::AGENT_OBSERVE.to_string(),
            locked: DispatchMode::Serial,
            requested: DispatchMode::Emit,
        }
    );
}

#[tokio::test]
async fn policy_can_deny_a_tool_without_writing_an_effect() {
    let mut ctx = hosted();
    ctx.on_waterfall(events::TOOLS_PRE_EXECUTE, |mut call: ToolCall, next| {
        if call.arguments.contains("deny") {
            call.decision = "deny".into();
            return call;
        }
        next(call)
    })
    .unwrap();

    let mut turn = sample_turn();
    turn.arguments = "deny-me".into();
    let denied = run_agent_turn(&mut ctx, turn).await.unwrap();
    assert_eq!(denied.action, "denied:deny");
    assert!(denied.effect.is_empty());
}

#[tokio::test]
async fn child_authored_effect_text_is_replaced_by_the_broker() {
    let mut ctx = hosted();
    ctx.on_serial(loop_events::AGENT_ACT, |mut turn: AgentTurn| async move {
        turn.effect = "child-wrote-this".into();
        Ok::<_, String>(turn)
    })
    .unwrap();
    let turn = run_agent_turn(&mut ctx, sample_turn()).await.unwrap();
    assert_eq!(turn.effect, "broker:mission-1:search");
    assert_ne!(turn.effect, "child-wrote-this");
}

#[tokio::test]
async fn openinterpreter_plugin_is_optional_and_never_owns_domain() {
    let mut ctx = Context::new();
    let overlay = EnvironmentOverlay::new("macos-dev").with_layer(
        OverlayLayer::new("env")
            .enable("surfaces")
            .enable("agent-loop")
            .disable("openinterpreter"),
    );
    let loader = LoaderContext::new();
    let started = Arc::new(AtomicUsize::new(0));
    let started_for_plugin = Arc::clone(&started);
    let plugin = PluginSpec::new("openinterpreter", move |_config, ctx| {
        started_for_plugin.fetch_add(1, Ordering::SeqCst);
        hartevo_cordis::OpenInterpreterRuntimePlugin.apply(ctx);
    })
    .with_inject([keys::RUNTIME]);

    let report = load_plugins(
        &mut ctx,
        &loader,
        &overlay,
        &[
            surface_mapping_plugin(),
            hartevo_cordis::agent_loop_plugin(),
            plugin,
        ],
    )
    .unwrap();
    assert_eq!(
        report.started,
        [PluginId::new("surfaces"), PluginId::new("agent-loop")]
    );
    assert_eq!(report.omitted, [PluginId::new("openinterpreter")]);
    assert_eq!(started.load(Ordering::SeqCst), 0);
    hartevo_cordis::assert_host_owns_domain(&ctx).unwrap();
    assert_eq!(ctx.listener_count(loop_events::RUNTIME_OPENINTERPRETER), 0);

    let overlay = EnvironmentOverlay::new("macos-dev");
    let report = load_plugins(
        &mut ctx,
        &loader,
        &overlay,
        &[
            surface_mapping_with_openinterpreter_slot(),
            hartevo_cordis::agent_loop_plugin(),
            openinterpreter_runtime_plugin(),
        ],
    )
    .unwrap();
    assert!(report.started.contains(&PluginId::new("openinterpreter")));
    hartevo_cordis::assert_host_owns_domain(&ctx).unwrap();
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().plugin,
        Some("openinterpreter")
    );
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner,
        SurfaceOwner::Hartevo
    );
    assert_eq!(ctx.listener_count(loop_events::RUNTIME_OPENINTERPRETER), 1);
    ctx.emit(
        loop_events::RUNTIME_OPENINTERPRETER,
        &OpenInterpreterPresence::adapter(),
    )
    .unwrap();
    register_tool(&mut ctx, "search").unwrap();
    register_llm_stream(&mut ctx, "hartevo-local").unwrap();
    let turn = run_agent_turn(&mut ctx, sample_turn()).await.unwrap();
    assert_eq!(turn.observed, "domain:mission-1");
    assert_eq!(turn.effect, "broker:mission-1:search");
    assert_ne!(turn.observed, "openinterpreter");
}

#[tokio::test]
async fn openinterpreter_cannot_replace_domain_or_effect() {
    let mut ctx = hosted();
    ctx.provide(keys::DOMAIN, "openinterpreter-domain".to_string());
    ctx.provide(keys::EFFECT_BROKER, "openinterpreter-effect".to_string());
    let err = hartevo_cordis::assert_host_owns_domain(&ctx).unwrap_err();
    assert_eq!(err, AgentLoopError::OpenInterpreterOwnsDomain);
    let run = run_agent_turn(&mut ctx, sample_turn()).await.unwrap_err();
    assert_eq!(run, AgentLoopError::OpenInterpreterOwnsDomain);
}

#[tokio::test]
async fn optional_plugin_waits_for_runtime_inject() {
    let mut ctx = Context::new();
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new();
    let err = load_plugins(
        &mut ctx,
        &loader,
        &overlay,
        &[openinterpreter_runtime_plugin()],
    )
    .unwrap_err();
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![keys::RUNTIME.to_string()])
    );
    assert!(!ctx.has(keys::DOMAIN));
    assert!(!ctx.has(keys::EFFECT_BROKER));
}

#[tokio::test]
async fn teardown_unwinds_loop_locks_and_live_agents() {
    let mut ctx = hosted();
    let _ = run_agent_turn(&mut ctx, sample_turn()).await.unwrap();
    assert!(
        ctx.agents::<AgentsSurface>().unwrap().list().is_empty(),
        "completed turn must dispose the live agent; teardown still reverses the disposer"
    );
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
    for name in [
        loop_events::AGENT_OBSERVE,
        loop_events::AGENT_DECIDE,
        loop_events::AGENT_ACT,
        loop_events::AGENT_TURN,
        events::AGENT_CREATED,
        events::AGENT_DISPOSED,
    ] {
        assert_eq!(ctx.listener_count(name), 0);
        assert_eq!(ctx.event_mode(name), None, "{name} lock must reverse");
    }
}

#[test]
fn install_requires_mapped_surfaces() {
    let mut ctx = Context::new();
    let err = ctx.mount(hartevo_cordis::AgentLoop).unwrap_err();
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
            keys::LLM.to_string(),
            keys::AGENTS.to_string(),
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
            keys::RUNTIME.to_string(),
            keys::DESKTOP.to_string(),
        ])
    );
}

#[test]
fn child_runtime_owner_is_rejected() {
    let mut ctx = Context::new();
    map_surfaces(
        &mut ctx,
        hartevo_cordis::HartevoSurfaces {
            runtime: RuntimeSurface {
                owner: SurfaceOwner::Hartevo,
                plugin: None,
            },
            ..hartevo_cordis::HartevoSurfaces::default()
        },
    )
    .unwrap();
    ctx.provide(
        keys::RUNTIME,
        RuntimeSurface {
            owner: SurfaceOwner::OpenInterpreter,
            plugin: Some("openinterpreter"),
        },
    );
    let err = hartevo_cordis::assert_host_owns_domain(&ctx).unwrap_err();
    assert_eq!(err, AgentLoopError::ChildOwnsDomain);
}
