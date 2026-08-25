use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    AgentHandle, ConfigValue, Context, CordisError, DispatchMode, EnvironmentOverlay,
    LoaderContext, OverlayLayer, PluginId, PluginSpec, RuntimeAdapterSurface, Service, ToolCall,
    ToolResult, assert_openinterpreter_does_not_own_domain, assert_pipeline_locked, events, keys,
    load_plugins, map_hartevo_surfaces, openinterpreter_runtime_plugin,
};

struct FakeOpenInterpreterOwner;

impl Service for FakeOpenInterpreterOwner {
    fn apply(self, ctx: &mut Context) {
        ctx.provide(keys::DOMAIN, "openinterpreter-domain");
        ctx.provide(keys::EFFECT_BROKER, "openinterpreter-effect");
    }
}

#[test]
fn map_provides_primer_and_hartevo_owned_slots() {
    let mut ctx = Context::new();
    let mapped = map_hartevo_surfaces(&mut ctx).unwrap();

    assert!(ctx.has(keys::TOOLS));
    assert!(ctx.has(keys::LLM));
    assert!(ctx.has(keys::AGENTS));
    assert!(ctx.has(keys::DOMAIN));
    assert!(ctx.has(keys::EFFECT_BROKER));
    assert!(ctx.has(keys::RUNTIME));
    assert!(ctx.has(keys::DESKTOP));
    assert!(!ctx.has(keys::SESSIONS));

    assert!(Arc::ptr_eq(&mapped.tools, &ctx.tools().unwrap()));
    assert!(Arc::ptr_eq(&mapped.llm, &ctx.llm().unwrap()));
    assert!(Arc::ptr_eq(&mapped.agents, &ctx.agents().unwrap()));
    assert!(mapped.domain.owns_mission_and_truth());
    assert!(mapped.effect_broker.owns_effect());
    assert!(!mapped.runtime.owns_mission_truth_or_effect());
    assert_eq!(mapped.desktop.owner, "hartevo-desktop");
    assert_pipeline_locked(&ctx).unwrap();
    assert_openinterpreter_does_not_own_domain(&ctx).unwrap();
}

#[test]
fn tools_pipeline_events_stay_on_ctx_tools() {
    let mut ctx = Context::new();
    map_hartevo_surfaces(&mut ctx).unwrap();

    let order = Arc::new(Mutex::new(Vec::new()));
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(events::TOOLS_PRE_EXECUTE, move |call: ToolCall, next| {
            order
                .lock()
                .expect("order")
                .push(format!("pre:{}", call.name));
            if call.name == "blocked" {
                return call;
            }
            next(call)
        })
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(events::TOOLS_EXECUTE, move |call: ToolCall, next| {
            order
                .lock()
                .expect("order")
                .push(format!("exec:{}", call.name));
            next(call)
        })
        .unwrap();
    }

    let allowed = ctx
        .waterfall(
            events::TOOLS_PRE_EXECUTE,
            ToolCall {
                id: 1,
                name: "search".into(),
            },
        )
        .unwrap();
    let executed = ctx.waterfall(events::TOOLS_EXECUTE, allowed).unwrap();
    assert_eq!(executed.name, "search");
    ctx.emit(
        events::TOOLS_RESULT,
        &ToolResult {
            call: executed,
            output: "ok".into(),
        },
    )
    .unwrap();

    let blocked = ctx
        .waterfall(
            events::TOOLS_PRE_EXECUTE,
            ToolCall {
                id: 2,
                name: "blocked".into(),
            },
        )
        .unwrap();
    assert_eq!(blocked.name, "blocked");
    assert_eq!(
        *order.lock().expect("order"),
        ["pre:search", "exec:search", "pre:blocked"]
    );

    assert_eq!(
        ctx.event_mode(events::TOOLS_PRE_EXECUTE),
        Some(DispatchMode::Waterfall)
    );
    let err = ctx
        .emit(events::TOOLS_PRE_EXECUTE, &())
        .expect_err("pipeline events stay waterfall");
    assert_eq!(
        err,
        CordisError::ModeConflict {
            name: events::TOOLS_PRE_EXECUTE.to_string(),
            locked: DispatchMode::Waterfall,
            requested: DispatchMode::Emit,
        }
    );
}

#[test]
fn llm_streams_stay_on_ctx_llm() {
    let mut ctx = Context::new();
    let mapped = map_hartevo_surfaces(&mut ctx).unwrap();
    let request = mapped.llm.stream("hartevo-model");
    let wrapped = ctx.waterfall(events::LLM_STREAM, request.clone()).unwrap();
    assert_eq!(wrapped, request);
    assert_eq!(
        ctx.event_mode(events::LLM_STREAM),
        Some(DispatchMode::Waterfall)
    );
    assert_eq!(
        ctx.emit(events::LLM_STREAM, &request).unwrap_err(),
        CordisError::ModeConflict {
            name: events::LLM_STREAM.to_string(),
            locked: DispatchMode::Waterfall,
            requested: DispatchMode::Emit,
        }
    );
}

#[test]
fn live_agent_coordination_stays_on_ctx_agents() {
    let mut ctx = Context::new();
    let mapped = map_hartevo_surfaces(&mut ctx).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        ctx.on_emit(events::AGENTS_CREATED, move |handle: &AgentHandle| {
            seen.lock()
                .expect("seen")
                .push(format!("created:{}", handle.session_id));
        })
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_emit(events::AGENTS_DISPOSED, move |handle: &AgentHandle| {
            seen.lock()
                .expect("seen")
                .push(format!("disposed:{}", handle.session_id));
        })
        .unwrap();
    }

    let handle = mapped.agents.create("mission-session");
    ctx.emit(events::AGENTS_CREATED, &handle).unwrap();
    assert_eq!(mapped.agents.live_count(), 1);
    mapped.agents.dispose(&handle);
    ctx.emit(events::AGENTS_DISPOSED, &handle).unwrap();
    assert_eq!(mapped.agents.live_count(), 0);
    assert_eq!(
        *seen.lock().expect("seen"),
        ["created:mission-session", "disposed:mission-session"]
    );
    assert_eq!(
        ctx.waterfall(events::AGENTS_CREATED, handle).unwrap_err(),
        CordisError::ModeConflict {
            name: events::AGENTS_CREATED.to_string(),
            locked: DispatchMode::Emit,
            requested: DispatchMode::Waterfall,
        }
    );
}

#[test]
fn every_registration_unwinds_on_teardown() {
    let mut ctx = Context::new();
    map_hartevo_surfaces(&mut ctx).unwrap();
    assert!(ctx.listener_count(events::TOOLS_EXECUTE) > 0);
    assert!(ctx.listener_count(events::LLM_STREAM) > 0);
    assert!(ctx.listener_count(events::AGENTS_CREATED) > 0);
    ctx.teardown();
    assert!(!ctx.has(keys::TOOLS));
    assert!(!ctx.has(keys::LLM));
    assert!(!ctx.has(keys::AGENTS));
    assert!(!ctx.has(keys::DOMAIN));
    assert!(!ctx.has(keys::EFFECT_BROKER));
    assert!(!ctx.has(keys::RUNTIME));
    assert!(!ctx.has(keys::DESKTOP));
    assert_eq!(ctx.listener_count(events::TOOLS_EXECUTE), 0);
    assert_eq!(ctx.listener_count(events::LLM_STREAM), 0);
    assert_eq!(ctx.listener_count(events::AGENTS_CREATED), 0);
    assert_eq!(ctx.event_mode(events::TOOLS_EXECUTE), None);
}

#[test]
fn openinterpreter_is_optional_and_never_owns_domain() {
    let mut ctx = Context::new();
    map_hartevo_surfaces(&mut ctx).unwrap();
    let overlay = EnvironmentOverlay::new("macos-dev")
        .with_layer(OverlayLayer::new("env").disable("openinterpreter"));
    let loader = LoaderContext::new();
    let started = Arc::new(AtomicUsize::new(0));
    let started_for_plugin = Arc::clone(&started);
    let plugin = PluginSpec::new("openinterpreter", move |_config, ctx| {
        started_for_plugin.fetch_add(1, Ordering::SeqCst);
        hartevo_cordis::OpenInterpreterRuntimePlugin.apply(ctx);
    })
    .with_inject([keys::RUNTIME]);

    let report = load_plugins(&mut ctx, &loader, &overlay, &[plugin]).unwrap();
    assert_eq!(report.omitted, [PluginId::new("openinterpreter")]);
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_openinterpreter_does_not_own_domain(&ctx).unwrap();

    let overlay = EnvironmentOverlay::new("macos-dev");
    let report = load_plugins(
        &mut ctx,
        &loader,
        &overlay,
        &[openinterpreter_runtime_plugin()],
    )
    .unwrap();
    assert_eq!(report.started, [PluginId::new("openinterpreter")]);
    assert_openinterpreter_does_not_own_domain(&ctx).unwrap();
    assert_eq!(ctx.listener_count(events::RUNTIME_OPENINTERPRETER), 1);
    assert_eq!(
        ctx.domain::<RuntimeAdapterSurface>().as_deref(),
        None,
        "runtime adapter type must not occupy domain"
    );
    ctx.teardown();
    assert_eq!(ctx.listener_count(events::RUNTIME_OPENINTERPRETER), 0);
}

#[test]
fn openinterpreter_cannot_replace_domain_or_effect() {
    let mut ctx = Context::new();
    map_hartevo_surfaces(&mut ctx).unwrap();
    ctx.mount(FakeOpenInterpreterOwner).unwrap();
    let err = assert_openinterpreter_does_not_own_domain(&ctx).unwrap_err();
    assert_eq!(err, hartevo_cordis::MappingError::OpenInterpreterOwnsDomain);
}

#[test]
fn optional_plugin_waits_for_runtime_inject() {
    let mut ctx = Context::new();
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new().with("env", ConfigValue::string("dev"));
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
