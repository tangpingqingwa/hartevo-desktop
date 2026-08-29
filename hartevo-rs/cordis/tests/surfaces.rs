use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    AgentRef, Context, CordisError, CordisHost, DispatchMode, DomainSurface, EffectBrokerSurface,
    EnvironmentOverlay, LlmStream, LoaderContext, MAPPED_KEYS, PluginId, RuntimeSurface,
    SurfaceOwner, ToolCall, ToolsSurface, events, expected_mode, keys, register_agent,
    register_llm_stream, register_tool, run_tools_pipeline, stream_llm,
};

fn mapped() -> Context {
    let mut host = CordisHost::boot(false).unwrap();
    std::mem::take(host.context_mut())
}

#[test]
fn mapped_keys_are_provided_and_looked_up() {
    let ctx = mapped();
    assert_eq!(
        MAPPED_KEYS,
        [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
            keys::RUNTIME,
            keys::DESKTOP,
        ]
    );
    for key in MAPPED_KEYS {
        assert!(ctx.has(key), "{key} must be provided");
    }

    assert!(ctx.tools::<ToolsSurface>().is_some());
    assert!(ctx.llm::<hartevo_cordis::LlmSurface>().is_some());
    assert!(ctx.agents::<hartevo_cordis::AgentsSurface>().is_some());
    assert!(ctx.sessions::<u32>().is_none());
    assert_eq!(
        ctx.domain::<DomainSurface>().as_deref(),
        Some(&DomainSurface::default())
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().as_deref(),
        Some(&EffectBrokerSurface::default())
    );
    let runtime = ctx.runtime::<RuntimeSurface>().unwrap();
    assert_eq!(runtime.owner(), SurfaceOwner::Hartevo);
    assert_eq!(runtime.plugin(), None);
    assert_eq!(
        ctx.desktop::<hartevo_cordis::DesktopSurface>()
            .unwrap()
            .owner(),
        SurfaceOwner::Hartevo
    );
    assert!(ctx.get::<u32>(keys::TOOLS).is_none());
    assert!(ctx.get::<u32>(keys::AGENTS).is_none());
}

#[test]
fn tools_pipeline_locks_exactly_one_mode_per_event() {
    let mut ctx = mapped();
    for name in [
        events::TOOLS_PRE_EXECUTE,
        events::TOOLS_EXECUTE,
        events::TOOLS_POST_EXECUTE,
        events::TOOLS_RESULT,
    ] {
        assert_eq!(ctx.event_mode(name), expected_mode(name));
        assert_eq!(ctx.listener_count(name), 0);
    }

    let conflict = ctx
        .on_emit(events::TOOLS_PRE_EXECUTE, |_: &ToolCall| {})
        .unwrap_err();
    assert_eq!(
        conflict,
        CordisError::ModeConflict {
            name: events::TOOLS_PRE_EXECUTE.to_string(),
            locked: DispatchMode::Waterfall,
            requested: DispatchMode::Emit,
        }
    );
    let result_conflict = ctx
        .on_waterfall(events::TOOLS_RESULT, |call: ToolCall, next| next(call))
        .unwrap_err();
    assert_eq!(
        result_conflict,
        CordisError::ModeConflict {
            name: events::TOOLS_RESULT.to_string(),
            locked: DispatchMode::Emit,
            requested: DispatchMode::Waterfall,
        }
    );
}

#[test]
fn tools_pipeline_runs_on_ctx_tools_not_openinterpreter() {
    let mut ctx = mapped();
    register_tool(&mut ctx, "search").unwrap();
    assert_eq!(
        ctx.tools::<ToolsSurface>().unwrap().names(),
        ["search".to_string()]
    );

    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(
            events::TOOLS_PRE_EXECUTE,
            move |mut call: ToolCall, next| {
                seen.lock()
                    .expect("seen")
                    .push(format!("pre:{}", call.name));
                if call.arguments.contains("deny") {
                    call.decision = "deny".into();
                    return call;
                }
                next(call)
            },
        )
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(events::TOOLS_EXECUTE, move |mut call: ToolCall, next| {
            seen.lock()
                .expect("seen")
                .push(format!("execute:{}", call.name));
            call.result = format!("ran:{}", call.arguments);
            next(call)
        })
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |mut call: ToolCall, next| {
                seen.lock()
                    .expect("seen")
                    .push(format!("post:{}", call.name));
                call.result = format!("{}:ok", call.result);
                next(call)
            },
        )
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_emit(events::TOOLS_RESULT, move |call: &ToolCall| {
            seen.lock()
                .expect("seen")
                .push(format!("result:{}:{}", call.name, call.decision));
        })
        .unwrap();
    }

    let allowed =
        run_tools_pipeline(&mut ctx, ToolCall::new("search", "q=growth", "allow")).unwrap();
    assert_eq!(allowed.result, "ran:q=growth:ok");
    assert_eq!(allowed.decision, "allow");

    seen.lock().expect("seen").clear();
    let denied = run_tools_pipeline(&mut ctx, ToolCall::new("search", "deny-me", "allow")).unwrap();
    assert_eq!(denied.decision, "deny");
    assert!(denied.result.is_empty());
    assert_eq!(
        *seen.lock().expect("seen"),
        ["pre:search".to_string(), "result:search:deny".to_string()]
    );
    assert!(ctx.get::<String>("openinterpreter").is_none());
}

#[test]
fn llm_streams_register_on_ctx_llm_and_reverse() {
    let mut ctx = mapped();
    register_llm_stream(&mut ctx, "hartevo-local").unwrap();
    assert_eq!(
        ctx.llm::<hartevo_cordis::LlmSurface>().unwrap().streams(),
        ["hartevo-local".to_string()]
    );

    let wrapped = Arc::new(AtomicUsize::new(0));
    {
        let wrapped = Arc::clone(&wrapped);
        ctx.on_waterfall(events::LLM_STREAM, move |mut stream: LlmStream, next| {
            wrapped.fetch_add(1, Ordering::SeqCst);
            stream.body = format!("{}:{}", stream.model, stream.prompt);
            next(stream)
        })
        .unwrap();
    }
    let out = stream_llm(&mut ctx, LlmStream::new("hartevo-local", "hello")).unwrap();
    assert_eq!(out.body, "hartevo-local:hello");
    assert_eq!(wrapped.load(Ordering::SeqCst), 1);

    ctx.teardown();
    assert!(!ctx.has(keys::LLM));
    assert_eq!(ctx.listener_count(events::LLM_STREAM), 0);
    assert_eq!(ctx.event_mode(events::LLM_STREAM), None);
}

#[test]
fn agent_coordination_registers_on_ctx_agents_and_reverse() {
    let mut ctx = mapped();
    let agent = AgentRef::new("mission-1");
    register_agent(&mut ctx, agent.clone()).unwrap();
    assert_eq!(
        ctx.agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list()
            .as_slice(),
        std::slice::from_ref(&agent)
    );

    let created = Arc::new(Mutex::new(Vec::new()));
    {
        let created = Arc::clone(&created);
        ctx.on_emit(events::AGENT_CREATED, move |live: &AgentRef| {
            created.lock().expect("created").push(live.id.clone());
        })
        .unwrap();
    }
    ctx.emit(events::AGENT_CREATED, &agent).unwrap();
    assert_eq!(*created.lock().expect("created"), ["mission-1".to_string()]);

    ctx.teardown();
    assert!(!ctx.has(keys::AGENTS));
    assert_eq!(ctx.listener_count(events::AGENT_CREATED), 0);
    assert_eq!(ctx.event_mode(events::AGENT_CREATED), None);
}

#[test]
fn hartevo_owned_lookups_do_not_go_through_openinterpreter() {
    let mut ctx = mapped();
    ctx.provide("openinterpreter", "runtime-plugin").unwrap();
    assert_eq!(
        ctx.get::<&str>("openinterpreter").as_deref(),
        Some(&"runtime-plugin")
    );
    assert_ne!(keys::DOMAIN, "openinterpreter");
    assert_ne!(keys::EFFECT_BROKER, "openinterpreter");
    assert_ne!(keys::RUNTIME, "openinterpreter");
    assert_ne!(keys::DESKTOP, "openinterpreter");
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.desktop::<hartevo_cordis::DesktopSurface>()
            .unwrap()
            .owner(),
        SurfaceOwner::Hartevo
    );
    assert!(ctx.domain::<&str>().is_none());
    assert!(ctx.effect_broker::<&str>().is_none());
    assert!(ctx.runtime::<&str>().is_none());
    assert!(ctx.desktop::<&str>().is_none());
}

#[test]
fn mounted_authority_surfaces_reject_ordinary_provider_replacement() {
    let mut ctx = mapped();
    for key in [
        keys::DOMAIN,
        keys::EFFECT_BROKER,
        keys::RUNTIME,
        keys::DESKTOP,
    ] {
        assert_eq!(
            ctx.provide(key, "forged-owner").unwrap_err(),
            CordisError::ReservedServiceKey {
                key: key.to_string(),
            }
        );
    }
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.desktop::<hartevo_cordis::DesktopSurface>()
            .unwrap()
            .owner(),
        SurfaceOwner::Hartevo
    );
}

#[test]
fn teardown_undoes_every_registration_and_fresh_host_can_reload() {
    let mut ctx = mapped();
    register_tool(&mut ctx, "search").unwrap();
    register_llm_stream(&mut ctx, "hartevo-local").unwrap();
    register_agent(&mut ctx, AgentRef::new("mission-1")).unwrap();
    ctx.on_waterfall(events::TOOLS_EXECUTE, |call: ToolCall, next| next(call))
        .unwrap();
    ctx.on_waterfall(events::LLM_STREAM, |stream: LlmStream, next| next(stream))
        .unwrap();
    ctx.on_emit(events::AGENT_CREATED, |_: &AgentRef| {})
        .unwrap();

    assert_eq!(ctx.tools::<ToolsSurface>().unwrap().names().len(), 1);
    assert_eq!(
        ctx.llm::<hartevo_cordis::LlmSurface>()
            .unwrap()
            .streams()
            .len(),
        1
    );
    assert_eq!(
        ctx.agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list()
            .len(),
        1
    );
    assert_eq!(ctx.listener_count(events::TOOLS_EXECUTE), 1);
    assert_eq!(ctx.listener_count(events::LLM_STREAM), 1);
    assert!(ctx.listener_count(events::AGENT_CREATED) >= 2);

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
        events::TOOLS_PRE_EXECUTE,
        events::TOOLS_EXECUTE,
        events::TOOLS_POST_EXECUTE,
        events::TOOLS_RESULT,
        events::LLM_STREAM,
        events::AGENT_CREATED,
        events::AGENT_DISPOSED,
    ] {
        assert_eq!(ctx.listener_count(name), 0);
        assert_eq!(ctx.event_mode(name), None, "{name} lock must reverse");
    }

    let mut reloaded = mapped();
    register_tool(&mut reloaded, "search-2").unwrap();
    assert_eq!(
        reloaded.tools::<ToolsSurface>().unwrap().names(),
        ["search-2".to_string()]
    );
    assert_eq!(
        reloaded.event_mode(events::TOOLS_PRE_EXECUTE),
        Some(DispatchMode::Waterfall)
    );
}

#[test]
fn tool_and_llm_and_agent_register_require_mapped_keys() {
    let mut ctx = Context::new();
    assert_eq!(
        register_tool(&mut ctx, "search").unwrap_err(),
        CordisError::MissingDependencies(vec![keys::TOOLS.to_string()])
    );
    assert_eq!(
        register_llm_stream(&mut ctx, "hartevo-local").unwrap_err(),
        CordisError::MissingDependencies(vec![keys::LLM.to_string()])
    );
    assert_eq!(
        register_agent(&mut ctx, AgentRef::new("mission-1")).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::AGENTS.to_string()])
    );
}

#[test]
fn overlay_still_selects_plugins_instead_of_a_crate_boot_list() {
    let overlay = EnvironmentOverlay::new("macos-dev");
    let loader = LoaderContext::new();
    let (host, report) = CordisHost::boot_overlay(&overlay, &loader, false).unwrap();
    assert_eq!(
        report.started,
        [
            PluginId::new("surfaces"),
            PluginId::new("agent-loop"),
            PluginId::new("invariants"),
        ]
    );
    assert_eq!(report.disabled, [PluginId::new("openinterpreter")]);
    assert!(host.context().has(keys::DOMAIN));
    assert!(host.context().get::<&str>("openinterpreter").is_none());
}

#[test]
fn runtime_plugin_slot_may_name_openinterpreter_without_owning_domain() {
    let mut host = CordisHost::boot(true).unwrap();
    let ctx = host.context_mut();
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().plugin(),
        Some("openinterpreter")
    );
    assert_eq!(
        ctx.runtime::<RuntimeSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
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
fn openinterpreter_cannot_own_domain() {
    let mut host = CordisHost::boot(false).unwrap();
    let ctx = host.context_mut();
    assert_eq!(
        ctx.provide(keys::DOMAIN, "openinterpreter").unwrap_err(),
        CordisError::ReservedServiceKey {
            key: keys::DOMAIN.to_owned(),
        }
    );
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
}
