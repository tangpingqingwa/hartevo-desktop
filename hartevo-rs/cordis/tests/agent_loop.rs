use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{Duration, TimeZone, Utc};
use hartevo_cordis::{
    AgentLoop, AgentRef, AgentStep, Context, CordisError, CordisHost, DomainSurface,
    EffectBrokerSurface, EnvironmentOverlay, KernelApproval, KernelApprovalDecision,
    KernelConsentState, LlmStream, LoaderContext, RuntimeSurface, SessionContentBlock,
    SessionEventKind, SessionId, SessionMessageRole, SessionMessageSource, SessionStore,
    SessionSurfaceIntent, SurfaceOwner, ToolCall, TurnEndReason, events, keys, run_agent_step,
};

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
}

fn mapped_with_openinterpreter(openinterpreter: bool) -> Context {
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
    std::mem::take(host.context_mut())
}

fn mapped() -> Context {
    mapped_with_openinterpreter(false)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end fixture proves the exact AgentLoop-to-Session event order"
)]
fn full_step_streams_llm_runs_tool_and_registers_agent() {
    let mut ctx = mapped();
    let planned = Arc::new(AtomicUsize::new(0));
    {
        let planned = Arc::clone(&planned);
        ctx.on_waterfall(events::LLM_STREAM, move |mut stream: LlmStream, next| {
            planned.fetch_add(1, Ordering::SeqCst);
            stream.body = format!("plan:{}", stream.prompt);
            next(stream)
        })
        .unwrap();
    }
    {
        let sessions = ctx.sessions::<SessionStore>().unwrap();
        ctx.on_waterfall(events::TOOLS_EXECUTE, move |mut call: ToolCall, next| {
            let session = sessions
                .get(&SessionId::new("mission-1").unwrap())
                .unwrap()
                .unwrap();
            assert!(matches!(
                session.events().unwrap().last().map(|event| &event.kind),
                Some(SessionEventKind::ToolCall { call_id, .. })
                    if call_id == "call-search-1"
            ));
            call.result = format!("ran:{}", call.arguments);
            next(call)
        })
        .unwrap();
    }

    let created = Arc::new(Mutex::new(Vec::new()));
    {
        let created = Arc::clone(&created);
        ctx.on_emit(events::AGENT_CREATED, move |live: &AgentRef| {
            created.lock().expect("created").push(live.id.clone());
        })
        .unwrap();
    }

    let out = run_agent_step(
        &mut ctx,
        AgentStep::new("mission-1", "grow")
            .with_tool(ToolCall::new("search", "q=growth", "allow").with_call_id("call-search-1")),
    )
    .unwrap();

    assert_eq!(out.id, "mission-1");
    assert_eq!(out.plan.body, "plan:grow");
    assert_eq!(planned.load(Ordering::SeqCst), 1);
    assert_eq!(
        out.tool.as_ref().map(|call| call.result.as_str()),
        Some("ran:q=growth")
    );
    assert_eq!(
        ctx.agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list(),
        [AgentRef::new("mission-1")]
    );
    assert_eq!(*created.lock().expect("created"), ["mission-1".to_string()]);
    assert_eq!(
        ctx.domain::<DomainSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().unwrap().owner(),
        SurfaceOwner::Hartevo
    );
    assert!(ctx.get::<String>("openinterpreter").is_none());

    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .get(&SessionId::new("mission-1").unwrap())
        .unwrap()
        .unwrap();
    let events = session.events().unwrap();
    assert_eq!(events.len(), 8);
    assert!(matches!(
        events[0].kind,
        SessionEventKind::TurnStart { turn: 1 }
    ));
    assert!(matches!(
        events[1].kind,
        SessionEventKind::StepStart { turn: 1, step: 1 }
    ));
    let SessionEventKind::UserMessage { message, .. } = &events[2].kind else {
        panic!("third event must persist the user prompt");
    };
    let user_message = message.clone();
    assert_eq!(message.role, SessionMessageRole::User);
    assert_eq!(
        message.content,
        [SessionContentBlock::Text {
            text: "grow".into()
        }]
    );
    let SessionEventKind::AssistantMessage { message, .. } = &events[3].kind else {
        panic!("fourth event must persist the model output");
    };
    let assistant_message = message.clone();
    assert_eq!(message.role, SessionMessageRole::Assistant);
    assert_eq!(
        message.source,
        SessionMessageSource::Model {
            provider: "hartevo-local".into(),
            model: "hartevo-local".into(),
        }
    );
    assert_eq!(
        message.content,
        [
            SessionContentBlock::Text {
                text: "plan:grow".into(),
            },
            SessionContentBlock::ToolCall {
                id: "call-search-1".into(),
                name: "search".into(),
                arguments: "q=growth".into(),
            },
        ]
    );
    assert!(matches!(
        &events[4].kind,
        SessionEventKind::ToolCall {
            turn: 1,
            step: 1,
            call_id,
            name,
            arguments,
        } if call_id == "call-search-1" && name == "search" && arguments == "q=growth"
    ));
    let SessionEventKind::ToolResult {
        message, surface, ..
    } = &events[5].kind
    else {
        panic!("sixth event must persist the tool result");
    };
    let tool_message = message.clone();
    assert_eq!(
        message.source,
        SessionMessageSource::Tool {
            call_id: "call-search-1".into()
        }
    );
    assert_eq!(
        message.content,
        [SessionContentBlock::ToolResult {
            tool_call_id: "call-search-1".into(),
            content: vec![SessionContentBlock::Text {
                text: "ran:q=growth".into()
            }],
            is_error: false,
        }]
    );
    assert_eq!(surface, &SessionSurfaceIntent::append_from(vec![4]));
    assert!(matches!(
        events[6].kind,
        SessionEventKind::StepEnd { turn: 1, step: 1 }
    ));
    assert!(matches!(
        events[7].kind,
        SessionEventKind::TurnEnd {
            turn: 1,
            reason: TurnEndReason::Completed
        }
    ));
    assert_eq!(
        session.derive_messages().unwrap(),
        [user_message, assistant_message, tool_message]
    );
}

#[test]
fn missing_inject_keys_are_missing_dependencies() {
    let mut ctx = Context::new();
    assert_eq!(
        ctx.mount(AgentLoop).unwrap_err(),
        CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
            keys::TOOLS.to_string(),
            keys::LLM.to_string(),
            keys::SESSIONS.to_string(),
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
        ])
    );
    assert_eq!(ctx.listener_count(events::AGENT_CREATED), 0);

    ctx.provide(keys::AGENTS, "agents").unwrap();
    ctx.provide(keys::TOOLS, "tools").unwrap();
    assert_eq!(
        ctx.mount(AgentLoop).unwrap_err(),
        CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
            keys::SESSIONS.to_string(),
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
        ])
    );
    assert_eq!(
        run_agent_step(&mut ctx, AgentStep::new("mission-1", "grow")).unwrap_err(),
        CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
            keys::TOOLS.to_string(),
            keys::LLM.to_string(),
            keys::SESSIONS.to_string(),
            keys::DOMAIN.to_string(),
            keys::EFFECT_BROKER.to_string(),
        ])
    );
}

#[test]
fn openinterpreter_runtime_plugin_does_not_own_domain_or_effect() {
    let mut ctx = mapped_with_openinterpreter(true);

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

    let out = run_agent_step(&mut ctx, AgentStep::new("mission-oi", "plan")).unwrap();
    assert_eq!(out.id, "mission-oi");
    assert_eq!(
        ctx.agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list(),
        [AgentRef::new("mission-oi")]
    );
    let domain = ctx.domain::<DomainSurface>().unwrap();
    assert!(domain.consent());
    assert!(domain.approved());
    assert_eq!(
        ctx.effect_broker::<EffectBrokerSurface>().as_deref(),
        Some(&EffectBrokerSurface::default())
    );
}

#[test]
fn teardown_undoes_agents_and_loop_listeners() {
    let mut ctx = mapped();
    run_agent_step(&mut ctx, AgentStep::new("mission-1", "grow")).unwrap();
    assert_eq!(
        ctx.agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list()
            .len(),
        1
    );
    assert!(ctx.listener_count(events::AGENT_CREATED) >= 1);
    assert!(ctx.listener_count(events::AGENT_DISPOSED) >= 1);

    ctx.teardown();
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
        assert!(!ctx.has(key), "{key} must reverse on teardown");
    }
    assert_eq!(ctx.listener_count(events::AGENT_CREATED), 0);
    assert_eq!(ctx.listener_count(events::AGENT_DISPOSED), 0);
    assert_eq!(ctx.event_mode(events::AGENT_CREATED), None);
    assert_eq!(ctx.event_mode(events::AGENT_DISPOSED), None);

    let mut reloaded = mapped();
    run_agent_step(&mut reloaded, AgentStep::new("mission-2", "retry")).unwrap();
    assert_eq!(
        reloaded
            .agents::<hartevo_cordis::AgentsSurface>()
            .unwrap()
            .list(),
        [AgentRef::new("mission-2")]
    );
}

#[test]
fn overlay_still_selects_surface_mapping_then_agent_loop() {
    let overlay = EnvironmentOverlay::new("macos-dev");
    let loader = LoaderContext::new();
    let (mut host, report) = CordisHost::boot_overlay(&overlay, &loader, false).unwrap();
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
    let ctx = host.context_mut();
    assert_eq!(
        report.started,
        [
            hartevo_cordis::PluginId::new("surfaces"),
            hartevo_cordis::PluginId::new("agent-loop"),
            hartevo_cordis::PluginId::new("invariants"),
        ]
    );
    assert_eq!(
        report.disabled,
        [hartevo_cordis::PluginId::new("openinterpreter")]
    );
    assert!(ctx.has(keys::DOMAIN));
    assert!(ctx.has(keys::EFFECT_BROKER));
    assert_eq!(ctx.listener_count(events::AGENT_CREATED), 1);
    assert!(ctx.get::<&str>("openinterpreter").is_none());

    let out = run_agent_step(ctx, AgentStep::new("mission-overlay", "plan")).unwrap();
    assert_eq!(out.id, "mission-overlay");
}
