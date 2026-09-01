use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use hartevo_cordis::{
    AgentRef, Context, CordisError, CordisHost, DispatchMode, DomainSurface, EffectBrokerSurface,
    Emit, EnvironmentOverlay, EventKey, LlmAdapter, LlmAdapterStream, LlmChunkStream, LlmError,
    LlmGenerateRequest, LlmModelReasoning, LlmResolvedModel, LlmStream, LoaderContext, MAPPED_KEYS,
    PluginId, PromptAssembly, PromptError, PromptSection, RuntimeSurface, SessionCallConfig,
    SessionContentBlock, SessionFinishReason, SessionId, SessionLlmFailure, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionStreamBlockType, SessionStreamChunk,
    SessionToolSchema, SurfaceOwner, SystemPromptSurface, ToolCall, ToolsSurface, Waterfall,
    assemble_system_prompt, events, expected_mode, keys, prepare_llm_call, register_agent,
    register_llm_adapter, register_llm_stream, register_prompt_section, register_tool,
    register_tool_schema, run_tools_pipeline, session_events, stream_llm, stream_llm_request,
    stream_prepared_llm,
};

fn mapped() -> Context {
    let mut host = CordisHost::boot(false).unwrap();
    std::mem::take(host.context_mut())
}

fn call_config(provider: &str, model: &str) -> SessionCallConfig {
    SessionCallConfig {
        provider: provider.into(),
        model: model.into(),
        reasoning_effort: None,
        temperature: None,
        max_tokens: None,
        stop: None,
    }
}

fn request_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn ready_chunks(mut stream: LlmChunkStream) -> Vec<SessionStreamChunk> {
    let waker = futures_util::task::noop_waker_ref();
    let mut cx = TaskContext::from_waker(waker);
    let mut chunks = Vec::new();
    loop {
        match stream.as_mut().poll_next(&mut cx) {
            Poll::Ready(Some(chunk)) => chunks.push(chunk),
            Poll::Ready(None) => return chunks,
            Poll::Pending => panic!("test adapter streams must be immediately ready"),
        }
    }
}

#[derive(Clone)]
struct TestStreamingAdapter {
    generation: &'static str,
    seen: Arc<Mutex<Vec<(&'static str, LlmGenerateRequest)>>>,
    setup_failure: Option<SessionLlmFailure>,
    items: Vec<Result<SessionStreamChunk, SessionLlmFailure>>,
}

impl LlmAdapter for TestStreamingAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model))
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        self.seen
            .lock()
            .expect("seen")
            .push((self.generation, request));
        if let Some(failure) = &self.setup_failure {
            return Err(failure.clone());
        }
        Ok(Box::pin(futures_util::stream::iter(self.items.clone())))
    }
}

#[test]
fn mapped_keys_are_provided_and_looked_up() {
    let ctx = mapped();
    assert_eq!(
        MAPPED_KEYS,
        [
            keys::TOOLS,
            keys::SYSTEM_PROMPT,
            keys::LLM,
            keys::SESSIONS,
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
    assert!(ctx.system_prompt::<SystemPromptSurface>().is_some());
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
        events::TOOLS_PRE_EXECUTE.name(),
        events::TOOLS_EXECUTE.name(),
        events::TOOLS_POST_EXECUTE.name(),
        events::TOOLS_RESULT.name(),
    ] {
        assert_eq!(ctx.event_mode(name), expected_mode(name));
        assert_eq!(ctx.listener_count(name), 0);
    }

    let wrong_emit = EventKey::<Emit, ToolCall, ()>::new(
        events::TOOLS_PRE_EXECUTE.schema_id(),
        events::TOOLS_PRE_EXECUTE.name(),
    );
    let conflict = ctx.on_emit(wrong_emit, |_: &ToolCall| {}).unwrap_err();
    assert!(matches!(
        conflict,
        CordisError::SchemaConflict { ref name, ref locked, ref requested }
            if name == events::TOOLS_PRE_EXECUTE.name()
                && locked.mode() == DispatchMode::Waterfall
                && requested.mode() == DispatchMode::Emit
    ));
    let wrong_waterfall = EventKey::<Waterfall, ToolCall, ToolCall>::new(
        events::TOOLS_RESULT.schema_id(),
        events::TOOLS_RESULT.name(),
    );
    let result_conflict = ctx
        .on_waterfall(wrong_waterfall, |call: ToolCall, next| next(call))
        .unwrap_err();
    assert!(matches!(
        result_conflict,
        CordisError::SchemaConflict { ref name, ref locked, ref requested }
            if name == events::TOOLS_RESULT.name()
                && locked.mode() == DispatchMode::Emit
                && requested.mode() == DispatchMode::Waterfall
    ));
}

#[test]
fn all_twelve_mapped_events_keep_their_exact_typed_descriptors() {
    let ctx = mapped();
    macro_rules! assert_mapped {
        ($key:expr, $mode:expr) => {{
            let key = $key;
            assert_eq!(ctx.event_mode(key), Some($mode));
            assert_eq!(ctx.event_descriptor(key), Some(key.descriptor()));
            assert_eq!(expected_mode(key.name()), Some($mode));
        }};
    }
    assert_mapped!(events::SYSTEM_PROMPT_ASSEMBLE, DispatchMode::Waterfall);
    assert_mapped!(events::TOOLS_PRE_EXECUTE, DispatchMode::Waterfall);
    assert_mapped!(events::TOOLS_EXECUTE, DispatchMode::Waterfall);
    assert_mapped!(events::TOOLS_POST_EXECUTE, DispatchMode::Waterfall);
    assert_mapped!(events::TOOLS_RESULT, DispatchMode::Emit);
    assert_mapped!(events::LLM_STREAM, DispatchMode::Waterfall);
    assert_mapped!(events::AGENT_CREATED, DispatchMode::Emit);
    assert_mapped!(events::AGENT_DISPOSED, DispatchMode::Emit);
    assert_mapped!(events::AGENT_PRE_STEP, DispatchMode::Waterfall);
    assert_mapped!(events::AGENT_REQUEST, DispatchMode::Waterfall);
    assert_mapped!(session_events::SESSION_EVENT, DispatchMode::Emit);
    assert_mapped!(session_events::SESSION_FLUSH, DispatchMode::Parallel);
}

fn tool_schema(name: &str) -> SessionToolSchema {
    SessionToolSchema {
        name: name.into(),
        description: format!("{name} tool"),
        parameters: serde_json::Map::from_iter([(
            "type".into(),
            serde_json::Value::String("object".into()),
        )]),
    }
}

#[test]
fn prompt_and_tool_schema_assembly_is_deterministic_detached_and_reversible() {
    let mut ctx = mapped();
    let late = register_prompt_section(&mut ctx, PromptSection::new("zulu", 10, "Zulu.")).unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("first", 0, "First.")).unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("alpha", 10, "Alpha.")).unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("empty", 5, "")).unwrap();
    let zulu_tool = register_tool_schema(&mut ctx, tool_schema("zulu")).unwrap();
    register_tool_schema(&mut ctx, tool_schema("alpha")).unwrap();

    let frozen = assemble_system_prompt(&mut ctx).unwrap();
    assert_eq!(frozen.system(), Some("First.\n\nAlpha.\n\nZulu."));
    assert_eq!(
        frozen
            .tools()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zulu"]
    );

    late.dispose();
    zulu_tool.dispose();
    let current = assemble_system_prompt(&mut ctx).unwrap();
    assert_eq!(current.system(), Some("First.\n\nAlpha."));
    assert_eq!(
        current
            .tools()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha"]
    );
    assert_eq!(frozen.system(), Some("First.\n\nAlpha.\n\nZulu."));
    assert_eq!(frozen.tools().len(), 2);

    assert_eq!(
        register_prompt_section(&mut ctx, PromptSection::new("alpha", 99, "duplicate"))
            .unwrap_err(),
        CordisError::Prompt(PromptError::DuplicateSection {
            name: "alpha".into(),
        })
    );
    assert_eq!(
        register_tool_schema(&mut ctx, tool_schema("alpha")).unwrap_err(),
        CordisError::Prompt(PromptError::DuplicateTool {
            name: "alpha".into(),
        })
    );
}

#[test]
fn prompt_assembly_waterfall_is_authoritative_and_validated() {
    let mut ctx = mapped();
    register_prompt_section(&mut ctx, PromptSection::new("base", 0, "Base.")).unwrap();
    ctx.on_waterfall(events::SYSTEM_PROMPT_ASSEMBLE, |assembly, next| {
        next(assembly).with_system(Some("Wrapped.".into()))
    })
    .unwrap();
    assert_eq!(
        assemble_system_prompt(&mut ctx).unwrap().system(),
        Some("Wrapped.")
    );

    let mut invalid = mapped();
    invalid
        .on_waterfall(events::SYSTEM_PROMPT_ASSEMBLE, |assembly, _next| {
            assembly.with_tools(vec![tool_schema("dup"), tool_schema("dup")])
        })
        .unwrap();
    assert_eq!(
        assemble_system_prompt(&mut invalid).unwrap_err(),
        CordisError::Prompt(PromptError::DuplicateTool { name: "dup".into() })
    );

    let canonical = PromptAssembly::new(Some(String::new()), Vec::new());
    let mut empty = mapped();
    empty
        .on_waterfall(events::SYSTEM_PROMPT_ASSEMBLE, move |_assembly, _next| {
            canonical.clone()
        })
        .unwrap();
    assert_eq!(
        assemble_system_prompt(&mut empty).unwrap(),
        PromptAssembly::default()
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
                call.call_id = "middleware-must-not-rewrite-identity".into();
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
        ctx.on_waterfall(
            events::LEGACY_TOOLS_EXECUTE,
            move |mut call: ToolCall, next| {
                seen.lock()
                    .expect("seen")
                    .push(format!("execute:{}", call.name));
                call.result = format!("ran:{}", call.arguments);
                next(call)
            },
        )
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall(
            events::LEGACY_TOOLS_POST_EXECUTE,
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
        ctx.on_emit(events::LEGACY_TOOLS_RESULT, move |call: &ToolCall| {
            seen.lock()
                .expect("seen")
                .push(format!("result:{}:{}", call.name, call.decision));
        })
        .unwrap();
    }

    let allowed = run_tools_pipeline(
        &mut ctx,
        ToolCall::new("search", "q=growth", "allow").with_call_id("call-search-1"),
    )
    .unwrap();
    assert_eq!(allowed.call_id, "call-search-1");
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
fn llm_adapter_registration_is_atomic_reversible_and_generation_bound() {
    let mut ctx = mapped();
    let first = register_llm_adapter(
        &mut ctx,
        ["mock", "other"],
        |provider: &str, model: &str| Ok(LlmResolvedModel::new(provider, model)),
    )
    .unwrap();
    let llm = ctx.llm::<hartevo_cordis::LlmSurface>().unwrap();
    assert_eq!(llm.providers().unwrap(), ["mock", "other"]);

    assert_eq!(
        register_llm_adapter(&mut ctx, ["third", ""], |provider: &str, model: &str| Ok(
            LlmResolvedModel::new(provider, model)
        ),)
        .unwrap_err(),
        CordisError::Llm(LlmError::InvalidAdapter {
            expected: "non-empty provider names",
        })
    );
    assert_eq!(
        register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| Ok(
            LlmResolvedModel::new(provider, model)
        ),)
        .unwrap_err(),
        CordisError::Llm(LlmError::DuplicateAdapter {
            provider: "mock".into(),
        })
    );
    assert_eq!(llm.providers().unwrap(), ["mock", "other"]);

    let old = prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap();
    assert!(first.dispose());
    assert!(llm.providers().unwrap().is_empty());
    let second = register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model).with_default_max_tokens(32))
    })
    .unwrap();
    let current = prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap();
    assert_ne!(old.registration_id(), current.registration_id());
    assert_eq!(old.config().max_tokens, None);
    assert_eq!(current.config().max_tokens, Some(32));
    assert!(second.dispose());
}

#[test]
fn llm_adapter_preparation_validates_metadata_and_materializes_only_defaults() {
    let mut ctx = mapped();
    let llm = ctx.llm::<hartevo_cordis::LlmSurface>().unwrap();
    register_llm_adapter(&mut ctx, ["mock"], move |provider: &str, model: &str| {
        assert_eq!(llm.providers().unwrap(), ["mock"]);
        Ok(LlmResolvedModel::new(provider, model)
            .with_context_window(128_000)
            .with_default_max_tokens(4_096)
            .with_reasoning(LlmModelReasoning::new(
                vec!["low".into(), "high".into()],
                Some("high".into()),
            )))
    })
    .unwrap();

    let defaulted = prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap();
    assert_eq!(defaulted.config().reasoning_effort.as_deref(), Some("high"));
    assert_eq!(defaulted.config().max_tokens, Some(4_096));
    assert!(defaulted.adapter_defaults().reasoning_effort);
    assert!(defaulted.adapter_defaults().max_tokens);
    assert_eq!(defaulted.context_window(), Some(128_000));

    let mut explicit = call_config("mock", "model");
    explicit.reasoning_effort = Some("low".into());
    explicit.max_tokens = Some(512);
    let explicit = prepare_llm_call(&ctx, &explicit).unwrap();
    assert_eq!(explicit.config().reasoning_effort.as_deref(), Some("low"));
    assert_eq!(explicit.config().max_tokens, Some(512));
    assert!(!explicit.adapter_defaults().reasoning_effort);
    assert!(!explicit.adapter_defaults().max_tokens);

    let mut unsupported = call_config("mock", "model");
    unsupported.reasoning_effort = Some("max".into());
    assert_eq!(
        prepare_llm_call(&ctx, &unsupported).unwrap_err(),
        CordisError::Llm(LlmError::UnsupportedReasoningEffort {
            provider: "mock".into(),
            model: "model".into(),
            effort: "max".into(),
        })
    );

    register_llm_adapter(&mut ctx, ["invalid"], |_provider: &str, model: &str| {
        Ok(LlmResolvedModel::new("wrong", model))
    })
    .unwrap();
    assert!(matches!(
        prepare_llm_call(&ctx, &call_config("invalid", "model")),
        Err(CordisError::Llm(LlmError::InvalidModelInfo { .. }))
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one fixture proves generation binding, one-shot use, and mismatch non-consumption"
)]
fn prepared_stream_is_exact_generation_one_shot_and_request_bound() {
    let mut ctx = mapped();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let old = register_llm_adapter(
        &mut ctx,
        ["mock"],
        TestStreamingAdapter {
            generation: "old",
            seen: Arc::clone(&seen),
            setup_failure: None,
            items: vec![Ok(SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            })],
        },
    )
    .unwrap();
    let prepared = prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap();
    assert!(old.dispose());
    register_llm_adapter(
        &mut ctx,
        ["mock"],
        TestStreamingAdapter {
            generation: "new",
            seen: Arc::clone(&seen),
            setup_failure: None,
            items: vec![Ok(SessionStreamChunk::Finish {
                reason: SessionFinishReason::MaxTokens,
                replay_state: None,
            })],
        },
    )
    .unwrap();

    let order = Arc::new(Mutex::new(Vec::new()));
    let wrapped = Arc::new(AtomicUsize::new(0));
    let middleware = {
        let order = Arc::clone(&order);
        let seen = Arc::clone(&seen);
        let wrapped = Arc::clone(&wrapped);
        ctx.on_waterfall(events::LLM_STREAM, move |stream, next| {
            let request = stream.request().expect("generated request");
            assert_eq!(request.config().provider, "mock");
            assert_eq!(request.system(), Some("Be precise."));
            assert_eq!(
                request.session_id().map(SessionId::as_str),
                Some("session-1")
            );
            assert!(seen.lock().expect("seen").is_empty());
            order.lock().expect("order").push("waterfall");
            let wrapped = Arc::clone(&wrapped);
            next(stream)
                .map_chunk_stream(move |source| {
                    wrapped.fetch_add(1, Ordering::SeqCst);
                    source
                })
                .expect("downstream stream")
        })
        .unwrap()
    };
    let request = LlmGenerateRequest::new(
        prepared.config().clone(),
        vec![request_message("message-1", "hello")],
    )
    .with_system(Some("Be precise.".into()))
    .with_tools(vec![tool_schema("search")])
    .with_session_id(SessionId::new("session-1").unwrap());
    let chunks = ready_chunks(stream_prepared_llm(&mut ctx, &prepared, request.clone()).unwrap());
    assert_eq!(
        chunks,
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        }]
    );
    assert_eq!(*order.lock().expect("order"), ["waterfall"]);
    assert_eq!(wrapped.load(Ordering::SeqCst), 1);
    let calls = seen.lock().expect("seen");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "old");
    assert_eq!(calls[0].1, request);
    drop(calls);

    let error = stream_prepared_llm(&mut ctx, &prepared, request)
        .err()
        .expect("prepared call must reject reuse");
    assert_eq!(
        error,
        CordisError::Llm(LlmError::InvalidPreparedCall {
            expected: "one dispatch only",
        })
    );
    assert_eq!(*order.lock().expect("order"), ["waterfall"]);
    assert!(middleware.dispose());

    let current = prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap();
    let mut mismatched = current.config().clone();
    mismatched.max_tokens = Some(7);
    let error = stream_prepared_llm(
        &mut ctx,
        &current,
        LlmGenerateRequest::new(mismatched, Vec::new()),
    )
    .err()
    .expect("config mismatch must fail");
    assert!(matches!(
        error,
        CordisError::Llm(ref llm) if llm.code() == "INVALID_PREPARED_CALL"
    ));
    let chunks = ready_chunks(
        stream_prepared_llm(
            &mut ctx,
            &current,
            LlmGenerateRequest::new(current.config().clone(), Vec::new()),
        )
        .unwrap(),
    );
    assert!(matches!(
        chunks.as_slice(),
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::MaxTokens,
            ..
        }]
    ));
    assert_eq!(seen.lock().expect("seen").last().unwrap().0, "new");
}

#[test]
fn llm_stream_middleware_can_serve_no_adapter_but_cannot_replace_request() {
    let mut served = mapped();
    served
        .on_waterfall(events::LLM_STREAM, |stream, _next| {
            assert_eq!(
                stream
                    .request()
                    .unwrap()
                    .session_id()
                    .map(SessionId::as_str),
                Some("fallback-session")
            );
            stream.with_chunk_stream(Box::pin(futures_util::stream::iter([
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                },
            ])))
        })
        .unwrap();
    let request = LlmGenerateRequest::new(call_config("middleware", "model"), Vec::new())
        .with_session_id(SessionId::new("fallback-session").unwrap());
    assert!(matches!(
        ready_chunks(stream_llm_request(&mut served, request).unwrap()).as_slice(),
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            ..
        }]
    ));

    let mut missing = mapped();
    let chunks = ready_chunks(
        stream_llm_request(
            &mut missing,
            LlmGenerateRequest::new(call_config("missing", "model"), Vec::new()),
        )
        .unwrap(),
    );
    assert!(matches!(
        chunks.as_slice(),
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::Error { failure },
            ..
        }] if failure.code == "NO_ADAPTER"
    ));

    let mut replaced = mapped();
    replaced
        .on_waterfall(events::LLM_STREAM, |_stream, _next| {
            LlmStream::new("other", "lost request")
                .with_chunk_stream(Box::pin(futures_util::stream::empty()))
        })
        .unwrap();
    let error = stream_llm_request(
        &mut replaced,
        LlmGenerateRequest::new(call_config("missing", "model"), Vec::new()),
    )
    .err()
    .expect("middleware must retain the generated request");
    assert!(matches!(
        error,
        CordisError::Llm(ref llm) if llm.code() == "INVALID_STREAM_DISPATCH"
    ));
}

#[test]
fn adapter_setup_and_iteration_failures_become_one_terminal_chunk() {
    let mut ctx = mapped();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let aborted = SessionLlmFailure {
        message: "cancelled".into(),
        code: "ABORTED".into(),
        status: None,
        provider_retry_after_ms: None,
        request_id: None,
    };
    register_llm_adapter(
        &mut ctx,
        ["iterate"],
        TestStreamingAdapter {
            generation: "iterate",
            seen: Arc::clone(&seen),
            setup_failure: None,
            items: vec![
                Ok(SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                }),
                Err(aborted.clone()),
                Ok(SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                }),
            ],
        },
    )
    .unwrap();
    register_llm_adapter(
        &mut ctx,
        ["setup"],
        TestStreamingAdapter {
            generation: "setup",
            seen,
            setup_failure: Some(SessionLlmFailure {
                message: "offline".into(),
                code: "NETWORK".into(),
                status: Some(503),
                provider_retry_after_ms: None,
                request_id: None,
            }),
            items: Vec::new(),
        },
    )
    .unwrap();

    let iterate = ready_chunks(
        stream_llm_request(
            &mut ctx,
            LlmGenerateRequest::new(call_config("iterate", "model"), Vec::new()),
        )
        .unwrap(),
    );
    assert_eq!(iterate.len(), 2);
    assert!(matches!(
        &iterate[1],
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::Aborted { failure },
            ..
        } if failure == &aborted
    ));

    let setup = ready_chunks(
        stream_llm_request(
            &mut ctx,
            LlmGenerateRequest::new(call_config("setup", "model"), Vec::new()),
        )
        .unwrap(),
    );
    assert!(matches!(
        setup.as_slice(),
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::Error { failure },
            ..
        }] if failure.code == "NETWORK" && failure.status == Some(503)
    ));
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
    ctx.on_waterfall(events::LEGACY_TOOLS_EXECUTE, |call: ToolCall, next| {
        next(call)
    })
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
    assert_eq!(ctx.listener_count(events::LEGACY_TOOLS_EXECUTE), 1);
    assert_eq!(ctx.listener_count(events::LLM_STREAM), 1);
    assert!(ctx.listener_count(events::AGENT_CREATED) >= 2);

    ctx.teardown();
    for key in [
        keys::TOOLS,
        keys::SYSTEM_PROMPT,
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
    for name in [
        events::SYSTEM_PROMPT_ASSEMBLE.name(),
        events::TOOLS_PRE_EXECUTE.name(),
        events::TOOLS_EXECUTE.name(),
        events::TOOLS_POST_EXECUTE.name(),
        events::TOOLS_RESULT.name(),
        events::LLM_STREAM.name(),
        events::AGENT_CREATED.name(),
        events::AGENT_DISPOSED.name(),
        events::AGENT_PRE_STEP.name(),
        events::AGENT_REQUEST.name(),
        session_events::SESSION_EVENT.name(),
        session_events::SESSION_FLUSH.name(),
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
        register_prompt_section(&mut ctx, PromptSection::new("base", 0, "base")).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::SYSTEM_PROMPT.to_string()])
    );
    assert_eq!(
        register_tool_schema(&mut ctx, tool_schema("search")).unwrap_err(),
        CordisError::MissingDependencies(vec![keys::TOOLS.to_string()])
    );
    assert_eq!(
        register_llm_stream(&mut ctx, "hartevo-local").unwrap_err(),
        CordisError::MissingDependencies(vec![keys::LLM.to_string()])
    );
    assert_eq!(
        register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| Ok(
            LlmResolvedModel::new(provider, model)
        ),)
        .unwrap_err(),
        CordisError::MissingDependencies(vec![keys::LLM.to_string()])
    );
    assert_eq!(
        prepare_llm_call(&ctx, &call_config("mock", "model")).unwrap_err(),
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
