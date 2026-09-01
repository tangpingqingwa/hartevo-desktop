use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};

use chrono::{Duration, TimeZone, Utc};
use futures_util::FutureExt;
use hartevo_cordis::{
    AgentBuildAdmission, AgentCallAdmission, AgentInboxTarget, AgentLoop, AgentPreStepDecision,
    AgentRef, AgentRequestAdmission, AgentRequestLogState, AgentStep, Context, CordisError,
    CordisHost, DomainSurface, EffectBrokerSurface, EnvironmentOverlay, KernelApproval,
    KernelApprovalDecision, KernelConsentState, LlmAdapter, LlmAdapterStream, LlmChunkStream,
    LlmError, LlmGenerateRequest, LlmModelReasoning, LlmResolvedModel, LlmStream, LoaderContext,
    LoggedAgentCall, PromptError, PromptSection, RecordedAgentStream, RuntimeSurface,
    SessionCallConfig, SessionContentBlock, SessionError, SessionEventKind, SessionFinishReason,
    SessionHandle, SessionId, SessionLlmFailure, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionRequestHeaderReason, SessionStore, SessionStreamBlockType,
    SessionStreamChunk, SessionSurfaceIntent, SessionTokenUsage, SessionToolSchema, SurfaceOwner,
    ToolCall, TurnEndReason, admit_agent_request, admit_agent_step, build_agent_call,
    dispatch_agent_call, events, keys, log_agent_call, prepare_agent_call, prepare_agent_step,
    record_agent_stream, register_llm_adapter, register_prompt_section, register_tool_schema,
    run_agent_step, session_events,
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

fn user_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::User,
    }
}

fn assistant_message(id: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::Assistant,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::Model {
            provider: "mock".into(),
            model: "model".into(),
        },
    }
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
struct AgentStreamingAdapter {
    seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
}

impl LlmAdapter for AgentStreamingAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model).with_default_max_tokens(512))
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        self.seen.lock().expect("seen").push(request);
        Ok(Box::pin(futures_util::stream::iter([Ok(
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
        )])))
    }
}

#[derive(Clone)]
struct ScriptedAgentAdapter {
    items: Vec<Result<SessionStreamChunk, SessionLlmFailure>>,
}

impl LlmAdapter for ScriptedAgentAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        Ok(LlmResolvedModel::new(provider, model))
    }

    fn stream(&self, _request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        Ok(Box::pin(futures_util::stream::iter(self.items.clone())))
    }
}

fn ready_record_agent_stream(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
) -> Result<RecordedAgentStream, CordisError> {
    record_agent_stream(ctx, logged)
        .now_or_never()
        .expect("scripted stream must be immediately ready")
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

fn build_logged_turn(
    ctx: &mut Context,
    session: &SessionHandle,
    state: &mut AgentRequestLogState,
    message_id: &str,
    config: SessionCallConfig,
) -> (u64, LoggedAgentCall) {
    session
        .inbox()
        .append_next_turn(user_message(message_id, message_id))
        .unwrap();
    let turn = session.start_turn().unwrap();
    let AgentBuildAdmission::Call(call) = build_agent_call(
        ctx,
        session.id(),
        AgentInboxTarget::NextTurn,
        turn,
        1,
        config,
        state,
    )
    .unwrap() else {
        panic!("non-empty inbox must build one logged call");
    };
    (turn, call)
}

fn close_logged_turn(session: &SessionHandle, turn: u64) {
    session.finish_step(turn, 1).unwrap();
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
}

fn record_script(
    session_id: &str,
    items: Vec<Result<SessionStreamChunk, SessionLlmFailure>>,
) -> (SessionHandle, u64, Result<RecordedAgentStream, CordisError>) {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], ScriptedAgentAdapter { items }).unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new(session_id).unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (turn, logged) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "request",
        call_config("mock", "model"),
    );
    let result = ready_record_agent_stream(&mut ctx, &logged);
    (session, turn, result)
}

fn ok_chunks(
    chunks: Vec<SessionStreamChunk>,
) -> Vec<Result<SessionStreamChunk, SessionLlmFailure>> {
    chunks.into_iter().map(Ok).collect()
}

fn usage() -> SessionStreamChunk {
    SessionStreamChunk::Usage {
        usage: SessionTokenUsage {
            input_tokens: 2,
            output_tokens: 3,
            total_tokens: Some(5),
            cache_read_tokens: None,
            cache_write_tokens: None,
            reasoning_tokens: Some(1),
        },
    }
}

fn assert_protocol_rejected(
    session_id: &str,
    chunks: Vec<SessionStreamChunk>,
    expected: &'static str,
    persisted_prefix: usize,
) {
    let (session, turn, result) = record_script(session_id, ok_chunks(chunks));
    assert_eq!(
        result,
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected,
        }))
    );
    assert_eq!(
        session.assistant_chunks(turn, 1).unwrap().len(),
        persisted_prefix
    );
}

#[test]
fn pre_step_defaults_to_the_exact_claimed_batch_before_any_step_event() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("pre-step-default").unwrap())
        .unwrap();
    let next_step = user_message("step-context", "context");
    let next_turn = user_message("turn-prompt", "prompt");
    session.inbox().append_next_step(next_step.clone()).unwrap();
    session.inbox().append_next_turn(next_turn.clone()).unwrap();
    let turn = session.start_turn().unwrap();
    let before = session.events().unwrap().len();

    let proposal =
        prepare_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 1).unwrap();

    assert_eq!(proposal.agent(), &AgentRef::new("pre-step-default"));
    assert_eq!(proposal.turn(), turn);
    assert_eq!(proposal.step(), 1);
    assert_eq!(
        proposal.decision(),
        &AgentPreStepDecision::Enter {
            messages: vec![next_step, next_turn],
            starts_request_series: false,
        }
    );
    let events = session.events().unwrap();
    assert_eq!(events.len(), before + 2);
    assert!(matches!(
        events[before].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextStep,
            ..
        }
    ));
    assert!(matches!(
        events[before + 1].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            ..
        }
    ));
    assert!(events[before..].iter().all(|event| !matches!(
        event.kind,
        SessionEventKind::StepStart { .. } | SessionEventKind::UserMessage { .. }
    )));
}

#[test]
fn admitted_step_commits_start_then_the_exact_nonempty_batch() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("step-entry").unwrap())
        .unwrap();
    let context = user_message("step-context", "context");
    let prompt = user_message("turn-prompt", "prompt");
    session.inbox().append_next_step(context.clone()).unwrap();
    session.inbox().append_next_turn(prompt.clone()).unwrap();
    let turn = session.start_turn().unwrap();
    let before = session.events().unwrap().len();

    let admitted =
        admit_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 1).unwrap();

    assert_eq!(
        admitted.decision(),
        &AgentPreStepDecision::Enter {
            messages: vec![context.clone(), prompt.clone()],
            starts_request_series: false,
        }
    );
    let events = session.events().unwrap();
    assert_eq!(events.len(), before + 5);
    assert!(matches!(
        events[before].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextStep,
            ..
        }
    ));
    assert!(matches!(
        events[before + 1].kind,
        SessionEventKind::AgentInboxSpliced {
            target: AgentInboxTarget::NextTurn,
            ..
        }
    ));
    assert!(matches!(
        events[before + 2].kind,
        SessionEventKind::StepStart { turn: 1, step: 1 }
    ));
    assert!(matches!(
        &events[before + 3].kind,
        SessionEventKind::UserMessage { message, .. } if message == &context
    ));
    assert!(matches!(
        &events[before + 4].kind,
        SessionEventKind::UserMessage { message, .. } if message == &prompt
    ));
    assert_eq!(session.derive_messages().unwrap(), [context, prompt]);
}

#[test]
fn empty_admission_opens_no_step_and_preserves_request_series() {
    let mut ctx = mapped();
    ctx.on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| {
        proposal
            .replace_messages(Vec::new())
            .with_starts_request_series()
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("step-entry-empty").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("removed", "removed"))
        .unwrap();
    let turn = session.start_turn().unwrap();

    let admitted =
        admit_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 1).unwrap();

    assert_eq!(
        admitted.decision(),
        &AgentPreStepDecision::Enter {
            messages: Vec::new(),
            starts_request_series: true,
        }
    );
    assert!(!session.inbox().has_pending().unwrap());
    assert!(session.events().unwrap().iter().all(|event| !matches!(
        event.kind,
        SessionEventKind::StepStart { .. } | SessionEventKind::UserMessage { .. }
    )));
}

#[test]
fn stale_step_fails_before_the_complete_entry_batch() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("step-entry-stale").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("claimed", "claimed"))
        .unwrap();
    let turn = session.start_turn().unwrap();

    assert_eq!(
        admit_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 2),
        Err(CordisError::Session(SessionError::UnexpectedStep {
            turn,
            expected: 1,
            actual: 2,
        }))
    );
    assert!(!session.inbox().has_pending().unwrap());
    assert!(session.events().unwrap().iter().all(|event| !matches!(
        event.kind,
        SessionEventKind::StepStart { .. } | SessionEventKind::UserMessage { .. }
    )));
}

#[test]
fn step_entry_publishes_the_committed_batch_in_order_and_rejects_reentry() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("step-entry-observed").unwrap())
        .unwrap();
    let first = user_message("first", "first");
    let second = user_message("second", "second");
    session.inbox().append_next_step(first).unwrap();
    session.inbox().append_next_turn(second).unwrap();
    let turn = session.start_turn().unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let complete_at_start = Arc::new(Mutex::new(false));
    let reentry_error = Arc::new(Mutex::new(None));
    {
        let observed = Arc::clone(&observed);
        let complete_at_start = Arc::clone(&complete_at_start);
        let reentry_error = Arc::clone(&reentry_error);
        let callback_session = session.clone();
        ctx.on_emit(session_events::SESSION_EVENT, move |record| {
            match &record.event.kind {
                SessionEventKind::StepStart { .. } => {
                    observed.lock().unwrap().push("step".to_string());
                    let events = callback_session.events().unwrap();
                    *complete_at_start.lock().unwrap() = matches!(
                        events[events.len() - 3..],
                        [
                            hartevo_cordis::SessionEvent {
                                kind: SessionEventKind::StepStart { .. },
                                ..
                            },
                            hartevo_cordis::SessionEvent {
                                kind: SessionEventKind::UserMessage { .. },
                                ..
                            },
                            hartevo_cordis::SessionEvent {
                                kind: SessionEventKind::UserMessage { .. },
                                ..
                            },
                        ]
                    );
                    *reentry_error.lock().unwrap() = Some(
                        callback_session
                            .append_user_message(user_message("nested", "nested"))
                            .unwrap_err(),
                    );
                }
                SessionEventKind::UserMessage { message, .. } => {
                    observed.lock().unwrap().push(message.id.clone());
                }
                _ => {}
            }
        })
        .unwrap();
    }

    admit_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 1).unwrap();

    assert_eq!(*observed.lock().unwrap(), ["step", "first", "second"]);
    assert!(*complete_at_start.lock().unwrap());
    assert_eq!(
        *reentry_error.lock().unwrap(),
        Some(SessionError::AppendInProgress {
            id: session.id().clone(),
        })
    );
    assert_eq!(session.derive_messages().unwrap().len(), 2);
}

#[test]
fn request_admission_freezes_messages_before_replacing_only_config() {
    let mut ctx = mapped();
    ctx.on_waterfall(events::AGENT_PRE_STEP, |proposal, next| {
        next(proposal).with_starts_request_series()
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-admission").unwrap())
        .unwrap();
    let prompt = user_message("prompt", "prompt");
    let later = user_message("later", "later");
    session.inbox().append_next_turn(prompt.clone()).unwrap();
    let turn = session.start_turn().unwrap();
    {
        let callback_session = session.clone();
        let later = later.clone();
        ctx.on_waterfall(events::AGENT_REQUEST, move |request, next| {
            assert_eq!(request.agent(), &AgentRef::new("request-admission"));
            assert_eq!(request.turn(), turn);
            assert_eq!(request.step(), 1);
            assert_eq!(request.config(), &call_config("seed", "seed-model"));
            callback_session.append_user_message(later.clone()).unwrap();
            next(request.with_config(call_config("routed", "routed-model")))
        })
        .unwrap();
    }

    let admission = admit_agent_request(
        &mut ctx,
        session.id(),
        AgentInboxTarget::NextTurn,
        turn,
        1,
        call_config("seed", "seed-model"),
    )
    .unwrap();
    let AgentRequestAdmission::Request(prepared) = admission else {
        panic!("a non-empty admitted step must prepare one request");
    };

    assert_eq!(prepared.agent(), &AgentRef::new("request-admission"));
    assert_eq!(prepared.turn(), turn);
    assert_eq!(prepared.step(), 1);
    assert_eq!(prepared.config(), &call_config("routed", "routed-model"));
    assert_eq!(prepared.messages(), std::slice::from_ref(&prompt));
    assert!(prepared.starts_request_series());
    assert_eq!(session.derive_messages().unwrap(), [prompt, later]);
    assert_eq!(session.request_header().unwrap(), None);
    assert_eq!(session.request_context().unwrap(), None);
}

#[test]
fn reject_and_empty_step_skip_request_waterfall() {
    let request_calls = Arc::new(AtomicUsize::new(0));

    let mut rejected_ctx = mapped();
    {
        let request_calls = Arc::clone(&request_calls);
        rejected_ctx
            .on_waterfall(events::AGENT_REQUEST, move |request, next| {
                request_calls.fetch_add(1, Ordering::SeqCst);
                next(request)
            })
            .unwrap();
    }
    rejected_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| proposal.reject())
        .unwrap();
    let rejected_session = rejected_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-rejected").unwrap())
        .unwrap();
    rejected_session
        .inbox()
        .append_next_turn(user_message("reject", "reject"))
        .unwrap();
    let rejected_turn = rejected_session.start_turn().unwrap();
    let rejected = admit_agent_request(
        &mut rejected_ctx,
        rejected_session.id(),
        AgentInboxTarget::NextTurn,
        rejected_turn,
        1,
        call_config("", ""),
    )
    .unwrap();
    assert!(matches!(
        rejected,
        AgentRequestAdmission::NoRequest(proposal)
            if proposal.decision() == &AgentPreStepDecision::Reject
    ));

    let mut empty_ctx = mapped();
    {
        let request_calls = Arc::clone(&request_calls);
        empty_ctx
            .on_waterfall(events::AGENT_REQUEST, move |request, next| {
                request_calls.fetch_add(1, Ordering::SeqCst);
                next(request)
            })
            .unwrap();
    }
    empty_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| {
            proposal.replace_messages(Vec::new())
        })
        .unwrap();
    let empty_session = empty_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-empty").unwrap())
        .unwrap();
    empty_session
        .inbox()
        .append_next_turn(user_message("empty", "empty"))
        .unwrap();
    let empty_turn = empty_session.start_turn().unwrap();
    let empty = admit_agent_request(
        &mut empty_ctx,
        empty_session.id(),
        AgentInboxTarget::NextTurn,
        empty_turn,
        1,
        call_config("", ""),
    )
    .unwrap();
    assert!(matches!(
        empty,
        AgentRequestAdmission::NoRequest(proposal)
            if matches!(proposal.decision(), AgentPreStepDecision::Enter { messages, .. } if messages.is_empty())
    ));
    assert_eq!(request_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_request_config_fails_after_step_entry_before_request_events() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-invalid-config").unwrap())
        .unwrap();
    let prompt = user_message("prompt", "prompt");
    session.inbox().append_next_turn(prompt.clone()).unwrap();
    let turn = session.start_turn().unwrap();

    assert_eq!(
        admit_agent_request(
            &mut ctx,
            session.id(),
            AgentInboxTarget::NextTurn,
            turn,
            1,
            call_config("", ""),
        ),
        Err(CordisError::Session(
            SessionError::InvalidAgentRequestConfig {
                expected: "non-empty provider and model",
            }
        ))
    );
    assert_eq!(session.derive_messages().unwrap(), [prompt]);
    assert_eq!(session.request_header().unwrap(), None);
    assert_eq!(session.request_context().unwrap(), None);
    assert!(matches!(
        session.start_step(turn),
        Err(SessionError::StepAlreadyOpen { turn: open_turn, step: 1 })
            if open_turn == turn
    ));
}

#[test]
fn request_admission_rechecks_the_exact_open_step_after_waterfall() {
    let mut ctx = mapped();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-step-moved").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("prompt", "prompt"))
        .unwrap();
    let turn = session.start_turn().unwrap();
    {
        let callback_session = session.clone();
        ctx.on_waterfall(events::AGENT_REQUEST, move |request, next| {
            callback_session.finish_step(turn, 1).unwrap();
            next(request)
        })
        .unwrap();
    }

    assert_eq!(
        admit_agent_request(
            &mut ctx,
            session.id(),
            AgentInboxTarget::NextTurn,
            turn,
            1,
            call_config("provider", "model"),
        ),
        Err(CordisError::Session(SessionError::NoOpenStep { turn }))
    );
    assert!(matches!(
        session.events().unwrap().last().map(|event| &event.kind),
        Some(SessionEventKind::StepEnd { turn: end_turn, step: 1 }) if *end_turn == turn
    ));
}

#[test]
fn agent_call_preparation_resolves_adapter_or_preserves_no_adapter_fallback() {
    let mut ctx = mapped();
    ctx.on_waterfall(events::AGENT_PRE_STEP, |proposal, next| {
        next(proposal).with_starts_request_series()
    })
    .unwrap();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model)
            .with_context_window(64_000)
            .with_default_max_tokens(2_048)
            .with_reasoning(LlmModelReasoning::new(
                vec!["high".into()],
                Some("high".into()),
            )))
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("prepared-agent-call").unwrap())
        .unwrap();
    let prompt = user_message("prompt", "prompt");
    session.inbox().append_next_turn(prompt.clone()).unwrap();
    let turn = session.start_turn().unwrap();

    let AgentCallAdmission::Call(call) = prepare_agent_call(
        &mut ctx,
        session.id(),
        AgentInboxTarget::NextTurn,
        turn,
        1,
        call_config("mock", "model"),
    )
    .unwrap() else {
        panic!("non-empty admission must prepare a call");
    };
    assert_eq!(call.messages(), std::slice::from_ref(&prompt));
    assert_eq!(call.config().reasoning_effort.as_deref(), Some("high"));
    assert_eq!(call.config().max_tokens, Some(2_048));
    assert!(call.adapter_defaults().unwrap().reasoning_effort);
    assert!(call.adapter_defaults().unwrap().max_tokens);
    assert_eq!(call.context_window(), Some(64_000));
    assert!(call.starts_request_series());
    assert!(call.prepared_llm_call().is_some());
    assert_eq!(session.request_header().unwrap(), None);
    assert_eq!(session.request_context().unwrap(), None);

    let mut fallback_ctx = mapped();
    let fallback_session = fallback_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("unregistered-agent-call").unwrap())
        .unwrap();
    fallback_session
        .inbox()
        .append_next_turn(user_message("fallback", "fallback"))
        .unwrap();
    let fallback_turn = fallback_session.start_turn().unwrap();
    let fallback_config = call_config("middleware-route", "model");
    let AgentCallAdmission::Call(fallback) = prepare_agent_call(
        &mut fallback_ctx,
        fallback_session.id(),
        AgentInboxTarget::NextTurn,
        fallback_turn,
        1,
        fallback_config.clone(),
    )
    .unwrap() else {
        panic!("middleware-served route still reaches the call boundary");
    };
    assert_eq!(fallback.config(), &fallback_config);
    assert!(fallback.prepared_llm_call().is_none());
    assert!(fallback.adapter_defaults().is_none());
    assert_eq!(fallback.context_window(), None);
}

#[test]
fn agent_call_skips_adapter_on_reject_and_rechecks_step_after_preparation() {
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut rejected_ctx = mapped();
    {
        let adapter_calls = Arc::clone(&adapter_calls);
        register_llm_adapter(
            &mut rejected_ctx,
            ["mock"],
            move |provider: &str, model: &str| {
                adapter_calls.fetch_add(1, Ordering::SeqCst);
                Ok(LlmResolvedModel::new(provider, model))
            },
        )
        .unwrap();
    }
    rejected_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| proposal.reject())
        .unwrap();
    let rejected_session = rejected_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("adapter-skipped").unwrap())
        .unwrap();
    rejected_session
        .inbox()
        .append_next_turn(user_message("reject", "reject"))
        .unwrap();
    let rejected_turn = rejected_session.start_turn().unwrap();
    assert!(matches!(
        prepare_agent_call(
            &mut rejected_ctx,
            rejected_session.id(),
            AgentInboxTarget::NextTurn,
            rejected_turn,
            1,
            call_config("mock", "model"),
        )
        .unwrap(),
        AgentCallAdmission::NoCall(proposal)
            if proposal.decision() == &AgentPreStepDecision::Reject
    ));
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);

    let mut moved_ctx = mapped();
    let moved_session = moved_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("adapter-moved-step").unwrap())
        .unwrap();
    moved_session
        .inbox()
        .append_next_turn(user_message("prompt", "prompt"))
        .unwrap();
    let moved_turn = moved_session.start_turn().unwrap();
    {
        let moved_session = moved_session.clone();
        register_llm_adapter(
            &mut moved_ctx,
            ["mock"],
            move |provider: &str, model: &str| {
                moved_session.finish_step(moved_turn, 1).unwrap();
                Ok(LlmResolvedModel::new(provider, model))
            },
        )
        .unwrap();
    }
    assert!(matches!(
        prepare_agent_call(
            &mut moved_ctx,
            moved_session.id(),
            AgentInboxTarget::NextTurn,
            moved_turn,
            1,
            call_config("mock", "model"),
        ),
        Err(CordisError::Session(SessionError::NoOpenStep { turn })) if turn == moved_turn
    ));
}

#[test]
fn agent_build_logs_effective_header_context_and_deduplicates() {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model)
            .with_context_window(64_000)
            .with_default_max_tokens(2_048)
            .with_reasoning(LlmModelReasoning::new(
                vec!["low".into()],
                Some("low".into()),
            )))
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("logged-agent-call").unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());

    let (turn, initial) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "initial",
        call_config("mock", "model"),
    );
    assert_eq!(
        initial.header_reason(),
        Some(SessionRequestHeaderReason::Initial)
    );
    assert!(initial.context_appended());
    assert_eq!(
        initial.call().config().reasoning_effort.as_deref(),
        Some("low")
    );
    assert_eq!(initial.call().config().max_tokens, Some(2_048));
    assert_eq!(initial.call().context_window(), Some(64_000));
    let header = session.request_header().unwrap().unwrap();
    assert_eq!(header.config, initial.call().config().clone());
    assert!(header.adapter_defaults.unwrap().reasoning_effort);
    assert_eq!(header.system, None);
    assert_eq!(header.tools, None);
    assert_eq!(
        session.request_context().unwrap().unwrap().context_window,
        Some(64_000)
    );
    close_logged_turn(&session, turn);

    let (turn, unchanged) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "unchanged",
        call_config("mock", "model"),
    );
    assert_eq!(unchanged.header_reason(), None);
    assert!(!unchanged.context_appended());
    close_logged_turn(&session, turn);

    let mut explicit = call_config("mock", "model");
    explicit.reasoning_effort = Some("low".into());
    explicit.max_tokens = Some(512);
    let (turn, changed) = build_logged_turn(&mut ctx, &session, &mut state, "changed", explicit);
    assert_eq!(
        changed.header_reason(),
        Some(SessionRequestHeaderReason::Change)
    );
    assert!(!changed.context_appended());
    assert_eq!(
        session.request_header().unwrap().unwrap().adapter_defaults,
        None
    );
    close_logged_turn(&session, turn);

    let events = session.events().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, SessionEventKind::RequestHeader { .. }))
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.kind, SessionEventKind::RequestContext { .. }))
            .count(),
        1
    );
}

#[test]
fn agent_build_preserves_series_change_and_resume_reasons() {
    let mut ctx = mapped();
    let pre_steps = Arc::new(AtomicUsize::new(0));
    {
        let pre_steps = Arc::clone(&pre_steps);
        ctx.on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
            let index = pre_steps.fetch_add(1, Ordering::SeqCst);
            let proposal = next(proposal);
            if index == 0 {
                proposal
            } else {
                proposal.with_starts_request_series()
            }
        })
        .unwrap();
    }
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(
            LlmResolvedModel::new(provider, model).with_context_window(if model == "wide" {
                128_000
            } else {
                64_000
            }),
        )
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-reasons").unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (turn, initial) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "initial",
        call_config("mock", "model"),
    );
    assert_eq!(
        initial.header_reason(),
        Some(SessionRequestHeaderReason::Initial)
    );
    close_logged_turn(&session, turn);

    let (turn, series) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "series",
        call_config("mock", "model"),
    );
    assert_eq!(
        series.header_reason(),
        Some(SessionRequestHeaderReason::Series)
    );
    assert!(!series.context_appended());
    close_logged_turn(&session, turn);

    let (turn, changed_series) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "wide",
        call_config("mock", "wide"),
    );
    assert_eq!(
        changed_series.header_reason(),
        Some(SessionRequestHeaderReason::Change)
    );
    assert!(changed_series.context_appended());
    assert_eq!(changed_series.call().context_window(), Some(128_000));
    assert!(matches!(
        session.events().unwrap().iter().rev().find_map(|event| {
            let SessionEventKind::RequestHeader { request } = &event.kind else {
                return None;
            };
            Some(request.clone())
        }),
        Some(request)
            if request.reason == SessionRequestHeaderReason::Change && request.starts_series
    ));
    close_logged_turn(&session, turn);

    let mut resumed = AgentRequestLogState::new(session.id().clone());
    let (turn, resume) = build_logged_turn(
        &mut ctx,
        &session,
        &mut resumed,
        "resume",
        call_config("mock", "wide"),
    );
    assert_eq!(
        resume.header_reason(),
        Some(SessionRequestHeaderReason::Resume)
    );
    assert!(!resume.context_appended());
    close_logged_turn(&session, turn);
}

#[test]
fn agent_build_turns_surface_replacement_into_a_series_boundary() {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model).with_context_window(64_000))
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("surface-series").unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (turn, initial) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "before-replace",
        call_config("mock", "model"),
    );
    assert_eq!(initial.call().request().surface_generation(), 0);
    let node = session.surface().unwrap().nodes[0];
    session
        .append_assistant_message_with_surface(
            turn,
            1,
            assistant_message("summary", "summary"),
            SessionSurfaceIntent::replace(node, node, vec![node]),
        )
        .unwrap();
    close_logged_turn(&session, turn);

    let (turn, series) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "after-replace",
        call_config("mock", "model"),
    );
    assert_eq!(series.call().request().surface_generation(), 1);
    assert_eq!(
        series.header_reason(),
        Some(SessionRequestHeaderReason::Series)
    );
    assert!(!series.context_appended());
    assert_eq!(state.surface_generation(), Some(1));
    close_logged_turn(&session, turn);
}

#[test]
fn agent_build_freezes_and_persists_prompt_tools_in_harness_order() {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model))
    })
    .unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("zulu", 10, "Zulu.")).unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("first", 0, "First.")).unwrap();
    register_prompt_section(&mut ctx, PromptSection::new("alpha", 10, "Alpha.")).unwrap();
    register_tool_schema(&mut ctx, tool_schema("zulu")).unwrap();
    register_tool_schema(&mut ctx, tool_schema("alpha")).unwrap();

    let order = Arc::new(Mutex::new(Vec::new()));
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(events::SYSTEM_PROMPT_ASSEMBLE, move |assembly, next| {
            order.lock().unwrap().push("assemble");
            next(assembly)
        })
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
            order.lock().unwrap().push("pre-step");
            next(proposal)
        })
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(events::AGENT_REQUEST, move |request, next| {
            order.lock().unwrap().push("request");
            next(request)
        })
        .unwrap();
    }

    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("prompt-tools").unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (turn, first) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "first-call",
        call_config("mock", "model"),
    );
    assert_eq!(*order.lock().unwrap(), ["assemble", "pre-step", "request"]);
    assert_eq!(
        first.call().assembly().system(),
        Some("First.\n\nAlpha.\n\nZulu.")
    );
    assert_eq!(
        first
            .call()
            .assembly()
            .tools()
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "zulu"]
    );
    let first_header = session.request_header().unwrap().unwrap();
    assert_eq!(
        first_header.system.as_deref(),
        Some("First.\n\nAlpha.\n\nZulu.")
    );
    assert_eq!(
        first_header.tools.as_ref().unwrap(),
        first.call().assembly().tools()
    );

    register_prompt_section(&mut ctx, PromptSection::new("later", 20, "Later.")).unwrap();
    register_tool_schema(&mut ctx, tool_schema("later")).unwrap();
    assert_eq!(
        first.call().assembly().system(),
        Some("First.\n\nAlpha.\n\nZulu.")
    );
    assert_eq!(first.call().assembly().tools().len(), 2);
    close_logged_turn(&session, turn);

    let (turn, changed) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "changed-call",
        call_config("mock", "model"),
    );
    assert_eq!(
        changed.header_reason(),
        Some(SessionRequestHeaderReason::Change)
    );
    assert_eq!(
        changed.call().assembly().system(),
        Some("First.\n\nAlpha.\n\nZulu.\n\nLater.")
    );
    assert_eq!(changed.call().assembly().tools().len(), 3);
    assert!(!changed.context_appended());
    close_logged_turn(&session, turn);
}

#[test]
fn invalid_prompt_assembly_stops_before_step_request_adapter_and_request_state() {
    let mut ctx = mapped();
    ctx.on_waterfall(events::SYSTEM_PROMPT_ASSEMBLE, |assembly, _next| {
        assembly.with_tools(vec![tool_schema("dup"), tool_schema("dup")])
    })
    .unwrap();
    let pre_steps = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let adapters = Arc::new(AtomicUsize::new(0));
    {
        let pre_steps = Arc::clone(&pre_steps);
        ctx.on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
            pre_steps.fetch_add(1, Ordering::SeqCst);
            next(proposal)
        })
        .unwrap();
    }
    {
        let requests = Arc::clone(&requests);
        ctx.on_waterfall(events::AGENT_REQUEST, move |request, next| {
            requests.fetch_add(1, Ordering::SeqCst);
            next(request)
        })
        .unwrap();
    }
    {
        let adapters = Arc::clone(&adapters);
        register_llm_adapter(&mut ctx, ["mock"], move |provider: &str, model: &str| {
            adapters.fetch_add(1, Ordering::SeqCst);
            Ok(LlmResolvedModel::new(provider, model))
        })
        .unwrap();
    }
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("invalid-prompt").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("prompt", "prompt"))
        .unwrap();
    let turn = session.start_turn().unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());

    assert_eq!(
        build_agent_call(
            &mut ctx,
            session.id(),
            AgentInboxTarget::NextTurn,
            turn,
            1,
            call_config("mock", "model"),
            &mut state,
        )
        .unwrap_err(),
        CordisError::Prompt(PromptError::DuplicateTool { name: "dup".into() })
    );
    assert_eq!(pre_steps.load(Ordering::SeqCst), 0);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(adapters.load(Ordering::SeqCst), 0);
    assert!(!state.header_logged());
    assert_eq!(state.surface_generation(), None);
    assert_eq!(session.request_header().unwrap(), None);
    assert_eq!(session.request_context().unwrap(), None);
    assert!(session.events().unwrap().iter().all(|event| !matches!(
        event.kind,
        SessionEventKind::StepStart { .. }
            | SessionEventKind::RequestHeader { .. }
            | SessionEventKind::RequestContext { .. }
    )));
}

#[test]
fn request_state_batch_is_atomic_and_reentry_safe() {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model).with_context_window(64_000))
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-state-batch").unwrap())
        .unwrap();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let complete_at_header = Arc::new(Mutex::new(false));
    let reentry_error = Arc::new(Mutex::new(None));
    {
        let observed = Arc::clone(&observed);
        let complete_at_header = Arc::clone(&complete_at_header);
        let reentry_error = Arc::clone(&reentry_error);
        let callback_session = session.clone();
        ctx.on_emit(session_events::SESSION_EVENT, move |record| {
            match &record.event.kind {
                SessionEventKind::RequestHeader { .. } => {
                    observed.lock().unwrap().push("header");
                    let events = callback_session.events().unwrap();
                    *complete_at_header.lock().unwrap() = matches!(
                        events[events.len() - 2..],
                        [
                            hartevo_cordis::SessionEvent {
                                kind: SessionEventKind::RequestHeader { .. },
                                ..
                            },
                            hartevo_cordis::SessionEvent {
                                kind: SessionEventKind::RequestContext { .. },
                                ..
                            },
                        ]
                    );
                    *reentry_error.lock().unwrap() = Some(
                        callback_session
                            .append_user_message(user_message("nested", "nested"))
                            .unwrap_err(),
                    );
                }
                SessionEventKind::RequestContext { .. } => {
                    observed.lock().unwrap().push("context");
                }
                _ => {}
            }
        })
        .unwrap();
    }
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (turn, logged) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "batch",
        call_config("mock", "model"),
    );
    assert_eq!(
        logged.header_reason(),
        Some(SessionRequestHeaderReason::Initial)
    );
    assert_eq!(*observed.lock().unwrap(), ["header", "context"]);
    assert!(*complete_at_header.lock().unwrap());
    assert_eq!(
        *reentry_error.lock().unwrap(),
        Some(SessionError::AppendInProgress {
            id: session.id().clone(),
        })
    );
    close_logged_turn(&session, turn);
}

#[test]
fn stale_request_state_logging_preserves_events_and_state() {
    let mut ctx = mapped();
    register_llm_adapter(&mut ctx, ["mock"], |provider: &str, model: &str| {
        Ok(LlmResolvedModel::new(provider, model).with_context_window(64_000))
    })
    .unwrap();
    let stale_session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-state-stale").unwrap())
        .unwrap();
    stale_session
        .inbox()
        .append_next_turn(user_message("stale", "stale"))
        .unwrap();
    let stale_turn = stale_session.start_turn().unwrap();
    let AgentCallAdmission::Call(stale_call) = prepare_agent_call(
        &mut ctx,
        stale_session.id(),
        AgentInboxTarget::NextTurn,
        stale_turn,
        1,
        call_config("mock", "model"),
    )
    .unwrap() else {
        panic!("stale fixture must prepare a call");
    };
    stale_session.finish_step(stale_turn, 1).unwrap();
    let mut stale_state = AgentRequestLogState::new(stale_session.id().clone());
    assert!(matches!(
        log_agent_call(&ctx, &mut stale_state, stale_call),
        Err(CordisError::Session(SessionError::NoOpenStep { turn })) if turn == stale_turn
    ));
    assert!(!stale_state.header_logged());
    assert_eq!(stale_state.surface_generation(), None);
    assert_eq!(stale_session.request_header().unwrap(), None);
    assert_eq!(stale_session.request_context().unwrap(), None);
}

#[test]
fn request_log_state_mismatch_and_no_call_never_touch_the_adapter_or_state() {
    let adapter_calls = Arc::new(AtomicUsize::new(0));
    let mut ctx = mapped();
    {
        let adapter_calls = Arc::clone(&adapter_calls);
        register_llm_adapter(&mut ctx, ["mock"], move |provider: &str, model: &str| {
            adapter_calls.fetch_add(1, Ordering::SeqCst);
            Ok(LlmResolvedModel::new(provider, model))
        })
        .unwrap();
    }
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-state-owner").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("mismatch", "mismatch"))
        .unwrap();
    let turn = session.start_turn().unwrap();
    let mut wrong_state = AgentRequestLogState::new(SessionId::new("different-session").unwrap());
    assert_eq!(
        build_agent_call(
            &mut ctx,
            session.id(),
            AgentInboxTarget::NextTurn,
            turn,
            1,
            call_config("mock", "model"),
            &mut wrong_state,
        )
        .unwrap_err(),
        CordisError::Session(SessionError::RequestLogStateSessionMismatch {
            expected: SessionId::new("different-session").unwrap(),
            actual: session.id().clone(),
        })
    );
    assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    assert!(!wrong_state.header_logged());
    assert!(session.inbox().has_pending().unwrap());
    assert!(session.events().unwrap().iter().all(|event| !matches!(
        event.kind,
        SessionEventKind::StepStart { .. }
            | SessionEventKind::RequestHeader { .. }
            | SessionEventKind::RequestContext { .. }
    )));

    let mut rejected_ctx = mapped();
    rejected_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| proposal.reject())
        .unwrap();
    let rejected_session = rejected_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("request-state-reject").unwrap())
        .unwrap();
    rejected_session
        .inbox()
        .append_next_turn(user_message("reject", "reject"))
        .unwrap();
    let rejected_turn = rejected_session.start_turn().unwrap();
    let mut rejected_state = AgentRequestLogState::new(rejected_session.id().clone());
    assert!(matches!(
        build_agent_call(
            &mut rejected_ctx,
            rejected_session.id(),
            AgentInboxTarget::NextTurn,
            rejected_turn,
            1,
            call_config("missing", "model"),
            &mut rejected_state,
        )
        .unwrap(),
        AgentBuildAdmission::NoCall(proposal)
            if proposal.decision() == &AgentPreStepDecision::Reject
    ));
    assert!(!rejected_state.header_logged());
    assert_eq!(rejected_state.surface_generation(), None);
    assert_eq!(rejected_session.request_header().unwrap(), None);
    assert_eq!(rejected_session.request_context().unwrap(), None);
}

#[test]
fn logged_agent_call_dispatches_exact_request_without_session_writes() {
    let mut ctx = mapped();
    register_prompt_section(
        &mut ctx,
        PromptSection::new("core", 0, "Follow the durable plan."),
    )
    .unwrap();
    register_tool_schema(&mut ctx, tool_schema("search")).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    register_llm_adapter(
        &mut ctx,
        ["mock"],
        AgentStreamingAdapter {
            seen: Arc::clone(&seen),
        },
    )
    .unwrap();
    let waterfall_calls = Arc::new(AtomicUsize::new(0));
    {
        let waterfall_calls = Arc::clone(&waterfall_calls);
        ctx.on_waterfall(events::LLM_STREAM, move |stream, next| {
            waterfall_calls.fetch_add(1, Ordering::SeqCst);
            assert!(stream.request().is_some());
            next(stream)
        })
        .unwrap();
    }

    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("stream-dispatch").unwrap())
        .unwrap();
    let mut state = AgentRequestLogState::new(session.id().clone());
    let (_turn, logged) = build_logged_turn(
        &mut ctx,
        &session,
        &mut state,
        "request-1",
        call_config("mock", "model"),
    );
    let before = session.events().unwrap();
    let chunks = ready_chunks(dispatch_agent_call(&mut ctx, &logged).unwrap());
    assert!(matches!(
        chunks.as_slice(),
        [SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            ..
        }]
    ));
    assert_eq!(waterfall_calls.load(Ordering::SeqCst), 1);
    let requests = seen.lock().expect("seen");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.config().provider, "mock");
    assert_eq!(request.config().model, "model");
    assert_eq!(request.config().max_tokens, Some(512));
    assert_eq!(request.messages(), [user_message("request-1", "request-1")]);
    assert_eq!(request.system(), Some("Follow the durable plan."));
    assert_eq!(
        request.tools(),
        Some(std::slice::from_ref(&tool_schema("search")))
    );
    assert_eq!(request.session_id(), Some(session.id()));
    drop(requests);
    assert_eq!(session.events().unwrap(), before);

    let error = dispatch_agent_call(&mut ctx, &logged)
        .err()
        .expect("prepared logged call must be one-shot");
    assert_eq!(
        error,
        CordisError::Llm(LlmError::InvalidPreparedCall {
            expected: "one dispatch only",
        })
    );
    assert_eq!(waterfall_calls.load(Ordering::SeqCst), 1);

    let stale_session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("stale-stream-dispatch").unwrap())
        .unwrap();
    let mut stale_state = AgentRequestLogState::new(stale_session.id().clone());
    let (stale_turn, stale_call) = build_logged_turn(
        &mut ctx,
        &stale_session,
        &mut stale_state,
        "stale-request",
        call_config("mock", "model"),
    );
    stale_session.finish_step(stale_turn, 1).unwrap();
    let stale_events = stale_session.events().unwrap();
    assert!(matches!(
        dispatch_agent_call(&mut ctx, &stale_call),
        Err(CordisError::Session(SessionError::NoOpenStep { turn }))
            if turn == stale_turn
    ));
    assert_eq!(waterfall_calls.load(Ordering::SeqCst), 1);
    assert_eq!(seen.lock().expect("seen").len(), 1);
    assert_eq!(stale_session.events().unwrap(), stale_events);
}

#[test]
fn recorded_agent_stream_validates_and_persists_exact_chunk_order() {
    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Reasoning,
        },
        SessionStreamChunk::BlockStart {
            index: 1,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::ReasoningDelta {
            index: 0,
            text: "plan".into(),
        },
        SessionStreamChunk::TextDelta {
            index: 1,
            text: "answer".into(),
        },
        SessionStreamChunk::BlockStart {
            index: 2,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::ToolCallDelta {
            index: 2,
            id: "call-1".into(),
            name: Some("search".into()),
            arguments_delta: "{\"q\":\"rust\"}".into(),
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Reasoning {
                text: "plan".into(),
            },
        },
        SessionStreamChunk::BlockEnd {
            index: 1,
            block: SessionContentBlock::Text {
                text: "answer".into(),
            },
        },
        SessionStreamChunk::BlockEnd {
            index: 2,
            block: SessionContentBlock::ToolCall {
                id: "call-1".into(),
                name: "search".into(),
                arguments: "{\"q\":\"rust\"}".into(),
            },
        },
        usage(),
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::ToolCalls,
            replay_state: None,
        },
    ];
    let (session, turn, result) = record_script("record-valid-stream", ok_chunks(chunks.clone()));
    let recorded = result.unwrap();
    let stored = session.assistant_chunks(turn, 1).unwrap();

    assert_eq!(recorded.turn(), turn);
    assert_eq!(recorded.step(), 1);
    assert_eq!(recorded.finish(), &SessionFinishReason::ToolCalls);
    assert_eq!(
        recorded.chunk_seqs(),
        stored.iter().map(|record| record.seq).collect::<Vec<_>>()
    );
    assert_eq!(
        stored
            .iter()
            .map(|record| record.chunk.clone())
            .collect::<Vec<_>>(),
        chunks
    );
    assert!(
        !session
            .events()
            .unwrap()
            .iter()
            .any(|event| matches!(event.kind, SessionEventKind::AssistantMessage { .. }))
    );
    close_logged_turn(&session, turn);
}

#[test]
fn normalized_terminal_failures_persist_after_valid_partial_blocks() {
    for (session_id, failure, expected) in [
        (
            "record-error-stream",
            SessionLlmFailure {
                message: "connection reset".into(),
                code: "NETWORK".into(),
                status: None,
                provider_retry_after_ms: None,
                request_id: Some("req-error".into()),
            },
            "error",
        ),
        (
            "record-aborted-stream",
            SessionLlmFailure {
                message: "cancelled".into(),
                code: "ABORTED".into(),
                status: None,
                provider_retry_after_ms: None,
                request_id: Some("req-aborted".into()),
            },
            "aborted",
        ),
    ] {
        let (session, turn, result) = record_script(
            session_id,
            vec![
                Ok(SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                }),
                Ok(SessionStreamChunk::TextDelta {
                    index: 0,
                    text: "partial".into(),
                }),
                Err(failure.clone()),
                Ok(SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "must not escape normalization".into(),
                    },
                }),
            ],
        );
        let recorded = result.unwrap();
        match (expected, recorded.finish()) {
            ("error", SessionFinishReason::Error { failure: actual })
            | ("aborted", SessionFinishReason::Aborted { failure: actual }) => {
                assert_eq!(actual, &failure);
            }
            _ => panic!("normalized failure must keep its terminal class"),
        }
        let stored = session.assistant_chunks(turn, 1).unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(recorded.chunk_seqs().len(), 3);
        assert!(matches!(
            stored.last().map(|record| &record.chunk),
            Some(SessionStreamChunk::Finish { .. })
        ));
        session.finish_step(turn, 1).unwrap();
        session.finish_turn(turn, TurnEndReason::Error).unwrap();
    }
}

#[test]
fn recorded_agent_stream_rejects_invalid_block_grammar_before_append() {
    assert_protocol_rejected(
        "stream-index-range",
        vec![SessionStreamChunk::BlockStart {
            index: 9_007_199_254_740_992,
            block_type: SessionStreamBlockType::Text,
        }],
        "block indexes within the non-negative JavaScript safe-integer range",
        0,
    );
    assert_protocol_rejected(
        "stream-repeat-open",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
        ],
        "one open block per index",
        1,
    );
    assert_protocol_rejected(
        "stream-text-without-open",
        vec![SessionStreamChunk::TextDelta {
            index: 0,
            text: "orphan".into(),
        }],
        "each delta to target an open block of its matching type",
        0,
    );
    assert_protocol_rejected(
        "stream-reasoning-mismatch",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::ReasoningDelta {
                index: 0,
                text: "wrong".into(),
            },
        ],
        "each delta to target an open block of its matching type",
        1,
    );
    assert_protocol_rejected(
        "stream-tool-mismatch",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::ToolCallDelta {
                index: 0,
                id: "call-1".into(),
                name: Some("search".into()),
                arguments_delta: "{}".into(),
            },
        ],
        "each delta to target an open block of its matching type",
        1,
    );
    assert_protocol_rejected(
        "stream-end-without-open",
        vec![SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text {
                text: "orphan".into(),
            },
        }],
        "block-end to target an open block",
        0,
    );
    assert_protocol_rejected(
        "stream-end-type-mismatch",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Reasoning {
                    text: "wrong".into(),
                },
            },
        ],
        "block-end content to match its open block type",
        1,
    );
}

#[test]
fn recorded_agent_stream_rejects_invalid_terminal_grammar_before_append() {
    assert_protocol_rejected(
        "stream-duplicate-usage",
        vec![usage(), usage()],
        "at most one usage chunk before finish",
        1,
    );
    assert_protocol_rejected(
        "stream-success-with-open-block",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
        ],
        "successful finish to close every open block",
        1,
    );
    assert_protocol_rejected(
        "stream-missing-finish",
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::TextDelta {
                index: 0,
                text: "complete prefix".into(),
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Text {
                    text: "complete prefix".into(),
                },
            },
        ],
        "exactly one terminal finish chunk",
        3,
    );
    assert_protocol_rejected(
        "stream-after-finish",
        vec![
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
            usage(),
        ],
        "no chunks after one terminal finish",
        1,
    );
}

#[test]
fn pre_step_wrappers_replace_messages_without_losing_request_series() {
    let mut ctx = mapped();
    let replacement = user_message("replacement", "rewritten");
    {
        let replacement = replacement.clone();
        ctx.on_waterfall(events::AGENT_PRE_STEP, move |proposal, next| {
            next(proposal).replace_messages(vec![replacement.clone()])
        })
        .unwrap();
    }
    ctx.on_waterfall(events::AGENT_PRE_STEP, |proposal, next| {
        next(proposal).with_starts_request_series()
    })
    .unwrap();
    let session = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("pre-step-rewrite").unwrap())
        .unwrap();
    session
        .inbox()
        .append_next_turn(user_message("original", "original"))
        .unwrap();
    let turn = session.start_turn().unwrap();

    let proposal =
        prepare_agent_step(&mut ctx, session.id(), AgentInboxTarget::NextTurn, turn, 1).unwrap();

    assert_eq!(proposal.agent(), &AgentRef::new("pre-step-rewrite"));
    assert_eq!(proposal.turn(), turn);
    assert_eq!(proposal.step(), 1);
    assert_eq!(
        proposal.into_decision(),
        AgentPreStepDecision::Enter {
            messages: vec![replacement],
            starts_request_series: true,
        }
    );
}

#[test]
fn pre_step_rejects_or_invalidates_after_claim_without_opening_a_step() {
    let mut rejected_ctx = mapped();
    rejected_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| proposal.reject())
        .unwrap();
    let rejected_session = rejected_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("pre-step-rejected").unwrap())
        .unwrap();
    rejected_session
        .inbox()
        .append_next_turn(user_message("rejected", "rejected"))
        .unwrap();
    let rejected_turn = rejected_session.start_turn().unwrap();
    let rejected = admit_agent_step(
        &mut rejected_ctx,
        rejected_session.id(),
        AgentInboxTarget::NextTurn,
        rejected_turn,
        1,
    )
    .unwrap();
    assert_eq!(rejected.decision(), &AgentPreStepDecision::Reject);
    assert!(!rejected_session.inbox().has_pending().unwrap());
    assert!(
        !rejected_session
            .events()
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                SessionEventKind::StepStart { .. } | SessionEventKind::UserMessage { .. }
            ))
    );

    let mut invalid_ctx = mapped();
    invalid_ctx
        .on_waterfall(events::AGENT_PRE_STEP, |proposal, _next| {
            proposal.replace_messages(vec![SessionMessage {
                id: "invalid-assistant".into(),
                role: SessionMessageRole::Assistant,
                content: vec![SessionContentBlock::Text {
                    text: "invalid".into(),
                }],
                source: SessionMessageSource::User,
            }])
        })
        .unwrap();
    let invalid_session = invalid_ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("pre-step-invalid").unwrap())
        .unwrap();
    invalid_session
        .inbox()
        .append_next_turn(user_message("valid", "valid"))
        .unwrap();
    let invalid_turn = invalid_session.start_turn().unwrap();
    assert_eq!(
        admit_agent_step(
            &mut invalid_ctx,
            invalid_session.id(),
            AgentInboxTarget::NextTurn,
            invalid_turn,
            1,
        ),
        Err(CordisError::Session(SessionError::UnexpectedMessageRole {
            event_type: "agent/pre-step",
            expected: SessionMessageRole::User,
            actual: SessionMessageRole::Assistant,
        }))
    );
    assert!(!invalid_session.inbox().has_pending().unwrap());
    assert!(
        !invalid_session
            .events()
            .unwrap()
            .iter()
            .any(|event| matches!(
                event.kind,
                SessionEventKind::StepStart { .. } | SessionEventKind::UserMessage { .. }
            ))
    );
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
            keys::SYSTEM_PROMPT.to_string(),
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
            keys::SYSTEM_PROMPT.to_string(),
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
            keys::SYSTEM_PROMPT.to_string(),
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
