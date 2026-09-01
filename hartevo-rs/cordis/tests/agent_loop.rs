use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context as TaskContext, Poll};

use chrono::{Duration, TimeZone, Utc};
use futures_util::FutureExt;
use hartevo_cordis::{
    AgentBuildAdmission, AgentCallAdmission, AgentInboxTarget, AgentLoop, AgentPreStepDecision,
    AgentRef, AgentRequestAdmission, AgentRequestLogState, AgentStep, Context, CordisError,
    CordisHost, DomainSurface, EffectBrokerSurface, EnvironmentOverlay, KernelApproval,
    KernelApprovalDecision, KernelConsentState, LifecycleCancellation, LlmAdapter,
    LlmAdapterStream, LlmChunkStream, LlmError, LlmGenerateRequest, LlmModelReasoning,
    LlmResolvedModel, LlmStream, LoaderContext, LoggedAgentCall, PromptError, PromptSection,
    RecordedAgentStream, RuntimeSurface, SessionCallConfig, SessionContentBlock, SessionError,
    SessionEventKind, SessionFinishReason, SessionHandle, SessionId, SessionLlmFailure,
    SessionMessage, SessionMessageRole, SessionMessageSource, SessionReplayEnvelope,
    SessionRequestHeaderReason, SessionStore, SessionStreamBlockType, SessionStreamChunk,
    SessionSurfaceIntent, SessionTokenUsage, SessionToolSchema, SurfaceOwner,
    TOOL_ABORTED_BEFORE_DISPATCH, ToolCall, ToolDefinition, ToolDispatchExecution,
    ToolDispatchResult, ToolExecutionMode, ToolExecutionPreparation, ToolExecutionResult,
    ToolPostExecution, ToolRunContext, ToolsSurface, TurnEndReason, admit_agent_request,
    admit_agent_step, build_agent_call, commit_agent_stream, commit_agent_tool_results,
    dispatch_agent_call, dispatch_tool_execution, events, finalize_tool_execution, keys,
    log_agent_call, post_tool_execution, prepare_agent_call, prepare_agent_step,
    prepare_agent_tool_calls, prepare_agent_tool_executions, record_agent_stream,
    register_llm_adapter, register_prompt_section, register_tool, register_tool_concurrency,
    register_tool_definition, register_tool_guard, register_tool_schema, run_agent_step,
    run_agent_tool_batch, run_agent_tool_batch_with_limit,
    run_agent_tool_batch_with_limit_and_cancellation, schedule_agent_tool_calls, session_events,
};
use serde_json::json;

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

fn plugin_message(id: &str, plugin: &str, text: &str) -> SessionMessage {
    SessionMessage {
        id: id.into(),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: text.into() }],
        source: SessionMessageSource::Plugin {
            plugin: plugin.into(),
        },
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

fn tool_call_chunks(index: u64, id: &str, name: &str, arguments: &str) -> [SessionStreamChunk; 2] {
    [
        SessionStreamChunk::BlockStart {
            index,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index,
            block: SessionContentBlock::ToolCall {
                id: id.into(),
                name: name.into(),
                arguments: arguments.into(),
            },
        },
    ]
}

fn finalize_scheduled_tools(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &RecordedAgentStream,
) -> Vec<ToolExecutionResult> {
    prepare_agent_tool_executions(ctx, logged, recorded)
        .unwrap()
        .into_iter()
        .map(|preparation| {
            let ToolExecutionPreparation::Dispatch(prepared) = preparation else {
                panic!("test tool must be admitted for dispatch");
            };
            let dispatched = dispatch_tool_execution(ctx, prepared).unwrap();
            let post = post_tool_execution(ctx, dispatched).unwrap();
            finalize_tool_execution(ctx, post)
        })
        .collect()
}

fn durable_tool_result_message(
    session_id: &str,
    turn: u64,
    step: u64,
    result: &ToolExecutionResult,
) -> SessionMessage {
    SessionMessage {
        id: format!(
            "{session_id}:turn:{turn}:step:{step}:tool-result:{}",
            result.input().call_seq()
        ),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::ToolResult {
            tool_call_id: result.input().call_id().into(),
            content: result.content().to_vec(),
            is_error: result.is_error(),
        }],
        source: SessionMessageSource::Tool {
            call_id: result.input().call_id().into(),
        },
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

fn recorded_script(
    session_id: &str,
    chunks: Vec<SessionStreamChunk>,
) -> (
    Context,
    SessionHandle,
    u64,
    LoggedAgentCall,
    RecordedAgentStream,
) {
    recorded_items_script(session_id, ok_chunks(chunks))
}

fn recorded_items_script(
    session_id: &str,
    items: Vec<Result<SessionStreamChunk, SessionLlmFailure>>,
) -> (
    Context,
    SessionHandle,
    u64,
    LoggedAgentCall,
    RecordedAgentStream,
) {
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
    let recorded = ready_record_agent_stream(&mut ctx, &logged).unwrap();
    (ctx, session, turn, logged, recorded)
}

fn ok_chunks(
    chunks: Vec<SessionStreamChunk>,
) -> Vec<Result<SessionStreamChunk, SessionLlmFailure>> {
    chunks.into_iter().map(Ok).collect()
}

fn usage() -> SessionStreamChunk {
    SessionStreamChunk::Usage {
        usage: token_usage(),
    }
}

fn token_usage() -> SessionTokenUsage {
    SessionTokenUsage {
        input_tokens: 2,
        output_tokens: 3,
        total_tokens: Some(5),
        cache_read_tokens: None,
        cache_write_tokens: None,
        reasoning_tokens: Some(1),
    }
}

fn replay_state(response_id: &str, blocks: &[&str]) -> SessionReplayEnvelope {
    SessionReplayEnvelope {
        response: serde_json::json!({ "responseId": response_id }),
        blocks: Some(
            blocks
                .iter()
                .map(|block| serde_json::json!(block))
                .collect(),
        ),
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
    assert_eq!(recorded.session_id(), session.id());
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
fn committed_agent_stream_assembles_authoritative_blocks_and_exact_provenance() {
    let replay = replay_state("response-1", &["reasoning", "text", "tool"]);
    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 9,
            block_type: SessionStreamBlockType::Reasoning,
        },
        SessionStreamChunk::BlockStart {
            index: 2,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::ReasoningDelta {
            index: 9,
            text: "draft plan".into(),
        },
        SessionStreamChunk::TextDelta {
            index: 2,
            text: "draft answer".into(),
        },
        SessionStreamChunk::BlockEnd {
            index: 2,
            block: SessionContentBlock::Text {
                text: "authoritative answer".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 7,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::ToolCallDelta {
            index: 7,
            id: "call-7".into(),
            name: Some("search".into()),
            arguments_delta: "{\"q\":\"rust\"}".into(),
        },
        SessionStreamChunk::BlockEnd {
            index: 7,
            block: SessionContentBlock::ToolCall {
                id: "call-7".into(),
                name: "search".into(),
                arguments: "{\"q\":\"rust\"}".into(),
            },
        },
        SessionStreamChunk::BlockEnd {
            index: 9,
            block: SessionContentBlock::Reasoning {
                text: "authoritative plan".into(),
            },
        },
        usage(),
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::ToolCalls,
            replay_state: Some(replay.clone()),
        },
    ];
    let (ctx, session, turn, logged, mut recorded) = recorded_script("commit-assembled", chunks);
    let source_seqs = recorded.chunk_seqs().to_vec();

    let committed = commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let message = committed.message().expect("successful finish commits");

    assert_eq!(
        message.content,
        [
            SessionContentBlock::Reasoning {
                text: "authoritative plan".into(),
            },
            SessionContentBlock::Text {
                text: "authoritative answer".into(),
            },
            SessionContentBlock::ToolCall {
                id: "call-7".into(),
                name: "search".into(),
                arguments: "{\"q\":\"rust\"}".into(),
            },
        ]
    );
    assert_eq!(
        message.source,
        SessionMessageSource::Model {
            provider: "mock".into(),
            model: "model".into(),
        }
    );
    assert_eq!(committed.finish(), &SessionFinishReason::ToolCalls);
    assert_eq!(committed.replay_state(), Some(&replay));
    assert_eq!(committed.usage(), Some(&token_usage()));
    assert!(recorded.message_committed());
    let events = session.events().unwrap();
    let SessionEventKind::AssistantMessage {
        message: durable,
        surface,
        ..
    } = &events.last().expect("assistant event").kind
    else {
        panic!("last event must be the committed assistant message");
    };
    assert_eq!(durable, message);
    assert_eq!(surface, &SessionSurfaceIntent::append_from(source_seqs));
    close_logged_turn(&session, turn);
}

#[test]
fn max_token_commit_drops_tool_calls_and_prunes_replay_in_lockstep() {
    let replay = replay_state("max-1", &["text-meta", "tool-meta", "reasoning-meta"]);
    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text {
                text: "partial".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 1,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 1,
            block: SessionContentBlock::ToolCall {
                id: "call-1".into(),
                name: "unsafe".into(),
                arguments: "{\"open\":".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 2,
            block_type: SessionStreamBlockType::Reasoning,
        },
        SessionStreamChunk::BlockEnd {
            index: 2,
            block: SessionContentBlock::Reasoning {
                text: "tail".into(),
            },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::MaxTokens,
            replay_state: Some(replay),
        },
    ];
    let (ctx, session, turn, logged, mut recorded) = recorded_script("commit-max", chunks);

    let committed = commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();

    assert_eq!(
        committed.message().unwrap().content,
        [
            SessionContentBlock::Text {
                text: "partial".into(),
            },
            SessionContentBlock::Reasoning {
                text: "tail".into(),
            },
        ]
    );
    assert_eq!(
        committed.replay_state(),
        Some(&replay_state("max-1", &["text-meta", "reasoning-meta"]))
    );
    close_logged_turn(&session, turn);
}

#[test]
fn empty_success_commits_once_and_stays_out_of_derived_history() {
    let chunks = vec![SessionStreamChunk::Finish {
        reason: SessionFinishReason::Stop,
        replay_state: None,
    }];
    let (ctx, session, turn, logged, mut recorded) = recorded_script("commit-empty", chunks);
    let source_seqs = recorded.chunk_seqs().to_vec();

    let committed = commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();

    assert_eq!(committed.message().unwrap().content, []);
    assert!(
        session
            .derive_messages()
            .unwrap()
            .iter()
            .all(|message| message.id != committed.message().unwrap().id)
    );
    let before_repeat = session.events().unwrap();
    assert_eq!(
        commit_agent_stream(&ctx, &logged, &mut recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "one assistant-message commit per recorded stream",
        }))
    );
    assert_eq!(session.events().unwrap(), before_repeat);
    let SessionEventKind::AssistantMessage { surface, .. } =
        &before_repeat.last().expect("assistant event").kind
    else {
        panic!("empty successful content still owns a durable assistant event");
    };
    assert_eq!(surface, &SessionSurfaceIntent::append_from(source_seqs));
    close_logged_turn(&session, turn);
}

#[test]
fn failed_stream_returns_usage_without_fabricating_an_assistant_message() {
    let failure = SessionLlmFailure {
        message: "upstream unavailable".into(),
        code: "UPSTREAM".into(),
        status: Some(503),
        provider_retry_after_ms: Some(50),
        request_id: Some("request-failed".into()),
    };
    let items = vec![
        Ok(SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        }),
        Ok(SessionStreamChunk::TextDelta {
            index: 0,
            text: "partial".into(),
        }),
        Ok(usage()),
        Err(failure.clone()),
    ];
    let (ctx, session, turn, logged, mut recorded) = recorded_items_script("commit-failure", items);

    let committed = commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();

    assert!(committed.message().is_none());
    assert_eq!(committed.finish(), &SessionFinishReason::Error { failure });
    assert!(committed.usage().is_some());
    assert!(!recorded.message_committed());
    assert!(
        session
            .events()
            .unwrap()
            .iter()
            .all(|event| !matches!(event.kind, SessionEventKind::AssistantMessage { .. }))
    );
    session.finish_step(turn, 1).unwrap();
    session.finish_turn(turn, TurnEndReason::Error).unwrap();
}

#[test]
fn commit_omits_misaligned_replay_and_rejects_foreign_recorded_sequences() {
    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::Text { text: "one".into() },
        },
        SessionStreamChunk::BlockStart {
            index: 1,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 1,
            block: SessionContentBlock::Text { text: "two".into() },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: Some(replay_state("misaligned", &["only-one"])),
        },
    ];
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("commit-replay-mismatch", chunks);
    let committed = commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    assert!(committed.replay_state().is_none());
    assert_eq!(committed.message().unwrap().content.len(), 2);
    close_logged_turn(&session, turn);

    let foreign = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("commit-foreign").unwrap())
        .unwrap();
    let mut foreign_state = AgentRequestLogState::new(foreign.id().clone());
    let (_foreign_turn, foreign_logged) = build_logged_turn(
        &mut ctx,
        &foreign,
        &mut foreign_state,
        "foreign-request",
        call_config("mock", "model"),
    );
    let mut source_recorded = recorded_script(
        "commit-source",
        vec![SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        }],
    )
    .4;
    assert_eq!(
        commit_agent_stream(&ctx, &foreign_logged, &mut source_recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "recorded session, turn, and step to match the logged call",
        }))
    );
    assert!(
        foreign
            .events()
            .unwrap()
            .iter()
            .all(|event| !matches!(event.kind, SessionEventKind::AssistantMessage { .. }))
    );
}

#[test]
fn scheduled_tool_calls_preserve_model_order_raw_arguments_and_durable_sequences() {
    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 7,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 7,
            block: SessionContentBlock::ToolCall {
                id: "call-first".into(),
                name: "search".into(),
                arguments: "{broken".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 1,
            block_type: SessionStreamBlockType::Text,
        },
        SessionStreamChunk::BlockEnd {
            index: 1,
            block: SessionContentBlock::Text {
                text: "working".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 3,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 3,
            block: SessionContentBlock::ToolCall {
                id: "call-second".into(),
                name: "write".into(),
                arguments: String::new(),
            },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::ToolCalls,
            replay_state: None,
        },
    ];
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("schedule-ordered", chunks);
    let executions = Arc::new(AtomicUsize::new(0));
    {
        let executions = Arc::clone(&executions);
        ctx.on_waterfall(
            events::TOOLS_EXECUTE,
            move |call: ToolDispatchExecution, next| {
                executions.fetch_add(1, Ordering::SeqCst);
                next(call)
            },
        )
        .unwrap();
    }
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let history_before = session.derive_messages().unwrap();

    let scheduled = schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    assert_eq!(scheduled.len(), 2);
    assert_eq!(scheduled[0].call_id, "call-first");
    assert_eq!(scheduled[0].name, "search");
    assert_eq!(scheduled[0].arguments, "{broken");
    assert_eq!(scheduled[1].call_id, "call-second");
    assert_eq!(scheduled[1].name, "write");
    assert_eq!(scheduled[1].arguments, "");
    assert_eq!(
        recorded.tool_call_seqs(),
        scheduled.iter().map(|call| call.seq).collect::<Vec<_>>()
    );
    assert!(recorded.tool_calls_scheduled());
    assert_eq!(session.tool_calls(turn, 1).unwrap(), scheduled);
    assert_eq!(session.derive_messages().unwrap(), history_before);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
    assert!(
        session
            .events()
            .unwrap()
            .iter()
            .all(|event| !matches!(event.kind, SessionEventKind::ToolResult { .. }))
    );
    close_logged_turn(&session, turn);
}

#[test]
fn zero_call_scheduling_is_one_shot_without_new_session_events() {
    let (ctx, session, turn, logged, mut recorded) = recorded_script(
        "schedule-empty",
        vec![SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            replay_state: None,
        }],
    );
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let before = session.events().unwrap();

    assert_eq!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap(),
        []
    );
    assert!(recorded.tool_calls_scheduled());
    assert!(recorded.tool_call_seqs().is_empty());
    assert_eq!(session.events().unwrap(), before);
    assert_eq!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "one tool-call scheduling pass per recorded stream",
        }))
    );
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn scheduling_rejects_duplicate_ids_and_preexisting_calls_before_mutation() {
    let duplicate_chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::ToolCall {
                id: "duplicate".into(),
                name: "first".into(),
                arguments: "{}".into(),
            },
        },
        SessionStreamChunk::BlockStart {
            index: 1,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 1,
            block: SessionContentBlock::ToolCall {
                id: "duplicate".into(),
                name: "second".into(),
                arguments: "[]".into(),
            },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::ToolCalls,
            replay_state: None,
        },
    ];
    let (ctx, session, turn, logged, mut recorded) =
        recorded_script("schedule-duplicate", duplicate_chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let before = session.events().unwrap();
    assert_eq!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "unique tool-call ids within one assistant message",
        }))
    );
    assert_eq!(session.events().unwrap(), before);
    assert!(!recorded.tool_calls_scheduled());
    assert!(recorded.tool_call_seqs().is_empty());
    close_logged_turn(&session, turn);

    let chunks = vec![
        SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::ToolCall,
        },
        SessionStreamChunk::BlockEnd {
            index: 0,
            block: SessionContentBlock::ToolCall {
                id: "model-call".into(),
                name: "search".into(),
                arguments: "{}".into(),
            },
        },
        SessionStreamChunk::Finish {
            reason: SessionFinishReason::ToolCalls,
            replay_state: None,
        },
    ];
    let (ctx, session, turn, logged, mut recorded) =
        recorded_script("schedule-preexisting", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    session
        .append_tool_call(turn, 1, "foreign-call", "foreign", "raw")
        .unwrap();
    let before = session.events().unwrap();
    assert_eq!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "only this scheduling pass's exact durable tool-call prefix",
        }))
    );
    assert_eq!(session.events().unwrap(), before);
    assert!(!recorded.tool_calls_scheduled());
    assert!(recorded.tool_call_seqs().is_empty());
    close_logged_turn(&session, turn);
}

#[test]
fn scheduling_fails_closed_without_commit_on_closed_step_or_foreign_call() {
    let chunks = vec![SessionStreamChunk::Finish {
        reason: SessionFinishReason::Stop,
        replay_state: None,
    }];
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("schedule-boundaries", chunks.clone());
    let before = session.events().unwrap();
    assert_eq!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "a committed assistant message before tool-call scheduling",
        }))
    );
    assert_eq!(session.events().unwrap(), before);

    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    session.finish_step(turn, 1).unwrap();
    let before_closed = session.events().unwrap();
    assert!(matches!(
        schedule_agent_tool_calls(&ctx, &logged, &mut recorded),
        Err(CordisError::Session(SessionError::NoOpenStep { turn: actual }))
            if actual == turn
    ));
    assert_eq!(session.events().unwrap(), before_closed);
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();

    let source = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("schedule-source").unwrap())
        .unwrap();
    let mut source_state = AgentRequestLogState::new(source.id().clone());
    let (source_turn, source_logged) = build_logged_turn(
        &mut ctx,
        &source,
        &mut source_state,
        "source-request",
        call_config("mock", "model"),
    );
    let mut source_recorded = ready_record_agent_stream(&mut ctx, &source_logged).unwrap();
    commit_agent_stream(&ctx, &source_logged, &mut source_recorded).unwrap();

    let foreign = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("schedule-foreign").unwrap())
        .unwrap();
    let mut foreign_state = AgentRequestLogState::new(foreign.id().clone());
    let (foreign_turn, foreign_logged) = build_logged_turn(
        &mut ctx,
        &foreign,
        &mut foreign_state,
        "foreign-request",
        call_config("mock", "model"),
    );
    let before_source = source.events().unwrap();
    let before_foreign = foreign.events().unwrap();
    assert_eq!(
        schedule_agent_tool_calls(&ctx, &foreign_logged, &mut source_recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "recorded session, turn, and step to match the logged call",
        }))
    );
    assert_eq!(source.events().unwrap(), before_source);
    assert_eq!(foreign.events().unwrap(), before_foreign);
    close_logged_turn(&source, source_turn);
    close_logged_turn(&foreign, foreign_turn);
}

#[test]
fn prepared_tool_inputs_preserve_durable_identity_and_parse_harness_arguments() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        8,
        "call-object",
        "search",
        r#"{"q":"rust","limit":2}"#,
    ));
    chunks.extend(tool_call_chunks(2, "call-empty", "empty", ""));
    chunks.extend(tool_call_chunks(5, "call-scalar", "scalar", r#""literal""#));
    chunks.extend(tool_call_chunks(
        1,
        "call-malformed",
        "malformed",
        "{broken",
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (ctx, session, turn, logged, mut recorded) = recorded_script("prepare-arguments", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let scheduled = schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let before = session.events().unwrap();

    let prepared = prepare_agent_tool_calls(&ctx, &logged, &recorded).unwrap();

    assert_eq!(prepared.len(), 4);
    assert_eq!(
        prepared
            .iter()
            .map(hartevo_cordis::ToolExecutionInput::call_seq)
            .collect::<Vec<_>>(),
        scheduled.iter().map(|call| call.seq).collect::<Vec<_>>()
    );
    assert_eq!(
        prepared
            .iter()
            .map(hartevo_cordis::ToolExecutionInput::call_id)
            .collect::<Vec<_>>(),
        ["call-object", "call-empty", "call-scalar", "call-malformed"]
    );
    assert!(
        prepared
            .iter()
            .all(|input| input.turn() == turn && input.step() == 1)
    );
    assert_eq!(prepared[0].name(), "search");
    assert_eq!(prepared[0].raw_arguments(), r#"{"q":"rust","limit":2}"#);
    assert_eq!(prepared[0].arguments(), &json!({ "q": "rust", "limit": 2 }));
    assert_eq!(prepared[1].raw_arguments(), "");
    assert_eq!(prepared[1].arguments(), &json!({}));
    assert_eq!(prepared[2].raw_arguments(), r#""literal""#);
    assert_eq!(prepared[2].arguments(), &json!("literal"));
    assert_eq!(prepared[3].raw_arguments(), "{broken");
    assert_eq!(prepared[3].arguments(), &json!("{broken"));
    assert_eq!(session.events().unwrap(), before);
    assert!(
        before
            .iter()
            .all(|event| !matches!(event.kind, SessionEventKind::ToolResult { .. }))
    );
    close_logged_turn(&session, turn);
}

#[test]
fn tool_execution_mode_is_live_argument_sensitive_and_fail_closed() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "search-parallel",
        "search",
        r#"{"parallel":true}"#,
    ));
    chunks.extend(tool_call_chunks(
        1,
        "search-exclusive",
        "search",
        r#"{"parallel":false}"#,
    ));
    chunks.extend(tool_call_chunks(2, "error-call", "error-tool", "{}"));
    chunks.extend(tool_call_chunks(
        3,
        "unknown-call",
        "unknown",
        r#"{"parallel":true}"#,
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) = recorded_script("prepare-modes", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let prepared = prepare_agent_tool_calls(&ctx, &logged, &recorded).unwrap();
    register_tool(&mut ctx, "search").unwrap();
    register_tool(&mut ctx, "error-tool").unwrap();
    let tools = ctx.tools::<ToolsSurface>().unwrap();

    assert_eq!(
        tools.execution_mode(&prepared[0]),
        ToolExecutionMode::Exclusive
    );
    let search_classifier = register_tool_concurrency(&mut ctx, "search", |arguments| {
        Ok(arguments
            .get("parallel")
            .and_then(serde_json::Value::as_bool)
            == Some(true))
    })
    .unwrap();
    let _error_classifier =
        register_tool_concurrency(&mut ctx, "error-tool", |_| Err("classifier failed".into()))
            .unwrap();

    assert_eq!(
        tools.execution_mode(&prepared[0]),
        ToolExecutionMode::Parallel
    );
    assert_eq!(
        tools.execution_mode(&prepared[1]),
        ToolExecutionMode::Exclusive
    );
    assert_eq!(
        tools.execution_mode(&prepared[2]),
        ToolExecutionMode::Exclusive
    );
    assert_eq!(
        tools.execution_mode(&prepared[3]),
        ToolExecutionMode::Exclusive
    );
    let replacement = register_tool_schema(&mut ctx, tool_schema("search")).unwrap();
    assert_eq!(
        tools.execution_mode(&prepared[0]),
        ToolExecutionMode::Exclusive
    );
    assert!(replacement.dispose());
    assert_eq!(
        tools.execution_mode(&prepared[0]),
        ToolExecutionMode::Parallel
    );
    assert!(search_classifier.dispose());
    assert_eq!(
        tools.execution_mode(&prepared[0]),
        ToolExecutionMode::Exclusive
    );
    close_logged_turn(&session, turn);
}

#[test]
fn tool_execution_preparation_rejects_unscheduled_foreign_and_closed_steps() {
    let chunks = vec![SessionStreamChunk::Finish {
        reason: SessionFinishReason::Stop,
        replay_state: None,
    }];
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("prepare-boundaries", chunks.clone());
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    let before_unscheduled = session.events().unwrap();
    assert_eq!(
        prepare_agent_tool_calls(&ctx, &logged, &recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "durably scheduled tool calls before execution preparation",
        }))
    );
    assert_eq!(session.events().unwrap(), before_unscheduled);
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let foreign = ctx
        .sessions::<SessionStore>()
        .unwrap()
        .create(SessionId::new("prepare-foreign").unwrap())
        .unwrap();
    let mut foreign_state = AgentRequestLogState::new(foreign.id().clone());
    let (foreign_turn, foreign_logged) = build_logged_turn(
        &mut ctx,
        &foreign,
        &mut foreign_state,
        "foreign-request",
        call_config("mock", "model"),
    );
    let before_source = session.events().unwrap();
    let before_foreign = foreign.events().unwrap();
    assert_eq!(
        prepare_agent_tool_calls(&ctx, &foreign_logged, &recorded),
        Err(CordisError::Llm(LlmError::InvalidStreamProtocol {
            expected: "recorded session, turn, and step to match the logged call",
        }))
    );
    assert_eq!(session.events().unwrap(), before_source);
    assert_eq!(foreign.events().unwrap(), before_foreign);
    close_logged_turn(&foreign, foreign_turn);

    session.finish_step(turn, 1).unwrap();
    let before_closed = session.events().unwrap();
    assert!(matches!(
        prepare_agent_tool_calls(&ctx, &logged, &recorded),
        Err(CordisError::Session(SessionError::NoOpenStep { turn: actual }))
            if actual == turn
    ));
    assert_eq!(session.events().unwrap(), before_closed);
    session.finish_turn(turn, TurnEndReason::Completed).unwrap();
}

#[test]
fn agent_tool_pre_execution_is_ordered_monotonic_and_session_read_only() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "parallel-call",
        "parallel",
        r#"{"parallel":true}"#,
    ));
    chunks.extend(tool_call_chunks(1, "guarded-call", "guarded", "{}"));
    chunks.extend(tool_call_chunks(2, "policy-call", "policy-denied", "{}"));
    chunks.extend(tool_call_chunks(3, "approval-call", "approval", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("pre-execution-order", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    register_tool_concurrency(&mut ctx, "parallel", |arguments| {
        Ok(arguments
            .get("parallel")
            .and_then(serde_json::Value::as_bool)
            == Some(true))
    })
    .unwrap();
    register_tool(&mut ctx, "guarded").unwrap();
    register_tool(&mut ctx, "policy-denied").unwrap();
    register_tool(&mut ctx, "approval").unwrap();

    let policy_order = Arc::new(Mutex::new(Vec::new()));
    {
        let policy_order = Arc::clone(&policy_order);
        ctx.on_waterfall(
            events::TOOLS_PRE_EXECUTE,
            move |mut call: ToolCall, next| {
                let durable = call
                    .execution_input()
                    .expect("N52 policy must receive the immutable durable input");
                assert_eq!(durable.call_id(), call.call_id);
                if call.name == "parallel" {
                    assert_eq!(durable.arguments(), &json!({ "parallel": true }));
                }
                policy_order.lock().unwrap().push(call.name.clone());
                match call.name.as_str() {
                    "policy-denied" => {
                        call.decision = "deny".into();
                        call.result = "blocked by policy".into();
                        call
                    }
                    "approval" => {
                        call.decision = "ask".into();
                        call.result = "approval is required".into();
                        call
                    }
                    _ => next(call),
                }
            },
        )
        .unwrap();
    }
    register_tool_guard(&mut ctx, |input| {
        (input.name() == "guarded").then(|| "blocked by monotonic guard".into())
    })
    .unwrap();
    let before = session.events().unwrap();

    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();

    assert_eq!(prepared.len(), 4);
    assert_eq!(
        *policy_order.lock().unwrap(),
        ["parallel", "guarded", "policy-denied", "approval"]
    );
    let tools = ctx.tools::<ToolsSurface>().unwrap();
    let ToolExecutionPreparation::Dispatch(parallel) = &prepared[0] else {
        panic!("parallel call should dispatch");
    };
    assert_eq!(parallel.input().call_id(), "parallel-call");
    assert_eq!(parallel.mode(), ToolExecutionMode::Parallel);
    assert!(tools.preparation_is_current(parallel));
    let ToolExecutionPreparation::Denied(guarded) = &prepared[1] else {
        panic!("guarded call should be denied");
    };
    assert_eq!(guarded.reason(), "blocked by monotonic guard");
    let ToolExecutionPreparation::Denied(policy) = &prepared[2] else {
        panic!("policy call should be denied");
    };
    assert_eq!(policy.reason(), "blocked by policy");
    let ToolExecutionPreparation::Denied(approval) = &prepared[3] else {
        panic!("ask must fail closed without an approval channel");
    };
    assert_eq!(approval.reason(), "approval is required");
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tool_pre_execution_rejects_rewrites_stale_registrations_unknowns_and_guard_panics() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "rewrite-call", "rewrite", "{}"));
    chunks.extend(tool_call_chunks(1, "stale-call", "stale", "{}"));
    chunks.extend(tool_call_chunks(2, "unknown-call", "unknown", "{}"));
    chunks.extend(tool_call_chunks(3, "panic-call", "panic", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("pre-execution-fail-closed", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    register_tool(&mut ctx, "rewrite").unwrap();
    let stale = register_tool_concurrency(&mut ctx, "stale", |_| Ok(true)).unwrap();
    register_tool(&mut ctx, "panic").unwrap();
    ctx.on_waterfall(events::TOOLS_PRE_EXECUTE, |mut call: ToolCall, next| {
        if call.name == "rewrite" {
            call.arguments = r#"{"rewritten":true}"#.into();
        }
        next(call)
    })
    .unwrap();
    let stale = Arc::new(Mutex::new(Some(stale)));
    {
        let stale = Arc::clone(&stale);
        register_tool_guard(&mut ctx, move |input| {
            if input.name() == "stale" {
                stale.lock().unwrap().take().unwrap().dispose();
            }
            None
        })
        .unwrap();
    }
    register_tool_guard(&mut ctx, |input| {
        assert_ne!(input.name(), "panic", "guard panic must be contained");
        None
    })
    .unwrap();
    let before = session.events().unwrap();

    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();

    let reasons = prepared
        .iter()
        .map(|outcome| match outcome {
            ToolExecutionPreparation::Dispatch(_) => panic!("every call must fail closed"),
            ToolExecutionPreparation::Denied(denied) => denied.reason(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        [
            "tools/pre-execute cannot rewrite durable tool identity or arguments",
            "tool registration changed during pre-execution",
            "unknown tool \"unknown\"",
            "tool guard panicked for \"panic\"",
        ]
    );
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn exact_tool_dispatch_runs_each_body_once_and_normalizes_errors_without_session_writes() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "success-call",
        "success",
        r#"{"value":7}"#,
    ));
    chunks.extend(tool_call_chunks(1, "error-call", "error", "{}"));
    chunks.extend(tool_call_chunks(2, "panic-call", "panic", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("exact-tool-dispatch", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let body_order = Arc::new(Mutex::new(Vec::new()));
    {
        let body_order = Arc::clone(&body_order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("success"), move |input| {
                body_order.lock().unwrap().push(input.call_id().to_string());
                assert_eq!(input.arguments(), &json!({ "value": 7 }));
                Ok(json!({ "echo": input.arguments() }))
            })
            .with_concurrency(|arguments| Ok(arguments.get("value").is_some())),
        )
        .unwrap();
    }
    {
        let body_order = Arc::clone(&body_order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("error"), move |input| {
                body_order.lock().unwrap().push(input.call_id().to_string());
                Err("executor rejected the call".into())
            }),
        )
        .unwrap();
    }
    {
        let body_order = Arc::clone(&body_order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("panic"), move |input| {
                body_order.lock().unwrap().push(input.call_id().to_string());
                panic!("executor panic for {}", input.call_id());
            }),
        )
        .unwrap();
    }
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    assert!(matches!(
        &prepared[0],
        ToolExecutionPreparation::Dispatch(dispatch)
            if dispatch.mode() == ToolExecutionMode::Parallel
    ));

    let outcomes = prepared
        .into_iter()
        .map(|preparation| match preparation {
            ToolExecutionPreparation::Dispatch(dispatch) => {
                dispatch_tool_execution(&mut ctx, dispatch).unwrap()
            }
            ToolExecutionPreparation::Denied(denied) => {
                panic!("unexpected denial: {}", denied.reason())
            }
        })
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes[0].result(),
        &ToolDispatchResult::Success {
            value: json!({ "echo": { "value": 7 } }),
        }
    );
    assert_eq!(
        outcomes[1].result(),
        &ToolDispatchResult::Failure {
            message: "executor rejected the call".into(),
        }
    );
    assert_eq!(
        outcomes[2].result(),
        &ToolDispatchResult::Failure {
            message: "tool \"panic\" panicked".into(),
        }
    );
    assert_eq!(
        *body_order.lock().unwrap(),
        ["success-call", "error-call", "panic-call"]
    );
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tool_dispatch_fences_stale_replacements_and_schema_only_registrations() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "stale-call", "replaceable", "{}"));
    chunks.extend(tool_call_chunks(1, "schema-call", "schema-only", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("stale-tool-dispatch", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let old_calls = Arc::new(AtomicUsize::new(0));
    let old_registration = {
        let old_calls = Arc::clone(&old_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("replaceable"), move |_| {
                old_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("old"))
            }),
        )
        .unwrap()
    };
    register_tool_schema(&mut ctx, tool_schema("schema-only")).unwrap();
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    assert!(old_registration.dispose());
    let replacement_calls = Arc::new(AtomicUsize::new(0));
    {
        let replacement_calls = Arc::clone(&replacement_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("replaceable"), move |_| {
                replacement_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("replacement"))
            }),
        )
        .unwrap();
    }

    let mut prepared = prepared.into_iter();
    let ToolExecutionPreparation::Dispatch(stale) = prepared.next().unwrap() else {
        panic!("old exact registration should prepare before replacement");
    };
    let ToolExecutionPreparation::Dispatch(schema_only) = prepared.next().unwrap() else {
        panic!("schema-only registration should reach typed dispatch failure");
    };
    assert_eq!(
        dispatch_tool_execution(&mut ctx, stale).unwrap().result(),
        &ToolDispatchResult::Failure {
            message: "tool registration changed before dispatch".into(),
        }
    );
    assert_eq!(
        dispatch_tool_execution(&mut ctx, schema_only)
            .unwrap()
            .result(),
        &ToolDispatchResult::Failure {
            message: "tool \"schema-only\" has no registered executor".into(),
        }
    );
    assert_eq!(old_calls.load(Ordering::SeqCst), 0);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 0);

    let fresh = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let ToolExecutionPreparation::Dispatch(fresh) = fresh.into_iter().next().unwrap() else {
        panic!("replacement should require and receive a fresh preparation");
    };
    assert_eq!(
        dispatch_tool_execution(&mut ctx, fresh).unwrap().result(),
        &ToolDispatchResult::Success {
            value: json!("replacement"),
        }
    );
    assert_eq!(old_calls.load(Ordering::SeqCst), 0);
    assert_eq!(replacement_calls.load(Ordering::SeqCst), 1);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tools_execute_waterfall_wraps_the_exact_body_and_may_replace_its_result() {
    let mut chunks = tool_call_chunks(0, "around-call", "around", r#"{"value":7}"#).to_vec();
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) = recorded_script("tool-around", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    {
        let order = Arc::clone(&order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("around"), move |input| {
                order.lock().unwrap().push("body");
                assert_eq!(input.arguments(), &json!({ "value": 7 }));
                Ok(json!("body-result"))
            }),
        )
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(
            events::TOOLS_EXECUTE,
            move |execution: ToolDispatchExecution, next| {
                assert_eq!(execution.input().call_id(), "around-call");
                order.lock().unwrap().push("outer-before");
                let execution = next(execution);
                assert_eq!(
                    execution.result(),
                    Some(&ToolDispatchResult::Success {
                        value: json!("inner-result")
                    })
                );
                order.lock().unwrap().push("outer-after");
                execution
            },
        )
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(
            events::TOOLS_EXECUTE,
            move |execution: ToolDispatchExecution, next| {
                order.lock().unwrap().push("inner-before");
                let execution = next(execution);
                assert_eq!(
                    execution.result(),
                    Some(&ToolDispatchResult::Success {
                        value: json!("body-result")
                    })
                );
                order.lock().unwrap().push("inner-after");
                execution.complete(ToolDispatchResult::Success {
                    value: json!("inner-result"),
                })
            },
        )
        .unwrap();
    }
    let before = session.events().unwrap();
    let mut prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let ToolExecutionPreparation::Dispatch(prepared) = prepared.remove(0) else {
        panic!("around call must be admitted");
    };

    let outcome = dispatch_tool_execution(&mut ctx, prepared).unwrap();

    assert_eq!(
        outcome.result(),
        &ToolDispatchResult::Success {
            value: json!("inner-result")
        }
    );
    assert_eq!(
        *order.lock().unwrap(),
        [
            "outer-before",
            "inner-before",
            "body",
            "inner-after",
            "outer-after"
        ]
    );
    assert_eq!(ctx.listener_count(events::TOOLS_EXECUTE), 2);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tools_execute_short_circuit_and_wrapper_panic_never_leak_a_terminal_or_retry() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "skip-call", "skip", "{}"));
    chunks.extend(tool_call_chunks(1, "panic-call", "wrapper-panic", "{}"));
    chunks.extend(tool_call_chunks(2, "error-call", "body-error", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-around-failures", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let body_calls = Arc::new(AtomicUsize::new(0));
    for name in ["skip", "wrapper-panic"] {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("must-not-run"))
            }),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("body-error"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Err("body rejected".into())
            }),
        )
        .unwrap();
    }
    let saw_body_error = Arc::new(AtomicUsize::new(0));
    {
        let saw_body_error = Arc::clone(&saw_body_error);
        ctx.on_waterfall(
            events::TOOLS_EXECUTE,
            move |execution: ToolDispatchExecution, next| match execution.input().name() {
                "skip" => execution.complete(ToolDispatchResult::Success {
                    value: json!("short-circuited"),
                }),
                "wrapper-panic" => panic!("wrapper broke"),
                "body-error" => {
                    let execution = next(execution);
                    assert_eq!(
                        execution.result(),
                        Some(&ToolDispatchResult::Failure {
                            message: "body rejected".into()
                        })
                    );
                    saw_body_error.fetch_add(1, Ordering::SeqCst);
                    execution
                }
                _ => next(execution),
            },
        )
        .unwrap();
    }
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let mut outcomes = Vec::new();
    for preparation in prepared {
        let ToolExecutionPreparation::Dispatch(prepared) = preparation else {
            panic!("every registered call must be admitted");
        };
        outcomes.push(dispatch_tool_execution(&mut ctx, prepared).unwrap());
        assert_eq!(ctx.listener_count(events::TOOLS_EXECUTE), 1);
    }

    assert_eq!(
        outcomes[0].result(),
        &ToolDispatchResult::Success {
            value: json!("short-circuited")
        }
    );
    assert_eq!(
        outcomes[1].result(),
        &ToolDispatchResult::Failure {
            message: "tools/execute wrapper panicked".into()
        }
    );
    assert_eq!(
        outcomes[2].result(),
        &ToolDispatchResult::Failure {
            message: "body rejected".into()
        }
    );
    assert_eq!(body_calls.load(Ordering::SeqCst), 1);
    assert_eq!(saw_body_error.load(Ordering::SeqCst), 1);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tools_post_execute_preserves_by_default_then_wraps_and_replaces_success() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "plain-call", "plain", "{}"));
    chunks.extend(tool_call_chunks(1, "replace-call", "replace", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-post-execute", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    for (name, value) in [("plain", "plain-body"), ("replace", "replace-body")] {
        let order = Arc::clone(&order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                order.lock().unwrap().push(value);
                Ok(json!(value))
            }),
        )
        .unwrap();
    }
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let mut prepared = prepared.into_iter();
    let ToolExecutionPreparation::Dispatch(plain) = prepared.next().unwrap() else {
        panic!("plain call must be admitted");
    };
    let ToolExecutionPreparation::Dispatch(replace) = prepared.next().unwrap() else {
        panic!("replace call must be admitted");
    };
    let before = session.events().unwrap();

    let plain = dispatch_tool_execution(&mut ctx, plain).unwrap();
    let plain = post_tool_execution(&mut ctx, plain).unwrap();
    assert_eq!(
        plain.result(),
        &ToolDispatchResult::Success {
            value: json!("plain-body")
        }
    );
    order.lock().unwrap().clear();
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |execution: ToolPostExecution, next| {
                order.lock().unwrap().push("outer-before");
                let execution = next(execution);
                assert_eq!(
                    execution.result(),
                    &ToolDispatchResult::Success {
                        value: json!("post-replacement")
                    }
                );
                order.lock().unwrap().push("outer-after");
                execution
            },
        )
        .unwrap();
    }
    {
        let order = Arc::clone(&order);
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |execution: ToolPostExecution, next| {
                assert_eq!(execution.input().call_id(), "replace-call");
                order.lock().unwrap().push("inner-before");
                let execution = next(execution);
                order.lock().unwrap().push("inner-after");
                execution.replace_success(json!("post-replacement"))
            },
        )
        .unwrap();
    }

    let replace = dispatch_tool_execution(&mut ctx, replace).unwrap();
    let replace = post_tool_execution(&mut ctx, replace).unwrap();

    assert_eq!(
        replace.result(),
        &ToolDispatchResult::Success {
            value: json!("post-replacement")
        }
    );
    assert_eq!(
        *order.lock().unwrap(),
        [
            "replace-body",
            "outer-before",
            "inner-before",
            "inner-after",
            "outer-after"
        ]
    );
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
fn tools_post_execute_blocks_failed_replacement_and_listener_panic_without_replay() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "block-call", "block", "{}"));
    chunks.extend(tool_call_chunks(1, "failed-call", "body-failure", "{}"));
    chunks.extend(tool_call_chunks(2, "panic-call", "post-panic", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-post-failures", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let body_calls = Arc::new(AtomicUsize::new(0));
    for name in ["block", "post-panic"] {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("body-success"))
            }),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("body-failure"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Err("body failed".into())
            }),
        )
        .unwrap();
    }
    ctx.on_waterfall(
        events::TOOLS_POST_EXECUTE,
        move |execution: ToolPostExecution, next| match execution.input().name() {
            "block" => execution.block("blocked by post policy"),
            "body-failure" => {
                assert_eq!(
                    execution.result(),
                    &ToolDispatchResult::Failure {
                        message: "body failed".into()
                    }
                );
                execution.replace_success(json!("must-not-recover"))
            }
            "post-panic" => panic!("post policy broke"),
            _ => next(execution),
        },
    )
    .unwrap();
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let mut outcomes = Vec::new();
    for preparation in prepared {
        let ToolExecutionPreparation::Dispatch(prepared) = preparation else {
            panic!("every registered call must be admitted");
        };
        let dispatched = dispatch_tool_execution(&mut ctx, prepared).unwrap();
        outcomes.push(post_tool_execution(&mut ctx, dispatched).unwrap());
    }

    assert_eq!(
        outcomes[0].result(),
        &ToolDispatchResult::Failure {
            message: "blocked by post policy".into()
        }
    );
    assert_eq!(
        outcomes[1].result(),
        &ToolDispatchResult::Failure {
            message: "tools/post-execute cannot replace the value of a failed result".into()
        }
    );
    assert_eq!(
        outcomes[2].result(),
        &ToolDispatchResult::Failure {
            message: "tools/post-execute listener panicked".into()
        }
    );
    assert_eq!(body_calls.load(Ordering::SeqCst), 3);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the captured-definition and observer order in one fixture.
fn tools_final_result_uses_captured_projection_and_contains_every_observer() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "final-success-call",
        "final-success",
        r#"{"value":7}"#,
    ));
    chunks.extend(tool_call_chunks(
        1,
        "final-failure-call",
        "final-failure",
        "{}",
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-final-result", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let success_registration = {
        let body_order = Arc::clone(&order);
        let render_order = Arc::clone(&order);
        let finalizer_order = Arc::clone(&order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("final-success"), move |input| {
                body_order.lock().unwrap().push("success-body");
                assert_eq!(input.arguments(), &json!({ "value": 7 }));
                Ok(json!({ "answer": 7 }))
            })
            .with_output_renderer(move |arguments, value| {
                render_order.lock().unwrap().push("success-render");
                assert_eq!(arguments, &json!({ "value": 7 }));
                assert_eq!(value, &json!({ "answer": 7 }));
                Ok(vec![SessionContentBlock::Text {
                    text: "rendered success".into(),
                }])
            })
            .with_content_finalizer(move |input, result| {
                finalizer_order.lock().unwrap().push("success-finalize");
                assert_eq!(input.call_id(), "final-success-call");
                assert_eq!(
                    result.result(),
                    &ToolDispatchResult::Success {
                        value: json!({ "answer": 7 })
                    }
                );
                Ok(Some(vec![SessionContentBlock::Text {
                    text: "finalized success".into(),
                }]))
            }),
        )
        .unwrap()
    };
    {
        let body_order = Arc::clone(&order);
        let render_order = Arc::clone(&order);
        let finalizer_order = Arc::clone(&order);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("final-failure"), move |_| {
                body_order.lock().unwrap().push("failure-body");
                Err("body failed before rendering".into())
            })
            .with_output_renderer(move |_, _| {
                render_order.lock().unwrap().push("failure-render");
                Ok(Vec::new())
            })
            .with_content_finalizer(move |input, result| {
                finalizer_order.lock().unwrap().push("failure-finalize");
                assert_eq!(input.call_id(), "final-failure-call");
                assert!(result.is_error());
                Ok(Some(vec![SessionContentBlock::Text {
                    text: "finalized failure".into(),
                }]))
            }),
        )
        .unwrap();
    }
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let mut post_outcomes = Vec::new();
    for preparation in prepared {
        let ToolExecutionPreparation::Dispatch(prepared) = preparation else {
            panic!("both registered calls must be admitted");
        };
        let dispatched = dispatch_tool_execution(&mut ctx, prepared).unwrap();
        post_outcomes.push(post_tool_execution(&mut ctx, dispatched).unwrap());
    }

    assert!(success_registration.dispose());
    let replacement_body_calls = Arc::new(AtomicUsize::new(0));
    {
        let replacement_body_calls = Arc::clone(&replacement_body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("final-success"), move |_| {
                replacement_body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("replacement body"))
            })
            .with_output_renderer(|_, _| {
                Ok(vec![SessionContentBlock::Text {
                    text: "replacement renderer".into(),
                }])
            })
            .with_content_finalizer(|_, _| {
                Ok(Some(vec![SessionContentBlock::Text {
                    text: "replacement finalizer".into(),
                }]))
            }),
        )
        .unwrap();
    }

    let observer_panics = Arc::new(AtomicUsize::new(0));
    {
        let observer_panics = Arc::clone(&observer_panics);
        ctx.on_emit(events::TOOLS_RESULT, move |_: &ToolExecutionResult| {
            observer_panics.fetch_add(1, Ordering::SeqCst);
            panic!("result observer panic");
        })
        .unwrap();
    }
    let observer_errors = Arc::new(AtomicUsize::new(0));
    {
        let observer_errors = Arc::clone(&observer_errors);
        ctx.try_on_emit(events::TOOLS_RESULT, move |_: &ToolExecutionResult| {
            observer_errors.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("result observer error"))
        })
        .unwrap();
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let observed = Arc::clone(&observed);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            let [SessionContentBlock::Text { text }] = result.content() else {
                panic!("final result must have one text block");
            };
            observed.lock().unwrap().push((
                result.input().call_id().to_string(),
                result.result().clone(),
                text.clone(),
            ));
        })
        .unwrap();
    }

    let mut post_outcomes = post_outcomes.into_iter();
    let success = finalize_tool_execution(&mut ctx, post_outcomes.next().unwrap());
    let failure = finalize_tool_execution(&mut ctx, post_outcomes.next().unwrap());

    assert_eq!(
        success.result(),
        &ToolDispatchResult::Success {
            value: json!({ "answer": 7 })
        }
    );
    assert_eq!(
        success.content(),
        [SessionContentBlock::Text {
            text: "finalized success".into()
        }]
    );
    assert_eq!(
        failure.result(),
        &ToolDispatchResult::Failure {
            message: "body failed before rendering".into()
        }
    );
    assert_eq!(
        failure.content(),
        [SessionContentBlock::Text {
            text: "finalized failure".into()
        }]
    );
    assert_eq!(
        *order.lock().unwrap(),
        [
            "success-body",
            "failure-body",
            "success-render",
            "success-finalize",
            "failure-finalize",
        ]
    );
    assert_eq!(replacement_body_calls.load(Ordering::SeqCst), 0);
    assert_eq!(observer_panics.load(Ordering::SeqCst), 2);
    assert_eq!(observer_errors.load(Ordering::SeqCst), 2);
    assert_eq!(
        *observed.lock().unwrap(),
        [
            (
                "final-success-call".into(),
                ToolDispatchResult::Success {
                    value: json!({ "answer": 7 })
                },
                "finalized success".into(),
            ),
            (
                "final-failure-call".into(),
                ToolDispatchResult::Failure {
                    message: "body failed before rendering".into()
                },
                "finalized failure".into(),
            ),
        ]
    );
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep every fail-closed projection class in one matrix.
fn tools_final_result_normalizes_projection_failures_without_replay() {
    let cases = [
        ("missing-call", "missing-renderer"),
        ("renderer-error-call", "renderer-error"),
        ("renderer-panic-call", "renderer-panic"),
        ("finalizer-error-call", "finalizer-error"),
        ("finalizer-panic-call", "finalizer-panic"),
    ];
    let mut chunks = Vec::new();
    for (index, (call_id, name)) in (0_u64..).zip(cases.iter()) {
        chunks.extend(tool_call_chunks(index, call_id, name, "{}"));
    }
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-final-failures", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let body_calls = Arc::new(AtomicUsize::new(0));
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("missing-renderer"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("missing"))
            }),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("renderer-error"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("renderer error"))
            })
            .with_output_renderer(|_, _| Err("projection rejected".into())),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("renderer-panic"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("renderer panic"))
            })
            .with_output_renderer(|_, _| panic!("projection panic")),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("finalizer-error"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("finalizer error"))
            })
            .with_output_renderer(|_, _| {
                Ok(vec![SessionContentBlock::Text {
                    text: "rendered".into(),
                }])
            })
            .with_content_finalizer(|_, _| Err("finalization rejected".into())),
        )
        .unwrap();
    }
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("finalizer-panic"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("finalizer panic"))
            })
            .with_output_renderer(|_, _| {
                Ok(vec![SessionContentBlock::Text {
                    text: "rendered".into(),
                }])
            })
            .with_content_finalizer(|_, _| panic!("finalizer panic")),
        )
        .unwrap();
    }
    let observer_calls = Arc::new(AtomicUsize::new(0));
    {
        let observer_calls = Arc::clone(&observer_calls);
        ctx.on_emit(events::TOOLS_RESULT, move |_: &ToolExecutionResult| {
            observer_calls.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    }
    let before = session.events().unwrap();
    let prepared = prepare_agent_tool_executions(&mut ctx, &logged, &recorded).unwrap();
    let results = prepared
        .into_iter()
        .map(|preparation| {
            let ToolExecutionPreparation::Dispatch(prepared) = preparation else {
                panic!("every projection failure fixture must be admitted");
            };
            let dispatched = dispatch_tool_execution(&mut ctx, prepared).unwrap();
            let post = post_tool_execution(&mut ctx, dispatched).unwrap();
            finalize_tool_execution(&mut ctx, post)
        })
        .collect::<Vec<_>>();

    let messages = results
        .iter()
        .map(|result| match result.result() {
            ToolDispatchResult::Success { .. } => panic!("projection failures must fail closed"),
            ToolDispatchResult::Failure { message } => message.as_str(),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [
            "tool \"missing-renderer\" has no registered output renderer",
            "tool \"renderer-error\" output renderer failed: projection rejected",
            "tool \"renderer-panic\" output renderer panicked",
            "tool \"finalizer-error\" content finalizer failed: finalization rejected",
            "tool \"finalizer-panic\" content finalizer panicked",
        ]
    );
    for result in &results {
        let ToolDispatchResult::Failure { message } = result.result() else {
            unreachable!();
        };
        assert_eq!(
            result.content(),
            [SessionContentBlock::Text {
                text: format!("Error: {message}")
            }]
        );
    }
    assert_eq!(body_calls.load(Ordering::SeqCst), 5);
    assert_eq!(observer_calls.load(Ordering::SeqCst), 5);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the two-result durable ordering proof in one fixture.
fn final_tool_results_commit_in_model_order_with_exact_call_provenance() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "commit-success-call",
        "commit-success",
        "{}",
    ));
    chunks.extend(tool_call_chunks(
        1,
        "commit-failure-call",
        "commit-failure",
        "{}",
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-result-commit", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    register_tool_definition(
        &mut ctx,
        ToolDefinition::new(tool_schema("commit-success"), |_| {
            Ok(json!({ "answer": 7 }))
        })
        .with_output_renderer(|_, value| {
            assert_eq!(value, &json!({ "answer": 7 }));
            Ok(vec![SessionContentBlock::Text {
                text: "rendered seven".into(),
            }])
        }),
    )
    .unwrap();
    register_tool_definition(
        &mut ctx,
        ToolDefinition::new(tool_schema("commit-failure"), |_| Err("body failed".into()))
            .with_output_renderer(|_, _| unreachable!("failures do not use the renderer")),
    )
    .unwrap();
    let call_seqs = recorded.tool_call_seqs().to_vec();
    let results = finalize_scheduled_tools(&mut ctx, &logged, &recorded);

    let messages = commit_agent_tool_results(&ctx, &logged, &mut recorded, &results).unwrap();

    assert!(recorded.tool_results_committed());
    assert_eq!(recorded.tool_result_seqs().len(), 2);
    assert_eq!(
        messages
            .iter()
            .map(|message| match &message.source {
                SessionMessageSource::Tool { call_id } => call_id.as_str(),
                _ => panic!("committed result must have tool provenance"),
            })
            .collect::<Vec<_>>(),
        ["commit-success-call", "commit-failure-call"]
    );
    let result_events = session
        .events()
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::ToolResult {
                message,
                error,
                surface,
                ..
            } => Some((message, error, surface)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(result_events.len(), 2);
    assert_eq!(result_events[0].0, messages[0]);
    assert_eq!(result_events[1].0, messages[1]);
    assert!(result_events.iter().all(|(_, error, _)| error.is_none()));
    assert_eq!(
        result_events[0].2,
        SessionSurfaceIntent::append_from(vec![call_seqs[0]])
    );
    assert_eq!(
        result_events[1].2,
        SessionSurfaceIntent::append_from(vec![call_seqs[1]])
    );
    assert!(matches!(
        messages[0].content.as_slice(),
        [SessionContentBlock::ToolResult {
            is_error: false,
            content,
            ..
        }] if content == &[SessionContentBlock::Text { text: "rendered seven".into() }]
    ));
    assert!(matches!(
        messages[1].content.as_slice(),
        [SessionContentBlock::ToolResult {
            is_error: true,
            content,
            ..
        }] if content == &[SessionContentBlock::Text { text: "Error: body failed".into() }]
    ));
    let derived = session.derive_messages().unwrap();
    assert_eq!(&derived[derived.len() - messages.len()..], messages);
    let after = session.events().unwrap();
    assert!(commit_agent_tool_results(&ctx, &logged, &mut recorded, &results).is_err());
    assert_eq!(session.events().unwrap(), after);
    close_logged_turn(&session, turn);
}

#[test]
fn tool_result_commit_rejects_order_drift_and_resumes_an_exact_prefix() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "prefix-a-call", "prefix-a", "{}"));
    chunks.extend(tool_call_chunks(1, "prefix-b-call", "prefix-b", "{}"));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-result-prefix", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    for name in ["prefix-a", "prefix-b"] {
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| Ok(json!(name))).with_output_renderer(
                |_, value| {
                    Ok(vec![SessionContentBlock::Text {
                        text: value.as_str().unwrap().into(),
                    }])
                },
            ),
        )
        .unwrap();
    }
    let mut results = finalize_scheduled_tools(&mut ctx, &logged, &recorded);
    results.reverse();
    let before = session.events().unwrap();
    assert!(commit_agent_tool_results(&ctx, &logged, &mut recorded, &results).is_err());
    assert_eq!(session.events().unwrap(), before);
    assert!(recorded.tool_result_seqs().is_empty());
    results.reverse();

    let prefix_message = durable_tool_result_message(session.id().as_str(), turn, 1, &results[0]);
    let prefix_seq = session
        .append_tool_result_with_surface(
            turn,
            1,
            prefix_message,
            SessionSurfaceIntent::append_from(vec![recorded.tool_call_seqs()[0]]),
        )
        .unwrap();
    let messages = commit_agent_tool_results(&ctx, &logged, &mut recorded, &results).unwrap();

    assert_eq!(recorded.tool_result_seqs()[0], prefix_seq);
    assert_eq!(recorded.tool_result_seqs().len(), 2);
    assert!(recorded.tool_results_committed());
    assert_eq!(
        session
            .events()
            .unwrap()
            .iter()
            .filter(|event| matches!(event.kind, SessionEventKind::ToolResult { .. }))
            .count(),
        2
    );
    let derived = session.derive_messages().unwrap();
    assert_eq!(&derived[derived.len() - 2..], messages);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep execution, denial, observation, and commit order together.
fn tool_batch_driver_settles_allowed_denied_and_unknown_calls_once_in_model_order() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(0, "batch-allow-call", "batch-allow", "{}"));
    chunks.extend(tool_call_chunks(1, "batch-deny-call", "batch-deny", "{}"));
    chunks.extend(tool_call_chunks(
        2,
        "batch-unknown-call",
        "batch-unknown",
        "{}",
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-batch-driver", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    {
        let bodies = Arc::clone(&bodies);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("batch-allow"), move |_| {
                bodies.lock().unwrap().push("allow-body");
                Ok(json!("allowed"))
            })
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    let late_registration = {
        let bodies = Arc::clone(&bodies);
        Arc::new(Mutex::new(Some(
            register_tool_definition(
                &mut ctx,
                ToolDefinition::new(tool_schema("batch-unknown"), move |_| {
                    bodies.lock().unwrap().push("late-body");
                    Ok(json!("must not run"))
                })
                .with_output_renderer(|_, _| Ok(Vec::new())),
            )
            .unwrap(),
        )))
    };
    {
        let bodies = Arc::clone(&bodies);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("batch-deny"), move |_| {
                bodies.lock().unwrap().push("denied-body");
                Ok(json!("must not run"))
            })
            .with_content_finalizer(|input, result| {
                assert_eq!(input.call_id(), "batch-deny-call");
                assert!(result.is_error());
                Ok(Some(vec![SessionContentBlock::Text {
                    text: "denial finalized".into(),
                }]))
            }),
        )
        .unwrap();
    }
    ctx.on_waterfall(events::TOOLS_PRE_EXECUTE, |mut call: ToolCall, next| {
        if call.name == "batch-deny" {
            call.decision = "deny".into();
            call.result = "blocked by policy".into();
            call
        } else {
            next(call)
        }
    })
    .unwrap();
    let post_order = Arc::new(Mutex::new(Vec::new()));
    {
        let post_order = Arc::clone(&post_order);
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |execution: ToolPostExecution, next| {
                post_order
                    .lock()
                    .unwrap()
                    .push(execution.input().call_id().to_string());
                next(execution)
            },
        )
        .unwrap();
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let observed = Arc::clone(&observed);
        let late_registration = Arc::clone(&late_registration);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            if result.input().call_id() == "batch-allow-call" {
                assert!(late_registration.lock().unwrap().take().unwrap().dispose());
            }
            observed
                .lock()
                .unwrap()
                .push((result.input().call_id().to_string(), result.is_error()));
        })
        .unwrap();
    }

    let results = run_agent_tool_batch(&mut ctx, &logged, &mut recorded).unwrap();

    assert!(recorded.tool_batch_started());
    assert!(recorded.tool_results_committed());
    assert_eq!(*bodies.lock().unwrap(), ["allow-body"]);
    assert_eq!(
        *post_order.lock().unwrap(),
        ["batch-allow-call", "batch-deny-call", "batch-unknown-call"]
    );
    assert_eq!(
        *observed.lock().unwrap(),
        [
            ("batch-allow-call".into(), false),
            ("batch-deny-call".into(), true),
            ("batch-unknown-call".into(), true),
        ]
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.input().call_id())
            .collect::<Vec<_>>(),
        ["batch-allow-call", "batch-deny-call", "batch-unknown-call"]
    );
    assert_eq!(
        results[1].content(),
        [SessionContentBlock::Text {
            text: "denial finalized".into()
        }]
    );
    assert_eq!(
        results[2].content(),
        [SessionContentBlock::Text {
            text: "Error: unknown tool \"batch-unknown\"".into()
        }]
    );
    let durable_order = session
        .events()
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::ToolResult { message, .. } => match message.source {
                SessionMessageSource::Tool { call_id } => Some(call_id),
                _ => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        durable_order,
        ["batch-allow-call", "batch-deny-call", "batch-unknown-call"]
    );
    let after = session.events().unwrap();
    assert!(run_agent_tool_batch(&mut ctx, &logged, &mut recorded).is_err());
    assert_eq!(*bodies.lock().unwrap(), ["allow-body"]);
    assert_eq!(session.events().unwrap(), after);
    close_logged_turn(&session, turn);
}

#[test]
fn tool_batch_driver_never_replays_a_call_with_a_preexisting_durable_result() {
    let mut chunks = tool_call_chunks(0, "already-result-call", "already-result", "{}").to_vec();
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-batch-preexisting-result", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let body_calls = Arc::new(AtomicUsize::new(0));
    {
        let body_calls = Arc::clone(&body_calls);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("already-result"), move |_| {
                body_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!("must not replay"))
            })
            .with_output_renderer(|_, _| Ok(Vec::new())),
        )
        .unwrap();
    }
    session
        .append_tool_result_with_surface(
            turn,
            1,
            SessionMessage {
                id: "already-result-message".into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::ToolResult {
                    tool_call_id: "already-result-call".into(),
                    content: vec![SessionContentBlock::Text {
                        text: "already durable".into(),
                    }],
                    is_error: false,
                }],
                source: SessionMessageSource::Tool {
                    call_id: "already-result-call".into(),
                },
            },
            SessionSurfaceIntent::append_from(vec![recorded.tool_call_seqs()[0]]),
        )
        .unwrap();
    let before = session.events().unwrap();

    assert!(run_agent_tool_batch(&mut ctx, &logged, &mut recorded).is_err());
    assert!(!recorded.tool_batch_started());
    assert_eq!(body_calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.events().unwrap(), before);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep overlap, refill, barrier, and result order in one proof.
fn tool_scheduler_bounds_a_rolling_pool_and_preserves_model_order_barriers() {
    #[derive(Default)]
    struct Probe {
        active: usize,
        max_active: usize,
        started: Vec<&'static str>,
        finished: Vec<&'static str>,
        exclusive_active: Option<usize>,
        exclusive_finished: bool,
        after_exclusive: bool,
    }

    let mut chunks = Vec::new();
    for (index, name) in ["pool-1", "pool-2", "pool-3", "barrier", "pool-after"]
        .into_iter()
        .enumerate()
    {
        chunks.extend(tool_call_chunks(
            u64::try_from(index).unwrap(),
            &format!("{name}-call"),
            name,
            "{}",
        ));
    }
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-scheduler-rolling", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let probe = Arc::new((Mutex::new(Probe::default()), Condvar::new()));
    for name in ["pool-1", "pool-2", "pool-3"] {
        let probe = Arc::clone(&probe);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                let (state, changed) = &*probe;
                let mut state = state.lock().unwrap();
                state.active += 1;
                state.max_active = state.max_active.max(state.active);
                state.started.push(name);
                changed.notify_all();
                if name == "pool-1" {
                    let (next, timeout) = changed
                        .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                            !state.started.contains(&"pool-3")
                        })
                        .unwrap();
                    state = next;
                    if timeout.timed_out() && !state.started.contains(&"pool-3") {
                        state.active -= 1;
                        changed.notify_all();
                        return Err("rolling pool did not refill".into());
                    }
                } else if name == "pool-3" {
                    let (next, timeout) = changed
                        .wait_timeout_while(state, std::time::Duration::from_secs(2), |state| {
                            !state.finished.contains(&"pool-1")
                        })
                        .unwrap();
                    state = next;
                    if timeout.timed_out() && !state.finished.contains(&"pool-1") {
                        state.active -= 1;
                        changed.notify_all();
                        return Err("first rolling call did not settle".into());
                    }
                }
                state.active -= 1;
                state.finished.push(name);
                changed.notify_all();
                Ok(json!(name))
            })
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    {
        let probe = Arc::clone(&probe);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("barrier"), move |_| {
                let (state, _) = &*probe;
                let mut state = state.lock().unwrap();
                state.exclusive_active = Some(state.active);
                state.exclusive_finished = true;
                Ok(json!("barrier"))
            })
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    {
        let probe = Arc::clone(&probe);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("pool-after"), move |_| {
                let (state, _) = &*probe;
                let mut state = state.lock().unwrap();
                state.after_exclusive = state.exclusive_finished;
                Ok(json!("pool-after"))
            })
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let observed = Arc::clone(&observed);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            observed
                .lock()
                .unwrap()
                .push(result.input().call_id().to_string());
        })
        .unwrap();
    }
    let around_dispatch = Arc::new(Mutex::new(Vec::new()));
    {
        let around_dispatch = Arc::clone(&around_dispatch);
        ctx.on_waterfall(
            events::TOOLS_EXECUTE,
            move |execution: ToolDispatchExecution, next| {
                let call_id = execution.input().call_id().to_string();
                let execution = next(execution);
                assert!(execution.result().is_some());
                around_dispatch.lock().unwrap().push(call_id);
                execution
            },
        )
        .unwrap();
    }

    let results = run_agent_tool_batch_with_limit(&mut ctx, &logged, &mut recorded, 2).unwrap();

    assert!(results.iter().all(|result| !result.is_error()));
    assert_eq!(
        *observed.lock().unwrap(),
        [
            "pool-1-call",
            "pool-2-call",
            "pool-3-call",
            "barrier-call",
            "pool-after-call",
        ]
    );
    let (state, _) = &*probe;
    let state = state.lock().unwrap();
    assert_eq!(state.max_active, 2);
    assert_eq!(state.exclusive_active, Some(0));
    assert!(state.after_exclusive);
    assert!(state.started.contains(&"pool-3"));
    assert!(state.finished.contains(&"pool-1"));
    drop(state);
    let mut around_dispatch = around_dispatch.lock().unwrap().clone();
    around_dispatch.sort();
    assert_eq!(
        around_dispatch,
        [
            "barrier-call",
            "pool-1-call",
            "pool-2-call",
            "pool-3-call",
            "pool-after-call",
        ]
    );
    assert!(recorded.tool_results_committed());
    assert_eq!(recorded.tool_result_seqs().len(), 5);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep live reclassification and barrier timing together.
fn tool_scheduler_reclassifies_an_unstarted_call_into_an_exclusive_barrier() {
    let mut chunks = Vec::new();
    for (index, name) in ["reclass-first", "reclass-running", "reclass-next"]
        .into_iter()
        .enumerate()
    {
        chunks.extend(tool_call_chunks(
            u64::try_from(index).unwrap(),
            &format!("{name}-call"),
            name,
            "{}",
        ));
    }
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-scheduler-reclassify", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let active = Arc::new(AtomicUsize::new(0));
    let release_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
    register_tool_definition(
        &mut ctx,
        ToolDefinition::new(tool_schema("reclass-first"), |_| Ok(json!("first")))
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
    )
    .unwrap();
    {
        let active = Arc::clone(&active);
        let release_running = Arc::clone(&release_running);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("reclass-running"), move |_| {
                active.fetch_add(1, Ordering::SeqCst);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while !release_running.load(Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::yield_now();
                }
                active.fetch_sub(1, Ordering::SeqCst);
                if release_running.load(Ordering::SeqCst) {
                    Ok(json!("running"))
                } else {
                    Err("ordered result observer did not release running call".into())
                }
            })
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    let next_saw_active = Arc::new(AtomicUsize::new(usize::MAX));
    {
        let active = Arc::clone(&active);
        let next_saw_active = Arc::clone(&next_saw_active);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema("reclass-next"), move |_| {
                next_saw_active.store(active.load(Ordering::SeqCst), Ordering::SeqCst);
                Ok(json!("next"))
            })
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    let parallel_shadow = Arc::new(Mutex::new(Some(
        register_tool_concurrency(&mut ctx, "reclass-next", |_| Ok(true)).unwrap(),
    )));
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let parallel_shadow = Arc::clone(&parallel_shadow);
        let release_running = Arc::clone(&release_running);
        let observed = Arc::clone(&observed);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            observed
                .lock()
                .unwrap()
                .push(result.input().call_id().to_string());
            if result.input().call_id() == "reclass-first-call" {
                assert!(parallel_shadow.lock().unwrap().take().unwrap().dispose());
                release_running.store(true, Ordering::SeqCst);
            }
        })
        .unwrap();
    }

    let results = run_agent_tool_batch_with_limit(&mut ctx, &logged, &mut recorded, 2).unwrap();

    assert!(results.iter().all(|result| !result.is_error()));
    assert_eq!(next_saw_active.load(Ordering::SeqCst), 0);
    assert_eq!(
        *observed.lock().unwrap(),
        [
            "reclass-first-call",
            "reclass-running-call",
            "reclass-next-call",
        ]
    );
    assert!(recorded.tool_results_committed());
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the zero-stage and durable-result proof together.
fn tool_scheduler_pre_cancel_commits_canonical_results_without_running_tool_stages() {
    let mut chunks = Vec::new();
    for (index, name) in ["cancel-before-a", "cancel-before-b"]
        .into_iter()
        .enumerate()
    {
        chunks.extend(tool_call_chunks(
            u64::try_from(index).unwrap(),
            &format!("{name}-call"),
            name,
            "{}",
        ));
    }
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-scheduler-pre-cancel", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let stages = Arc::new(AtomicUsize::new(0));
    for name in ["cancel-before-a", "cancel-before-b"] {
        let stages = Arc::clone(&stages);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                stages.fetch_add(1, Ordering::SeqCst);
                Ok(json!("must not run"))
            })
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, _| Ok(Vec::new())),
        )
        .unwrap();
    }
    {
        let stages = Arc::clone(&stages);
        ctx.on_waterfall(events::TOOLS_PRE_EXECUTE, move |call: ToolCall, next| {
            stages.fetch_add(1, Ordering::SeqCst);
            next(call)
        })
        .unwrap();
    }
    {
        let stages = Arc::clone(&stages);
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |result: ToolPostExecution, next| {
                stages.fetch_add(1, Ordering::SeqCst);
                next(result)
            },
        )
        .unwrap();
    }
    {
        let stages = Arc::clone(&stages);
        ctx.on_emit(events::TOOLS_RESULT, move |_: &ToolExecutionResult| {
            stages.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    }
    let cancellation = LifecycleCancellation::default();
    cancellation.cancel();

    let results = run_agent_tool_batch_with_limit_and_cancellation(
        &mut ctx,
        &logged,
        &mut recorded,
        2,
        &cancellation,
    )
    .unwrap();

    assert_eq!(stages.load(Ordering::SeqCst), 0);
    assert!(cancellation.is_cancelled());
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(ToolExecutionResult::is_error));
    assert!(results.iter().all(|result| {
        result
            .error()
            .map(|error| (error.name.as_str(), error.code.as_str()))
            == Some(("AbortError", TOOL_ABORTED_BEFORE_DISPATCH))
            && result.content()
                == [SessionContentBlock::Text {
                    text: "Error: tool call aborted before dispatch".into(),
                }]
    }));
    let durable = session
        .events()
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::ToolResult { message, error, .. } => Some((message, error)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(durable.len(), 2);
    assert!(durable.iter().all(|(message, error)| {
        matches!(message.source, SessionMessageSource::Tool { .. })
            && error.as_ref().map(|error| error.code.as_str()) == Some(TOOL_ABORTED_BEFORE_DISPATCH)
    }));
    let after = session.events().unwrap();
    assert!(
        run_agent_tool_batch_with_limit_and_cancellation(
            &mut ctx,
            &logged,
            &mut recorded,
            2,
            &cancellation,
        )
        .is_err()
    );
    assert_eq!(session.events().unwrap(), after);
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep pool timing, drain, and ordered persistence together.
fn tool_scheduler_mid_pool_cancel_drains_started_calls_and_synthesizes_the_rest() {
    let mut chunks = Vec::new();
    for (index, name) in [
        "cancel-pool-1",
        "cancel-pool-2",
        "cancel-pool-3",
        "cancel-pool-4",
    ]
    .into_iter()
    .enumerate()
    {
        chunks.extend(tool_call_chunks(
            u64::try_from(index).unwrap(),
            &format!("{name}-call"),
            name,
            "{}",
        ));
    }
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-scheduler-mid-cancel", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let cancellation = LifecycleCancellation::default();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    for name in [
        "cancel-pool-1",
        "cancel-pool-2",
        "cancel-pool-3",
        "cancel-pool-4",
    ] {
        let cancellation = cancellation.clone();
        let bodies = Arc::clone(&bodies);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new(tool_schema(name), move |_| {
                bodies.lock().unwrap().push(name);
                if name == "cancel-pool-2" {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while !cancellation.is_cancelled() && std::time::Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    if !cancellation.is_cancelled() {
                        return Err("ordered first result did not cancel the batch".into());
                    }
                }
                Ok(json!(name))
            })
            .with_concurrency(|_| Ok(true))
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let cancellation = cancellation.clone();
        let observed = Arc::clone(&observed);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            observed
                .lock()
                .unwrap()
                .push(result.input().call_id().to_string());
            if result.input().call_id() == "cancel-pool-1-call" {
                cancellation.cancel();
            }
        })
        .unwrap();
    }

    let results = run_agent_tool_batch_with_limit_and_cancellation(
        &mut ctx,
        &logged,
        &mut recorded,
        2,
        &cancellation,
    )
    .unwrap();

    let mut bodies = bodies.lock().unwrap().clone();
    bodies.sort_unstable();
    assert_eq!(bodies, ["cancel-pool-1", "cancel-pool-2"]);
    assert_eq!(
        *observed.lock().unwrap(),
        ["cancel-pool-1-call", "cancel-pool-2-call"]
    );
    assert!(cancellation.is_cancelled());
    assert_eq!(results.len(), 4);
    assert_eq!(
        results
            .iter()
            .map(ToolExecutionResult::is_error)
            .collect::<Vec<_>>(),
        [false, false, true, true]
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.error().map(|error| error.code.as_str()))
            .collect::<Vec<_>>(),
        [
            None,
            None,
            Some(TOOL_ABORTED_BEFORE_DISPATCH),
            Some(TOOL_ABORTED_BEFORE_DISPATCH),
        ]
    );
    let durable = session
        .events()
        .unwrap()
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::ToolResult { message, error, .. } => {
                let SessionMessageSource::Tool { call_id } = message.source else {
                    return None;
                };
                Some((call_id, error.map(|error| error.code)))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        durable,
        [
            ("cancel-pool-1-call".into(), None),
            ("cancel-pool-2-call".into(), None),
            (
                "cancel-pool-3-call".into(),
                Some(TOOL_ABORTED_BEFORE_DISPATCH.into()),
            ),
            (
                "cancel-pool-4-call".into(),
                Some(TOOL_ABORTED_BEFORE_DISPATCH.into()),
            ),
        ]
    );
    assert!(recorded.tool_results_committed());
    close_logged_turn(&session, turn);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep body, post-policy, and final-result order together.
fn tool_result_contexts_preserve_order_and_only_success_may_conclude() {
    let mut chunks = Vec::new();
    chunks.extend(tool_call_chunks(
        0,
        "context-success-call",
        "context-success",
        "{}",
    ));
    chunks.extend(tool_call_chunks(
        1,
        "context-block-call",
        "context-block",
        "{}",
    ));
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-result-contexts", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();

    let success_body = plugin_message("context-success-body", "success-body", "body context");
    let success_post = plugin_message("context-success-post", "success-post", "post context");
    let blocked_body = plugin_message("context-block-body", "block-body", "discarded context");
    let blocked_post = plugin_message("context-block-post", "block-post", "blocking context");
    {
        let success_body = success_body.clone();
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new_with_run_context(
                tool_schema("context-success"),
                move |run: &ToolRunContext| {
                    assert_eq!(run.call_id(), "context-success-call");
                    run.defer_context(success_body.clone());
                    run.conclude_turn();
                    Ok(json!("success"))
                },
            )
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    {
        let blocked_body = blocked_body.clone();
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new_with_run_context(
                tool_schema("context-block"),
                move |run: &ToolRunContext| {
                    run.defer_context(blocked_body.clone());
                    run.conclude_turn();
                    Ok(json!("blocked"))
                },
            )
            .with_output_renderer(|_, value| {
                Ok(vec![SessionContentBlock::Text {
                    text: value.as_str().unwrap().into(),
                }])
            }),
        )
        .unwrap();
    }
    {
        let success_post = success_post.clone();
        let blocked_post = blocked_post.clone();
        ctx.on_waterfall(
            events::TOOLS_POST_EXECUTE,
            move |execution: ToolPostExecution, next| {
                let call_id = execution.input().call_id().to_string();
                let execution = next(execution);
                if call_id == "context-success-call" {
                    execution
                        .replace_success(json!("post-success"))
                        .with_additional_context(success_post.clone())
                } else {
                    execution
                        .block("blocked after body")
                        .with_additional_context(blocked_post.clone())
                }
            },
        )
        .unwrap();
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    {
        let observed = Arc::clone(&observed);
        ctx.on_emit(events::TOOLS_RESULT, move |result: &ToolExecutionResult| {
            observed.lock().unwrap().push((
                result.input().call_id().to_string(),
                result.additional_contexts().to_vec(),
                result.concludes_turn(),
                result.is_error(),
            ));
        })
        .unwrap();
    }

    let results = run_agent_tool_batch(&mut ctx, &logged, &mut recorded).unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].additional_contexts(),
        [success_body.clone(), success_post.clone()]
    );
    assert!(results[0].concludes_turn());
    assert!(!results[0].is_error());
    assert_eq!(
        results[1].additional_contexts(),
        std::slice::from_ref(&blocked_post)
    );
    assert!(!results[1].concludes_turn());
    assert!(results[1].is_error());
    assert_eq!(
        *observed.lock().unwrap(),
        [
            (
                "context-success-call".into(),
                vec![success_body, success_post],
                true,
                false,
            ),
            ("context-block-call".into(), vec![blocked_post], false, true,),
        ]
    );
    assert!(session.inbox().next_step().unwrap().is_empty());
    assert!(recorded.tool_results_committed());
    close_logged_turn(&session, turn);
}

#[test]
fn malformed_tool_result_context_becomes_a_final_failure_without_replay() {
    let mut chunks = tool_call_chunks(0, "invalid-context-call", "invalid-context", "{}").to_vec();
    chunks.push(SessionStreamChunk::Finish {
        reason: SessionFinishReason::ToolCalls,
        replay_state: None,
    });
    let (mut ctx, session, turn, logged, mut recorded) =
        recorded_script("tool-invalid-context", chunks);
    commit_agent_stream(&ctx, &logged, &mut recorded).unwrap();
    schedule_agent_tool_calls(&ctx, &logged, &mut recorded).unwrap();
    let bodies = Arc::new(AtomicUsize::new(0));
    {
        let bodies = Arc::clone(&bodies);
        register_tool_definition(
            &mut ctx,
            ToolDefinition::new_with_run_context(
                tool_schema("invalid-context"),
                move |run: &ToolRunContext| {
                    bodies.fetch_add(1, Ordering::SeqCst);
                    run.defer_context(assistant_message("invalid-context-message", "invalid"));
                    run.conclude_turn();
                    Ok(json!("value"))
                },
            )
            .with_output_renderer(|_, _| Ok(Vec::new())),
        )
        .unwrap();
    }

    let results = run_agent_tool_batch(&mut ctx, &logged, &mut recorded).unwrap();

    assert_eq!(bodies.load(Ordering::SeqCst), 1);
    assert_eq!(results.len(), 1);
    assert!(results[0].is_error());
    assert!(results[0].additional_contexts().is_empty());
    assert!(!results[0].concludes_turn());
    assert!(matches!(
        results[0].result(),
        ToolDispatchResult::Failure { message }
            if message.contains("tool additional context is invalid")
    ));
    assert!(session.inbox().next_step().unwrap().is_empty());
    assert!(run_agent_tool_batch(&mut ctx, &logged, &mut recorded).is_err());
    assert_eq!(bodies.load(Ordering::SeqCst), 1);
    close_logged_turn(&session, turn);
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
        ctx.on_waterfall(
            events::LEGACY_TOOLS_EXECUTE,
            move |mut call: ToolCall, next| {
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
            },
        )
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
