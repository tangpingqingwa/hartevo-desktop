//! Cordis-hosted agent loop. OpenInterpreter is an optional runtime plugin,
//! never the loop and never the owner of Domain or Effect.

use std::collections::{HashMap, HashSet};

use futures_util::StreamExt;

use crate::context::{Context, CordisError, keys};
use crate::inbox::AgentInboxTarget;
use crate::invariants::enforce_invariants;
use crate::service::Service;
use crate::session::{
    SessionCallConfig, SessionCallConfigAdapterDefaults, SessionContentBlock, SessionEpochHeader,
    SessionError, SessionEventKind, SessionFinishReason, SessionHandle, SessionId, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionReplayEnvelope, SessionRequestContext,
    SessionRequestHeaderReason, SessionStore, SessionStreamBlockType, SessionStreamChunk,
    SessionSurfaceIntent, SessionTokenUsage, SessionToolCall, SessionToolError, TurnEndReason,
    validate_agent_request_config, validate_agent_user_message, validate_content_blocks,
};
use crate::surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentRequest, AgentsSurface, DomainSurface,
    EffectBrokerSurface, LlmChunkStream, LlmError, LlmGenerateRequest, LlmStream, LlmSurface,
    PreparedLlmCall, PromptAssembly, RuntimeSurface, ToolCall, ToolExecutionInput,
    ToolExecutionPreparation, ToolExecutionResult, ToolsSurface, assemble_system_prompt, events,
    prepare_llm_call, prepare_tool_execution, register_agent, run_tools_pipeline, stream_llm,
    stream_llm_request, stream_prepared_llm,
};

/// Inject keys the loop looks up. Runtime is optional at apply time.
pub const AGENT_LOOP_KEYS: &[&str] = &[
    keys::AGENTS,
    keys::TOOLS,
    keys::SYSTEM_PROMPT,
    keys::LLM,
    keys::SESSIONS,
    keys::DOMAIN,
    keys::EFFECT_BROKER,
];

/// Plugin that hosts one Cordis agent loop on already-mapped surfaces.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AgentLoop;

impl Service for AgentLoop {
    fn inject() -> &'static [&'static str] {
        AGENT_LOOP_KEYS
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        ctx.on_emit(events::AGENT_CREATED, |_: &AgentRef| {})?;
        ctx.on_emit(events::AGENT_DISPOSED, |_: &AgentRef| {})?;
        Ok(())
    }
}

/// One planning step. Optional tool runs through the mapped tools pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStep {
    pub id: String,
    pub prompt: String,
    pub tool: Option<ToolCall>,
}

impl AgentStep {
    #[must_use]
    pub fn new(id: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            prompt: prompt.into(),
            tool: None,
        }
    }

    #[must_use]
    pub fn with_tool(mut self, tool: ToolCall) -> Self {
        self.tool = Some(tool);
        self
    }
}

/// Frozen outcome of [`run_agent_step`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStepResult {
    pub id: String,
    pub plan: LlmStream,
    pub tool: Option<ToolCall>,
}

/// Request-ready state frozen before adapter resolution or request persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAgentRequest {
    agent: AgentRef,
    turn: u64,
    step: u64,
    config: SessionCallConfig,
    messages: Vec<SessionMessage>,
    assembly: PromptAssembly,
    starts_request_series: bool,
    surface_generation: u64,
}

impl PreparedAgentRequest {
    #[must_use]
    pub const fn agent(&self) -> &AgentRef {
        &self.agent
    }

    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[must_use]
    pub const fn config(&self) -> &SessionCallConfig {
        &self.config
    }

    #[must_use]
    pub fn messages(&self) -> &[SessionMessage] {
        &self.messages
    }

    #[must_use]
    pub const fn assembly(&self) -> &PromptAssembly {
        &self.assembly
    }

    #[must_use]
    pub const fn starts_request_series(&self) -> bool {
        self.starts_request_series
    }

    #[must_use]
    pub const fn surface_generation(&self) -> u64 {
        self.surface_generation
    }
}

/// Whether N42 admitted a model request for this proposed step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRequestAdmission {
    NoRequest(AgentPreStep),
    Request(PreparedAgentRequest),
}

/// N43 request state plus an optional exact adapter-generation preparation.
#[derive(Debug, Clone)]
pub struct PreparedAgentCall {
    request: Box<PreparedAgentRequest>,
    prepared: Option<PreparedLlmCall>,
}

impl PreparedAgentCall {
    #[must_use]
    pub fn request(&self) -> &PreparedAgentRequest {
        self.request.as_ref()
    }

    #[must_use]
    pub fn config(&self) -> &SessionCallConfig {
        self.prepared
            .as_ref()
            .map_or_else(|| self.request.config(), PreparedLlmCall::config)
    }

    #[must_use]
    pub fn messages(&self) -> &[SessionMessage] {
        self.request.messages()
    }

    #[must_use]
    pub fn assembly(&self) -> &PromptAssembly {
        self.request.assembly()
    }

    #[must_use]
    pub const fn starts_request_series(&self) -> bool {
        self.request.starts_request_series()
    }

    #[must_use]
    pub fn adapter_defaults(&self) -> Option<&SessionCallConfigAdapterDefaults> {
        self.prepared
            .as_ref()
            .map(PreparedLlmCall::adapter_defaults)
    }

    #[must_use]
    pub fn context_window(&self) -> Option<u64> {
        self.prepared
            .as_ref()
            .and_then(PreparedLlmCall::context_window)
    }

    #[must_use]
    pub const fn prepared_llm_call(&self) -> Option<&PreparedLlmCall> {
        self.prepared.as_ref()
    }
}

/// Whether one proposed step reached exact adapter preparation.
#[derive(Debug, Clone)]
pub enum AgentCallAdmission {
    NoCall(AgentPreStep),
    Call(PreparedAgentCall),
}

/// Per-loop request-log state bound to one exact Session.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentRequestLogState {
    session_id: SessionId,
    header_logged: bool,
    surface_generation: Option<u64>,
}

impl AgentRequestLogState {
    #[must_use]
    pub const fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            header_logged: false,
            surface_generation: None,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn header_logged(&self) -> bool {
        self.header_logged
    }

    #[must_use]
    pub const fn surface_generation(&self) -> Option<u64> {
        self.surface_generation
    }
}

/// One N44 call after its effective request state is durably logged.
#[derive(Debug, Clone)]
pub struct LoggedAgentCall {
    call: PreparedAgentCall,
    header_reason: Option<SessionRequestHeaderReason>,
    context_appended: bool,
}

impl LoggedAgentCall {
    #[must_use]
    pub const fn call(&self) -> &PreparedAgentCall {
        &self.call
    }

    #[must_use]
    pub fn into_call(self) -> PreparedAgentCall {
        self.call
    }

    #[must_use]
    pub const fn header_reason(&self) -> Option<SessionRequestHeaderReason> {
        self.header_reason
    }

    #[must_use]
    pub const fn context_appended(&self) -> bool {
        self.context_appended
    }
}

/// Whether one proposed step reached durable request-state logging.
#[derive(Debug, Clone)]
pub enum AgentBuildAdmission {
    NoCall(AgentPreStep),
    Call(LoggedAgentCall),
}

/// Durable raw-stream outcome retained for downstream block assembly.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordedAgentStream {
    session_id: SessionId,
    turn: u64,
    step: u64,
    chunk_seqs: Vec<u64>,
    finish: SessionFinishReason,
    message_committed: bool,
    tool_call_seqs: Vec<u64>,
    tool_calls_scheduled: bool,
    tool_result_seqs: Vec<u64>,
    tool_results_committed: bool,
}

impl RecordedAgentStream {
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn step(&self) -> u64 {
        self.step
    }

    #[must_use]
    pub fn chunk_seqs(&self) -> &[u64] {
        &self.chunk_seqs
    }

    #[must_use]
    pub const fn finish(&self) -> &SessionFinishReason {
        &self.finish
    }

    #[must_use]
    pub const fn message_committed(&self) -> bool {
        self.message_committed
    }

    /// Exact durable `tool/call` prefix appended by N50.
    #[must_use]
    pub fn tool_call_seqs(&self) -> &[u64] {
        &self.tool_call_seqs
    }

    #[must_use]
    pub const fn tool_calls_scheduled(&self) -> bool {
        self.tool_calls_scheduled
    }

    /// Exact durable `tool/result` prefix appended or adopted by N57.
    #[must_use]
    pub fn tool_result_seqs(&self) -> &[u64] {
        &self.tool_result_seqs
    }

    #[must_use]
    pub const fn tool_results_committed(&self) -> bool {
        self.tool_results_committed
    }
}

/// One recorded model attempt after N49's assistant-message boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentStreamCommit {
    message: Option<SessionMessage>,
    usage: Option<SessionTokenUsage>,
    finish: SessionFinishReason,
    replay_state: Option<SessionReplayEnvelope>,
}

impl AgentStreamCommit {
    /// Successful provider attempts commit one message, including an empty one.
    #[must_use]
    pub const fn message(&self) -> Option<&SessionMessage> {
        self.message.as_ref()
    }

    #[must_use]
    pub const fn usage(&self) -> Option<&SessionTokenUsage> {
        self.usage.as_ref()
    }

    #[must_use]
    pub const fn finish(&self) -> &SessionFinishReason {
        &self.finish
    }

    #[must_use]
    pub const fn replay_state(&self) -> Option<&SessionReplayEnvelope> {
        self.replay_state.as_ref()
    }
}

/// Claim the exact inbox batch, then run the authoritative pre-step waterfall.
///
/// This boundary intentionally returns before `step/start`; the future driver
/// owns the matching reject/enter lifecycle transition.
pub fn prepare_agent_step(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
) -> Result<AgentPreStep, CordisError> {
    require_loop_surfaces(ctx)?;
    let session = agent_session(ctx, session_id)?;
    prepare_agent_step_for_session(ctx, &session, target, turn, step)
}

/// Run pre-step admission and atomically enter only a non-empty accepted step.
///
/// Reject and empty Enter decisions open no step. The future driver owns the
/// matching turn end and every request, model, tool, and step-end transition.
pub fn admit_agent_step(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
) -> Result<AgentPreStep, CordisError> {
    require_loop_surfaces(ctx)?;
    let session = agent_session(ctx, session_id)?;
    let proposal = prepare_agent_step_for_session(ctx, &session, target, turn, step)?;
    if let AgentPreStepDecision::Enter { messages, .. } = proposal.decision()
        && !messages.is_empty()
    {
        session.enter_agent_step(turn, step, messages)?;
    }
    Ok(proposal)
}

/// Enter one accepted step and prepare its exact model-request boundary.
///
/// The durable message snapshot is taken before `agent/request`; that
/// waterfall can replace only call configuration. Adapter lookup, request
/// persistence, streaming, and step closure remain future driver work.
pub fn admit_agent_request(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    seed_config: SessionCallConfig,
) -> Result<AgentRequestAdmission, CordisError> {
    let admission = admit_agent_step(ctx, session_id, target, turn, step)?;
    let starts_request_series = match admission.decision() {
        AgentPreStepDecision::Reject => {
            return Ok(AgentRequestAdmission::NoRequest(admission));
        }
        AgentPreStepDecision::Enter { messages, .. } if messages.is_empty() => {
            return Ok(AgentRequestAdmission::NoRequest(admission));
        }
        AgentPreStepDecision::Enter {
            starts_request_series,
            ..
        } => *starts_request_series,
    };

    let session = agent_session(ctx, session_id)?;
    let (messages, surface_generation) = session.agent_request_boundary(turn, step)?;
    let request = AgentRequest::new(admission.agent().clone(), turn, step, seed_config);
    let request = ctx.waterfall(events::AGENT_REQUEST, request)?;
    validate_agent_request_config(request.config())?;
    session.require_open_step(turn, step)?;

    Ok(AgentRequestAdmission::Request(PreparedAgentRequest {
        agent: admission.agent().clone(),
        turn,
        step,
        config: request.into_config(),
        messages,
        assembly: admission.assembly().clone(),
        starts_request_series,
        surface_generation,
    }))
}

/// Prepare the exact adapter generation for one N43-admitted request.
///
/// A missing adapter alone is retained as an unprepared call so the future
/// generic `llm/stream` Waterfall may serve it, matching Harness behavior.
pub fn prepare_agent_call(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    seed_config: SessionCallConfig,
) -> Result<AgentCallAdmission, CordisError> {
    let request = match admit_agent_request(ctx, session_id, target, turn, step, seed_config)? {
        AgentRequestAdmission::NoRequest(admission) => {
            return Ok(AgentCallAdmission::NoCall(admission));
        }
        AgentRequestAdmission::Request(request) => request,
    };
    let prepared = match prepare_llm_call(ctx, request.config()) {
        Ok(prepared) => Some(prepared),
        Err(CordisError::Llm(LlmError::NoAdapter { .. })) => None,
        Err(error) => return Err(error),
    };
    agent_session(ctx, session_id)?.require_open_step(turn, step)?;
    Ok(AgentCallAdmission::Call(PreparedAgentCall {
        request: Box::new(request),
        prepared,
    }))
}

/// Persist one prepared call's effective header and route metadata atomically.
pub fn log_agent_call(
    ctx: &Context,
    state: &mut AgentRequestLogState,
    call: PreparedAgentCall,
) -> Result<LoggedAgentCall, CordisError> {
    let session_id = SessionId::new(call.request().agent().id.clone())?;
    require_request_log_state_session(state, &session_id)?;
    let session = agent_session(ctx, &session_id)?;
    let surface_generation = call.request().surface_generation();
    let starts_series = call.starts_request_series()
        || state
            .surface_generation
            .is_some_and(|prior| prior != surface_generation);
    let header = SessionEpochHeader {
        config: call.config().clone(),
        adapter_defaults: call.adapter_defaults().cloned(),
        system: call.assembly().system().map(str::to_string),
        tools: (!call.assembly().tools().is_empty()).then(|| call.assembly().tools().to_vec()),
    };
    let context = SessionRequestContext {
        provider: call.config().provider.clone(),
        model: call.config().model.clone(),
        context_window: call.context_window(),
    };
    let recorded = session.record_agent_request_state(
        call.request().turn(),
        call.request().step(),
        header,
        state.header_logged,
        starts_series,
        context,
    )?;
    state.header_logged = true;
    state.surface_generation = Some(surface_generation);
    Ok(LoggedAgentCall {
        call,
        header_reason: recorded.header_reason,
        context_appended: recorded.context_appended,
    })
}

/// Compose N44 preparation with exact durable request-state logging.
pub fn build_agent_call(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    seed_config: SessionCallConfig,
    state: &mut AgentRequestLogState,
) -> Result<AgentBuildAdmission, CordisError> {
    require_request_log_state_session(state, session_id)?;
    match prepare_agent_call(ctx, session_id, target, turn, step, seed_config)? {
        AgentCallAdmission::NoCall(admission) => Ok(AgentBuildAdmission::NoCall(admission)),
        AgentCallAdmission::Call(call) => {
            log_agent_call(ctx, state, call).map(AgentBuildAdmission::Call)
        }
    }
}

/// Dispatch one N45-logged call into the raw provider-neutral stream boundary.
/// The stream remains unconsumed and no assistant/session event is appended.
pub fn dispatch_agent_call(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
) -> Result<LlmChunkStream, CordisError> {
    let call = logged.call();
    let request = call.request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    agent_session(ctx, &session_id)?.require_open_step(request.turn(), request.step())?;
    let generated = LlmGenerateRequest::new(call.config().clone(), call.messages().to_vec())
        .with_system(call.assembly().system().map(str::to_string))
        .with_tools(call.assembly().tools().to_vec())
        .with_session_id(session_id);
    match call.prepared_llm_call() {
        Some(prepared) => stream_prepared_llm(ctx, prepared, generated),
        None => stream_llm_request(ctx, generated),
    }
}

/// Dispatch and durably record one provider-neutral stream in exact order.
///
/// Each chunk is checked against the pinned Harness grammar before it is
/// appended. An invalid item is never written, while any already-committed
/// prefix remains durable and available for replay or recovery.
pub async fn record_agent_stream(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
) -> Result<RecordedAgentStream, CordisError> {
    let request = logged.call().request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    let turn = request.turn();
    let step = request.step();
    let mut stream = dispatch_agent_call(ctx, logged)?;
    let session = agent_session(ctx, &session_id)?;
    let mut grammar = AgentStreamGrammar::default();
    let mut chunk_seqs = Vec::new();

    while let Some(chunk) = stream.next().await {
        grammar.accept(&chunk)?;
        chunk_seqs.push(session.append_assistant_chunk(turn, step, chunk)?);
    }

    let finish = grammar.complete()?;
    session.require_open_step(turn, step)?;
    Ok(RecordedAgentStream {
        session_id,
        turn,
        step,
        chunk_seqs,
        finish,
        message_committed: false,
        tool_call_seqs: Vec::new(),
        tool_calls_scheduled: false,
        tool_result_seqs: Vec::new(),
        tool_results_committed: false,
    })
}

/// Assemble one N48-recorded stream and commit its successful assistant message.
///
/// The exact durable chunk provenance is replayed and revalidated before any
/// message append. Error and aborted finishes remain message-less for the
/// later request-error/retry boundary, and the open step is never closed here.
pub fn commit_agent_stream(
    ctx: &Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
) -> Result<AgentStreamCommit, CordisError> {
    let request = logged.call().request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    let turn = request.turn();
    let step = request.step();
    if recorded.session_id != session_id || recorded.turn != turn || recorded.step != step {
        return Err(invalid_stream_protocol(
            "recorded session, turn, and step to match the logged call",
        )
        .into());
    }
    if recorded.message_committed {
        return Err(
            invalid_stream_protocol("one assistant-message commit per recorded stream").into(),
        );
    }

    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let available = session.assistant_chunks(turn, step)?;
    let mut search_from = 0_usize;
    let mut chunks = Vec::with_capacity(recorded.chunk_seqs.len());
    for expected_seq in &recorded.chunk_seqs {
        let Some(offset) = available[search_from..]
            .iter()
            .position(|record| record.seq == *expected_seq)
        else {
            return Err(invalid_stream_protocol(
                "every recorded sequence to resolve to its durable assistant chunk in order",
            )
            .into());
        };
        let index = search_from + offset;
        chunks.push(available[index].chunk.clone());
        search_from = index + 1;
    }

    let mut grammar = AgentStreamGrammar::default();
    let mut assembler = AgentBlockAssembler::default();
    for chunk in &chunks {
        grammar.accept(chunk)?;
        assembler.push(chunk);
    }
    let finish = grammar.complete()?;
    if finish != recorded.finish {
        return Err(invalid_stream_protocol(
            "the durable terminal finish to match the recorded outcome",
        )
        .into());
    }
    let usage = assembler.usage.clone();

    if matches!(
        finish,
        SessionFinishReason::Error { .. } | SessionFinishReason::Aborted { .. }
    ) {
        return Ok(AgentStreamCommit {
            message: None,
            usage,
            finish,
            replay_state: None,
        });
    }

    let (content, replay_state) = assembler.assemble_success(&finish)?;
    let finish_seq = recorded.chunk_seqs.last().copied().ok_or_else(|| {
        invalid_stream_protocol("a durable terminal finish sequence before message commit")
    })?;
    let message = SessionMessage {
        id: format!(
            "{}:turn:{turn}:step:{step}:assistant:{finish_seq}",
            request.agent().id
        ),
        role: SessionMessageRole::Assistant,
        content,
        source: SessionMessageSource::Model {
            provider: logged.call().config().provider.clone(),
            model: logged.call().config().model.clone(),
        },
    };
    session.append_assistant_message_with_surface(
        turn,
        step,
        message.clone(),
        SessionSurfaceIntent::append_from(recorded.chunk_seqs.clone()),
    )?;
    recorded.message_committed = true;
    Ok(AgentStreamCommit {
        message: Some(message),
        usage,
        finish,
        replay_state,
    })
}

/// Durably schedule N49's committed assistant tool calls in exact model order.
///
/// This boundary records only log-owned `tool/call` events. It deliberately
/// leaves argument parsing, registry classification, policy, execution,
/// results, and step closure to later driver units.
pub fn schedule_agent_tool_calls(
    ctx: &Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
) -> Result<Vec<SessionToolCall>, CordisError> {
    let request = logged.call().request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    let turn = request.turn();
    let step = request.step();
    if recorded.session_id != session_id || recorded.turn != turn || recorded.step != step {
        return Err(invalid_stream_protocol(
            "recorded session, turn, and step to match the logged call",
        )
        .into());
    }
    if !recorded.message_committed {
        return Err(invalid_stream_protocol(
            "a committed assistant message before tool-call scheduling",
        )
        .into());
    }
    if recorded.tool_calls_scheduled {
        return Err(
            invalid_stream_protocol("one tool-call scheduling pass per recorded stream").into(),
        );
    }

    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let message = recorded_assistant_message(&session, logged, recorded)?;
    let planned = planned_tool_calls(&message)?;

    let existing = session.tool_calls(turn, step)?;
    if !tool_call_prefix_matches(&existing, &recorded.tool_call_seqs, &planned) {
        return Err(invalid_stream_protocol(
            "only this scheduling pass's exact durable tool-call prefix",
        )
        .into());
    }

    for (id, name, arguments) in planned.iter().skip(existing.len()) {
        let seq = session.append_tool_call(turn, step, id, name, arguments)?;
        recorded.tool_call_seqs.push(seq);
    }
    let scheduled = session.tool_calls(turn, step)?;
    if scheduled.len() != planned.len()
        || !tool_call_prefix_matches(&scheduled, &recorded.tool_call_seqs, &planned)
    {
        return Err(invalid_stream_protocol(
            "the scheduled tool calls to match the committed assistant message exactly",
        )
        .into());
    }
    recorded.tool_calls_scheduled = true;
    Ok(scheduled)
}

/// Materialize N50's exact durable calls for later policy and dispatch.
///
/// Preparation parses arguments without changing their durable raw form and
/// performs no registry classification or session mutation. A later scheduler
/// can therefore re-read each input's live execution mode immediately before
/// starting it.
pub fn prepare_agent_tool_calls(
    ctx: &Context,
    logged: &LoggedAgentCall,
    recorded: &RecordedAgentStream,
) -> Result<Vec<ToolExecutionInput>, CordisError> {
    let request = logged.call().request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    let turn = request.turn();
    let step = request.step();
    if recorded.session_id != session_id || recorded.turn != turn || recorded.step != step {
        return Err(invalid_stream_protocol(
            "recorded session, turn, and step to match the logged call",
        )
        .into());
    }
    if !recorded.tool_calls_scheduled {
        return Err(invalid_stream_protocol(
            "durably scheduled tool calls before execution preparation",
        )
        .into());
    }

    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let message = recorded_assistant_message(&session, logged, recorded)?;
    let planned = planned_tool_calls(&message)?;
    let scheduled = session.tool_calls(turn, step)?;
    if scheduled.len() != planned.len()
        || !tool_call_prefix_matches(&scheduled, &recorded.tool_call_seqs, &planned)
    {
        return Err(invalid_stream_protocol(
            "the exact durable tool-call sequence before execution preparation",
        )
        .into());
    }
    Ok(scheduled
        .iter()
        .map(ToolExecutionInput::from_session_call)
        .collect())
}

/// Run N51's exact durable inputs through ordered pre-execution policy in
/// model order. This stage still performs no tool body dispatch, result
/// persistence, or step/turn closure.
pub fn prepare_agent_tool_executions(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &RecordedAgentStream,
) -> Result<Vec<ToolExecutionPreparation>, CordisError> {
    prepare_agent_tool_calls(ctx, logged, recorded)?
        .into_iter()
        .map(|input| prepare_tool_execution(ctx, input))
        .collect()
}

/// Commit N56's final tool results to the exact open Session in model order.
///
/// Every result is identity-checked before the first append. An exact durable
/// prefix can be adopted after an interrupted caller and completed without
/// replaying tool execution; any drift fails closed.
pub fn commit_agent_tool_results(
    ctx: &Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    results: &[ToolExecutionResult],
) -> Result<Vec<SessionMessage>, CordisError> {
    if recorded.tool_results_committed {
        return Err(
            invalid_stream_protocol("one tool-result commit pass per recorded stream").into(),
        );
    }
    let inputs = prepare_agent_tool_calls(ctx, logged, recorded)?;
    if inputs.len() != results.len()
        || inputs
            .iter()
            .zip(results)
            .any(|(input, result)| input != result.input())
    {
        return Err(invalid_stream_protocol(
            "one final result for every exact durable tool call in model order",
        )
        .into());
    }
    for result in results {
        validate_content_blocks(result.content(), "tool/result")?;
    }

    let request = logged.call().request();
    let session_id = SessionId::new(request.agent().id.clone())?;
    let turn = request.turn();
    let step = request.step();
    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let planned = results
        .iter()
        .map(|result| PlannedToolResult {
            call_seq: result.input().call_seq(),
            message: SessionMessage {
                id: format!(
                    "{}:turn:{turn}:step:{step}:tool-result:{}",
                    request.agent().id,
                    result.input().call_seq()
                ),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::ToolResult {
                    tool_call_id: result.input().call_id().to_string(),
                    content: result.content().to_vec(),
                    is_error: result.is_error(),
                }],
                source: SessionMessageSource::Tool {
                    call_id: result.input().call_id().to_string(),
                },
            },
        })
        .collect::<Vec<_>>();

    let mut existing = durable_tool_results(&session, turn, step)?;
    if !tool_result_prefix_matches(&existing, &planned)
        || recorded.tool_result_seqs.len() > existing.len()
        || recorded
            .tool_result_seqs
            .iter()
            .zip(&existing)
            .any(|(expected, actual)| *expected != actual.seq)
    {
        return Err(invalid_stream_protocol(
            "only an exact durable model-order tool-result prefix",
        )
        .into());
    }
    recorded.tool_result_seqs.extend(
        existing
            .iter()
            .skip(recorded.tool_result_seqs.len())
            .map(|item| item.seq),
    );

    for result in planned.iter().skip(existing.len()) {
        let seq = session.append_tool_result_with_surface(
            turn,
            step,
            result.message.clone(),
            SessionSurfaceIntent::append_from(vec![result.call_seq]),
        )?;
        recorded.tool_result_seqs.push(seq);
    }
    existing = durable_tool_results(&session, turn, step)?;
    if existing.len() != planned.len()
        || !tool_result_prefix_matches(&existing, &planned)
        || existing
            .iter()
            .zip(&recorded.tool_result_seqs)
            .any(|(actual, expected)| actual.seq != *expected)
    {
        return Err(invalid_stream_protocol(
            "the durable tool results to match every final result exactly",
        )
        .into());
    }
    recorded.tool_results_committed = true;
    Ok(planned.into_iter().map(|result| result.message).collect())
}

#[derive(Debug, PartialEq, Eq)]
struct PlannedToolResult {
    call_seq: u64,
    message: SessionMessage,
}

#[derive(Debug, PartialEq, Eq)]
struct DurableToolResult {
    seq: u64,
    message: SessionMessage,
    error: Option<SessionToolError>,
    surface: SessionSurfaceIntent,
}

fn durable_tool_results(
    session: &SessionHandle,
    turn: u64,
    step: u64,
) -> Result<Vec<DurableToolResult>, SessionError> {
    Ok(session
        .events()?
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::ToolResult {
                turn: result_turn,
                step: result_step,
                message,
                error,
                surface,
            } if result_turn == turn && result_step == step => Some(DurableToolResult {
                seq: event.seq,
                message,
                error,
                surface,
            }),
            _ => None,
        })
        .collect())
}

fn tool_result_prefix_matches(
    existing: &[DurableToolResult],
    planned: &[PlannedToolResult],
) -> bool {
    existing.len() <= planned.len()
        && existing.iter().zip(planned).all(|(actual, expected)| {
            actual.message == expected.message
                && actual.error.is_none()
                && actual.surface == SessionSurfaceIntent::append_from(vec![expected.call_seq])
        })
}

type PlannedToolCall = (String, String, String);

fn recorded_assistant_message(
    session: &SessionHandle,
    logged: &LoggedAgentCall,
    recorded: &RecordedAgentStream,
) -> Result<SessionMessage, CordisError> {
    let finish_seq = recorded.chunk_seqs.last().copied().ok_or_else(|| {
        invalid_stream_protocol("a durable terminal finish sequence before tool-call scheduling")
    })?;
    let expected_id = format!(
        "{}:turn:{}:step:{}:assistant:{finish_seq}",
        logged.call().request().agent().id,
        recorded.turn,
        recorded.step
    );
    let expected_surface = SessionSurfaceIntent::append_from(recorded.chunk_seqs.clone());
    let expected_source = SessionMessageSource::Model {
        provider: logged.call().config().provider.clone(),
        model: logged.call().config().model.clone(),
    };
    let matching = session
        .events()?
        .into_iter()
        .filter_map(|event| match event.kind {
            SessionEventKind::AssistantMessage {
                turn,
                step,
                message,
                surface,
            } if turn == recorded.turn
                && step == recorded.step
                && message.id == expected_id
                && message.source == expected_source
                && surface == expected_surface =>
            {
                Some(message)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [message] = matching.as_slice() else {
        return Err(invalid_stream_protocol(
            "one exact durable assistant message with complete chunk provenance",
        )
        .into());
    };
    Ok(message.clone())
}

fn planned_tool_calls(message: &SessionMessage) -> Result<Vec<PlannedToolCall>, LlmError> {
    let planned = message
        .content
        .iter()
        .filter_map(|block| match block {
            SessionContentBlock::ToolCall {
                id,
                name,
                arguments,
            } => Some((id.clone(), name.clone(), arguments.clone())),
            SessionContentBlock::Text { .. }
            | SessionContentBlock::Reasoning { .. }
            | SessionContentBlock::ToolResult { .. } => None,
        })
        .collect::<Vec<_>>();
    let mut call_ids = HashSet::with_capacity(planned.len());
    if planned.iter().any(|(id, _, _)| !call_ids.insert(id)) {
        return Err(invalid_stream_protocol(
            "unique tool-call ids within one assistant message",
        ));
    }
    Ok(planned)
}

fn tool_call_prefix_matches(
    calls: &[SessionToolCall],
    expected_seqs: &[u64],
    planned: &[PlannedToolCall],
) -> bool {
    calls.len() == expected_seqs.len()
        && calls.len() <= planned.len()
        && calls.iter().zip(expected_seqs).zip(planned).all(
            |((call, expected_seq), (id, name, arguments))| {
                call.seq == *expected_seq
                    && call.call_id == *id
                    && call.name == *name
                    && call.arguments == *arguments
            },
        )
}

#[derive(Default)]
struct AgentBlockAssembler {
    order: Vec<u64>,
    blocks: HashMap<u64, Option<SessionContentBlock>>,
    usage: Option<SessionTokenUsage>,
    replay_state: Option<SessionReplayEnvelope>,
}

impl AgentBlockAssembler {
    fn push(&mut self, chunk: &SessionStreamChunk) {
        match chunk {
            SessionStreamChunk::BlockStart { index, .. } => {
                if !self.blocks.contains_key(index) {
                    self.order.push(*index);
                    self.blocks.insert(*index, None);
                }
            }
            SessionStreamChunk::BlockEnd { index, block } => {
                if let Some(slot) = self.blocks.get_mut(index)
                    && slot.is_none()
                {
                    *slot = Some(block.clone());
                }
            }
            SessionStreamChunk::Usage { usage } => self.usage = Some(usage.clone()),
            SessionStreamChunk::Finish { replay_state, .. } => {
                self.replay_state.clone_from(replay_state);
            }
            SessionStreamChunk::TextDelta { .. }
            | SessionStreamChunk::ReasoningDelta { .. }
            | SessionStreamChunk::ToolCallDelta { .. } => {}
        }
    }

    fn assemble_success(
        self,
        finish: &SessionFinishReason,
    ) -> Result<(Vec<SessionContentBlock>, Option<SessionReplayEnvelope>), LlmError> {
        let mut all = Vec::with_capacity(self.order.len());
        for index in self.order {
            let Some(Some(block)) = self.blocks.get(&index) else {
                return Err(invalid_stream_protocol(
                    "every successful assembled block to have one authoritative close",
                ));
            };
            all.push(block.clone());
        }
        let kept = all
            .iter()
            .map(|block| {
                !matches!(finish, SessionFinishReason::MaxTokens)
                    || !matches!(block, SessionContentBlock::ToolCall { .. })
            })
            .collect::<Vec<_>>();
        let content = all
            .iter()
            .zip(&kept)
            .filter(|(_, keep)| **keep)
            .map(|(block, _)| block.clone())
            .collect::<Vec<_>>();
        let replay_state = match self.replay_state {
            None => None,
            Some(envelope) => match envelope.blocks {
                None => Some(envelope),
                Some(blocks) if blocks.len() == all.len() => Some(SessionReplayEnvelope {
                    response: envelope.response,
                    blocks: Some(
                        blocks
                            .into_iter()
                            .zip(kept)
                            .filter_map(|(block, keep)| keep.then_some(block))
                            .collect(),
                    ),
                }),
                Some(_) => None,
            },
        };
        Ok((content, replay_state))
    }
}

const MAX_SAFE_STREAM_INDEX: u64 = 9_007_199_254_740_991;

#[derive(Default)]
struct AgentStreamGrammar {
    open: HashMap<u64, SessionStreamBlockType>,
    usage_seen: bool,
    finish: Option<SessionFinishReason>,
}

impl AgentStreamGrammar {
    fn accept(&mut self, chunk: &SessionStreamChunk) -> Result<(), LlmError> {
        if self.finish.is_some() {
            return Err(invalid_stream_protocol(
                "no chunks after one terminal finish",
            ));
        }
        match chunk {
            SessionStreamChunk::BlockStart { index, block_type } => {
                validate_stream_index(*index)?;
                if self.open.contains_key(index) {
                    return Err(invalid_stream_protocol("one open block per index"));
                }
                self.open.insert(*index, *block_type);
            }
            SessionStreamChunk::TextDelta { index, .. } => {
                self.validate_delta(*index, SessionStreamBlockType::Text)?;
            }
            SessionStreamChunk::ReasoningDelta { index, .. } => {
                self.validate_delta(*index, SessionStreamBlockType::Reasoning)?;
            }
            SessionStreamChunk::ToolCallDelta { index, .. } => {
                self.validate_delta(*index, SessionStreamBlockType::ToolCall)?;
            }
            SessionStreamChunk::BlockEnd { index, block } => {
                validate_stream_index(*index)?;
                let Some(open_type) = self.open.get(index).copied() else {
                    return Err(invalid_stream_protocol("block-end to target an open block"));
                };
                if stream_block_type(block) != Some(open_type) {
                    return Err(invalid_stream_protocol(
                        "block-end content to match its open block type",
                    ));
                }
                self.open.remove(index);
            }
            SessionStreamChunk::Usage { .. } => {
                if self.usage_seen {
                    return Err(invalid_stream_protocol(
                        "at most one usage chunk before finish",
                    ));
                }
                self.usage_seen = true;
            }
            SessionStreamChunk::Finish { reason, .. } => {
                if !self.open.is_empty()
                    && !matches!(
                        reason,
                        SessionFinishReason::Error { .. } | SessionFinishReason::Aborted { .. }
                    )
                {
                    return Err(invalid_stream_protocol(
                        "successful finish to close every open block",
                    ));
                }
                self.finish = Some(reason.clone());
            }
        }
        Ok(())
    }

    fn validate_delta(&self, index: u64, expected: SessionStreamBlockType) -> Result<(), LlmError> {
        validate_stream_index(index)?;
        if self.open.get(&index).copied() != Some(expected) {
            return Err(invalid_stream_protocol(
                "each delta to target an open block of its matching type",
            ));
        }
        Ok(())
    }

    fn complete(self) -> Result<SessionFinishReason, LlmError> {
        self.finish
            .ok_or_else(|| invalid_stream_protocol("exactly one terminal finish chunk"))
    }
}

fn validate_stream_index(index: u64) -> Result<(), LlmError> {
    if index > MAX_SAFE_STREAM_INDEX {
        return Err(invalid_stream_protocol(
            "block indexes within the non-negative JavaScript safe-integer range",
        ));
    }
    Ok(())
}

fn stream_block_type(block: &SessionContentBlock) -> Option<SessionStreamBlockType> {
    match block {
        SessionContentBlock::Text { .. } => Some(SessionStreamBlockType::Text),
        SessionContentBlock::Reasoning { .. } => Some(SessionStreamBlockType::Reasoning),
        SessionContentBlock::ToolCall { .. } => Some(SessionStreamBlockType::ToolCall),
        SessionContentBlock::ToolResult { .. } => None,
    }
}

const fn invalid_stream_protocol(expected: &'static str) -> LlmError {
    LlmError::InvalidStreamProtocol { expected }
}

fn require_request_log_state_session(
    state: &AgentRequestLogState,
    session_id: &SessionId,
) -> Result<(), SessionError> {
    if state.session_id == *session_id {
        return Ok(());
    }
    Err(SessionError::RequestLogStateSessionMismatch {
        expected: state.session_id.clone(),
        actual: session_id.clone(),
    })
}

fn agent_session(ctx: &Context, session_id: &SessionId) -> Result<SessionHandle, CordisError> {
    ctx.sessions::<SessionStore>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::SESSIONS.to_string()]))?
        .get(session_id)?
        .ok_or_else(|| {
            SessionError::SessionNotFound {
                id: session_id.clone(),
            }
            .into()
        })
}

fn prepare_agent_step_for_session(
    ctx: &mut Context,
    session: &SessionHandle,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
) -> Result<AgentPreStep, CordisError> {
    let claimed = session.inbox().claim(target, turn)?;
    let assembly = assemble_system_prompt(ctx)?;
    let proposal = AgentPreStep::enter(
        AgentRef::new(session.id().as_str()),
        turn,
        step,
        claimed,
        assembly,
    );
    let proposal = ctx.waterfall(events::AGENT_PRE_STEP, proposal)?;
    if let AgentPreStepDecision::Enter { messages, .. } = proposal.decision() {
        for message in messages {
            validate_agent_user_message(message, "agent/pre-step")?;
        }
    }
    Ok(proposal)
}

/// Register the live agent, plan via `ctx.llm`, optionally execute a tool,
/// then read Domain facts and write externally only through Effect Broker.
pub fn run_agent_step(ctx: &mut Context, step: AgentStep) -> Result<AgentStepResult, CordisError> {
    require_loop_surfaces(ctx)?;
    let sessions = ctx
        .sessions::<SessionStore>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::SESSIONS.to_string()]))?;
    let session = sessions.get_or_create(SessionId::new(step.id.clone())?)?;
    let turn = session.start_turn()?;
    if let Err(error) = enforce_invariants(ctx) {
        session.finish_turn(turn, TurnEndReason::Blocked)?;
        return Err(error);
    }
    let session_step = session.start_step(turn)?;

    let result = run_ready_agent_step(ctx, &session, turn, session_step, step);
    session.finish_step(turn, session_step)?;
    session.finish_turn(
        turn,
        if result.is_ok() {
            TurnEndReason::Completed
        } else {
            TurnEndReason::Error
        },
    )?;
    result
}

fn run_ready_agent_step(
    ctx: &mut Context,
    session: &SessionHandle,
    turn: u64,
    session_step: u64,
    step: AgentStep,
) -> Result<AgentStepResult, CordisError> {
    // Runtime may name OpenInterpreter as an adapter plugin; it is not the loop.
    let _runtime = ctx.runtime::<RuntimeSurface>();

    let AgentStep {
        id,
        prompt,
        mut tool,
    } = step;
    let agent = AgentRef::new(id.clone());
    register_agent(ctx, agent.clone())?;
    ctx.emit(events::AGENT_CREATED, &agent)?;

    session.append_user_message(SessionMessage {
        id: message_id(&id, turn, session_step, "user"),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text {
            text: prompt.clone(),
        }],
        source: SessionMessageSource::User,
    })?;

    if let Some(call) = &mut tool
        && call.call_id.is_empty()
    {
        call.call_id = message_id(&id, turn, session_step, "tool-1");
    }

    let plan = stream_llm(ctx, LlmStream::new("hartevo-local", prompt))?;
    let mut assistant_content = Vec::with_capacity(usize::from(tool.is_some()) + 1);
    if !plan.body.is_empty() {
        assistant_content.push(SessionContentBlock::Text {
            text: plan.body.clone(),
        });
    }
    if let Some(call) = &tool {
        assistant_content.push(SessionContentBlock::ToolCall {
            id: call.call_id.clone(),
            name: call.name.clone(),
            arguments: call.arguments.clone(),
        });
    }
    session.append_assistant_message(
        turn,
        session_step,
        SessionMessage {
            id: message_id(&id, turn, session_step, "assistant"),
            role: SessionMessageRole::Assistant,
            content: assistant_content,
            source: SessionMessageSource::Model {
                provider: "hartevo-local".into(),
                model: plan.model.clone(),
            },
        },
    )?;

    let tool = match tool {
        Some(call) => {
            let call_seq = session.append_tool_call(
                turn,
                session_step,
                call.call_id.clone(),
                call.name.clone(),
                call.arguments.clone(),
            )?;
            let completed = run_tools_pipeline(ctx, call)?;
            session.append_tool_result_with_surface(
                turn,
                session_step,
                SessionMessage {
                    id: message_id(&id, turn, session_step, "tool-result-1"),
                    role: SessionMessageRole::User,
                    content: vec![SessionContentBlock::ToolResult {
                        tool_call_id: completed.call_id.clone(),
                        content: vec![SessionContentBlock::Text {
                            text: completed.result.clone(),
                        }],
                        is_error: completed.decision != "allow",
                    }],
                    source: SessionMessageSource::Tool {
                        call_id: completed.call_id.clone(),
                    },
                },
                SessionSurfaceIntent::append_from(vec![call_seq]),
            )?;
            Some(completed)
        }
        None => None,
    };

    Ok(AgentStepResult { id, plan, tool })
}

fn message_id(id: &str, turn: u64, step: u64, kind: &str) -> String {
    format!("{id}:turn-{turn}:step-{step}:{kind}")
}

fn require_loop_surfaces(ctx: &Context) -> Result<(), CordisError> {
    let mut missing = Vec::new();
    if ctx.agents::<AgentsSurface>().is_none() {
        missing.push(keys::AGENTS.to_string());
    }
    if ctx.tools::<ToolsSurface>().is_none() {
        missing.push(keys::TOOLS.to_string());
    }
    if ctx
        .system_prompt::<crate::surface::SystemPromptSurface>()
        .is_none()
    {
        missing.push(keys::SYSTEM_PROMPT.to_string());
    }
    if ctx.llm::<LlmSurface>().is_none() {
        missing.push(keys::LLM.to_string());
    }
    if ctx.sessions::<SessionStore>().is_none() {
        missing.push(keys::SESSIONS.to_string());
    }
    if ctx.domain::<DomainSurface>().is_none() {
        missing.push(keys::DOMAIN.to_string());
    }
    if ctx.effect_broker::<EffectBrokerSurface>().is_none() {
        missing.push(keys::EFFECT_BROKER.to_string());
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(CordisError::MissingDependencies(missing))
    }
}
