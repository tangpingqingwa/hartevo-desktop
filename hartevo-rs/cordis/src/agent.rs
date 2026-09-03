//! Cordis-hosted agent loop. OpenInterpreter is an optional runtime plugin,
//! never the loop and never the owner of Domain or Effect.

use std::collections::{HashMap, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::time::Duration;

use futures_util::StreamExt;

use crate::approval::{ApprovalError, ApprovalOutcome, ApprovalRequest, request_approval};
use crate::compaction_automation::{
    ContextOverflowRecovery, compact_before_agent_step, recover_context_overflow,
};
use crate::context::{Context, CordisError, keys};
use crate::fiber::LifecycleCancellation;
use crate::inbox::AgentInboxTarget;
use crate::invariants::{enforce_invariants, enforce_runtime_invariants};
use crate::service::Service;
use crate::session::{
    SessionCallConfig, SessionCallConfigAdapterDefaults, SessionCancelCause, SessionContentBlock,
    SessionEpochHeader, SessionError, SessionEventKind, SessionFinishReason, SessionHandle,
    SessionId, SessionLlmFailure, SessionLlmRetry, SessionLlmRetryStarted, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionReplayEnvelope, SessionRequestContext,
    SessionRequestHeaderReason, SessionStore, SessionStreamBlockType, SessionStreamChunk,
    SessionSurfaceIntent, SessionTokenUsage, SessionToolCall, SessionToolError, TurnEndReason,
    validate_agent_request_config, validate_agent_user_message, validate_content_blocks,
};
use crate::surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentRequest, AgentRequestError,
    AgentRequestErrorAction, AgentStatusChange, AgentTurnStopping, AgentsSurface, DomainSurface,
    EffectBrokerSurface, HostToolAccess, LlmChunkStream, LlmError, LlmGenerateRequest, LlmStream,
    LlmSurface, PreparedLlmCall, PromptAssembly, RuntimeSurface, ToolCall, ToolExecutionInput,
    ToolExecutionPreparation, ToolExecutionResult, ToolPolicyPreparation, ToolsSurface,
    aborted_before_dispatch_tool_result, assemble_system_prompt, denied_tool_dispatch_outcome,
    dispatch_host_tool_execution_with_cancellation, dispatch_tool_execution_with_cancellation,
    events, finalize_allowed_tool_policy, finalize_tool_execution, post_tool_execution,
    prepare_llm_call, prepare_tool_execution, prepare_tool_policy, register_agent,
    run_tools_pipeline, schedule_tool_dispatch, settle_denied_tool_execution, stream_llm,
    stream_llm_request, stream_prepared_llm,
};

/// DeepSeek Harness-compatible default bound for overlapping tool bodies.
pub const DEFAULT_MAX_PARALLEL_TOOL_CALLS: usize = 10;

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
        ctx.on_emit(events::AGENT_STATUS, |_: &AgentStatusChange| {})?;
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

/// Final results and step-control metadata settled by one exact tool batch.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentToolBatchOutcome {
    results: Vec<ToolExecutionResult>,
    concludes_turn: bool,
}

impl AgentToolBatchOutcome {
    #[must_use]
    pub fn results(&self) -> &[ToolExecutionResult] {
        &self.results
    }

    #[must_use]
    pub const fn concludes_turn(&self) -> bool {
        self.concludes_turn
    }

    #[must_use]
    pub fn into_results(self) -> Vec<ToolExecutionResult> {
        self.results
    }
}

/// Durable terminal state produced by one complete Harness-compatible turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentTurnOutcome {
    turn: u64,
    steps: u64,
    reason: TurnEndReason,
}

impl AgentTurnOutcome {
    #[must_use]
    pub const fn turn(&self) -> u64 {
        self.turn
    }

    #[must_use]
    pub const fn steps(&self) -> u64 {
        self.steps
    }

    #[must_use]
    pub const fn reason(&self) -> TurnEndReason {
        self.reason
    }
}

/// Request-ready state frozen before adapter resolution or request persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAgentRequest {
    agent: AgentRef,
    session_id: SessionId,
    turn: u64,
    step: u64,
    cancellation: LifecycleCancellation,
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

    /// Durable Session driven by this request.
    ///
    /// Agent and Session identities are intentionally independent: a Desktop
    /// Runtime permit may publish a scoped live Agent while driving a
    /// Mission-backed Session with a different id.
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

    /// Exact caller-owned cancellation lineage shared by this Agent turn.
    #[must_use]
    pub const fn cancellation(&self) -> &LifecycleCancellation {
        &self.cancellation
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentToolBatchState {
    Ready,
    Started,
}

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
    tool_batch_state: AgentToolBatchState,
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

    #[must_use]
    pub const fn tool_batch_started(&self) -> bool {
        matches!(self.tool_batch_state, AgentToolBatchState::Started)
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
/// This boundary intentionally returns before `step/start`; the caller owns
/// the matching reject/enter lifecycle transition.
pub fn prepare_agent_step(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
) -> Result<AgentPreStep, CordisError> {
    require_loop_surfaces(ctx)?;
    let session = agent_session(ctx, session_id)?;
    let agent = AgentRef::new(session.id().as_str());
    prepare_agent_step_for_session(
        ctx,
        &session,
        &agent,
        target,
        turn,
        step,
        &LifecycleCancellation::default(),
    )
}

/// Run pre-step admission and atomically enter only a non-empty accepted step.
///
/// Reject and empty Enter decisions open no step. The complete driver owns the
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
    let agent = AgentRef::new(session.id().as_str());
    let proposal = prepare_agent_step_for_session(
        ctx,
        &session,
        &agent,
        target,
        turn,
        step,
        &LifecycleCancellation::default(),
    )?;
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
/// persistence, streaming, and step closure remain caller or driver work.
pub fn admit_agent_request(
    ctx: &mut Context,
    session_id: &SessionId,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    seed_config: SessionCallConfig,
) -> Result<AgentRequestAdmission, CordisError> {
    let agent = AgentRef::new(session_id.as_str());
    admit_agent_request_internal(
        ctx,
        session_id,
        AgentTurnRequest {
            agent: &agent,
            target,
            turn,
            step,
            seed_config,
            cancellation: &LifecycleCancellation::default(),
            allow_empty_continuation: false,
        },
    )
}

struct AgentTurnRequest<'a> {
    agent: &'a AgentRef,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    seed_config: SessionCallConfig,
    cancellation: &'a LifecycleCancellation,
    allow_empty_continuation: bool,
}

fn admit_agent_request_internal(
    ctx: &mut Context,
    session_id: &SessionId,
    request: AgentTurnRequest<'_>,
) -> Result<AgentRequestAdmission, CordisError> {
    let AgentTurnRequest {
        agent,
        target,
        turn,
        step,
        seed_config,
        cancellation,
        allow_empty_continuation,
    } = request;
    require_loop_surfaces(ctx)?;
    let session = agent_session(ctx, session_id)?;
    let admission =
        prepare_agent_step_for_session(ctx, &session, agent, target, turn, step, cancellation)?;
    let starts_request_series = match admission.decision() {
        AgentPreStepDecision::Reject => {
            return Ok(AgentRequestAdmission::NoRequest(admission));
        }
        AgentPreStepDecision::Enter { messages, .. }
            if messages.is_empty() && !allow_empty_continuation =>
        {
            return Ok(AgentRequestAdmission::NoRequest(admission));
        }
        AgentPreStepDecision::Enter {
            starts_request_series,
            ..
        } => *starts_request_series,
    };

    let admitted_messages = match admission.decision() {
        AgentPreStepDecision::Enter { messages, .. } => messages,
        AgentPreStepDecision::Reject => unreachable!("reject returned before step entry"),
    };
    session.enter_agent_step(turn, step, admitted_messages)?;
    let (messages, surface_generation) = session.agent_request_boundary(turn, step)?;
    let request = AgentRequest::new(
        admission.agent().clone(),
        turn,
        step,
        seed_config,
        cancellation.clone(),
    );
    let request = ctx.waterfall(events::AGENT_REQUEST, request)?;
    validate_agent_request_config(request.config())?;
    session.require_open_step(turn, step)?;

    let cancellation = request.cancellation().clone();
    Ok(AgentRequestAdmission::Request(PreparedAgentRequest {
        agent: admission.agent().clone(),
        session_id: session_id.clone(),
        turn,
        step,
        cancellation,
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
    prepare_admitted_agent_call(ctx, session_id, turn, step, request).map(AgentCallAdmission::Call)
}

fn prepare_admitted_agent_call(
    ctx: &mut Context,
    session_id: &SessionId,
    turn: u64,
    step: u64,
    request: PreparedAgentRequest,
) -> Result<PreparedAgentCall, CordisError> {
    if request.session_id() != session_id {
        return Err(SessionError::RequestLogStateSessionMismatch {
            expected: session_id.clone(),
            actual: request.session_id().clone(),
        }
        .into());
    }
    let prepared = match prepare_llm_call(ctx, request.config()) {
        Ok(prepared) => Some(prepared),
        Err(CordisError::Llm(LlmError::NoAdapter { .. })) => None,
        Err(error) => return Err(error),
    };
    agent_session(ctx, session_id)?.require_open_step(turn, step)?;
    Ok(PreparedAgentCall {
        request: Box::new(request),
        prepared,
    })
}

/// Persist one prepared call's effective header and route metadata atomically.
pub fn log_agent_call(
    ctx: &Context,
    state: &mut AgentRequestLogState,
    call: PreparedAgentCall,
) -> Result<LoggedAgentCall, CordisError> {
    let session_id = call.request().session_id().clone();
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

fn build_agent_turn_call(
    ctx: &mut Context,
    state: &mut AgentRequestLogState,
    request: AgentTurnRequest<'_>,
) -> Result<AgentBuildAdmission, CordisError> {
    let session_id = state.session_id().clone();
    let turn = request.turn;
    let step = request.step;
    let request = match admit_agent_request_internal(ctx, &session_id, request)? {
        AgentRequestAdmission::NoRequest(admission) => {
            return Ok(AgentBuildAdmission::NoCall(admission));
        }
        AgentRequestAdmission::Request(request) => request,
    };
    let call = prepare_admitted_agent_call(ctx, &session_id, turn, step, request)?;
    log_agent_call(ctx, state, call).map(AgentBuildAdmission::Call)
}

/// Rebuild one fresh provider attempt without reclaiming or reopening its step.
fn rebuild_agent_turn_call(
    ctx: &mut Context,
    state: &mut AgentRequestLogState,
    prior: &LoggedAgentCall,
) -> Result<LoggedAgentCall, CordisError> {
    let prior_request = prior.call().request();
    let agent = prior_request.agent().clone();
    let session_id = prior_request.session_id().clone();
    let turn = prior_request.turn();
    let step = prior_request.step();
    let cancellation = prior_request.cancellation().clone();
    let assembly = prior_request.assembly().clone();
    require_request_log_state_session(state, &session_id)?;

    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let header = session
        .request_header()?
        .ok_or(LlmError::InvalidPreparedCall {
            expected: "a durable request header before same-step retry",
        })?;
    let seed_config = request_proposal_from_header(header);
    let (messages, surface_generation) = session.agent_request_boundary(turn, step)?;
    let request = AgentRequest::new(agent.clone(), turn, step, seed_config, cancellation.clone());
    let request = ctx.waterfall(events::AGENT_REQUEST, request)?;
    validate_agent_request_config(request.config())?;
    session.require_open_step(turn, step)?;

    let request = PreparedAgentRequest {
        agent,
        session_id: session_id.clone(),
        turn,
        step,
        cancellation: request.cancellation().clone(),
        config: request.into_config(),
        messages,
        assembly,
        starts_request_series: false,
        surface_generation,
    };
    let call = prepare_admitted_agent_call(ctx, &session_id, turn, step, request)?;
    log_agent_call(ctx, state, call)
}

fn request_proposal_from_header(mut header: SessionEpochHeader) -> SessionCallConfig {
    if let Some(defaults) = header.adapter_defaults {
        if defaults.reasoning_effort {
            header.config.reasoning_effort = None;
        }
        if defaults.max_tokens {
            header.config.max_tokens = None;
        }
    }
    header.config
}

/// Run one complete durable agent turn over the canonical Cordis primitives.
///
/// Cancellation is content-free at this boundary and records its immutable
/// first typed cause. Legacy callers retain the stable legacy cause. Provider
/// request failures remain structured in the returned error while the Session
/// always receives an `Error` turn end.
pub async fn run_agent_turn(
    ctx: &mut Context,
    session_id: &SessionId,
    seed_config: SessionCallConfig,
    cancellation: &LifecycleCancellation,
) -> Result<AgentTurnOutcome, CordisError> {
    let agents = ctx
        .agents::<AgentsSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::AGENTS.to_string()]))?;
    let agent = agents
        .get(session_id.as_str())?
        .unwrap_or_else(|| AgentRef::new(session_id.as_str()));
    run_agent_turn_with_invariants(
        ctx,
        &agent,
        session_id,
        seed_config,
        cancellation,
        enforce_invariants,
        HostToolAccess::Denied,
    )
    .await
}

/// Run the same durable turn grammar under the read/plan Runtime gate.
///
/// This stays crate-private: [`crate::CordisHost`] exposes it only after
/// validating an unforgeable active Runtime permit from the same host.
pub(crate) async fn run_authorized_runtime_agent_turn(
    ctx: &mut Context,
    agent: &AgentRef,
    session_id: &SessionId,
    seed_config: SessionCallConfig,
    cancellation: &LifecycleCancellation,
) -> Result<AgentTurnOutcome, CordisError> {
    run_agent_turn_with_invariants(
        ctx,
        agent,
        session_id,
        seed_config,
        cancellation,
        enforce_runtime_invariants,
        HostToolAccess::RuntimeAuthorized,
    )
    .await
}

async fn run_agent_turn_with_invariants(
    ctx: &mut Context,
    agent: &AgentRef,
    session_id: &SessionId,
    seed_config: SessionCallConfig,
    cancellation: &LifecycleCancellation,
    enforce: fn(&Context) -> Result<(), CordisError>,
    host_tool_access: HostToolAccess,
) -> Result<AgentTurnOutcome, CordisError> {
    require_loop_surfaces(ctx)?;
    validate_agent_request_config(&seed_config)?;
    let session = agent_session(ctx, session_id)?;
    let turn = session.start_turn()?;

    if cancellation.is_cancelled() {
        let outcome = AgentTurnOutcome {
            turn,
            steps: 0,
            reason: cancelled_turn_reason(cancellation),
        };
        session.finish_turn(turn, outcome.reason)?;
        return Ok(outcome);
    }
    if let Err(error) = enforce(ctx) {
        session.finish_turn(turn, TurnEndReason::Blocked)?;
        return Err(error);
    }

    let mut current_step = None;
    let result = drive_agent_turn(
        ctx,
        agent,
        &session,
        turn,
        seed_config,
        cancellation,
        &mut current_step,
        host_tool_access,
    )
    .await;
    let reason = result.as_ref().map_or_else(
        |_| {
            if cancellation.is_cancelled() {
                cancelled_turn_reason(cancellation)
            } else {
                TurnEndReason::Error
            }
        },
        AgentTurnOutcome::reason,
    );

    if let Some(step) = current_step {
        match session.require_open_step(turn, step) {
            Ok(()) => session.finish_step(turn, step)?,
            Err(SessionError::NoOpenStep { .. }) => {}
            Err(error) => return Err(error.into()),
        }
    }
    session.finish_turn(turn, reason)?;
    result
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the durable turn driver keeps exact identity, cancellation, host admission, step ownership, and terminal steering together"
)]
async fn drive_agent_turn(
    ctx: &mut Context,
    agent: &AgentRef,
    session: &SessionHandle,
    turn: u64,
    seed_config: SessionCallConfig,
    cancellation: &LifecycleCancellation,
    current_step: &mut Option<u64>,
    host_tool_access: HostToolAccess,
) -> Result<AgentTurnOutcome, CordisError> {
    let mut target = AgentInboxTarget::NextTurn;
    let mut steps = 0_u64;
    let mut turn_end = None;
    let mut request_state = AgentRequestLogState::new(session.id().clone());

    loop {
        if cancellation.is_cancelled() {
            return Ok(AgentTurnOutcome {
                turn,
                steps,
                reason: cancelled_turn_reason(cancellation),
            });
        }
        let allow_empty_continuation = steps > 0 && turn_end.is_none();
        if maintain_agent_step_pressure(
            ctx,
            session,
            target,
            allow_empty_continuation,
            turn,
            cancellation,
        )
        .await?
        {
            return Ok(AgentTurnOutcome {
                turn,
                steps,
                reason: cancelled_turn_reason(cancellation),
            });
        }
        let step = steps
            .checked_add(1)
            .ok_or(SessionError::StepSequenceOverflow { turn })?;
        *current_step = Some(step);
        let admission = build_agent_turn_call(
            ctx,
            &mut request_state,
            AgentTurnRequest {
                agent,
                target,
                turn,
                step,
                seed_config: seed_config.clone(),
                cancellation,
                allow_empty_continuation,
            },
        )?;
        let logged = match admission {
            AgentBuildAdmission::NoCall(proposal) => match proposal.decision() {
                AgentPreStepDecision::Reject => {
                    return Ok(AgentTurnOutcome {
                        turn,
                        steps,
                        reason: TurnEndReason::Blocked,
                    });
                }
                AgentPreStepDecision::Enter { .. } => {
                    return Ok(AgentTurnOutcome {
                        turn,
                        steps,
                        reason: turn_end.unwrap_or(TurnEndReason::Completed),
                    });
                }
            },
            AgentBuildAdmission::Call(logged) => logged,
        };
        steps = step;

        let step_result = run_agent_turn_step(
            ctx,
            logged,
            &mut request_state,
            cancellation,
            host_tool_access,
        )
        .await;
        session.finish_step(turn, step)?;
        let step_end = step_result?;
        if let Some(reason @ TurnEndReason::Aborted(_)) = step_end {
            return Ok(AgentTurnOutcome {
                turn,
                steps,
                reason,
            });
        }
        if !matches!(turn_end, Some(TurnEndReason::MaxTokens)) {
            turn_end = step_end;
        }

        if cancellation.is_cancelled() {
            return Ok(AgentTurnOutcome {
                turn,
                steps,
                reason: cancelled_turn_reason(cancellation),
            });
        }
        if let Some(reason) = turn_end {
            if session.inbox().next_step()?.is_empty() {
                let stopping = AgentTurnStopping::new(agent.clone(), turn, cancellation.clone());
                let _ = ctx.serial(events::AGENT_TURN_STOPPING, stopping).await?;
                if cancellation.is_cancelled() {
                    return Ok(AgentTurnOutcome {
                        turn,
                        steps,
                        reason: cancelled_turn_reason(cancellation),
                    });
                }
            }
            if session.inbox().next_step()?.is_empty() {
                return Ok(AgentTurnOutcome {
                    turn,
                    steps,
                    reason,
                });
            }
        }
        target = AgentInboxTarget::NextStep;
    }
}

async fn maintain_agent_step_pressure(
    ctx: &mut Context,
    session: &SessionHandle,
    target: AgentInboxTarget,
    allow_empty_continuation: bool,
    turn: u64,
    cancellation: &LifecycleCancellation,
) -> Result<bool, SessionError> {
    if has_agent_step_candidate(session, target, allow_empty_continuation)? {
        // Harness pressure maintenance is best-effort: configuration or
        // summarization failure must not block the user's turn.
        let _ = compact_before_agent_step(ctx, session, turn, cancellation).await;
    }
    Ok(cancellation.is_cancelled())
}

fn has_agent_step_candidate(
    session: &SessionHandle,
    target: AgentInboxTarget,
    allow_empty_continuation: bool,
) -> Result<bool, SessionError> {
    if allow_empty_continuation {
        return Ok(true);
    }
    match target {
        AgentInboxTarget::NextTurn => Ok(!session.inbox().next_turn()?.is_empty()),
        AgentInboxTarget::NextStep => Ok(!session.inbox().next_step()?.is_empty()),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "same-step provider recovery and one authorized tool settlement remain one ordered durable operation"
)]
async fn run_agent_turn_step(
    ctx: &mut Context,
    mut logged: LoggedAgentCall,
    request_state: &mut AgentRequestLogState,
    cancellation: &LifecycleCancellation,
    host_tool_access: HostToolAccess,
) -> Result<Option<TurnEndReason>, CordisError> {
    let mut overflow_retries = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            return Ok(Some(cancelled_turn_reason(cancellation)));
        }
        let mut recorded = record_agent_stream(ctx, &logged).await?;
        if cancellation.is_cancelled() {
            return Ok(Some(cancelled_turn_reason(cancellation)));
        }
        let committed = commit_agent_stream(ctx, &logged, &mut recorded)?;
        if cancellation.is_cancelled() {
            return Ok(Some(cancelled_turn_reason(cancellation)));
        }

        let failed = match committed.finish() {
            SessionFinishReason::Error { failure } | SessionFinishReason::Aborted { failure } => {
                Some(failure.clone())
            }
            SessionFinishReason::Stop
            | SessionFinishReason::ToolCalls
            | SessionFinishReason::MaxTokens => None,
        };
        if let Some(failure) = failed {
            let request = logged.call().request();
            let session = agent_session(ctx, request.session_id())?;
            let overflow_recovery = recover_context_overflow(
                ctx,
                &session,
                request.turn(),
                overflow_retries,
                &failure,
                request.cancellation(),
            )
            .await
            .unwrap_or(ContextOverflowRecovery::PreserveFailure);
            if cancellation.is_cancelled() {
                return Ok(Some(cancelled_turn_reason(cancellation)));
            }
            if overflow_recovery.should_retry() {
                overflow_retries = overflow_retries.saturating_add(1);
                logged = rebuild_agent_turn_call(ctx, request_state, &logged)?;
                continue;
            }
            let recovery = AgentRequestError::new(
                request.agent().clone(),
                request.session_id().clone(),
                request.turn(),
                request.step(),
                logged.call().config().provider.clone(),
                failure.clone(),
                logged
                    .call()
                    .prepared_llm_call()
                    .and_then(PreparedLlmCall::retry_policy)
                    .cloned(),
                request.cancellation().clone(),
            );
            let recovery = ctx.try_waterfall(events::AGENT_REQUEST_ERROR, recovery)?;
            if cancellation.is_cancelled() {
                return Ok(Some(cancelled_turn_reason(cancellation)));
            }
            if recovery.action() != AgentRequestErrorAction::Retry {
                return Err(LlmError::RequestFailed { failure }.into());
            }
            if !prepare_scheduled_retry(ctx, &recovery, &failure, cancellation).await? {
                return Ok(Some(cancelled_turn_reason(cancellation)));
            }
            logged = rebuild_agent_turn_call(ctx, request_state, &logged)?;
            continue;
        }

        match committed.finish() {
            SessionFinishReason::MaxTokens => return Ok(Some(TurnEndReason::MaxTokens)),
            SessionFinishReason::Stop | SessionFinishReason::ToolCalls => {
                let calls = schedule_agent_tool_calls(ctx, &logged, &mut recorded)?;
                if calls.is_empty() {
                    return Ok(Some(TurnEndReason::Completed));
                }
                let outcome = run_agent_tool_batch_with_approval(
                    ctx,
                    &logged,
                    &mut recorded,
                    DEFAULT_MAX_PARALLEL_TOOL_CALLS,
                    cancellation,
                    host_tool_access,
                )
                .await?;
                if cancellation.is_cancelled() {
                    return Ok(Some(cancelled_turn_reason(cancellation)));
                }
                return if outcome.concludes_turn() {
                    Ok(Some(TurnEndReason::Completed))
                } else {
                    Ok(None)
                };
            }
            SessionFinishReason::Error { .. } | SessionFinishReason::Aborted { .. } => {
                unreachable!("provider failures return or retry above")
            }
        }
    }
}

async fn prepare_scheduled_retry(
    ctx: &Context,
    recovery: &AgentRequestError,
    failure: &SessionLlmFailure,
    cancellation: &LifecycleCancellation,
) -> Result<bool, CordisError> {
    let Some(schedule) = recovery.retry_schedule() else {
        return Ok(true);
    };
    let retry_session = agent_session(ctx, recovery.session_id())?;
    retry_session.append_llm_retry(SessionLlmRetry {
        retry_id: schedule.retry_id().to_owned(),
        turn: recovery.turn(),
        step: recovery.step(),
        provider: recovery.provider().to_owned(),
        mode: schedule.mode(),
        policy_key: schedule.policy_key().to_owned(),
        retry: schedule.retry(),
        max_retries: schedule.max_retries(),
        delay_ms: schedule.delay_ms(),
        failure: failure.clone(),
    })?;
    if !wait_for_retry(schedule.delay_ms(), cancellation).await || cancellation.is_cancelled() {
        return Ok(false);
    }
    retry_session.append_llm_retry_started(SessionLlmRetryStarted {
        retry_id: schedule.retry_id().to_owned(),
        turn: recovery.turn(),
        step: recovery.step(),
        retry: schedule.retry(),
    })?;
    Ok(!cancellation.is_cancelled())
}

async fn wait_for_retry(delay_ms: u64, cancellation: &LifecycleCancellation) -> bool {
    if cancellation.is_cancelled() {
        return false;
    }
    tokio::select! {
        biased;
        () = cancellation.cancelled() => false,
        () = tokio::time::sleep(Duration::from_millis(delay_ms)) => !cancellation.is_cancelled(),
    }
}

fn cancelled_turn_reason(cancellation: &LifecycleCancellation) -> TurnEndReason {
    TurnEndReason::Aborted(cancellation.cause().unwrap_or(SessionCancelCause::Legacy))
}

/// Dispatch one N45-logged call into the raw provider-neutral stream boundary.
/// The stream remains unconsumed and no assistant/session event is appended.
pub fn dispatch_agent_call(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
) -> Result<LlmChunkStream, CordisError> {
    let call = logged.call();
    let request = call.request();
    let session_id = request.session_id().clone();
    agent_session(ctx, &session_id)?.require_open_step(request.turn(), request.step())?;
    let generated = LlmGenerateRequest::new(call.config().clone(), call.messages().to_vec())
        .with_system(call.assembly().system().map(str::to_string))
        .with_tools(call.assembly().tools().to_vec())
        .with_session_id(session_id)
        .with_cancellation(request.cancellation().clone());
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
    let session_id = request.session_id().clone();
    let turn = request.turn();
    let step = request.step();
    let cancellation = request.cancellation().clone();
    let mut stream = dispatch_agent_call(ctx, logged)?;
    let session = agent_session(ctx, &session_id)?;
    let mut grammar = AgentStreamGrammar::default();
    let mut chunk_seqs = Vec::new();

    loop {
        let (chunk, interrupted) = tokio::select! {
            biased;
            chunk = stream.next() => {
                let Some(chunk) = chunk else {
                    break;
                };
                (chunk, false)
            }
            () = cancellation.cancelled() => (cancelled_stream_finish(), true),
        };
        let terminal = matches!(chunk, SessionStreamChunk::Finish { .. });
        grammar.accept(&chunk)?;
        chunk_seqs.push(session.append_assistant_chunk(turn, step, chunk)?);
        if interrupted || terminal && cancellation.is_cancelled() {
            break;
        }
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
        tool_batch_state: AgentToolBatchState::Ready,
    })
}

fn cancelled_stream_finish() -> SessionStreamChunk {
    SessionStreamChunk::Finish {
        reason: SessionFinishReason::Aborted {
            failure: SessionLlmFailure {
                message: "agent turn cancelled".into(),
                code: "ABORTED".into(),
                status: None,
                provider_retry_after_ms: None,
                request_id: None,
            },
        },
        replay_state: None,
    }
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
    let session_id = request.session_id().clone();
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
    let session_id = request.session_id().clone();
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
    let session_id = request.session_id().clone();
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
        .map(|call| ToolExecutionInput::from_session_call(request.agent(), session.id(), call))
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
    let session_id = request.session_id().clone();
    let turn = request.turn();
    let step = request.step();
    let session = agent_session(ctx, &session_id)?;
    session.require_open_step(turn, step)?;
    let planned = results
        .iter()
        .map(|result| PlannedToolResult {
            call_seq: result.input().call_seq(),
            error: result.error().cloned(),
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
        let seq = session.append_tool_result_with_error_and_surface(
            turn,
            step,
            result.message.clone(),
            result.error.clone(),
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

/// Run the exact scheduled calls through the canonical N52–N62 settlement.
///
/// Starting is one-shot even when a later stage fails, so a caller cannot
/// replay a body whose durable result became uncertain.
pub fn run_agent_tool_batch(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
) -> Result<Vec<ToolExecutionResult>, CordisError> {
    run_agent_tool_batch_outcome(ctx, logged, recorded).map(AgentToolBatchOutcome::into_results)
}

/// Run and settle one exact tool batch, exposing whether an authoritative
/// successful result requested turn conclusion.
pub fn run_agent_tool_batch_outcome(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
) -> Result<AgentToolBatchOutcome, CordisError> {
    run_agent_tool_batch_with_limit_and_cancellation_outcome(
        ctx,
        logged,
        recorded,
        DEFAULT_MAX_PARALLEL_TOOL_CALLS,
        &LifecycleCancellation::default(),
    )
}

/// Run one exact tool batch with a bounded rolling body pool and exclusive
/// barriers. Policy, post-processing, result observation, and durable commit
/// remain model ordered on the driver thread.
pub fn run_agent_tool_batch_with_limit(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    max_parallel_tool_calls: usize,
) -> Result<Vec<ToolExecutionResult>, CordisError> {
    run_agent_tool_batch_with_limit_and_cancellation_outcome(
        ctx,
        logged,
        recorded,
        max_parallel_tool_calls,
        &LifecycleCancellation::default(),
    )
    .map(AgentToolBatchOutcome::into_results)
}

/// Run one exact tool batch with N59's bound, N60 cancellation, and N62
/// result-context inbox settlement while preserving the legacy result vector.
///
/// Cancellation stops replenishment, drains already-started calls, and emits
/// canonical synthetic results for every call that never started.
pub fn run_agent_tool_batch_with_limit_and_cancellation(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    max_parallel_tool_calls: usize,
    cancellation: &LifecycleCancellation,
) -> Result<Vec<ToolExecutionResult>, CordisError> {
    run_agent_tool_batch_with_limit_and_cancellation_outcome(
        ctx,
        logged,
        recorded,
        max_parallel_tool_calls,
        cancellation,
    )
    .map(AgentToolBatchOutcome::into_results)
}

/// Run N59/N60 scheduling, durably commit every final result, then park all
/// accepted result contexts in one model-ordered next-step inbox batch.
pub fn run_agent_tool_batch_with_limit_and_cancellation_outcome(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    max_parallel_tool_calls: usize,
    cancellation: &LifecycleCancellation,
) -> Result<AgentToolBatchOutcome, CordisError> {
    if max_parallel_tool_calls == 0 {
        return Err(invalid_stream_protocol("a positive parallel tool-call limit").into());
    }
    if matches!(recorded.tool_batch_state, AgentToolBatchState::Started)
        || recorded.tool_results_committed
    {
        return Err(invalid_stream_protocol(
            "one tool batch start per recorded stream without execution replay",
        )
        .into());
    }
    let request = logged.call().request();
    let session_id = request.session_id().clone();
    let session = agent_session(ctx, &session_id)?;
    if !recorded.tool_result_seqs.is_empty()
        || !durable_tool_results(&session, request.turn(), request.step())?.is_empty()
    {
        return Err(
            invalid_stream_protocol("a fresh tool-result boundary before starting bodies").into(),
        );
    }
    let inputs = prepare_agent_tool_calls(ctx, logged, recorded)?;
    recorded.tool_batch_state = AgentToolBatchState::Started;
    let tools = ctx
        .tools::<ToolsSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::TOOLS.to_string()]))?;
    let results = run_tool_scheduler(
        ctx,
        &tools,
        &inputs,
        max_parallel_tool_calls,
        cancellation,
        |ctx, index| prepare_tool_execution(ctx, inputs[index].clone()),
    )?;
    finish_agent_tool_batch(ctx, logged, recorded, &session, results)
}

/// Resolve every pre-execute policy in model order, durably answer `ask`
/// decisions, then enter the unchanged bounded scheduler. No body starts while
/// an earlier approval is unresolved; live guards and registration identity
/// are still checked only when each call reaches its dispatch slot.
async fn run_agent_tool_batch_with_approval(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    max_parallel_tool_calls: usize,
    cancellation: &LifecycleCancellation,
    host_tool_access: HostToolAccess,
) -> Result<AgentToolBatchOutcome, CordisError> {
    if max_parallel_tool_calls == 0 {
        return Err(invalid_stream_protocol("a positive parallel tool-call limit").into());
    }
    if matches!(recorded.tool_batch_state, AgentToolBatchState::Started)
        || recorded.tool_results_committed
    {
        return Err(invalid_stream_protocol(
            "one tool batch start per recorded stream without execution replay",
        )
        .into());
    }
    let request = logged.call().request();
    let session = agent_session(ctx, request.session_id())?;
    if !recorded.tool_result_seqs.is_empty()
        || !durable_tool_results(&session, request.turn(), request.step())?.is_empty()
    {
        return Err(
            invalid_stream_protocol("a fresh tool-result boundary before starting bodies").into(),
        );
    }
    let inputs = prepare_agent_tool_calls(ctx, logged, recorded)?;
    recorded.tool_batch_state = AgentToolBatchState::Started;
    let mut policies = std::iter::repeat_with(|| None)
        .take(inputs.len())
        .collect::<Vec<_>>();
    for (index, input) in inputs.iter().cloned().enumerate() {
        if cancellation.is_cancelled() {
            break;
        }
        let policy = prepare_tool_policy(ctx, input)?;
        policies[index] = Some(match policy {
            ToolPolicyPreparation::Ask(pending) => {
                resolve_tool_approval(ctx, &session, request.agent(), pending, cancellation).await?
            }
            settled => settled,
        });
    }

    let tools = ctx
        .tools::<ToolsSurface>()
        .ok_or_else(|| CordisError::MissingDependencies(vec![keys::TOOLS.to_string()]))?;
    let results = if tools.has_host_tool(&inputs) {
        run_host_tool_batch(
            ctx,
            &inputs,
            &mut policies,
            cancellation,
            logged.call().config(),
            host_tool_access,
        )
        .await?
    } else {
        run_tool_scheduler(
            ctx,
            &tools,
            &inputs,
            max_parallel_tool_calls,
            cancellation,
            |ctx, index| finalize_resolved_tool_policy(ctx, &mut policies, index),
        )?
    };
    finish_agent_tool_batch(ctx, logged, recorded, &session, results)
}

/// A batch containing a host-local body becomes one ordered driver-thread
/// barrier. Ordinary batches retain the existing bounded parallel scheduler.
async fn run_host_tool_batch(
    ctx: &mut Context,
    inputs: &[ToolExecutionInput],
    policies: &mut [Option<ToolPolicyPreparation>],
    cancellation: &LifecycleCancellation,
    inherited_config: &SessionCallConfig,
    host_tool_access: HostToolAccess,
) -> Result<Vec<ToolExecutionResult>, CordisError> {
    let mut results = Vec::with_capacity(inputs.len());
    for index in 0..inputs.len() {
        if cancellation.is_cancelled() {
            results.extend(
                inputs[index..]
                    .iter()
                    .cloned()
                    .map(aborted_before_dispatch_tool_result),
            );
            break;
        }
        let preparation = finalize_resolved_tool_policy(ctx, policies, index)?;
        let result = match preparation {
            ToolExecutionPreparation::Dispatch(prepared) => {
                let outcome = dispatch_host_tool_execution_with_cancellation(
                    ctx,
                    prepared,
                    cancellation,
                    inherited_config.clone(),
                    host_tool_access,
                )
                .await?;
                let outcome = post_tool_execution(ctx, outcome)?;
                finalize_tool_execution(ctx, outcome)
            }
            ToolExecutionPreparation::Denied(denied) => settle_denied_tool_execution(ctx, denied)?,
        };
        results.push(result);
        if cancellation.is_cancelled() && index + 1 < inputs.len() {
            results.extend(
                inputs[index + 1..]
                    .iter()
                    .cloned()
                    .map(aborted_before_dispatch_tool_result),
            );
            break;
        }
    }
    Ok(results)
}

fn finalize_resolved_tool_policy(
    ctx: &mut Context,
    policies: &mut [Option<ToolPolicyPreparation>],
    index: usize,
) -> Result<ToolExecutionPreparation, CordisError> {
    let policy = policies
        .get_mut(index)
        .and_then(Option::take)
        .ok_or_else(|| {
            invalid_stream_protocol("one resolved policy for every started tool call")
        })?;
    match policy {
        ToolPolicyPreparation::Allow(allowed) => finalize_allowed_tool_policy(ctx, allowed),
        ToolPolicyPreparation::Denied(denied) => Ok(ToolExecutionPreparation::Denied(denied)),
        ToolPolicyPreparation::Ask(_) => Err(invalid_stream_protocol(
            "every tool approval to settle before body scheduling",
        )
        .into()),
    }
}

async fn resolve_tool_approval(
    ctx: &mut Context,
    session: &SessionHandle,
    agent: &AgentRef,
    pending: crate::surface::PendingToolApproval,
    cancellation: &LifecycleCancellation,
) -> Result<ToolPolicyPreparation, CordisError> {
    let tool_name = pending.input().name().to_owned();
    let call_id = pending.input().call_id().to_owned();
    let Ok(mut request) = ApprovalRequest::for_session(
        agent.clone(),
        session.id().clone(),
        tool_name.clone(),
        cancellation.clone(),
    )
    .and_then(|request| request.with_call_id(call_id)) else {
        return Ok(ToolPolicyPreparation::Denied(pending.deny(format!(
            "tool \"{tool_name}\" requires approval, but no approval channel is available"
        ))));
    };
    if let Some(reason) = pending.reason() {
        let Ok(request_with_reason) = request.with_reason(reason) else {
            return Ok(ToolPolicyPreparation::Denied(pending.deny(format!(
                "tool \"{tool_name}\" requires approval, but no approval channel is available"
            ))));
        };
        request = request_with_reason;
    }
    let outcome = match request_approval(ctx, session, request).await {
        Ok(outcome) => outcome,
        Err(ApprovalError::Cordis(error)) => return Err(error),
        Err(ApprovalError::Session(error)) => return Err(error.into()),
        Err(
            ApprovalError::ServiceUnavailable { .. }
            | ApprovalError::EmptyToolName
            | ApprovalError::EmptyCallId
            | ApprovalError::EmptyReason
            | ApprovalError::AgentSessionMismatch { .. }
            | ApprovalError::AgentUnavailable { .. },
        ) => ApprovalOutcome::Unavailable,
    };
    Ok(match outcome {
        ApprovalOutcome::AllowedOnce => ToolPolicyPreparation::Allow(pending.allow()),
        ApprovalOutcome::Rejected => ToolPolicyPreparation::Denied(
            pending.deny(format!("the user rejected tool \"{tool_name}\"")),
        ),
        ApprovalOutcome::Cancelled => ToolPolicyPreparation::Denied(
            pending.deny(format!("approval for tool \"{tool_name}\" was cancelled")),
        ),
        ApprovalOutcome::Unavailable => ToolPolicyPreparation::Denied(pending.deny(format!(
            "tool \"{tool_name}\" requires approval, but no approval channel is available"
        ))),
    })
}

fn run_tool_scheduler<F>(
    ctx: &mut Context,
    tools: &ToolsSurface,
    inputs: &[ToolExecutionInput],
    max_parallel_tool_calls: usize,
    cancellation: &LifecycleCancellation,
    mut prepare: F,
) -> Result<Vec<ToolExecutionResult>, CordisError>
where
    F: FnMut(&mut Context, usize) -> Result<ToolExecutionPreparation, CordisError>,
{
    let mut results = Vec::with_capacity(inputs.len());
    let mut next = 0;
    while next < inputs.len() {
        if cancellation.is_cancelled() {
            results.extend(
                inputs[next..]
                    .iter()
                    .cloned()
                    .map(aborted_before_dispatch_tool_result),
            );
            break;
        }
        if tools.execution_mode(&inputs[next]) == crate::surface::ToolExecutionMode::Exclusive {
            let preparation = prepare(ctx, next)?;
            let result = settle_tool_preparation(ctx, preparation, cancellation)?;
            results.push(result);
            next += 1;
            continue;
        }
        let outcome = run_parallel_tool_group(
            ctx,
            tools,
            inputs,
            next,
            max_parallel_tool_calls,
            cancellation,
            &mut prepare,
        )?;
        if outcome.consumed == 0 && !outcome.aborted {
            return Err(invalid_stream_protocol("the parallel scheduler to make progress").into());
        }
        next += outcome.consumed;
        results.extend(outcome.results);
        if outcome.aborted {
            results.extend(
                inputs[next..]
                    .iter()
                    .cloned()
                    .map(aborted_before_dispatch_tool_result),
            );
            break;
        }
    }
    Ok(results)
}

fn finish_agent_tool_batch(
    ctx: &mut Context,
    logged: &LoggedAgentCall,
    recorded: &mut RecordedAgentStream,
    session: &SessionHandle,
    results: Vec<ToolExecutionResult>,
) -> Result<AgentToolBatchOutcome, CordisError> {
    commit_agent_tool_results(ctx, logged, recorded, &results)?;
    let concludes_turn = results
        .iter()
        .any(|result| !result.is_error() && result.concludes_turn());
    let additional_contexts = results
        .iter()
        .flat_map(|result| result.additional_contexts().iter().cloned())
        .collect::<Vec<_>>();
    if !additional_contexts.is_empty() {
        session
            .inbox()
            .append_next_step_batch(additional_contexts)?;
    }
    Ok(AgentToolBatchOutcome {
        results,
        concludes_turn,
    })
}

fn settle_tool_preparation(
    ctx: &mut Context,
    preparation: ToolExecutionPreparation,
    cancellation: &LifecycleCancellation,
) -> Result<ToolExecutionResult, CordisError> {
    match preparation {
        ToolExecutionPreparation::Dispatch(prepared) => {
            let outcome = dispatch_tool_execution_with_cancellation(ctx, prepared, cancellation)?;
            let outcome = post_tool_execution(ctx, outcome)?;
            Ok(finalize_tool_execution(ctx, outcome))
        }
        ToolExecutionPreparation::Denied(denied) => settle_denied_tool_execution(ctx, denied),
    }
}

fn finalize_ready_tool_slots(
    ctx: &mut Context,
    slots: &mut [Option<crate::surface::ToolDispatchOutcome>],
    next_to_finalize: &mut usize,
    results: &mut Vec<ToolExecutionResult>,
) -> Result<(), CordisError> {
    while let Some(outcome) = slots.get_mut(*next_to_finalize).and_then(Option::take) {
        let outcome = post_tool_execution(ctx, outcome)?;
        results.push(finalize_tool_execution(ctx, outcome));
        *next_to_finalize += 1;
    }
    Ok(())
}

fn run_parallel_tool_group(
    ctx: &mut Context,
    tools: &ToolsSurface,
    inputs: &[ToolExecutionInput],
    start: usize,
    max_parallel_tool_calls: usize,
    cancellation: &LifecycleCancellation,
    prepare: &mut impl FnMut(&mut Context, usize) -> Result<ToolExecutionPreparation, CordisError>,
) -> Result<ParallelToolGroupOutcome, CordisError> {
    let group_inputs = &inputs[start..];
    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::channel();
        let mut slots = std::iter::repeat_with(|| None)
            .take(group_inputs.len())
            .collect::<Vec<_>>();
        let mut results = Vec::new();
        let mut next_to_start = 0;
        let mut next_to_finalize = 0;
        let mut in_flight = 0;
        let mut barrier_reached = false;
        let mut pending_exclusive = None;
        let mut aborted = cancellation.is_cancelled();

        loop {
            while !aborted
                && !barrier_reached
                && next_to_start < group_inputs.len()
                && in_flight < max_parallel_tool_calls
            {
                if next_to_start > 0
                    && tools.execution_mode(&group_inputs[next_to_start])
                        != crate::surface::ToolExecutionMode::Parallel
                {
                    barrier_reached = true;
                    break;
                }
                let preparation = prepare(ctx, start + next_to_start)?;
                match preparation {
                    ToolExecutionPreparation::Denied(denied) => {
                        slots[next_to_start] = Some(denied_tool_dispatch_outcome(denied));
                    }
                    ToolExecutionPreparation::Dispatch(prepared)
                        if prepared.mode() == crate::surface::ToolExecutionMode::Exclusive =>
                    {
                        pending_exclusive = Some((next_to_start, prepared));
                        barrier_reached = true;
                    }
                    ToolExecutionPreparation::Dispatch(prepared) => {
                        let dispatch = schedule_tool_dispatch(ctx, prepared, cancellation.clone())?;
                        let completion = sender.clone();
                        let index = next_to_start;
                        scope.spawn(move || {
                            let outcome = catch_unwind(AssertUnwindSafe(|| dispatch.dispatch()))
                                .unwrap_or_else(|_| {
                                    Err(invalid_stream_protocol(
                                        "a non-panicking tool scheduler worker",
                                    )
                                    .into())
                                });
                            let _ = completion.send((index, outcome));
                        });
                        in_flight += 1;
                    }
                }
                next_to_start += 1;
                finalize_ready_tool_slots(ctx, &mut slots, &mut next_to_finalize, &mut results)?;
                aborted |= cancellation.is_cancelled();
            }

            if in_flight == 0 {
                if let Some((index, prepared)) = pending_exclusive.take() {
                    if aborted {
                        next_to_start = index;
                        break;
                    }
                    slots[index] = Some(dispatch_tool_execution_with_cancellation(
                        ctx,
                        prepared,
                        cancellation,
                    )?);
                    finalize_ready_tool_slots(
                        ctx,
                        &mut slots,
                        &mut next_to_finalize,
                        &mut results,
                    )?;
                    aborted |= cancellation.is_cancelled();
                }
                break;
            }

            let (index, outcome) = receiver.recv().map_err(|_| {
                invalid_stream_protocol("every started tool scheduler worker to settle")
            })?;
            in_flight -= 1;
            slots[index] = Some(outcome?);
            finalize_ready_tool_slots(ctx, &mut slots, &mut next_to_finalize, &mut results)?;
            aborted |= cancellation.is_cancelled();
        }
        Ok(ParallelToolGroupOutcome {
            consumed: next_to_start,
            results,
            aborted,
        })
    })
}

struct ParallelToolGroupOutcome {
    consumed: usize,
    results: Vec<ToolExecutionResult>,
    aborted: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct PlannedToolResult {
    call_seq: u64,
    message: SessionMessage,
    error: Option<SessionToolError>,
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
                && actual.error == expected.error
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
    agent: &AgentRef,
    target: AgentInboxTarget,
    turn: u64,
    step: u64,
    cancellation: &LifecycleCancellation,
) -> Result<AgentPreStep, CordisError> {
    let claimed = session.inbox().claim(target, turn)?;
    let assembly = assemble_system_prompt(ctx)?;
    let proposal = AgentPreStep::enter(
        agent.clone(),
        turn,
        step,
        claimed,
        assembly,
        cancellation.clone(),
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
