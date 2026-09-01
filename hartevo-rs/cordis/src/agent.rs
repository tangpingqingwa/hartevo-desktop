//! Cordis-hosted agent loop. OpenInterpreter is an optional runtime plugin,
//! never the loop and never the owner of Domain or Effect.

use crate::context::{Context, CordisError, keys};
use crate::inbox::AgentInboxTarget;
use crate::invariants::enforce_invariants;
use crate::service::Service;
use crate::session::{
    SessionCallConfig, SessionCallConfigAdapterDefaults, SessionContentBlock, SessionEpochHeader,
    SessionError, SessionHandle, SessionId, SessionMessage, SessionMessageRole,
    SessionMessageSource, SessionRequestContext, SessionRequestHeaderReason, SessionStore,
    SessionSurfaceIntent, TurnEndReason, validate_agent_request_config,
    validate_agent_user_message,
};
use crate::surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentRequest, AgentsSurface, DomainSurface,
    EffectBrokerSurface, LlmChunkStream, LlmError, LlmGenerateRequest, LlmStream, LlmSurface,
    PreparedLlmCall, PromptAssembly, RuntimeSurface, ToolCall, ToolsSurface,
    assemble_system_prompt, events, prepare_llm_call, register_agent, run_tools_pipeline,
    stream_llm, stream_llm_request, stream_prepared_llm,
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
