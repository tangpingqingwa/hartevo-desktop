//! Cordis-hosted agent loop. OpenInterpreter is an optional runtime plugin,
//! never the loop and never the owner of Domain or Effect.

use crate::context::{Context, CordisError, keys};
use crate::inbox::AgentInboxTarget;
use crate::invariants::enforce_invariants;
use crate::service::Service;
use crate::session::{
    SessionContentBlock, SessionError, SessionHandle, SessionId, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionStore, SessionSurfaceIntent, TurnEndReason,
    validate_agent_user_message,
};
use crate::surface::{
    AgentPreStep, AgentPreStepDecision, AgentRef, AgentsSurface, DomainSurface,
    EffectBrokerSurface, LlmStream, LlmSurface, RuntimeSurface, ToolCall, ToolsSurface, events,
    register_agent, run_tools_pipeline, stream_llm,
};

/// Inject keys the loop looks up. Runtime is optional at apply time.
pub const AGENT_LOOP_KEYS: &[&str] = &[
    keys::AGENTS,
    keys::TOOLS,
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
    let proposal = AgentPreStep::enter(AgentRef::new(session.id().as_str()), turn, step, claimed);
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
