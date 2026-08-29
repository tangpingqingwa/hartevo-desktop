//! Cordis-hosted agent loop. OpenInterpreter is an optional runtime plugin,
//! never the loop and never the owner of Domain or Effect.

use crate::context::{Context, CordisError, keys};
use crate::invariants::enforce_invariants;
use crate::service::Service;
use crate::surface::{
    AgentRef, AgentsSurface, DomainSurface, EffectBrokerSurface, LlmStream, LlmSurface,
    RuntimeSurface, ToolCall, ToolsSurface, events, register_agent, run_tools_pipeline, stream_llm,
};

/// Inject keys the loop looks up. Runtime is optional at apply time.
pub const AGENT_LOOP_KEYS: &[&str] = &[
    keys::AGENTS,
    keys::TOOLS,
    keys::LLM,
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

/// Register the live agent, plan via `ctx.llm`, optionally execute a tool,
/// then read Domain facts and write externally only through Effect Broker.
pub fn run_agent_step(ctx: &mut Context, step: AgentStep) -> Result<AgentStepResult, CordisError> {
    require_loop_surfaces(ctx)?;
    enforce_invariants(ctx)?;
    // Runtime may name OpenInterpreter as an adapter plugin; it is not the loop.
    let _runtime = ctx.runtime::<RuntimeSurface>();

    let agent = AgentRef::new(step.id.clone());
    register_agent(ctx, agent.clone())?;
    ctx.emit(events::AGENT_CREATED, &agent)?;

    let plan = stream_llm(ctx, LlmStream::new("hartevo-local", step.prompt))?;
    let tool = match step.tool {
        Some(call) => Some(run_tools_pipeline(ctx, call)?),
        None => None,
    };

    Ok(AgentStepResult {
        id: step.id,
        plan,
        tool,
    })
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
