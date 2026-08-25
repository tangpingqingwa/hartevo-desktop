//! Cordis-hosted Rust agent loop.
//!
//! The host owns the ReAct cycle: observe Domain Kernel facts, stream a model
//! decision on `ctx.llm`, run the tools pipeline on `ctx.tools`, then propose
//! Effects only through `ctx.effect_broker`. OpenInterpreter is an optional
//! runtime plugin behind the existing adapter. The child process never owns
//! Mission, Truth, or Effect.

use crate::context::{Context, CordisError, keys};
use crate::event::DispatchMode;
use crate::loader::PluginSpec;
use crate::service::Service;
use crate::surface::{
    AgentRef, AgentsSurface, DomainSurface, EffectBrokerSurface, HartevoSurfaces, LlmStream,
    RuntimeSurface, SurfaceMapping, SurfaceOwner, ToolCall, events, register_agent,
    run_tools_pipeline, stream_llm,
};

/// Loop events. Each name is locked to exactly one dispatch mode.
pub mod loop_events {
    /// Serial step that reads Domain Kernel facts into the turn.
    pub const AGENT_OBSERVE: &str = "agent/observe";
    /// Serial step that records a model decision without mutating domain.
    pub const AGENT_DECIDE: &str = "agent/decide";
    /// Serial step that runs the tools pipeline after policy.
    pub const AGENT_ACT: &str = "agent/act";
    /// Observe-only notification after a turn settles.
    pub const AGENT_TURN: &str = "agent/turn";
    /// Observe-only adapter presence. Never carries Mission / Truth / Effect.
    pub const RUNTIME_OPENINTERPRETER: &str = "runtime/openinterpreter";
}

/// Fail-closed host contract: missing mapped keys, missing Domain/Effect
/// ownership, or a child process claiming those facts.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AgentLoopError {
    #[error("missing mapped service `{0}`")]
    MissingService(&'static str),
    #[error("{0}")]
    Cordis(#[from] CordisError),
    #[error("OpenInterpreter must not own Mission, Truth, or Effect")]
    OpenInterpreterOwnsDomain,
    #[error("child process must not own Domain Kernel facts")]
    ChildOwnsDomain,
    #[error("external write must go through the Effect Broker")]
    EffectBypassedBroker,
}

/// One hosted turn. Domain facts are copied in; they are never mutated by
/// the model or the optional OpenInterpreter plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTurn {
    pub mission_id: String,
    pub prompt: String,
    pub model: String,
    pub tool: String,
    pub arguments: String,
    pub observed: String,
    pub decision: String,
    pub action: String,
    pub effect: String,
    pub owner: SurfaceOwner,
}

impl AgentTurn {
    #[must_use]
    pub fn new(
        mission_id: impl Into<String>,
        prompt: impl Into<String>,
        model: impl Into<String>,
        tool: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            mission_id: mission_id.into(),
            prompt: prompt.into(),
            model: model.into(),
            tool: tool.into(),
            arguments: arguments.into(),
            observed: String::new(),
            decision: String::new(),
            action: String::new(),
            effect: String::new(),
            owner: SurfaceOwner::Hartevo,
        }
    }
}

/// Optional OpenInterpreter adapter presence. Never a Domain owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenInterpreterPresence {
    pub plugin: &'static str,
}

impl OpenInterpreterPresence {
    #[must_use]
    pub const fn adapter() -> Self {
        Self {
            plugin: "openinterpreter",
        }
    }
}

/// Host that owns the agent cycle. Surfaces come from PR 5 mapping.
#[derive(Debug, Default)]
pub struct AgentLoop;

impl Service for AgentLoop {
    fn inject() -> &'static [&'static str] {
        &[
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
            keys::RUNTIME,
            keys::DESKTOP,
        ]
    }

    fn apply(self, ctx: &mut Context) {
        lock_loop_events(ctx).expect("agent loop event locks");
    }
}

/// Map surfaces, then mount the hosted loop. OpenInterpreter is not started.
pub fn install_agent_loop(ctx: &mut Context) -> Result<(), AgentLoopError> {
    ctx.mount(SurfaceMapping::default())?;
    ctx.mount(AgentLoop)?;
    assert_host_owns_domain(ctx)?;
    Ok(())
}

/// Hosted loop plugin. Overlay selects it; it is not a crate boot list.
#[must_use]
pub fn agent_loop_plugin() -> PluginSpec {
    PluginSpec::new("agent-loop", |_config, ctx| {
        AgentLoop.apply(ctx);
    })
    .with_inject([
        keys::TOOLS,
        keys::LLM,
        keys::AGENTS,
        keys::DOMAIN,
        keys::EFFECT_BROKER,
        keys::RUNTIME,
        keys::DESKTOP,
    ])
}

/// Optional OpenInterpreter runtime plugin. Overlay may disable it.
///
/// Injects `runtime` only. Never provides `domain` or `effect_broker`.
#[derive(Debug)]
pub struct OpenInterpreterRuntimePlugin;

impl Service for OpenInterpreterRuntimePlugin {
    fn inject() -> &'static [&'static str] {
        &[keys::RUNTIME]
    }

    fn apply(self, ctx: &mut Context) {
        let Some(runtime) = ctx.runtime::<RuntimeSurface>() else {
            return;
        };
        if runtime.owner != SurfaceOwner::Hartevo {
            return;
        }
        let _ = ctx.lock_event(loop_events::RUNTIME_OPENINTERPRETER, DispatchMode::Emit);
        let _ = ctx.on_emit(
            loop_events::RUNTIME_OPENINTERPRETER,
            |_: &OpenInterpreterPresence| {},
        );
    }
}

/// Loader spec for the optional adapter. Overlay `disabled` keeps it off.
#[must_use]
pub fn openinterpreter_runtime_plugin() -> PluginSpec {
    PluginSpec::new("openinterpreter", |_config, ctx| {
        OpenInterpreterRuntimePlugin.apply(ctx);
    })
    .with_inject([keys::RUNTIME])
}

/// Surface mapping plugin used with the hosted loop.
#[must_use]
pub fn surface_mapping_plugin() -> PluginSpec {
    PluginSpec::new("surfaces", |_config, ctx| {
        SurfaceMapping::default().apply(ctx);
    })
}

/// Surface mapping that names OpenInterpreter in the runtime slot without
/// transferring Domain / Effect ownership.
#[must_use]
pub fn surface_mapping_with_openinterpreter_slot() -> PluginSpec {
    PluginSpec::new("surfaces", |_config, ctx| {
        SurfaceMapping {
            surfaces: HartevoSurfaces {
                runtime: RuntimeSurface {
                    owner: SurfaceOwner::Hartevo,
                    plugin: Some("openinterpreter"),
                },
                ..HartevoSurfaces::default()
            },
        }
        .apply(ctx);
    })
}

/// Run one hosted turn. Domain facts are read from `ctx.domain`; Effects are
/// proposed only through `ctx.effect_broker`. The optional OpenInterpreter
/// plugin is never consulted for Mission, Truth, or Effect.
pub async fn run_agent_turn(
    ctx: &mut Context,
    mut turn: AgentTurn,
) -> Result<AgentTurn, AgentLoopError> {
    assert_host_owns_domain(ctx)?;
    if turn.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    }

    let agent = AgentRef::new(turn.mission_id.clone());
    register_agent(ctx, agent.clone())?;
    ctx.emit(events::AGENT_CREATED, &agent)?;

    turn = ctx.serial(loop_events::AGENT_OBSERVE, turn).await?;
    if turn.observed.is_empty() {
        turn.observed = observe_from_domain(ctx, &turn)?;
    }
    if turn.owner != SurfaceOwner::Hartevo {
        dispose_live_agent(ctx, &agent);
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    }

    let stream = stream_llm(ctx, LlmStream::new(turn.model.clone(), turn.prompt.clone()))?;
    if turn.decision.is_empty() {
        turn.decision = if stream.body.is_empty() {
            format!("host:{}", turn.tool)
        } else {
            stream.body
        };
    }
    turn = ctx.serial(loop_events::AGENT_DECIDE, turn).await?;

    let call = run_tools_pipeline(
        ctx,
        ToolCall::new(turn.tool.clone(), turn.arguments.clone(), "allow"),
    )?;
    if call.decision != "allow" {
        turn.action = format!("denied:{}", call.decision);
        turn.effect.clear();
        ctx.emit(loop_events::AGENT_TURN, &turn)?;
        dispose_live_agent(ctx, &agent);
        return Ok(turn);
    }
    if turn.action.is_empty() {
        turn.action = if call.result.is_empty() {
            format!("ran:{}", call.name)
        } else {
            call.result
        };
    }
    turn = ctx.serial(loop_events::AGENT_ACT, turn).await?;

    // Child-authored effect text is discarded. Only the broker path writes.
    turn.effect.clear();
    turn.effect = propose_effect(ctx, &turn)?;
    ctx.emit(loop_events::AGENT_TURN, &turn)?;
    dispose_live_agent(ctx, &agent);
    Ok(turn)
}

fn dispose_live_agent(ctx: &mut Context, agent: &AgentRef) {
    if let Some(agents) = ctx.agents::<AgentsSurface>() {
        agents.unregister(&agent.id);
    }
    let _ = ctx.emit(events::AGENT_DISPOSED, agent);
}

fn observe_from_domain(ctx: &Context, turn: &AgentTurn) -> Result<String, AgentLoopError> {
    let domain = ctx
        .domain::<DomainSurface>()
        .ok_or(AgentLoopError::MissingService(keys::DOMAIN))?;
    if domain.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    }
    Ok(format!("domain:{}", turn.mission_id))
}

pub(crate) fn propose_effect(ctx: &Context, turn: &AgentTurn) -> Result<String, AgentLoopError> {
    let broker = ctx
        .effect_broker::<EffectBrokerSurface>()
        .ok_or(AgentLoopError::MissingService(keys::EFFECT_BROKER))?;
    if broker.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::EffectBypassedBroker);
    }
    Ok(format!("broker:{}:{}", turn.mission_id, turn.tool))
}

/// Domain Kernel remains the only business fact source. Effect Broker remains
/// the only external-write path. The child process never occupies those keys.
pub fn assert_host_owns_domain(ctx: &Context) -> Result<(), AgentLoopError> {
    if !ctx.has(keys::DOMAIN) {
        return Err(AgentLoopError::MissingService(keys::DOMAIN));
    }
    if !ctx.has(keys::EFFECT_BROKER) {
        return Err(AgentLoopError::MissingService(keys::EFFECT_BROKER));
    }
    if !ctx.has(keys::RUNTIME) {
        return Err(AgentLoopError::MissingService(keys::RUNTIME));
    }
    let Some(domain) = ctx.domain::<DomainSurface>() else {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    };
    let Some(broker) = ctx.effect_broker::<EffectBrokerSurface>() else {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    };
    let Some(runtime) = ctx.runtime::<RuntimeSurface>() else {
        return Err(AgentLoopError::ChildOwnsDomain);
    };
    if domain.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    }
    if broker.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::OpenInterpreterOwnsDomain);
    }
    if runtime.owner != SurfaceOwner::Hartevo {
        return Err(AgentLoopError::ChildOwnsDomain);
    }
    Ok(())
}

/// Primer dispatch mode for each hosted-loop event name.
#[must_use]
pub fn expected_loop_mode(name: &str) -> Option<DispatchMode> {
    match name {
        loop_events::AGENT_OBSERVE | loop_events::AGENT_DECIDE | loop_events::AGENT_ACT => {
            Some(DispatchMode::Serial)
        }
        loop_events::AGENT_TURN | loop_events::RUNTIME_OPENINTERPRETER => Some(DispatchMode::Emit),
        _ => None,
    }
}

fn lock_loop_events(ctx: &mut Context) -> Result<(), CordisError> {
    ctx.lock_event(loop_events::AGENT_OBSERVE, DispatchMode::Serial)?;
    ctx.lock_event(loop_events::AGENT_DECIDE, DispatchMode::Serial)?;
    ctx.lock_event(loop_events::AGENT_ACT, DispatchMode::Serial)?;
    ctx.lock_event(loop_events::AGENT_TURN, DispatchMode::Emit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AgentLoopError, AgentTurn, propose_effect};
    use crate::context::{Context, keys};
    use crate::surface::{EffectBrokerSurface, SurfaceMapping, SurfaceOwner};

    #[test]
    fn broker_bypass_fails_closed() {
        let mut ctx = Context::new();
        ctx.mount(SurfaceMapping::default()).unwrap();
        ctx.provide(
            keys::EFFECT_BROKER,
            EffectBrokerSurface {
                owner: SurfaceOwner::OpenInterpreter,
            },
        );
        let err =
            propose_effect(&ctx, &AgentTurn::new("m", "p", "model", "search", "q")).unwrap_err();
        assert_eq!(err, AgentLoopError::EffectBypassedBroker);
    }
}
