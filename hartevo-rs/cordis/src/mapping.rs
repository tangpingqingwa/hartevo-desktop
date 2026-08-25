//! Practice mapping of Hartevo surfaces onto Cordis services.
//!
//! This is a host map, not a second agent runtime. Primer pipeline events
//! stay on `ctx.tools` / `ctx.llm` / `ctx.agents`. Mission, Truth, and Effect
//! stay on Hartevo-owned `ctx.domain`, `ctx.effect_broker`, `ctx.runtime`, and
//! `ctx.desktop`. OpenInterpreter is an optional runtime plugin behind the
//! existing adapter and never owns those facts.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::context::{Context, CordisError, keys};
use crate::event::DispatchMode;
use crate::loader::PluginSpec;
use crate::service::Service;

/// Primer / Hartevo event names locked onto their owning service.
pub mod events {
    pub const TOOLS_PRE_EXECUTE: &str = "tools/pre-execute";
    pub const TOOLS_EXECUTE: &str = "tools/execute";
    pub const TOOLS_POST_EXECUTE: &str = "tools/post-execute";
    pub const TOOLS_RESULT: &str = "tools/result";
    pub const LLM_STREAM: &str = "llm/stream";
    pub const AGENTS_CREATED: &str = "agents/created";
    pub const AGENTS_DISPOSED: &str = "agents/disposed";
    pub const RUNTIME_OPENINTERPRETER: &str = "runtime/openinterpreter";
}

/// Fail-closed mapping contract: missing services, missing disposers, or a
/// plugin claiming Domain/Truth/Effect authority.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum MappingError {
    #[error("missing mapped service `{0}`")]
    MissingService(&'static str),
    #[error("event `{name}` must belong to `{owner}`, not `{claimed}`")]
    EventOwner {
        name: String,
        owner: &'static str,
        claimed: String,
    },
    #[error("event `{name}` is locked to {locked}, expected {expected}")]
    EventMode {
        name: String,
        locked: DispatchMode,
        expected: DispatchMode,
    },
    #[error("registration `{0}` has no disposer")]
    MissingDisposer(&'static str),
    #[error("OpenInterpreter must not own Mission, Truth, or Effect")]
    OpenInterpreterOwnsDomain,
}

/// Tool registry and execution pipeline on `ctx.tools`.
#[derive(Debug, Default)]
pub struct ToolsService {
    executions: AtomicU64,
}

impl ToolsService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct capability call. Pipeline interception uses `tools/*` events.
    pub fn execute(&self, name: impl Into<String>) -> ToolCall {
        let id = self.executions.fetch_add(1, Ordering::SeqCst) + 1;
        ToolCall {
            id,
            name: name.into(),
        }
    }
}

/// One tool invocation identity. Policy wraps this through waterfalls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub id: u64,
    pub name: String,
}

/// Frozen tool outcome observed on `tools/result`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub call: ToolCall,
    pub output: String,
}

/// Model streaming seam on `ctx.llm`.
#[derive(Debug, Default)]
pub struct LlmService {
    streams: AtomicU64,
}

impl LlmService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct capability call. Streaming interception uses `llm/stream`.
    pub fn stream(&self, model: impl Into<String>) -> LlmRequest {
        let id = self.streams.fetch_add(1, Ordering::SeqCst) + 1;
        LlmRequest {
            id,
            model: model.into(),
        }
    }
}

/// One model stream request. Listeners wrap chunks via waterfall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmRequest {
    pub id: u64,
    pub model: String,
}

/// Live agent coordination on `ctx.agents`. Does not own Domain facts.
#[derive(Debug, Default)]
pub struct AgentsService {
    live: AtomicU64,
}

impl AgentsService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, session_id: impl Into<String>) -> AgentHandle {
        self.live.fetch_add(1, Ordering::SeqCst);
        AgentHandle {
            session_id: session_id.into(),
        }
    }

    pub fn dispose(&self, _handle: &AgentHandle) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }

    #[must_use]
    pub fn live_count(&self) -> u64 {
        self.live.load(Ordering::SeqCst)
    }
}

/// Live agent identity used for coordination events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentHandle {
    pub session_id: String,
}

/// Domain Kernel remains the only Mission / Truth owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainKernelSurface {
    pub owner: &'static str,
}

impl DomainKernelSurface {
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: "hartevo-domain-kernel",
        }
    }

    #[must_use]
    pub fn owns_mission_and_truth(&self) -> bool {
        self.owner == "hartevo-domain-kernel"
    }
}

impl Default for DomainKernelSurface {
    fn default() -> Self {
        Self::new()
    }
}

/// Effect Broker remains the only external-write path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectBrokerSurface {
    pub owner: &'static str,
}

impl EffectBrokerSurface {
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: "hartevo-effect-broker",
        }
    }

    #[must_use]
    pub fn owns_effect(&self) -> bool {
        self.owner == "hartevo-effect-broker"
    }
}

impl Default for EffectBrokerSurface {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime Adapter is the child-process seam, not the Domain Kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeAdapterSurface {
    pub owner: &'static str,
}

impl RuntimeAdapterSurface {
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: "hartevo-runtime-adapter",
        }
    }

    #[must_use]
    pub fn owns_mission_truth_or_effect(&self) -> bool {
        false
    }
}

impl Default for RuntimeAdapterSurface {
    fn default() -> Self {
        Self::new()
    }
}

/// Desktop Shell projects Application state; it does not execute Effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopSurface {
    pub owner: &'static str,
}

impl DesktopSurface {
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: "hartevo-desktop",
        }
    }
}

impl Default for DesktopSurface {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of mapped services after a successful [`map_hartevo_surfaces`].
#[derive(Debug, Clone)]
pub struct SurfaceMap {
    pub tools: Arc<ToolsService>,
    pub llm: Arc<LlmService>,
    pub agents: Arc<AgentsService>,
    pub domain: Arc<DomainKernelSurface>,
    pub effect_broker: Arc<EffectBrokerSurface>,
    pub runtime: Arc<RuntimeAdapterSurface>,
    pub desktop: Arc<DesktopSurface>,
}

impl SurfaceMap {
    /// Look up mapped services. Missing keys fail closed.
    pub fn from_context(ctx: &Context) -> Result<Self, MappingError> {
        Ok(Self {
            tools: ctx
                .tools::<ToolsService>()
                .ok_or(MappingError::MissingService(keys::TOOLS))?,
            llm: ctx
                .llm::<LlmService>()
                .ok_or(MappingError::MissingService(keys::LLM))?,
            agents: ctx
                .agents::<AgentsService>()
                .ok_or(MappingError::MissingService(keys::AGENTS))?,
            domain: ctx
                .domain::<DomainKernelSurface>()
                .ok_or(MappingError::MissingService(keys::DOMAIN))?,
            effect_broker: ctx
                .effect_broker::<EffectBrokerSurface>()
                .ok_or(MappingError::MissingService(keys::EFFECT_BROKER))?,
            runtime: ctx
                .runtime::<RuntimeAdapterSurface>()
                .ok_or(MappingError::MissingService(keys::RUNTIME))?,
            desktop: ctx
                .desktop::<DesktopSurface>()
                .ok_or(MappingError::MissingService(keys::DESKTOP))?,
        })
    }

    /// Event names stay on their primer/Hartevo owner. Mixing owners errors.
    pub fn event_owner(name: &str) -> Result<&'static str, MappingError> {
        match name {
            events::TOOLS_PRE_EXECUTE
            | events::TOOLS_EXECUTE
            | events::TOOLS_POST_EXECUTE
            | events::TOOLS_RESULT => Ok(keys::TOOLS),
            events::LLM_STREAM => Ok(keys::LLM),
            events::AGENTS_CREATED | events::AGENTS_DISPOSED => Ok(keys::AGENTS),
            events::RUNTIME_OPENINTERPRETER => Ok(keys::RUNTIME),
            other => Err(MappingError::EventOwner {
                name: other.to_string(),
                owner: "unmapped",
                claimed: "unknown".to_string(),
            }),
        }
    }

    pub fn assert_event_owner(name: &str, claimed: &str) -> Result<(), MappingError> {
        let owner = Self::event_owner(name)?;
        if owner == claimed {
            Ok(())
        } else {
            Err(MappingError::EventOwner {
                name: name.to_string(),
                owner,
                claimed: claimed.to_string(),
            })
        }
    }
}

/// Confirm primer pipeline events are locked on their owning services.
pub fn assert_pipeline_locked(ctx: &Context) -> Result<(), MappingError> {
    const LOCKS: &[(&str, DispatchMode, &str)] = &[
        (
            events::TOOLS_PRE_EXECUTE,
            DispatchMode::Waterfall,
            keys::TOOLS,
        ),
        (events::TOOLS_EXECUTE, DispatchMode::Waterfall, keys::TOOLS),
        (
            events::TOOLS_POST_EXECUTE,
            DispatchMode::Waterfall,
            keys::TOOLS,
        ),
        (events::TOOLS_RESULT, DispatchMode::Emit, keys::TOOLS),
        (events::LLM_STREAM, DispatchMode::Waterfall, keys::LLM),
        (events::AGENTS_CREATED, DispatchMode::Emit, keys::AGENTS),
        (events::AGENTS_DISPOSED, DispatchMode::Emit, keys::AGENTS),
    ];
    for &(name, expected, owner) in LOCKS {
        SurfaceMap::assert_event_owner(name, owner)?;
        match ctx.event_mode(name) {
            Some(mode) if mode == expected => {}
            Some(locked) => {
                return Err(MappingError::EventMode {
                    name: name.to_string(),
                    locked,
                    expected,
                });
            }
            None => return Err(MappingError::MissingDisposer(name)),
        }
        if ctx.listener_count(name) == 0 {
            return Err(MappingError::MissingDisposer(name));
        }
    }
    Ok(())
}

/// OpenInterpreter (or any runtime plugin) must not replace Domain / Effect.
pub fn assert_openinterpreter_does_not_own_domain(ctx: &Context) -> Result<(), MappingError> {
    if ctx.has(keys::DOMAIN) && ctx.domain::<DomainKernelSurface>().is_none() {
        return Err(MappingError::OpenInterpreterOwnsDomain);
    }
    if ctx.has(keys::EFFECT_BROKER) && ctx.effect_broker::<EffectBrokerSurface>().is_none() {
        return Err(MappingError::OpenInterpreterOwnsDomain);
    }
    let domain = ctx
        .domain::<DomainKernelSurface>()
        .ok_or(MappingError::MissingService(keys::DOMAIN))?;
    let broker = ctx
        .effect_broker::<EffectBrokerSurface>()
        .ok_or(MappingError::MissingService(keys::EFFECT_BROKER))?;
    if !domain.owns_mission_and_truth() || !broker.owns_effect() {
        return Err(MappingError::OpenInterpreterOwnsDomain);
    }
    if ctx
        .runtime::<RuntimeAdapterSurface>()
        .is_some_and(|runtime| runtime.owns_mission_truth_or_effect())
    {
        return Err(MappingError::OpenInterpreterOwnsDomain);
    }
    Ok(())
}

/// Provide Hartevo-owned surfaces. Each `provide` is a reversible registration.
#[derive(Debug)]
pub struct HartevoSurfaces;

impl Service for HartevoSurfaces {
    fn apply(self, ctx: &mut Context) {
        ctx.provide(keys::DOMAIN, DomainKernelSurface::new());
        ctx.provide(keys::EFFECT_BROKER, EffectBrokerSurface::new());
        ctx.provide(keys::RUNTIME, RuntimeAdapterSurface::new());
        ctx.provide(keys::DESKTOP, DesktopSurface::new());
    }
}

/// Provide primer `tools` and lock pipeline events onto that service.
#[derive(Debug)]
pub struct ToolsSurface;

impl ToolsSurface {
    fn register(ctx: &mut Context) -> Result<(), MappingError> {
        ctx.provide(keys::TOOLS, ToolsService::new());
        register_passthrough(ctx, events::TOOLS_PRE_EXECUTE)?;
        register_passthrough(ctx, events::TOOLS_EXECUTE)?;
        register_passthrough(ctx, events::TOOLS_POST_EXECUTE)?;
        ctx.on_emit(events::TOOLS_RESULT, |_: &ToolResult| {})
            .map_err(|error| mapping_from_cordis(events::TOOLS_RESULT, &error))?;
        Ok(())
    }
}

impl Service for ToolsSurface {
    fn apply(self, ctx: &mut Context) {
        let _ = Self::register(ctx);
    }
}

/// Provide primer `llm` and lock model streams onto that service.
#[derive(Debug)]
pub struct LlmSurface;

impl LlmSurface {
    fn register(ctx: &mut Context) -> Result<(), MappingError> {
        ctx.provide(keys::LLM, LlmService::new());
        ctx.on_waterfall(events::LLM_STREAM, |request: LlmRequest, next| {
            next(request)
        })
        .map_err(|error| mapping_from_cordis(events::LLM_STREAM, &error))?;
        Ok(())
    }
}

impl Service for LlmSurface {
    fn apply(self, ctx: &mut Context) {
        let _ = Self::register(ctx);
    }
}

/// Provide primer `agents` and lock live coordination onto that service.
#[derive(Debug)]
pub struct AgentsSurface;

impl AgentsSurface {
    fn register(ctx: &mut Context) -> Result<(), MappingError> {
        ctx.provide(keys::AGENTS, AgentsService::new());
        ctx.on_emit(events::AGENTS_CREATED, |_: &AgentHandle| {})
            .map_err(|error| mapping_from_cordis(events::AGENTS_CREATED, &error))?;
        ctx.on_emit(events::AGENTS_DISPOSED, |_: &AgentHandle| {})
            .map_err(|error| mapping_from_cordis(events::AGENTS_DISPOSED, &error))?;
        Ok(())
    }
}

impl Service for AgentsSurface {
    fn apply(self, ctx: &mut Context) {
        let _ = Self::register(ctx);
    }
}

/// Map primer + Hartevo-owned surfaces. Registrations reverse on teardown.
pub fn map_hartevo_surfaces(ctx: &mut Context) -> Result<SurfaceMap, MappingError> {
    HartevoSurfaces.apply(ctx);
    ToolsSurface::register(ctx)?;
    LlmSurface::register(ctx)?;
    AgentsSurface::register(ctx)?;
    let mapped = SurfaceMap::from_context(ctx)?;
    assert_pipeline_locked(ctx)?;
    assert_openinterpreter_does_not_own_domain(ctx)?;
    Ok(mapped)
}

fn register_passthrough(ctx: &mut Context, name: &'static str) -> Result<(), MappingError> {
    ctx.on_waterfall(name, |call: ToolCall, next| next(call))
        .map_err(|error| mapping_from_cordis(name, &error))
}

fn mapping_from_cordis(name: &'static str, error: &CordisError) -> MappingError {
    match error {
        CordisError::ModeConflict {
            locked, requested, ..
        } => MappingError::EventMode {
            name: name.to_string(),
            locked: *locked,
            expected: *requested,
        },
        _ => MappingError::MissingDisposer(name),
    }
}

/// Optional OpenInterpreter runtime plugin. It injects `runtime` only.
///
/// The plugin never provides `domain` or `effect_broker`. Overlay `disabled`
/// keeps it off unless an environment selects it.
#[derive(Debug)]
pub struct OpenInterpreterRuntimePlugin;

impl Service for OpenInterpreterRuntimePlugin {
    fn inject() -> &'static [&'static str] {
        &[keys::RUNTIME]
    }

    fn apply(self, ctx: &mut Context) {
        if ctx.runtime::<RuntimeAdapterSurface>().is_none() {
            return;
        }
        let _ = ctx.on_emit(events::RUNTIME_OPENINTERPRETER, |(): &()| {});
    }
}

/// Loader spec for the optional OpenInterpreter plugin. Overlay may disable it.
#[must_use]
pub fn openinterpreter_runtime_plugin() -> PluginSpec {
    PluginSpec::new("openinterpreter", |_config, ctx| {
        OpenInterpreterRuntimePlugin.apply(ctx);
    })
    .with_inject([keys::RUNTIME])
}

#[cfg(test)]
mod tests {
    use super::{
        AgentsService, DomainKernelSurface, EffectBrokerSurface, MappingError, SurfaceMap,
        ToolCall, events,
    };
    use crate::context::keys;

    #[test]
    fn primer_events_belong_to_named_services() {
        SurfaceMap::assert_event_owner(events::TOOLS_PRE_EXECUTE, keys::TOOLS).unwrap();
        SurfaceMap::assert_event_owner(events::TOOLS_EXECUTE, keys::TOOLS).unwrap();
        SurfaceMap::assert_event_owner(events::TOOLS_POST_EXECUTE, keys::TOOLS).unwrap();
        SurfaceMap::assert_event_owner(events::TOOLS_RESULT, keys::TOOLS).unwrap();
        SurfaceMap::assert_event_owner(events::LLM_STREAM, keys::LLM).unwrap();
        SurfaceMap::assert_event_owner(events::AGENTS_CREATED, keys::AGENTS).unwrap();
        SurfaceMap::assert_event_owner(events::AGENTS_DISPOSED, keys::AGENTS).unwrap();
    }

    #[test]
    fn claiming_tools_pipeline_on_llm_fails_closed() {
        let err = SurfaceMap::assert_event_owner(events::TOOLS_EXECUTE, keys::LLM).unwrap_err();
        assert_eq!(
            err,
            MappingError::EventOwner {
                name: events::TOOLS_EXECUTE.to_string(),
                owner: keys::TOOLS,
                claimed: keys::LLM.to_string(),
            }
        );
    }

    #[test]
    fn domain_and_effect_owners_are_hartevo() {
        assert!(DomainKernelSurface::new().owns_mission_and_truth());
        assert!(EffectBrokerSurface::new().owns_effect());
        assert_eq!(AgentsService::new().live_count(), 0);
        let call = ToolCall {
            id: 1,
            name: "search".into(),
        };
        assert_eq!(call.name, "search");
    }
}
