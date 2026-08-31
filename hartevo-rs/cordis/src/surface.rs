//! Map Hartevo surfaces onto Cordis service keys.
//!
//! Practice mapping, not a second runtime. Plugins look up `ctx.tools`,
//! `ctx.llm`, `ctx.agents`, plus Hartevo-owned `ctx.domain`,
//! `ctx.effect_broker`, `ctx.runtime`, and `ctx.desktop`. Registrations
//! reverse through the existing `effect()` / `on()` disposer stack.
//! OpenInterpreter is never provided on those Hartevo-owned keys.

use std::sync::{Arc, Mutex};

use crate::context::{Context, CordisError, keys};
use crate::event::{DispatchMode, EventKey, EventModeMarker};
use crate::session::{SessionStore, events as session_events};

/// Cordis keys this mapping provides and looks up.
pub const MAPPED_KEYS: &[&str] = &[
    keys::TOOLS,
    keys::LLM,
    keys::SESSIONS,
    keys::AGENTS,
    keys::DOMAIN,
    keys::EFFECT_BROKER,
    keys::RUNTIME,
    keys::DESKTOP,
];

/// Primer event names owned by the mapped surfaces.
pub mod events {
    use crate::event::{Emit, EventKey, EventSchemaId, Waterfall};

    use super::{AgentRef, LlmStream, ToolCall};

    /// Allow / deny / ask waterfall before a tool body runs.
    pub const TOOLS_PRE_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.pre-execute.v1"),
        "tools/pre-execute",
    );
    /// Around-dispatch waterfall wrapping the tool body.
    pub const TOOLS_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.execute.v1"),
        "tools/execute",
    );
    /// Inspect / replace waterfall after a tool body.
    pub const TOOLS_POST_EXECUTE: EventKey<Waterfall, ToolCall, ToolCall> = EventKey::new(
        EventSchemaId::new("hartevo.tools.post-execute.v1"),
        "tools/post-execute",
    );
    /// Observe-only notification of the frozen tool outcome.
    pub const TOOLS_RESULT: EventKey<Emit, ToolCall, ()> = EventKey::new(
        EventSchemaId::new("hartevo.tools.result.v1"),
        "tools/result",
    );
    /// Intercept / wrap every streaming model call.
    pub const LLM_STREAM: EventKey<Waterfall, LlmStream, LlmStream> =
        EventKey::new(EventSchemaId::new("hartevo.llm.stream.v1"), "llm/stream");
    /// Live agent published after scoped setup.
    pub const AGENT_CREATED: EventKey<Emit, AgentRef, ()> = EventKey::new(
        EventSchemaId::new("hartevo.agent.created.v1"),
        "agent/created",
    );
    /// Live agent left the registry.
    pub const AGENT_DISPOSED: EventKey<Emit, AgentRef, ()> = EventKey::new(
        EventSchemaId::new("hartevo.agent.disposed.v1"),
        "agent/disposed",
    );
}

/// Who currently owns a mapped surface. OpenInterpreter never owns Mission,
/// Truth, or Effect, and is not a valid owner for domain / effect_broker /
/// runtime / desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SurfaceOwner {
    #[default]
    Hartevo,
    OpenInterpreter,
}

impl SurfaceOwner {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hartevo => "hartevo",
            Self::OpenInterpreter => "openinterpreter",
        }
    }
}

/// One tool pipeline call. Policy may rewrite [`ToolCall::decision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: String,
    pub decision: String,
    pub result: String,
}

impl ToolCall {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        arguments: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            arguments: arguments.into(),
            decision: decision.into(),
            result: String::new(),
        }
    }
}

/// One model stream request. Waterfall listeners may wrap [`LlmStream::body`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmStream {
    pub model: String,
    pub prompt: String,
    pub body: String,
}

impl LlmStream {
    #[must_use]
    pub fn new(model: impl Into<String>, prompt: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            prompt: prompt.into(),
            body: String::new(),
        }
    }
}

/// Live agent identity registered on `ctx.agents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRef {
    pub id: String,
}

impl AgentRef {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

/// Tools pipeline service provided at `ctx.tools`.
#[derive(Debug, Clone)]
pub struct ToolsSurface {
    names: Arc<Mutex<Vec<String>>>,
}

impl ToolsSurface {
    fn new() -> Self {
        Self {
            names: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register(&self, name: impl Into<String>) {
        self.names.lock().expect("tools names").push(name.into());
    }

    pub fn unregister(&self, name: &str) {
        self.names
            .lock()
            .expect("tools names")
            .retain(|registered| registered != name);
    }

    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.names.lock().expect("tools names").clone()
    }
}

/// Model stream service provided at `ctx.llm`.
#[derive(Debug, Clone)]
pub struct LlmSurface {
    streams: Arc<Mutex<Vec<String>>>,
}

impl LlmSurface {
    fn new() -> Self {
        Self {
            streams: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register_stream(&self, model: impl Into<String>) {
        self.streams.lock().expect("llm streams").push(model.into());
    }

    pub fn unregister_stream(&self, model: &str) {
        self.streams
            .lock()
            .expect("llm streams")
            .retain(|registered| registered != model);
    }

    #[must_use]
    pub fn streams(&self) -> Vec<String> {
        self.streams.lock().expect("llm streams").clone()
    }
}

/// Live agent coordination provided at `ctx.agents`.
#[derive(Debug, Clone)]
pub struct AgentsSurface {
    live: Arc<Mutex<Vec<AgentRef>>>,
}

impl AgentsSurface {
    fn new() -> Self {
        Self {
            live: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register(&self, agent: AgentRef) {
        self.live.lock().expect("agents").push(agent);
    }

    pub fn unregister(&self, id: &str) {
        self.live
            .lock()
            .expect("agents")
            .retain(|agent| agent.id != id);
    }

    #[must_use]
    pub fn list(&self) -> Vec<AgentRef> {
        self.live.lock().expect("agents").clone()
    }
}

/// Hartevo Domain Kernel handle. OpenInterpreter never owns this key.
///
/// Cordis does not reimplement Domain Kernel. These flags are the host-side
/// fail-closed view of consent, approval, local-first, SQLCipher, and eval.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) consent: bool,
    pub(crate) approved: bool,
    pub(crate) local_first: bool,
    pub(crate) sqlcipher: bool,
    pub(crate) eval_gate: bool,
}

impl DomainSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn consent(&self) -> bool {
        self.consent
    }

    #[must_use]
    pub const fn approved(&self) -> bool {
        self.approved
    }

    #[must_use]
    pub const fn local_first(&self) -> bool {
        self.local_first
    }

    #[must_use]
    pub const fn sqlcipher(&self) -> bool {
        self.sqlcipher
    }

    #[must_use]
    pub const fn eval_gate(&self) -> bool {
        self.eval_gate
    }
}

impl Default for DomainSurface {
    fn default() -> Self {
        Self {
            owner: SurfaceOwner::Hartevo,
            consent: false,
            approved: false,
            local_first: true,
            sqlcipher: true,
            eval_gate: true,
        }
    }
}

/// Hartevo Effect Broker handle. The only external-write path.
///
/// `receipt_is_verification` stays false: Receipt ≠ Verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EffectBrokerSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) receipt_is_verification: bool,
}

impl EffectBrokerSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn receipt_is_verification(&self) -> bool {
        self.receipt_is_verification
    }
}

/// Optional runtime plugin slot. OpenInterpreter may sit here as an adapter
/// plugin; it still does not own Mission, Truth, or Effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeSurface {
    pub(crate) owner: SurfaceOwner,
    pub(crate) plugin: Option<&'static str>,
}

impl RuntimeSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }

    #[must_use]
    pub const fn plugin(&self) -> Option<&'static str> {
        self.plugin
    }
}

/// Desktop shell handle. Hartevo-owned; not an OpenInterpreter surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DesktopSurface {
    pub(crate) owner: SurfaceOwner,
}

impl DesktopSurface {
    #[must_use]
    pub const fn owner(&self) -> SurfaceOwner {
        self.owner
    }
}

/// Bundle of Hartevo-owned surfaces. Mapping, not a second host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HartevoSurfaces {
    pub(crate) domain: DomainSurface,
    pub(crate) effect_broker: EffectBrokerSurface,
    pub(crate) runtime: RuntimeSurface,
    pub(crate) desktop: DesktopSurface,
}

/// Non-forgeable crate-internal authority for Hartevo surface registration.
/// The public owner label on [`HartevoSurfaces`] is configuration data only;
/// it never creates this token.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HartevoSurfaceAuthority {
    marker: AuthorityMarker,
}

#[derive(Debug, Clone, Copy)]
struct AuthorityMarker;

impl HartevoSurfaceAuthority {
    pub(crate) const fn is_valid(self) -> bool {
        let _ = self.marker;
        true
    }
}

fn trusted_surface_authority() -> HartevoSurfaceAuthority {
    HartevoSurfaceAuthority {
        marker: AuthorityMarker,
    }
}

impl Default for HartevoSurfaces {
    fn default() -> Self {
        Self {
            domain: DomainSurface::default(),
            effect_broker: EffectBrokerSurface::default(),
            runtime: RuntimeSurface {
                owner: SurfaceOwner::Hartevo,
                plugin: None,
            },
            desktop: DesktopSurface {
                owner: SurfaceOwner::Hartevo,
            },
        }
    }
}

/// Provide mapped services and lock primer event names to one dispatch mode.
///
/// Tools pipeline: three waterfalls plus observe-only `tools/result`.
/// LLM streams: `llm/stream` waterfall. Agent coordination: emit-only
/// `agent/created` / `agent/disposed`. Domain / effect_broker / runtime /
/// desktop are Hartevo-owned lookups and never go through OpenInterpreter.
pub(crate) fn map_surfaces(
    ctx: &mut Context,
    surfaces: HartevoSurfaces,
) -> Result<(), CordisError> {
    let authority = trusted_surface_authority();
    if !authority.is_valid() {
        return Err(CordisError::ReservedServiceKey {
            key: keys::DOMAIN.to_string(),
        });
    }
    require_hartevo_owned("domain", surfaces.domain.owner)?;
    require_hartevo_owned("effect_broker", surfaces.effect_broker.owner)?;
    require_hartevo_owned("runtime", surfaces.runtime.owner)?;
    require_hartevo_owned("desktop", surfaces.desktop.owner)?;
    if let Some(key) = MAPPED_KEYS.iter().copied().find(|key| ctx.has(key)) {
        return Err(CordisError::SurfaceAlreadyMapped { key });
    }
    validate_mapped_events(ctx)?;

    let session_dispatcher = ctx.event_reentry()?;
    ctx.provide(keys::TOOLS, ToolsSurface::new())?;
    ctx.provide(keys::LLM, LlmSurface::new())?;
    ctx.provide(
        keys::SESSIONS,
        SessionStore::with_event_dispatcher(session_dispatcher),
    )?;
    ctx.provide(keys::AGENTS, AgentsSurface::new())?;
    ctx.provide_reserved(authority, keys::DOMAIN, surfaces.domain)?;
    ctx.provide_reserved(authority, keys::EFFECT_BROKER, surfaces.effect_broker)?;
    ctx.provide_reserved(authority, keys::RUNTIME, surfaces.runtime)?;
    ctx.provide_reserved(authority, keys::DESKTOP, surfaces.desktop)?;
    lock_mapped_events(ctx)
}

fn validate_mapped_events(ctx: &Context) -> Result<(), CordisError> {
    validate_mapped_event(ctx, events::TOOLS_PRE_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_POST_EXECUTE)?;
    validate_mapped_event(ctx, events::TOOLS_RESULT)?;
    validate_mapped_event(ctx, events::LLM_STREAM)?;
    validate_mapped_event(ctx, events::AGENT_CREATED)?;
    validate_mapped_event(ctx, events::AGENT_DISPOSED)?;
    validate_mapped_event(ctx, session_events::SESSION_EVENT)?;
    validate_mapped_event(ctx, session_events::SESSION_FLUSH)?;
    Ok(())
}

fn validate_mapped_event<M, P, Output>(
    ctx: &Context,
    key: EventKey<M, P, Output>,
) -> Result<(), CordisError>
where
    M: EventModeMarker,
    P: 'static,
    Output: 'static,
{
    let requested = key.descriptor();
    if let Some(locked) = ctx.event_descriptor(key)
        && locked != requested
    {
        return Err(CordisError::SchemaConflict {
            name: key.name().to_string(),
            locked,
            requested,
        });
    }
    Ok(())
}

/// Rebind only the Hartevo Domain provider in place. Its provider identity and
/// owner stay stable while generation/notification advance exactly once.
pub(crate) fn rebind_hartevo_domain(
    ctx: &mut Context,
    domain: DomainSurface,
) -> Result<(), CordisError> {
    let _ = ctx.replace_hartevo_domain(trusted_surface_authority(), domain)?;
    Ok(())
}

fn lock_mapped_events(ctx: &mut Context) -> Result<(), CordisError> {
    ctx.lock_event_key(events::TOOLS_PRE_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_POST_EXECUTE)?;
    ctx.lock_event_key(events::TOOLS_RESULT)?;
    ctx.lock_event_key(events::LLM_STREAM)?;
    ctx.lock_event_key(events::AGENT_CREATED)?;
    ctx.lock_event_key(events::AGENT_DISPOSED)?;
    ctx.lock_event_key(session_events::SESSION_EVENT)?;
    ctx.lock_event_key(session_events::SESSION_FLUSH)?;
    Ok(())
}

fn require_hartevo_owned(key: &'static str, owner: SurfaceOwner) -> Result<(), CordisError> {
    if owner != SurfaceOwner::Hartevo {
        return Err(CordisError::InvalidSurfaceOwner {
            key,
            owner: owner.as_str(),
        });
    }
    Ok(())
}

/// Register a tool name on `ctx.tools` and reverse it on teardown.
pub fn register_tool(ctx: &mut Context, name: impl Into<String>) -> Result<(), CordisError> {
    let Some(tools) = ctx.tools::<ToolsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    };
    let name = name.into();
    tools.register(name.clone());
    ctx.effect(move || tools.unregister(&name));
    Ok(())
}

/// Register a model stream on `ctx.llm` and reverse it on teardown.
pub fn register_llm_stream(ctx: &mut Context, model: impl Into<String>) -> Result<(), CordisError> {
    let Some(llm) = ctx.llm::<LlmSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    };
    let model = model.into();
    llm.register_stream(model.clone());
    ctx.effect(move || llm.unregister_stream(&model));
    Ok(())
}

/// Register live agent coordination on `ctx.agents` and reverse it on teardown.
pub fn register_agent(ctx: &mut Context, agent: AgentRef) -> Result<(), CordisError> {
    let Some(agents) = ctx.agents::<AgentsSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
        ]));
    };
    let id = agent.id.clone();
    agents.register(agent);
    ctx.effect(move || agents.unregister(&id));
    Ok(())
}

/// Dispatch one tools pipeline call through the locked event names.
pub fn run_tools_pipeline(ctx: &mut Context, mut call: ToolCall) -> Result<ToolCall, CordisError> {
    call = ctx.waterfall(events::TOOLS_PRE_EXECUTE, call)?;
    if call.decision != "allow" {
        ctx.emit(events::TOOLS_RESULT, &call)?;
        return Ok(call);
    }
    call = ctx.waterfall(events::TOOLS_EXECUTE, call)?;
    call = ctx.waterfall(events::TOOLS_POST_EXECUTE, call)?;
    ctx.emit(events::TOOLS_RESULT, &call)?;
    Ok(call)
}

/// Dispatch one model stream through `llm/stream`.
pub fn stream_llm(ctx: &mut Context, request: LlmStream) -> Result<LlmStream, CordisError> {
    ctx.waterfall(events::LLM_STREAM, request)
}

/// Primer dispatch mode for each mapped event name.
#[must_use]
pub fn expected_mode(name: impl AsRef<str>) -> Option<DispatchMode> {
    match name.as_ref() {
        "tools/pre-execute" | "tools/execute" | "tools/post-execute" | "llm/stream" => {
            Some(DispatchMode::Waterfall)
        }
        "tools/result" | "agent/created" | "agent/disposed" | "session/event" => {
            Some(DispatchMode::Emit)
        }
        "session/flush" => Some(DispatchMode::Parallel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Waterfall;

    #[test]
    fn sealed_mapping_rejects_forged_owner_with_typed_error_before_mount() {
        let mut ctx = Context::new();
        let mut surfaces = HartevoSurfaces::default();
        surfaces.domain.owner = SurfaceOwner::OpenInterpreter;
        assert_eq!(
            map_surfaces(&mut ctx, surfaces).unwrap_err(),
            CordisError::InvalidSurfaceOwner {
                key: "domain",
                owner: "openinterpreter",
            }
        );
        assert!(MAPPED_KEYS.iter().all(|key| !ctx.has(key)));
    }

    #[test]
    fn duplicate_sealed_mapping_is_typed_and_keeps_original_authority() {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap();
        assert!(matches!(
            map_surfaces(&mut ctx, HartevoSurfaces::default()),
            Err(CordisError::SurfaceAlreadyMapped { key }) if key == keys::TOOLS
        ));
        assert_eq!(
            ctx.domain::<DomainSurface>().unwrap().owner(),
            SurfaceOwner::Hartevo
        );
    }

    #[test]
    fn all_seven_event_descriptors_preflight_before_any_surface_provider_mutation() {
        let mut ctx = Context::new();
        let incompatible_last_key = EventKey::<Waterfall, AgentRef, AgentRef>::new(
            events::AGENT_DISPOSED.schema_id(),
            events::AGENT_DISPOSED.name(),
        );
        ctx.lock_event_key(incompatible_last_key).unwrap();
        let descriptor_before = ctx.event_descriptor(events::AGENT_DISPOSED).unwrap();

        let error = map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap_err();

        assert!(matches!(
            error,
            CordisError::SchemaConflict { ref name, ref locked, ref requested }
                if name == events::AGENT_DISPOSED.name()
                    && locked == &descriptor_before
                    && requested == &events::AGENT_DISPOSED.descriptor()
        ));
        assert!(MAPPED_KEYS.iter().all(|key| !ctx.has(key)));
        assert_eq!(
            ctx.event_descriptor(events::AGENT_DISPOSED),
            Some(descriptor_before)
        );
        for name in [
            events::TOOLS_PRE_EXECUTE.name(),
            events::TOOLS_EXECUTE.name(),
            events::TOOLS_POST_EXECUTE.name(),
            events::TOOLS_RESULT.name(),
            events::LLM_STREAM.name(),
            events::AGENT_CREATED.name(),
        ] {
            assert_eq!(
                ctx.event_descriptor(name),
                None,
                "{name} must stay untouched"
            );
        }
    }

    #[test]
    fn authorized_domain_rebind_preserves_identity_and_never_touches_broker() {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, HartevoSurfaces::default()).unwrap();
        let domain_before = ctx.provider_snapshot(keys::DOMAIN).unwrap();
        let broker_before = ctx.provider_snapshot(keys::EFFECT_BROKER).unwrap();
        let bound = DomainSurface {
            consent: true,
            approved: true,
            ..DomainSurface::default()
        };

        rebind_hartevo_domain(&mut ctx, bound).unwrap();
        let domain_after = ctx.provider_snapshot(keys::DOMAIN).unwrap();
        let broker_after = ctx.provider_snapshot(keys::EFFECT_BROKER).unwrap();
        assert_eq!(domain_after.provider_id, domain_before.provider_id);
        assert_eq!(domain_after.owner_uid, domain_before.owner_uid);
        assert_eq!(domain_after.generation, domain_before.generation + 1);
        assert_eq!(domain_after.notify_count, domain_before.notify_count + 1);
        assert_eq!(domain_after.disposer_count, domain_before.disposer_count);
        assert_eq!(broker_after, broker_before);
        assert!(ctx.domain::<DomainSurface>().unwrap().consent());
        assert!(ctx.domain::<DomainSurface>().unwrap().approved());
    }
}
