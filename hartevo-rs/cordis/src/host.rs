//! Desktop-facing Cordis host. Mounts SurfaceMapping, AgentLoop, and
//! InvariantGate, and issues typed Runtime permits. The symbolic AgentLoop is
//! not Desktop Runtime authority; OpenInterpreter remains an optional adapter.

use chrono::{DateTime, Utc};

use crate::agent::{AgentLoop, AgentStep, AgentStepResult, run_agent_step};
use crate::authority::{
    AuthorityScope, RuntimeDispatchCompletion, RuntimeDispatchLease, RuntimeDispatchPermit,
};
use crate::context::{Context, CordisError, keys};
use crate::invariants::{
    InvariantGate, OPENINTERPRETER, apply_effect, enforce_invariants, enforce_runtime_invariants,
};
use crate::kernel::{
    KernelApproval, KernelConsentRecord, KernelConsentState, bind_domain_kernel_facts,
};
use crate::loader::{
    EnvironmentOverlay, LoadReport, LoaderContext, PluginId, PluginSpec, load_plugins,
};
use crate::service::Service;
use crate::surface::{
    AgentRef, AgentsSurface, DesktopSurface, DomainSurface, EffectBrokerSurface, HartevoSurfaces,
    LlmSurface, RuntimeSurface, SurfaceOwner, ToolsSurface, events, map_surfaces,
    rebind_hartevo_domain,
};

/// Overlay-selected plugin ids the desktop host starts.
pub const HOST_PLUGIN_IDS: &[&str] = &["surfaces", "agent-loop", "invariants"];

/// Optional OpenInterpreter adapter plugin id. Never the loop.
pub const OPENINTERPRETER_PLUGIN_ID: &str = OPENINTERPRETER;

/// Live Cordis context owned by the desktop host.
pub struct CordisHost {
    ctx: Context,
    bound_scope: Option<AuthorityScope>,
    active_runtime: Option<ActiveRuntimeDispatch>,
    next_runtime_serial: u64,
}

#[derive(Debug)]
struct ActiveRuntimeDispatch {
    serial: u64,
    scope: AuthorityScope,
    agent_id: String,
    lease: std::sync::Arc<RuntimeDispatchLease>,
}

impl std::fmt::Debug for CordisHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CordisHost")
            .field("ctx", &self.ctx)
            .field("bound_scope", &self.bound_scope)
            .field("active_runtime", &self.active_runtime)
            .field("next_runtime_serial", &self.next_runtime_serial)
            .finish()
    }
}

impl CordisHost {
    /// Mount the sealed Hartevo surfaces, AgentLoop, and InvariantGate on a
    /// fresh context.
    ///
    /// `runtime_plugin` may name OpenInterpreter as an optional adapter on
    /// [`RuntimeSurface::plugin`]. Domain and Effect stay Hartevo-owned.
    pub fn boot(openinterpreter: bool) -> Result<Self, CordisError> {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, desktop_surfaces(openinterpreter))?;
        ctx.mount(AgentLoop)?;
        ctx.mount(InvariantGate)?;
        Ok(Self {
            ctx,
            bound_scope: None,
            active_runtime: None,
            next_runtime_serial: 0,
        })
    }

    /// Same three services, selected by overlay rather than a crate boot list.
    pub fn boot_overlay(
        overlay: &EnvironmentOverlay,
        loader: &LoaderContext,
        openinterpreter: bool,
    ) -> Result<(Self, LoadReport), CordisError> {
        let mut ctx = Context::new();
        let mapping_surfaces = desktop_surfaces(openinterpreter);
        let mapping = PluginSpec::new("surfaces", move |_config, ctx| {
            map_surfaces(ctx, mapping_surfaces)
        });
        let loop_plugin = PluginSpec::new("agent-loop", |_config, ctx| AgentLoop.apply(ctx))
            .with_inject(AgentLoop::inject().iter().copied());
        let gate = PluginSpec::new("invariants", |_config, ctx| InvariantGate.apply(ctx))
            .with_inject(InvariantGate::inject().iter().copied());
        let adapter = PluginSpec::new(OPENINTERPRETER_PLUGIN_ID, |_config, ctx| {
            ctx.provide(OPENINTERPRETER, "adapter").map(|_| ())
        })
        .with_inject([keys::RUNTIME])
        .with_disabled(!openinterpreter);

        let report = load_plugins(
            &mut ctx,
            loader,
            overlay,
            &[mapping, loop_plugin, gate, adapter],
        )?;
        Ok((
            Self {
                ctx,
                bound_scope: None,
                active_runtime: None,
                next_runtime_serial: 0,
            },
            report,
        ))
    }

    #[must_use]
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// Mutable plugin context for callers that own this host. Reserved
    /// authority keys remain protected by [`Context::provide`], and the sealed
    /// authority mapping API is not public.
    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.ctx
    }

    /// Fail closed, then run one legacy symbolic Cordis agent step.
    ///
    /// This API exercises the generic tool/LLM surface and is not the Desktop
    /// production Runtime path. Desktop uses [`Self::authorize_runtime`].
    pub fn step(&mut self, step: AgentStep) -> Result<AgentStepResult, CordisError> {
        enforce_invariants(&self.ctx)?;
        run_agent_step(&mut self.ctx, step)
    }

    /// Issue a one-shot permit for one exact durable Runtime scope.
    ///
    /// This method only performs short, in-memory gate work. Desktop must drop
    /// its host mutex guard before invoking Application or doing process I/O.
    pub fn authorize_runtime(
        &mut self,
        scope: &AuthorityScope,
    ) -> Result<RuntimeDispatchPermit, CordisError> {
        self.reap_abandoned_runtime();
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        let Some(runtime) = scope.runtime() else {
            return Err(CordisError::RuntimeAuthorityUnbound);
        };
        let Some(bound_scope) = self.bound_scope.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if bound_scope != scope {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        host_is_cordis_loop(self)?;
        enforce_runtime_invariants(&self.ctx)?;

        let Some(agents) = self.ctx.agents::<AgentsSurface>() else {
            return Err(CordisError::MissingDependencies(vec![
                keys::AGENTS.to_string(),
            ]));
        };
        let serial = self
            .next_runtime_serial
            .checked_add(1)
            .ok_or(CordisError::RuntimeDispatchSerialOverflow)?;
        let agent = AgentRef::new(format!(
            "{}:{}:{}:{}",
            scope.project_id(),
            scope.mission_id(),
            runtime.generation(),
            serial
        ));
        let started = self
            .ctx
            .prepare_emit(events::AGENT_CREATED, agent.clone())?;
        let disposed = self
            .ctx
            .prepare_emit(events::AGENT_DISPOSED, agent.clone())?;
        let (permit, lease) = RuntimeDispatchPermit::issue(
            serial,
            scope.clone(),
            agent.id.clone(),
            std::sync::Arc::clone(&agents),
            started,
            disposed,
        );
        agents.register(agent.clone());
        self.next_runtime_serial = serial;
        self.active_runtime = Some(ActiveRuntimeDispatch {
            serial,
            scope: scope.clone(),
            agent_id: agent.id.clone(),
            lease,
        });
        Ok(permit)
    }

    /// Settle an issued Runtime permit and return an out-of-lock lifecycle
    /// notification. The caller must release its host lock before announcing.
    pub fn finish_runtime(
        &mut self,
        permit: RuntimeDispatchPermit,
    ) -> Result<RuntimeDispatchCompletion, CordisError> {
        self.reap_abandoned_runtime();
        let Some(active) = self.active_runtime.as_ref() else {
            return Err(CordisError::RuntimePermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.agent_id != permit.agent_id()
            || !permit.owns_lease(&active.lease)
        {
            return Err(CordisError::RuntimePermitMismatch);
        }
        self.active_runtime = None;
        Ok(permit.complete())
    }

    /// External write path. Invariants must pass; OpenInterpreter cannot write.
    pub fn apply_effect(&self) -> Result<(), CordisError> {
        apply_effect(&self.ctx)
    }

    /// Bind live Domain Kernel facts onto the already-mounted DomainSurface.
    ///
    /// Production boot stays fail-closed. After ApplicationService has a
    /// project/mission with live Consent/Approval, desktop calls this before
    /// `step` / `apply_effect`. Missing facts leave both flags false.
    pub fn bind_domain_kernel(
        &mut self,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_runtime();
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        self.bound_scope = None;
        self.bind_domain_kernel_facts(consent, record, approval, now)
    }

    /// Bind exact scoped Domain facts before [`Self::dispatch_runtime`].
    pub fn bind_domain_kernel_scope(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_runtime();
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        self.bind_domain_kernel_facts(consent, record, approval, now)?;
        self.bound_scope = Some(scope);
        Ok(())
    }

    fn bind_domain_kernel_facts(
        &mut self,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        let Some(mounted) = self.ctx.domain::<DomainSurface>() else {
            return Err(CordisError::MissingDependencies(vec![
                keys::DOMAIN.to_string(),
            ]));
        };
        let bound = bind_domain_kernel_facts(*mounted, consent, record, approval, now);
        rebind_hartevo_domain(&mut self.ctx, bound)
    }

    #[must_use]
    pub fn bound_scope(&self) -> Option<&AuthorityScope> {
        self.bound_scope.as_ref()
    }

    #[must_use]
    pub fn active_runtime_scope(&self) -> Option<&AuthorityScope> {
        self.active_runtime
            .as_ref()
            .filter(|active| active.lease.is_active())
            .map(|active| &active.scope)
    }

    #[must_use]
    pub fn runtime_plugin(&self) -> Option<&'static str> {
        self.ctx
            .runtime::<RuntimeSurface>()
            .and_then(|runtime| runtime.plugin)
    }

    #[must_use]
    pub fn mounted_keys(&self) -> [&'static str; 7] {
        [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
            keys::RUNTIME,
            keys::DESKTOP,
        ]
    }

    pub fn teardown(&mut self) {
        if let Some(active) = self.active_runtime.take() {
            active.lease.release();
        }
        self.bound_scope = None;
        self.ctx.teardown();
    }

    /// Register a Runtime-start observer. Notifications prepared while the
    /// host is locked are always invoked by the dispatcher after unlock.
    pub fn on_runtime_started<F>(&mut self, observer: F) -> Result<(), CordisError>
    where
        F: Fn(&AgentRef) + Send + Sync + 'static,
    {
        self.ctx
            .on_emit(events::AGENT_CREATED, observer)
            .map(|_| ())
    }

    /// Register a Runtime-finished observer. The completion notification is
    /// returned from [`Self::finish_runtime`] for out-of-lock dispatch.
    pub fn on_runtime_finished<F>(&mut self, observer: F) -> Result<(), CordisError>
    where
        F: Fn(&AgentRef) + Send + Sync + 'static,
    {
        self.ctx
            .on_emit(events::AGENT_DISPOSED, observer)
            .map(|_| ())
    }

    fn reap_abandoned_runtime(&mut self) {
        if self
            .active_runtime
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            self.active_runtime = None;
        }
    }
}

/// Default host surfaces. OpenInterpreter may occupy the runtime plugin slot.
///
/// Consent and approval stay fail-closed (`DomainSurface::default()`). Live
/// Domain Kernel facts are bound after boot, before `step` / `apply_effect`.
#[must_use]
fn desktop_surfaces(openinterpreter: bool) -> HartevoSurfaces {
    HartevoSurfaces {
        runtime: RuntimeSurface {
            owner: SurfaceOwner::Hartevo,
            plugin: openinterpreter.then_some(OPENINTERPRETER),
        },
        ..HartevoSurfaces::default()
    }
}

/// Boot-time host check: the seven keys, Hartevo ownership of Domain/Effect,
/// Receipt ≠ Verification, and local-first/sqlcipher/eval_gate.
///
/// Consent and approval are *not* required here. They are step-time
/// invariants of [`CordisHost::step`] / [`apply_effect`].
pub fn host_is_cordis_loop(host: &CordisHost) -> Result<(), CordisError> {
    for key in host.mounted_keys() {
        if !host.ctx.has(key) {
            return Err(CordisError::MissingDependencies(vec![key.to_string()]));
        }
    }
    if host.ctx.tools::<ToolsSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::TOOLS.to_string(),
        ]));
    }
    if host.ctx.llm::<LlmSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    }
    if host.ctx.agents::<AgentsSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
        ]));
    }
    let Some(domain) = host.ctx.domain::<DomainSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::DOMAIN.to_string(),
        ]));
    };
    if domain.owner != SurfaceOwner::Hartevo {
        return Err(CordisError::MissingDependencies(vec![
            keys::DOMAIN.to_string(),
        ]));
    }
    if !domain.local_first {
        return Err(CordisError::MissingDependencies(vec![
            crate::invariants::missing::LOCAL_FIRST.to_string(),
        ]));
    }
    if !domain.sqlcipher {
        return Err(CordisError::MissingDependencies(vec![
            crate::invariants::missing::SQLCIPHER.to_string(),
        ]));
    }
    if !domain.eval_gate {
        return Err(CordisError::MissingDependencies(vec![
            crate::invariants::missing::EVAL.to_string(),
        ]));
    }
    let Some(broker) = host.ctx.effect_broker::<EffectBrokerSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::EFFECT_BROKER.to_string(),
        ]));
    };
    if broker.owner != SurfaceOwner::Hartevo {
        return Err(CordisError::MissingDependencies(vec![
            keys::EFFECT_BROKER.to_string(),
        ]));
    }
    if broker.receipt_is_verification {
        return Err(CordisError::MissingDependencies(vec![
            crate::invariants::missing::VERIFICATION.to_string(),
        ]));
    }
    let Some(runtime) = host.ctx.runtime::<RuntimeSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::RUNTIME.to_string(),
        ]));
    };
    if runtime.owner != SurfaceOwner::Hartevo {
        return Err(CordisError::MissingDependencies(vec![
            keys::RUNTIME.to_string(),
        ]));
    }
    let Some(desktop) = host.ctx.desktop::<DesktopSurface>() else {
        return Err(CordisError::MissingDependencies(vec![
            keys::DESKTOP.to_string(),
        ]));
    };
    if desktop.owner != SurfaceOwner::Hartevo {
        return Err(CordisError::MissingDependencies(vec![
            keys::DESKTOP.to_string(),
        ]));
    }
    Ok(())
}

#[must_use]
pub fn host_plugin_ids() -> [PluginId; 3] {
    [
        PluginId::new(HOST_PLUGIN_IDS[0]),
        PluginId::new(HOST_PLUGIN_IDS[1]),
        PluginId::new(HOST_PLUGIN_IDS[2]),
    ]
}
