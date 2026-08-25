//! Desktop-facing Cordis host. Mounts SurfaceMapping, AgentLoop, and
//! InvariantGate so the live loop is [`run_agent_step`], not OpenInterpreter.

use chrono::{DateTime, Utc};

use crate::agent::{AgentLoop, AgentStep, AgentStepResult, run_agent_step};
use crate::context::{Context, CordisError, keys};
use crate::invariants::{InvariantGate, OPENINTERPRETER, apply_effect, enforce_invariants};
use crate::kernel::{
    KernelApproval, KernelConsentRecord, KernelConsentState, bind_domain_kernel_facts,
};
use crate::loader::{
    EnvironmentOverlay, LoadReport, LoaderContext, PluginId, PluginSpec, load_plugins,
};
use crate::service::Service;
use crate::surface::{
    AgentsSurface, DomainSurface, EffectBrokerSurface, HartevoSurfaces, LlmSurface, RuntimeSurface,
    SurfaceMapping, SurfaceOwner, ToolsSurface,
};

/// Overlay-selected plugin ids the desktop host starts.
pub const HOST_PLUGIN_IDS: &[&str] = &["surfaces", "agent-loop", "invariants"];

/// Optional OpenInterpreter adapter plugin id. Never the loop.
pub const OPENINTERPRETER_PLUGIN_ID: &str = OPENINTERPRETER;

/// Live Cordis context owned by the desktop host.
pub struct CordisHost {
    ctx: Context,
}

impl std::fmt::Debug for CordisHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CordisHost")
            .field("ctx", &self.ctx)
            .finish()
    }
}

impl CordisHost {
    /// Mount SurfaceMapping, AgentLoop, and InvariantGate on a fresh context.
    ///
    /// `runtime_plugin` may name OpenInterpreter as an optional adapter on
    /// [`RuntimeSurface::plugin`]. Domain and Effect stay Hartevo-owned.
    pub fn boot(surfaces: HartevoSurfaces) -> Result<Self, CordisError> {
        let mut ctx = Context::new();
        ctx.mount(SurfaceMapping { surfaces })?;
        ctx.mount(AgentLoop)?;
        ctx.mount(InvariantGate)?;
        Ok(Self { ctx })
    }

    /// Same three services, selected by overlay rather than a crate boot list.
    pub fn boot_overlay(
        overlay: &EnvironmentOverlay,
        loader: &LoaderContext,
        surfaces: &HartevoSurfaces,
        openinterpreter: bool,
    ) -> Result<(Self, LoadReport), CordisError> {
        let mut ctx = Context::new();
        let mapping_surfaces = *surfaces;
        let mapping = PluginSpec::new("surfaces", move |_config, ctx| {
            SurfaceMapping {
                surfaces: mapping_surfaces,
            }
            .apply(ctx);
        });
        let loop_plugin = PluginSpec::new("agent-loop", |_config, ctx| {
            AgentLoop.apply(ctx);
        })
        .with_inject(AgentLoop::inject().iter().copied());
        let gate = PluginSpec::new("invariants", |_config, ctx| {
            InvariantGate.apply(ctx);
        })
        .with_inject(InvariantGate::inject().iter().copied());
        let adapter = PluginSpec::new(OPENINTERPRETER_PLUGIN_ID, |_config, ctx| {
            ctx.provide(OPENINTERPRETER, "adapter");
        })
        .with_inject([keys::RUNTIME])
        .with_disabled(!openinterpreter);

        let report = load_plugins(
            &mut ctx,
            loader,
            overlay,
            &[mapping, loop_plugin, gate, adapter],
        )?;
        Ok((Self { ctx }, report))
    }

    #[must_use]
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// Fail closed, then run one Cordis-hosted agent step.
    ///
    /// Consent and approval are step-time invariants, not boot stamps.
    pub fn step(&mut self, step: AgentStep) -> Result<AgentStepResult, CordisError> {
        enforce_invariants(&self.ctx)?;
        run_agent_step(&mut self.ctx, step)
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
        let Some(mounted) = self.ctx.domain::<DomainSurface>() else {
            return Err(CordisError::MissingDependencies(vec![
                keys::DOMAIN.to_string(),
            ]));
        };
        let bound = bind_domain_kernel_facts(*mounted, consent, record, approval, now);
        self.ctx.replace(keys::DOMAIN, bound);
        Ok(())
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
        self.ctx.teardown();
    }
}

/// Default host surfaces. OpenInterpreter may occupy the runtime plugin slot.
///
/// Consent and approval stay fail-closed (`DomainSurface::default()`). Live
/// Domain Kernel facts are bound after boot, before `step` / `apply_effect`.
#[must_use]
pub fn desktop_surfaces(openinterpreter: bool) -> HartevoSurfaces {
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
