//! Desktop-facing Cordis host. Mounts SurfaceMapping, automatic compaction,
//! AgentLoop, the local spawn provider, and InvariantGate, and issues typed
//! Domain-command and Runtime permits. The symbolic AgentLoop is not Desktop
//! Runtime authority; OpenInterpreter remains an optional adapter.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::agent::{
    AgentLoop, AgentStep, AgentStepResult, AgentTurnOutcome, run_agent_step,
    run_authorized_runtime_agent_turn,
};
use crate::authority::{
    AuthorityScope, DomainCommandBinding, DomainCommandLease, DomainCommandPermit,
    EffectExecutionBinding, EffectExecutionLease, EffectExecutionPermit,
    EffectReconciliationBinding, EffectReconciliationLease, EffectReconciliationPermit,
    EffectVerificationBinding, EffectVerificationLease, EffectVerificationPermit,
    RuntimeAgentRetention, RuntimeDispatchCompletion, RuntimeDispatchLease,
    RuntimeDispatchNotifications, RuntimeDispatchPermit, RuntimeStatusCompletion,
};
use crate::compaction_automation::CompactionAutomation;
use crate::context::{Context, CordisError, TeardownPermit, TeardownTransaction, keys};
use crate::event::PreparedEmit;
use crate::fiber::LifecycleCancellation;
use crate::invariants::{InvariantGate, OPENINTERPRETER, apply_effect, enforce_runtime_invariants};
use crate::kernel::{
    KernelApproval, KernelConsentRecord, KernelConsentState, bind_domain_kernel_facts,
};
use crate::loader::{
    EnvironmentOverlay, LoadReport, LoaderContext, PluginId, PluginSpec, load_plugins,
};
use crate::service::Service;
use crate::session::{SessionCallConfig, SessionId, SessionStore};
use crate::subagent::{
    SUBAGENT_SPAWN_IN_PROCESS_PLUGIN_ID, SpawnInProcessSubagent, SubagentRun, SubagentRuntime,
    SubagentStartRequest,
};
use crate::surface::{
    AgentPublicationCommit, AgentRef, AgentStatus, AgentStatusChange, AgentsSurface,
    DesktopSurface, DomainSurface, EffectBrokerSurface, HartevoSurfaces, LlmSurface,
    RuntimeSurface, SurfaceOwner, SystemPromptSurface, ToolsSurface, events, map_surfaces,
    rebind_hartevo_domain,
};

/// Overlay-selected plugin ids the desktop host starts.
pub const HOST_PLUGIN_IDS: &[&str] = &[
    "surfaces",
    "compaction-basic",
    "agent-loop",
    SUBAGENT_SPAWN_IN_PROCESS_PLUGIN_ID,
    "invariants",
];

/// Optional OpenInterpreter adapter plugin id. Never the loop.
pub const OPENINTERPRETER_PLUGIN_ID: &str = OPENINTERPRETER;

/// Live Cordis context owned by the desktop host.
pub struct CordisHost {
    ctx: Context,
    bound_scope: Option<AuthorityScope>,
    active_domain_command: Option<ActiveDomainCommand>,
    next_domain_command_serial: u64,
    active_effect_execution: Option<ActiveEffectExecution>,
    next_effect_execution_serial: u64,
    active_effect_reconciliation: Option<ActiveEffectReconciliation>,
    next_effect_reconciliation_serial: u64,
    active_effect_verification: Option<ActiveEffectVerification>,
    next_effect_verification_serial: u64,
    active_runtime: Option<ActiveRuntimeDispatch>,
    runtime_agents: HashMap<RuntimeAgentKey, RetainedRuntimeAgent>,
    deferred_runtime_status: Vec<RuntimeStatusCompletion>,
    next_runtime_serial: u64,
}

#[derive(Debug)]
struct ActiveDomainCommand {
    serial: u64,
    scope: AuthorityScope,
    command: DomainCommandBinding,
    lease: std::sync::Arc<DomainCommandLease>,
}

#[derive(Debug)]
struct ActiveEffectExecution {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectExecutionBinding,
    lease: std::sync::Arc<EffectExecutionLease>,
}

#[derive(Debug)]
struct ActiveEffectReconciliation {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectReconciliationBinding,
    lease: std::sync::Arc<EffectReconciliationLease>,
}

#[derive(Debug)]
struct ActiveEffectVerification {
    serial: u64,
    scope: AuthorityScope,
    binding: EffectVerificationBinding,
    lease: std::sync::Arc<EffectVerificationLease>,
}

#[derive(Debug)]
struct ActiveRuntimeDispatch {
    serial: u64,
    scope: AuthorityScope,
    agent_id: String,
    lease: std::sync::Arc<RuntimeDispatchLease>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RuntimeAgentKey {
    tenant: String,
    project: String,
    mission: String,
}

/// Durable-domain identity of one retained Runtime Agent.
///
/// This deliberately omits every revision and capability. Desktop may use the
/// ids to reopen Application state, but must recompute authority before a new
/// Runtime dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeAgentIdentity {
    tenant: String,
    project: String,
    mission: String,
}

impl RuntimeAgentIdentity {
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &str {
        &self.mission
    }
}

impl From<&AuthorityScope> for RuntimeAgentKey {
    fn from(scope: &AuthorityScope) -> Self {
        Self {
            tenant: scope.tenant_id().to_owned(),
            project: scope.project_id().to_owned(),
            mission: scope.mission_id().to_owned(),
        }
    }
}

#[derive(Debug)]
struct RetainedRuntimeAgent {
    agent: AgentRef,
    retention: Arc<RuntimeAgentRetention>,
}

struct RuntimeAgentDisposal {
    publication: Option<AgentPublicationCommit>,
    notification: Option<PreparedEmit>,
}

impl RuntimeAgentDisposal {
    fn announce(mut self) {
        drop(self.publication.take());
        if let Some(notification) = self.notification.take() {
            let _ = notification.dispatch_contained();
        }
    }
}

fn prepare_runtime_status_notifications(
    context: &Context,
    agent: &AgentRef,
) -> Result<(PreparedEmit, PreparedEmit), CordisError> {
    let running = context.prepare_emit(
        events::AGENT_STATUS,
        AgentStatusChange::new(agent.clone(), AgentStatus::Running),
    )?;
    let idle = context.prepare_emit(
        events::AGENT_STATUS,
        AgentStatusChange::new(agent.clone(), AgentStatus::Idle),
    )?;
    Ok((running, idle))
}

/// Owned second half of one Host teardown transaction.
///
/// The Host is already inert when this value is returned. Calling
/// [`Self::announce`] outside an outer coordinator lock publishes contained
/// Runtime Idle observations before completing teardown of the old Context.
/// Dropping it skips callbacks but still completes all cleanup.
pub struct CordisHostTeardown {
    context: Option<Context>,
    permit: Option<TeardownPermit>,
    statuses: Vec<RuntimeStatusCompletion>,
    agents: Vec<RuntimeAgentDisposal>,
}

impl CordisHostTeardown {
    const fn busy() -> Self {
        Self {
            context: None,
            permit: None,
            statuses: Vec::new(),
            agents: Vec::new(),
        }
    }

    fn new(
        context: Context,
        permit: TeardownPermit,
        statuses: Vec<RuntimeStatusCompletion>,
        agents: Vec<RuntimeAgentDisposal>,
    ) -> Self {
        Self {
            context: Some(context),
            permit: Some(permit),
            statuses,
            agents,
        }
    }

    /// Publish exceptional Runtime Idle transitions without listener veto,
    /// then finish teardown of the exact old Context generation.
    pub fn announce(mut self) {
        for status in std::mem::take(&mut self.statuses) {
            status.announce();
        }
        for agent in std::mem::take(&mut self.agents) {
            agent.announce();
        }
        self.complete();
    }

    fn complete(&mut self) {
        self.statuses.clear();
        self.agents.clear();
        let (Some(mut context), Some(permit)) = (self.context.take(), self.permit.take()) else {
            return;
        };
        context.complete_teardown(permit);
    }
}

impl Drop for CordisHostTeardown {
    fn drop(&mut self) {
        self.complete();
    }
}

impl std::fmt::Debug for CordisHostTeardown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CordisHostTeardown")
            .field("acquired", &self.context.is_some())
            .field("pending_statuses", &self.statuses.len())
            .field("pending_agents", &self.agents.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CordisHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CordisHost")
            .field("ctx", &self.ctx)
            .field("bound_scope", &self.bound_scope)
            .field("active_domain_command", &self.active_domain_command)
            .field(
                "next_domain_command_serial",
                &self.next_domain_command_serial,
            )
            .field("active_effect_execution", &self.active_effect_execution)
            .field(
                "next_effect_execution_serial",
                &self.next_effect_execution_serial,
            )
            .field(
                "active_effect_reconciliation",
                &self.active_effect_reconciliation,
            )
            .field(
                "next_effect_reconciliation_serial",
                &self.next_effect_reconciliation_serial,
            )
            .field(
                "active_effect_verification",
                &self.active_effect_verification,
            )
            .field(
                "next_effect_verification_serial",
                &self.next_effect_verification_serial,
            )
            .field("active_runtime", &self.active_runtime)
            .field("runtime_agents", &self.runtime_agents.len())
            .field(
                "deferred_runtime_status",
                &self.deferred_runtime_status.len(),
            )
            .field("next_runtime_serial", &self.next_runtime_serial)
            .finish()
    }
}

impl CordisHost {
    /// Mount the sealed Hartevo surfaces, automatic compaction, AgentLoop,
    /// local spawn provider, and InvariantGate on a fresh context.
    ///
    /// `runtime_plugin` may name OpenInterpreter as an optional adapter on
    /// [`RuntimeSurface::plugin`]. Domain and Effect stay Hartevo-owned.
    pub fn boot(openinterpreter: bool) -> Result<Self, CordisError> {
        let mut ctx = Context::new();
        map_surfaces(&mut ctx, desktop_surfaces(openinterpreter))?;
        ctx.mount(CompactionAutomation::default())?;
        ctx.mount(AgentLoop)?;
        ctx.mount(SpawnInProcessSubagent::default())?;
        ctx.mount(InvariantGate)?;
        Ok(Self {
            ctx,
            bound_scope: None,
            active_domain_command: None,
            next_domain_command_serial: 0,
            active_effect_execution: None,
            next_effect_execution_serial: 0,
            active_effect_reconciliation: None,
            next_effect_reconciliation_serial: 0,
            active_effect_verification: None,
            next_effect_verification_serial: 0,
            active_runtime: None,
            runtime_agents: HashMap::new(),
            deferred_runtime_status: Vec::new(),
            next_runtime_serial: 0,
        })
    }

    /// Same host services, selected by overlay rather than a crate boot list.
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
        let compaction = PluginSpec::new("compaction-basic", |_config, ctx| {
            CompactionAutomation::default().apply(ctx)
        })
        .with_inject(CompactionAutomation::inject().iter().copied());
        let loop_plugin = PluginSpec::new("agent-loop", |_config, ctx| AgentLoop.apply(ctx))
            .with_inject(AgentLoop::inject().iter().copied());
        let spawn_subagent =
            PluginSpec::new(SUBAGENT_SPAWN_IN_PROCESS_PLUGIN_ID, |_config, ctx| {
                SpawnInProcessSubagent::default().apply(ctx)
            })
            .with_inject(SpawnInProcessSubagent::inject().iter().copied());
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
            &[
                mapping,
                compaction,
                loop_plugin,
                spawn_subagent,
                gate,
                adapter,
            ],
        )?;
        Ok((
            Self {
                ctx,
                bound_scope: None,
                active_domain_command: None,
                next_domain_command_serial: 0,
                active_effect_execution: None,
                next_effect_execution_serial: 0,
                active_effect_reconciliation: None,
                next_effect_reconciliation_serial: 0,
                active_effect_verification: None,
                next_effect_verification_serial: 0,
                active_runtime: None,
                runtime_agents: HashMap::new(),
                deferred_runtime_status: Vec::new(),
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
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
        }
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
        let key = RuntimeAgentKey::from(scope);
        let retained = self.runtime_agents.get(&key);
        let agent = retained.map_or_else(
            || {
                AgentRef::new(format!(
                    "{}:{}:{}:{}",
                    scope.project_id(),
                    scope.mission_id(),
                    runtime.generation(),
                    serial
                ))
            },
            |retained| retained.agent.clone(),
        );
        let (running_status, idle_status) =
            prepare_runtime_status_notifications(&self.ctx, &agent)?;
        let (retention, retained_publication) = retained.map_or_else(
            || (Arc::new(RuntimeAgentRetention::default()), None),
            |retained| (Arc::clone(&retained.retention), retained.retention.take()),
        );
        let (started, unpublished) = if retained_publication.is_some() {
            (None, None)
        } else {
            (
                Some(
                    self.ctx
                        .prepare_emit(events::AGENT_CREATED, agent.clone())?,
                ),
                Some(agents.prepare_publication(agent.clone())),
            )
        };
        if retained.is_none() {
            self.runtime_agents.insert(
                key,
                RetainedRuntimeAgent {
                    agent: agent.clone(),
                    retention: Arc::clone(&retention),
                },
            );
        }
        let notifications = RuntimeDispatchNotifications::new(started, running_status, idle_status);
        let (permit, lease) = RuntimeDispatchPermit::issue(
            serial,
            scope.clone(),
            agent.clone(),
            unpublished,
            retained_publication,
            retention,
            notifications,
        );
        self.next_runtime_serial = serial;
        self.active_runtime = Some(ActiveRuntimeDispatch {
            serial,
            scope: scope.clone(),
            agent_id: agent.id.clone(),
            lease,
        });
        Ok(permit)
    }

    /// Drive one canonical Session turn under an exact active Runtime permit.
    ///
    /// Unlike the general agent entry, this uses read/plan invariants and
    /// therefore never invents consent or approval. The caller must retain the
    /// same one-shot permit that authorized the Application Runtime operation.
    pub async fn run_authorized_runtime_agent_turn(
        &mut self,
        permit: &RuntimeDispatchPermit,
        session_id: &SessionId,
        seed_config: SessionCallConfig,
        cancellation: &LifecycleCancellation,
    ) -> Result<AgentTurnOutcome, CordisError> {
        self.require_active_runtime_permit(permit)?;
        run_authorized_runtime_agent_turn(
            &mut self.ctx,
            permit.agent(),
            session_id,
            seed_config,
            cancellation,
        )
        .await
    }

    /// Establish and synchronously drive one fresh local child under the exact
    /// active parent Runtime permit.
    ///
    /// The inherited config is frozen by value before child publication. This
    /// keeps the single mutable Context host-owned instead of lending it to a
    /// detached `'static` provider future.
    pub async fn run_authorized_local_subagent(
        &mut self,
        permit: &RuntimeDispatchPermit,
        provider: &str,
        request: SubagentStartRequest,
        inherited_config: SessionCallConfig,
    ) -> Result<Arc<dyn SubagentRun>, CordisError> {
        self.require_active_runtime_permit(permit)?;
        if !request.parent.is_same_lifecycle(permit.agent()) {
            return Err(CordisError::RuntimePermitMismatch);
        }
        if request
            .parent_session
            .as_ref()
            .is_some_and(|session| session.as_str() != permit.scope().mission_id())
        {
            return Err(CordisError::RuntimePermitMismatch);
        }
        let runtime = self
            .ctx
            .subagents::<SubagentRuntime>()
            .ok_or_else(|| CordisError::MissingDependencies(vec![keys::SUBAGENTS.to_string()]))?;
        runtime
            .start_local(&mut self.ctx, provider, request, inherited_config)
            .await
            .map_err(Into::into)
    }

    fn require_active_runtime_permit(
        &mut self,
        permit: &RuntimeDispatchPermit,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_runtime();
        let Some(active) = self.active_runtime.as_ref() else {
            return Err(CordisError::RuntimePermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.agent_id != permit.agent_id()
            || !permit.owns_lease(&active.lease)
            || !permit.has_live_publication()
        {
            return Err(CordisError::RuntimePermitMismatch);
        }
        let Some(agents) = self.ctx.agents::<AgentsSurface>() else {
            return Err(CordisError::MissingDependencies(vec![
                keys::AGENTS.to_string(),
            ]));
        };
        if !agents
            .list()
            .iter()
            .any(|agent| agent.is_same_lifecycle(permit.agent()))
        {
            return Err(CordisError::RuntimePermitMismatch);
        }
        Ok(())
    }

    /// Settle an issued Runtime permit and return its out-of-lock Idle
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

    /// Issue a one-shot permit for one exact Application-owned Domain command.
    ///
    /// This admits scope only. Application/Domain Kernel still validate and
    /// persist the command, while Effect Broker retains every external-write
    /// capability.
    pub fn authorize_domain_command(
        &mut self,
        scope: &AuthorityScope,
        command: DomainCommandBinding,
    ) -> Result<DomainCommandPermit, CordisError> {
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
        }
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if scope.runtime().is_some() {
            return Err(CordisError::DomainCommandRuntimeBound);
        }
        let Some(bound_scope) = self.bound_scope.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if bound_scope != scope {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        host_is_cordis_loop(self)?;
        enforce_runtime_invariants(&self.ctx)?;

        let serial = self
            .next_domain_command_serial
            .checked_add(1)
            .ok_or(CordisError::DomainCommandSerialOverflow)?;
        let (permit, lease) = DomainCommandPermit::issue(serial, scope.clone(), command.clone());
        self.next_domain_command_serial = serial;
        self.active_domain_command = Some(ActiveDomainCommand {
            serial,
            scope: scope.clone(),
            command,
            lease,
        });
        Ok(permit)
    }

    /// Settle one exact Domain command after Application returns.
    pub fn finish_domain_command(
        &mut self,
        permit: DomainCommandPermit,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_domain_command();
        let Some(active) = self.active_domain_command.as_ref() else {
            return Err(CordisError::DomainCommandPermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.command != *permit.command()
            || !permit.owns_lease(&active.lease)
        {
            return Err(CordisError::DomainCommandPermitMismatch);
        }
        self.active_domain_command = None;
        permit.complete();
        Ok(())
    }

    /// Issue a one-shot permit for one exact, already-approved Effect.
    ///
    /// Cordis validates only the bound scope, immutable digests, and host-side
    /// invariants. Desktop must release its mutex before Application gives the
    /// real Effect Broker an executor and independent verifier.
    pub fn authorize_effect_execution(
        &mut self,
        scope: &AuthorityScope,
        binding: EffectExecutionBinding,
    ) -> Result<EffectExecutionPermit, CordisError> {
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
        }
        if scope.runtime().is_some() {
            return Err(CordisError::EffectExecutionRuntimeBound);
        }
        let Some(bound_scope) = self.bound_scope.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if bound_scope != scope {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        host_is_cordis_loop(self)?;
        apply_effect(&self.ctx)?;

        let serial = self
            .next_effect_execution_serial
            .checked_add(1)
            .ok_or(CordisError::EffectExecutionSerialOverflow)?;
        let (permit, lease) = EffectExecutionPermit::issue(serial, scope.clone(), binding.clone());
        self.next_effect_execution_serial = serial;
        self.active_effect_execution = Some(ActiveEffectExecution {
            serial,
            scope: scope.clone(),
            binding,
            lease,
        });
        Ok(permit)
    }

    /// Settle one exact Effect execution after Application/Broker returns.
    pub fn finish_effect_execution(
        &mut self,
        permit: EffectExecutionPermit,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_effect_execution();
        let Some(active) = self.active_effect_execution.as_ref() else {
            return Err(CordisError::EffectExecutionPermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.binding != *permit.binding()
            || !permit.owns_lease(&active.lease)
        {
            return Err(CordisError::EffectExecutionPermitMismatch);
        }
        self.active_effect_execution = None;
        permit.complete();
        Ok(())
    }

    /// Issue a one-shot permit for one exact uncertain-Effect observation.
    ///
    /// This path checks only generic host/runtime invariants. It deliberately
    /// does not call `apply_effect`, because the original approval window may
    /// have expired and reconciliation has no provider-write capability.
    pub fn authorize_effect_reconciliation(
        &mut self,
        scope: &AuthorityScope,
        binding: EffectReconciliationBinding,
    ) -> Result<EffectReconciliationPermit, CordisError> {
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
        }
        if scope.runtime().is_some() {
            return Err(CordisError::EffectReconciliationRuntimeBound);
        }
        let Some(bound_scope) = self.bound_scope.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if bound_scope != scope {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        host_is_cordis_loop(self)?;
        enforce_runtime_invariants(&self.ctx)?;

        let serial = self
            .next_effect_reconciliation_serial
            .checked_add(1)
            .ok_or(CordisError::EffectReconciliationSerialOverflow)?;
        let (permit, lease) =
            EffectReconciliationPermit::issue(serial, scope.clone(), binding.clone());
        self.next_effect_reconciliation_serial = serial;
        self.active_effect_reconciliation = Some(ActiveEffectReconciliation {
            serial,
            scope: scope.clone(),
            binding,
            lease,
        });
        Ok(permit)
    }

    /// Settle one exact read/recovery observation after Application returns.
    pub fn finish_effect_reconciliation(
        &mut self,
        permit: EffectReconciliationPermit,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_effect_reconciliation();
        let Some(active) = self.active_effect_reconciliation.as_ref() else {
            return Err(CordisError::EffectReconciliationPermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.binding != *permit.binding()
            || !permit.owns_lease(&active.lease)
        {
            return Err(CordisError::EffectReconciliationPermitMismatch);
        }
        self.active_effect_reconciliation = None;
        permit.complete();
        Ok(())
    }

    /// Issue a one-shot permit for one exact independent Receipt
    /// verification.  Verification is read-only coordination and therefore
    /// does not call `apply_effect` or admit Runtime authority.
    pub fn authorize_effect_verification(
        &mut self,
        scope: &AuthorityScope,
        binding: EffectVerificationBinding,
    ) -> Result<EffectVerificationPermit, CordisError> {
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
        }
        if scope.runtime().is_some() {
            return Err(CordisError::EffectVerificationRuntimeBound);
        }
        let Some(bound_scope) = self.bound_scope.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if bound_scope != scope {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        host_is_cordis_loop(self)?;
        enforce_runtime_invariants(&self.ctx)?;

        let serial = self
            .next_effect_verification_serial
            .checked_add(1)
            .ok_or(CordisError::EffectVerificationSerialOverflow)?;
        let (permit, lease) =
            EffectVerificationPermit::issue(serial, scope.clone(), binding.clone());
        self.next_effect_verification_serial = serial;
        self.active_effect_verification = Some(ActiveEffectVerification {
            serial,
            scope: scope.clone(),
            binding,
            lease,
        });
        Ok(permit)
    }

    /// Settle one exact independent Receipt verification after
    /// Desktop/Application returns.
    pub fn finish_effect_verification(
        &mut self,
        permit: EffectVerificationPermit,
    ) -> Result<(), CordisError> {
        self.reap_abandoned_effect_verification();
        let Some(active) = self.active_effect_verification.as_ref() else {
            return Err(CordisError::EffectVerificationPermitMismatch);
        };
        if active.serial != permit.serial()
            || active.scope != *permit.scope()
            || active.binding != *permit.binding()
            || !permit.owns_lease(&active.lease)
        {
            return Err(CordisError::EffectVerificationPermitMismatch);
        }
        self.active_effect_verification = None;
        permit.complete();
        Ok(())
    }

    /// Legacy symbolic Effect invariant probe. It never executes a provider.
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
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
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
        self.reap_abandoned_domain_command();
        self.reap_abandoned_effect_execution();
        self.reap_abandoned_effect_reconciliation();
        self.reap_abandoned_effect_verification();
        self.reap_abandoned_runtime();
        if self.active_domain_command.is_some() {
            return Err(CordisError::DomainCommandDispatchBusy);
        }
        if self.active_runtime.is_some() {
            return Err(CordisError::RuntimeDispatchBusy);
        }
        if self.active_effect_execution.is_some() {
            return Err(CordisError::EffectExecutionDispatchBusy);
        }
        if self.active_effect_reconciliation.is_some() {
            return Err(CordisError::EffectReconciliationDispatchBusy);
        }
        if self.active_effect_verification.is_some() {
            return Err(CordisError::EffectVerificationDispatchBusy);
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

    /// Resolve ids for one exact retained Agent lifecycle without returning
    /// stale Runtime authority from its preceding turn.
    #[must_use]
    pub fn retained_runtime_agent_identity(
        &self,
        agent: &AgentRef,
    ) -> Option<RuntimeAgentIdentity> {
        self.runtime_agents
            .iter()
            .find(|(_, retained)| retained.agent.is_same_lifecycle(agent))
            .map(|(key, _)| RuntimeAgentIdentity {
                tenant: key.tenant.clone(),
                project: key.project.clone(),
                mission: key.mission.clone(),
            })
    }

    #[must_use]
    pub fn active_domain_command_scope(&self) -> Option<&AuthorityScope> {
        self.active_domain_command
            .as_ref()
            .filter(|active| active.lease.is_active())
            .map(|active| &active.scope)
    }

    #[must_use]
    pub fn active_effect_execution_scope(&self) -> Option<&AuthorityScope> {
        self.active_effect_execution
            .as_ref()
            .filter(|active| active.lease.is_active())
            .map(|active| &active.scope)
    }

    #[must_use]
    pub fn active_effect_reconciliation_scope(&self) -> Option<&AuthorityScope> {
        self.active_effect_reconciliation
            .as_ref()
            .filter(|active| active.lease.is_active())
            .map(|active| &active.scope)
    }

    #[must_use]
    pub fn active_effect_verification_scope(&self) -> Option<&AuthorityScope> {
        self.active_effect_verification
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
    pub fn mounted_keys(&self) -> [&'static str; 10] {
        [
            keys::TOOLS,
            keys::SYSTEM_PROMPT,
            keys::LLM,
            keys::SESSIONS,
            keys::AGENTS,
            keys::COMPACTION,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
            keys::RUNTIME,
            keys::DESKTOP,
        ]
    }

    /// Make this Host inert and return the owned completion for the old
    /// Context. Externally synchronized callers should release their Host lock
    /// before calling [`CordisHostTeardown::announce`].
    pub fn teardown(&mut self) -> CordisHostTeardown {
        let mut disposal_notifications = self
            .runtime_agents
            .iter()
            .map(|(key, retained)| {
                (
                    key.clone(),
                    self.ctx
                        .prepare_emit(events::AGENT_DISPOSED, retained.agent.clone())
                        .ok(),
                )
            })
            .collect::<HashMap<_, _>>();
        let TeardownTransaction::Acquired(permit) = self.ctx.try_begin_teardown() else {
            return CordisHostTeardown::busy();
        };
        self.reap_abandoned_runtime();
        let mut statuses = std::mem::take(&mut self.deferred_runtime_status);
        if let Some(active) = self.active_domain_command.take() {
            active.lease.release();
        }
        if let Some(active) = self.active_effect_execution.take() {
            active.lease.release();
        }
        if let Some(active) = self.active_effect_reconciliation.take() {
            active.lease.release();
        }
        if let Some(active) = self.active_effect_verification.take() {
            active.lease.release();
        }
        if let Some(active) = self.active_runtime.take()
            && let Some(status) = active.lease.release_for_teardown()
        {
            statuses.push(status);
        }
        let agents = self
            .runtime_agents
            .drain()
            .filter_map(|(key, retained)| {
                retained
                    .retention
                    .take()
                    .map(|publication| RuntimeAgentDisposal {
                        publication: Some(publication),
                        notification: disposal_notifications.remove(&key).flatten(),
                    })
            })
            .collect();
        self.bound_scope = None;
        let context = std::mem::take(&mut self.ctx);
        CordisHostTeardown::new(context, permit, statuses, agents)
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

    /// Register an Agent-disposed observer.
    ///
    /// Runtime completion leaves the Mission Agent live and Idle. This
    /// observer runs only when the owning Host is actually torn down.
    pub fn on_runtime_finished<F>(&mut self, observer: F) -> Result<(), CordisError>
    where
        F: Fn(&AgentRef) + Send + Sync + 'static,
    {
        self.ctx
            .on_emit(events::AGENT_DISPOSED, observer)
            .map(|_| ())
    }

    /// Take one-shot Idle observations left by abandoned Runtime permits.
    /// Callers must release any outer Host lock before announcing them.
    pub fn take_deferred_runtime_status(&mut self) -> Vec<RuntimeStatusCompletion> {
        self.reap_abandoned_runtime();
        std::mem::take(&mut self.deferred_runtime_status)
    }

    fn reap_abandoned_runtime(&mut self) {
        if self
            .active_runtime
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            let active = self
                .active_runtime
                .take()
                .expect("the inactive Runtime lease was just observed");
            if let Some(status) = active.lease.take_deferred_status() {
                self.deferred_runtime_status.push(status);
            }
        }
    }

    fn reap_abandoned_domain_command(&mut self) {
        if self
            .active_domain_command
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            self.active_domain_command = None;
        }
    }

    fn reap_abandoned_effect_execution(&mut self) {
        if self
            .active_effect_execution
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            self.active_effect_execution = None;
        }
    }

    fn reap_abandoned_effect_reconciliation(&mut self) {
        if self
            .active_effect_reconciliation
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            self.active_effect_reconciliation = None;
        }
    }

    fn reap_abandoned_effect_verification(&mut self) {
        if self
            .active_effect_verification
            .as_ref()
            .is_some_and(|active| !active.lease.is_active())
        {
            self.active_effect_verification = None;
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

/// Boot-time host check: the ten keys, Hartevo ownership of Domain/Effect,
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
    if host.ctx.system_prompt::<SystemPromptSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::SYSTEM_PROMPT.to_string(),
        ]));
    }
    if host.ctx.llm::<LlmSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::LLM.to_string(),
        ]));
    }
    if host.ctx.sessions::<SessionStore>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::SESSIONS.to_string(),
        ]));
    }
    if host.ctx.agents::<AgentsSurface>().is_none() {
        return Err(CordisError::MissingDependencies(vec![
            keys::AGENTS.to_string(),
        ]));
    }
    if host
        .ctx
        .get::<CompactionAutomation>(keys::COMPACTION)
        .is_none()
    {
        return Err(CordisError::MissingDependencies(vec![
            keys::COMPACTION.to_string(),
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
pub fn host_plugin_ids() -> [PluginId; 5] {
    [
        PluginId::new(HOST_PLUGIN_IDS[0]),
        PluginId::new(HOST_PLUGIN_IDS[1]),
        PluginId::new(HOST_PLUGIN_IDS[2]),
        PluginId::new(HOST_PLUGIN_IDS[3]),
        PluginId::new(HOST_PLUGIN_IDS[4]),
    ]
}
