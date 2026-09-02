use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::ThreadId;

use crate::config::ConfigValue;
use crate::effect::{Disposer, Registration, RegistrationHandle};
use crate::event::{
    Accumulate, Bail, BailOutcome, DispatchMode, Emit, EventBus, EventDescriptor, EventError,
    EventErrors, EventKey, EventModeMarker, EventOptions, EventScope, ListenerHandle, Parallel,
    PreparedEmit, Serial, TryWaterfallNext, Waterfall, WaterfallFailure, WaterfallNext,
    into_cordis_error,
};
use crate::fiber::{Fiber, FiberState, FiberUid};
use crate::loader::{PluginFactory, PluginFactoryId};
use crate::registry::{PendingEntry, Registry};
use crate::service::{
    Service, ServiceAssociation, ServiceCaller, ServiceHandle, ServiceIntercept, ServiceLookup,
    ServiceOptions, ServiceOrigin, ServiceScope, ServiceShadow, associated_key,
};
use crate::surface::{DomainSurface, HartevoSurfaceAuthority};

static NEXT_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProviderKey {
    namespace: String,
    key: String,
}

impl ProviderKey {
    fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

/// Opaque provider authorization identity. It is distinct from the owning
/// Fiber and from the mutable provider generation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(u64);

impl fmt::Debug for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ProviderId").field(&self.0).finish()
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Capability for owner-checked ordinary provider replacement.
///
/// Handles are minted only by successful ordinary registration. Their fields
/// are private, so a caller cannot forge an owner, namespace, provider id, or
/// generation. Reserved Hartevo providers never return a public handle.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderHandle {
    context_id: u64,
    namespace: String,
    key: String,
    provider_id: ProviderId,
    owner_uid: FiberUid,
    generation: u64,
}

impl ProviderHandle {
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub const fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    #[must_use]
    pub const fn owner_uid(&self) -> FiberUid {
        self.owner_uid
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Owner-checked replacement convenience method.
    pub fn replace<T: Any + Send + Sync>(
        &self,
        ctx: &mut Context,
        value: T,
    ) -> Result<Self, CordisError> {
        ctx.replace_provider(self, value)
    }
}

impl fmt::Debug for ProviderHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHandle")
            .field("context_id", &self.context_id)
            .field("namespace", &self.namespace)
            .field("key", &self.key)
            .field("provider_id", &self.provider_id)
            .field("owner_uid", &self.owner_uid)
            .field("generation", &self.generation)
            .finish()
    }
}

struct ProviderRecord {
    value: Arc<dyn Any + Send + Sync>,
    provider_id: ProviderId,
    owner_uid: FiberUid,
    generation: u64,
    notify_count: u64,
    service_options: ServiceOptions,
    origin: ProviderOriginSnapshot,
}

#[derive(Clone)]
struct ProviderOriginSnapshot {
    shared_namespaces: Vec<String>,
    metadata: ConfigValue,
}

impl ProviderOriginSnapshot {
    fn new(shared_namespaces: Vec<String>, metadata: ConfigValue) -> Self {
        Self {
            shared_namespaces,
            metadata,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderSnapshot {
    pub(crate) namespace: String,
    pub(crate) key: String,
    pub(crate) provider_id: ProviderId,
    pub(crate) owner_uid: FiberUid,
    pub(crate) generation: u64,
    pub(crate) notify_count: u64,
    pub(crate) value_identity: usize,
    pub(crate) disposer_count: usize,
}

/// Handle for a pending or activated repeatable plugin factory.
#[derive(Clone)]
pub struct PendingHandle {
    id: u64,
    factory_id: PluginFactoryId,
    fiber: Fiber,
}

impl PartialEq for PendingHandle {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.factory_id == other.factory_id
            && self.fiber.uid() == other.fiber.uid()
    }
}

impl Eq for PendingHandle {}

impl PendingHandle {
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub const fn factory_id(&self) -> PluginFactoryId {
        self.factory_id
    }

    #[must_use]
    pub fn fiber(&self) -> Fiber {
        self.fiber.clone()
    }

    #[must_use]
    pub fn state(&self) -> FiberState {
        self.fiber.state()
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.is_disposed() && self.state() == FiberState::Pending
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.is_disposed() && self.state() == FiberState::Active
    }

    /// Whether the owning Context has published this Fiber's terminal
    /// tombstone. Tombstoning itself is intentionally Context-owned so that a
    /// public handle cannot bypass registration and pending cleanup.
    #[must_use]
    pub fn is_disposed(&self) -> bool {
        self.fiber.is_disposed()
    }
}

impl fmt::Debug for PendingHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingHandle")
            .field("id", &self.id)
            .field("factory_id", &self.factory_id)
            .field("fiber", &self.fiber)
            .finish()
    }
}

/// Conventional Cordis / Hartevo service keys. Plugins look up by these names.
pub mod keys {
    pub const APPROVAL: &str = "approval";
    pub const TOOLS: &str = "tools";
    pub const SYSTEM_PROMPT: &str = "systemPrompt";
    pub const LLM: &str = "llm";
    pub const SESSIONS: &str = "sessions";
    pub const AGENTS: &str = "agents";
    pub const COMPACTION: &str = "compaction";
    pub const DOMAIN: &str = "domain";
    pub const EFFECT_BROKER: &str = "effect_broker";
    pub const RUNTIME: &str = "runtime";
    pub const DESKTOP: &str = "desktop";
}

/// Failure starting a plugin, mixing event modes, or joining dispatch errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CordisError {
    #[error("missing inject dependencies: {}", .0.join(", "))]
    MissingDependencies(Vec<String>),
    #[error("event `{name}` is locked to {locked}, cannot use {requested}")]
    ModeConflict {
        name: String,
        locked: DispatchMode,
        requested: DispatchMode,
    },
    #[error("event `{name}` descriptor conflict: locked {locked}, requested {requested}")]
    SchemaConflict {
        name: String,
        locked: EventDescriptor,
        requested: EventDescriptor,
    },
    #[error("event `{name}` requires a complete typed descriptor")]
    EventDescriptorRequired { name: String },
    #[error("event listener identity allocation overflowed")]
    ListenerIdentityOverflow,
    #[error("event `{name}` emit listener failed: {error}")]
    Emit {
        name: String,
        #[source]
        error: EventError,
    },
    #[error("event `{name}` parallel listeners failed: {errors}")]
    ParallelJoin {
        name: String,
        #[source]
        errors: EventErrors,
    },
    #[error("event `{name}` serial listener failed: {error}")]
    Serial {
        name: String,
        #[source]
        error: EventError,
    },
    #[error("event `{name}` bail listener failed: {error}")]
    Bail {
        name: String,
        #[source]
        error: EventError,
    },
    #[error("event `{name}` waterfall listener failed: {error}")]
    Waterfall {
        name: String,
        #[source]
        error: EventError,
    },
    #[error("event `{name}` accumulate listener failed: {error}")]
    Accumulate {
        name: String,
        #[source]
        error: EventError,
    },
    #[error("event `{name}` payload type mismatch")]
    PayloadType { name: String },
    #[error("Cordis authority scope field `{field}` is empty or not canonical")]
    InvalidAuthorityScope { field: &'static str },
    #[error("Cordis authority revision `{field}` must be positive")]
    InvalidAuthorityRevision { field: &'static str },
    #[error("Cordis authority digest `{field}` must be canonical lowercase sha256")]
    InvalidAuthorityDigest { field: &'static str },
    #[error("Cordis authority dispatch requires an exact bound authority scope")]
    AuthorityScopeUnbound,
    #[error("Cordis authority dispatch scope does not match the bound Domain scope")]
    AuthorityScopeMismatch,
    #[error("Cordis Runtime dispatch scope has no durable Runtime binding")]
    RuntimeAuthorityUnbound,
    #[error("Cordis Runtime dispatch is already active")]
    RuntimeDispatchBusy,
    #[error("Cordis Runtime dispatch permit does not match the active operation")]
    RuntimePermitMismatch,
    #[error("Cordis Runtime dispatch serial overflowed")]
    RuntimeDispatchSerialOverflow,
    #[error("Cordis Agent `{id}` is already published")]
    AgentAlreadyPublished { id: String },
    #[error("Cordis Agent registry mutex is poisoned")]
    AgentRegistryPoisoned,
    #[error("Cordis Runtime coordinator mutex is poisoned")]
    RuntimeCoordinatorPoisoned,
    #[error("Cordis Domain command scope must not carry Runtime authority")]
    DomainCommandRuntimeBound,
    #[error("Cordis Domain command dispatch is already active")]
    DomainCommandDispatchBusy,
    #[error("Cordis Domain command permit does not match the active operation")]
    DomainCommandPermitMismatch,
    #[error("Cordis Domain command serial overflowed")]
    DomainCommandSerialOverflow,
    #[error("Cordis Domain command coordinator mutex is poisoned")]
    DomainCommandCoordinatorPoisoned,
    #[error("Cordis Effect execution scope must not carry Runtime authority")]
    EffectExecutionRuntimeBound,
    #[error("Cordis Effect execution dispatch is already active")]
    EffectExecutionDispatchBusy,
    #[error("Cordis Effect execution permit does not match the active operation")]
    EffectExecutionPermitMismatch,
    #[error("Cordis Effect execution serial overflowed")]
    EffectExecutionSerialOverflow,
    #[error("Cordis Effect execution coordinator mutex is poisoned")]
    EffectExecutionCoordinatorPoisoned,
    #[error("Cordis Effect reconciliation scope must not carry Runtime authority")]
    EffectReconciliationRuntimeBound,
    #[error("Cordis Effect reconciliation dispatch is already active")]
    EffectReconciliationDispatchBusy,
    #[error("Cordis Effect reconciliation permit does not match the active operation")]
    EffectReconciliationPermitMismatch,
    #[error("Cordis Effect reconciliation serial overflowed")]
    EffectReconciliationSerialOverflow,
    #[error("Cordis Effect reconciliation coordinator mutex is poisoned")]
    EffectReconciliationCoordinatorPoisoned,
    #[error("Cordis Effect verification scope must not carry Runtime authority")]
    EffectVerificationRuntimeBound,
    #[error("Cordis Effect verification dispatch is already active")]
    EffectVerificationDispatchBusy,
    #[error("Cordis Effect verification permit does not match the active operation")]
    EffectVerificationPermitMismatch,
    #[error("Cordis Effect verification serial overflowed")]
    EffectVerificationSerialOverflow,
    #[error("Cordis Effect verification coordinator mutex is poisoned")]
    EffectVerificationCoordinatorPoisoned,
    #[error("service key `{key}` is reserved to its mounted authority owner")]
    ReservedServiceKey { key: String },
    #[error("surface `{key}` cannot be mounted by authority owner `{owner}`")]
    InvalidSurfaceOwner {
        key: &'static str,
        owner: &'static str,
    },
    #[error("Cordis surface key `{key}` is already mapped")]
    SurfaceAlreadyMapped { key: &'static str },
    #[error("provider `{namespace}/{key}` is already registered")]
    DuplicateProvider { namespace: String, key: String },
    #[error("provider `{key}` is owned by another Fiber")]
    ProviderOwnerMismatch { key: String },
    #[error("provider handle `{key}` is stale")]
    StaleProviderHandle { key: String },
    #[error("provider `{namespace}/{key}` is not registered")]
    ProviderNotFound { namespace: String, key: String },
    #[error("Fiber `{uid}` does not belong to this Context")]
    FiberContextMismatch { uid: FiberUid },
    #[error("Fiber `{uid}` is disposed")]
    FiberDisposed { uid: FiberUid },
    #[error("Fiber `{requested}` is outside the active Fiber `{current}` scope")]
    FiberScopeViolation {
        current: FiberUid,
        requested: FiberUid,
    },
    #[error("Fiber `{uid}` cannot be disposed while its activation callback is running")]
    FiberBusy { uid: FiberUid },
    #[error("provider generation for `{key}` overflowed")]
    ProviderGenerationOverflow { key: String },
    #[error("provider identity allocation overflowed")]
    ProviderIdentityOverflow,
    #[error("associated accessor `{key}` is read-only")]
    ReadOnlyAssociatedAccessor { key: String },
    #[error("pending plugin factory `{id}` is already mounted")]
    DuplicatePluginFactory { id: PluginFactoryId },
    #[error("plugin factory `{id}` activation failed: {source}")]
    PluginActivation {
        id: PluginFactoryId,
        #[source]
        source: Box<CordisError>,
    },
    #[error("plugin callback panicked: {message}")]
    PluginCallbackPanicked { message: String },
    #[error("registration cleanup panicked: {message}")]
    CleanupPanicked { message: String },
    #[error("asynchronous lifecycle effects require a repeatable Fiber runtime")]
    AsyncEffectRequiresFiber,
    #[error("Fiber `{uid}` is not managed by the asynchronous lifecycle runtime")]
    FiberRuntimeUnavailable { uid: FiberUid },
    #[error("plugin `{id}` requires an owned lifecycle callback")]
    LifecycleFactoryRequired { id: crate::loader::PluginId },
    #[error("plugin catalog id `{id}` is already bound to a different factory")]
    PluginCatalogConflict { id: crate::loader::PluginId },
    #[error("plugin runtime `{id}` is being deleted")]
    RuntimeDeleting { id: crate::loader::PluginId },
    #[error("plugin factory is one-shot and cannot transition again: {}", .ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))]
    NonRepeatableFactory { ids: Vec<crate::loader::PluginId> },
    #[error("lifecycle runtime is not running inside Tokio")]
    AsyncRuntimeUnavailable,
    #[error("lifecycle runtime is shutting down")]
    RuntimeShuttingDown,
    #[error("lifecycle transition ticket allocation overflowed")]
    TransitionTicketOverflow,
    #[error("plugin config revision overflowed")]
    ConfigRevisionOverflow,
    #[error("plugin runtime generation allocation overflowed")]
    RuntimeGenerationOverflow,
    #[error("lifecycle ContextView for Fiber `{uid}` is stale")]
    StaleLifecycleView { uid: FiberUid },
    #[error("wait for Fiber `{uid}` activation was cancelled")]
    WaitCancelled { uid: FiberUid },
    #[error("provider guard for `{namespace}/{key}` failed: {source}")]
    ProviderGuard {
        namespace: String,
        key: String,
        #[source]
        source: Box<CordisError>,
    },
    #[error("cleanup also failed after `{failure}`: {cleanup}")]
    CleanupAfterFailure {
        failure: Box<CordisError>,
        cleanup: Box<CordisError>,
    },
    #[error("pending factory notification failed after committing {handle:?}: {source}")]
    PendingNotification {
        handle: PendingHandle,
        #[source]
        source: Box<CordisError>,
    },
    #[error("provider notification failed after committing {handle:?}: {source}")]
    ProviderNotification {
        handle: ProviderHandle,
        #[source]
        source: Box<CordisError>,
    },
    #[error(
        "reserved provider `{key}` notification failed after committing generation {generation}: {source}"
    )]
    ReservedProviderNotification {
        key: String,
        generation: u64,
        #[source]
        source: Box<CordisError>,
    },
    #[error(transparent)]
    Interpolate(#[from] crate::config::InterpolateError),
    #[error(transparent)]
    Prompt(#[from] crate::surface::PromptError),
    #[error(transparent)]
    Llm(#[from] crate::surface::LlmError),
    #[error(transparent)]
    Session(#[from] crate::session::SessionError),
}

/// Service container and plugin host.
pub struct Context {
    id: u64,
    event_gate: Arc<EventOperationGate>,
    services: HashMap<String, Arc<dyn Any + Send + Sync>>,
    providers: HashMap<ProviderKey, ProviderRecord>,
    next_provider_id: u64,
    /// Plugin-context interpolation source. Distinct from the loader context.
    vars: ConfigValue,
    effects: Vec<Registration>,
    events: EventBus,
    reserved_services: HashSet<String>,
    root: Fiber,
    current_fiber: FiberUid,
    fibers: HashMap<FiberUid, Fiber>,
    registry: Registry,
    mounted_factories: HashMap<PluginFactoryId, Fiber>,
    activating_factories: HashSet<PluginFactoryId>,
    notifying_pending: bool,
    activation_depth: usize,
}

struct EventGeneration;

struct EventOperationState {
    generation: Arc<EventGeneration>,
    open: bool,
    active: usize,
    active_by_thread: HashMap<ThreadId, usize>,
}

struct EventOperationGate {
    state: Mutex<EventOperationState>,
    drained: Condvar,
}

/// Result of atomically closing and draining one reusable Context generation.
/// The acquired permit has no Drop behavior: an unwind before explicit
/// completion deliberately leaves event re-entry fail-closed.
pub(crate) enum TeardownTransaction {
    Busy,
    Acquired(TeardownPermit),
}

pub(crate) struct TeardownPermit {
    context_id: u64,
    gate: Arc<EventOperationGate>,
    generation: Arc<EventGeneration>,
}

impl EventOperationGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(EventOperationState {
                generation: Arc::new(EventGeneration),
                open: true,
                active: 0,
                active_by_thread: HashMap::new(),
            }),
            drained: Condvar::new(),
        }
    }

    fn current_generation(&self) -> Option<Arc<EventGeneration>> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.open.then(|| Arc::clone(&state.generation))
    }

    fn enter(self: &Arc<Self>, generation: &Arc<EventGeneration>) -> Option<EventOperationPermit> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !state.open || !Arc::ptr_eq(&state.generation, generation) {
            return None;
        }
        let thread_id = std::thread::current().id();
        let next_active = state.active.checked_add(1)?;
        let next_thread_active = state
            .active_by_thread
            .get(&thread_id)
            .copied()
            .unwrap_or_default()
            .checked_add(1)?;
        state.active = next_active;
        state.active_by_thread.insert(thread_id, next_thread_active);
        Some(EventOperationPermit {
            gate: Arc::clone(self),
            thread_id,
        })
    }

    /// Close a reusable Context generation and drain every operation. Calling
    /// this from an operation on the same thread is rejected before `open` is
    /// changed, because that operation cannot drain until the callback returns.
    fn try_close_and_drain_reusable(&self) -> Option<Arc<EventGeneration>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !state.open
            || state
                .active_by_thread
                .contains_key(&std::thread::current().id())
        {
            return None;
        }
        let generation = Arc::clone(&state.generation);
        state.open = false;
        while state.active != 0 {
            state = match self.drained.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        Some(generation)
    }

    /// Permanently close a Context while allowing Drop to run from inside one
    /// of its own callbacks. The caller's exact outstanding permits remain
    /// valid until their stack frames return; permits on every other thread
    /// must drain before structural cleanup starts.
    fn close_and_drain_for_drop(&self) {
        let thread_id = std::thread::current().id();
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.open = false;
        let caller_active = state
            .active_by_thread
            .get(&thread_id)
            .copied()
            .unwrap_or_default();
        while state.active != caller_active {
            state = match self.drained.wait(state) {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    /// Publish a fresh generation only after reusable teardown completed all
    /// structural cleanup. There is deliberately no RAII reopen on unwind.
    fn reopen_after_completed_teardown(&self, generation: &Arc<EventGeneration>) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert!(!state.open, "a teardown permit owns one closed generation");
        debug_assert_eq!(state.active, 0);
        assert!(
            Arc::ptr_eq(&state.generation, generation),
            "a teardown permit completes only its exact generation"
        );
        state.generation = Arc::new(EventGeneration);
        state.open = true;
    }
}

struct EventOperationPermit {
    gate: Arc<EventOperationGate>,
    thread_id: ThreadId,
}

impl Drop for EventOperationPermit {
    fn drop(&mut self) {
        let mut state = match self.gate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.active = state
            .active
            .checked_sub(1)
            .expect("an event operation permit owns one active count");
        let remove_thread = {
            let thread_active = state
                .active_by_thread
                .get_mut(&self.thread_id)
                .expect("an event operation permit owns one thread-local active count");
            *thread_active = thread_active
                .checked_sub(1)
                .expect("an event operation permit owns one thread-local active count");
            *thread_active == 0
        };
        if remove_thread {
            state.active_by_thread.remove(&self.thread_id);
        }
        // A self-excluding Context Drop waits for `active == caller_active`,
        // so every other-thread decrement can satisfy its predicate.
        self.gate.drained.notify_all();
    }
}

/// Cloneable typed event capability for safe callback re-entry.
///
/// The capability captures one exact Context, active Fiber owner, and event
/// scope without retaining a borrow of [`Context`] or [`ContextView`]. It may
/// therefore be moved into a `'static` listener, where registration and
/// recursive dispatch continue to use the normal snapshot semantics. Every
/// listener it creates is owned by the captured Fiber and is removed when that
/// Fiber is cleaned up.
///
/// It supports synchronous Emit and awaited Parallel dispatch only. It
/// deliberately does not grant provider, Fiber-lifecycle, or
/// [`crate::LifecycleContextView`] authority.
#[derive(Clone)]
pub struct EventReentry {
    context_id: u64,
    gate: Arc<EventOperationGate>,
    generation: Arc<EventGeneration>,
    events: EventBus,
    owner: Fiber,
    listener_scope: EventScope,
    dispatch_target: Option<EventScope>,
}

impl EventReentry {
    fn new(
        context_id: u64,
        gate: Arc<EventOperationGate>,
        generation: Arc<EventGeneration>,
        events: EventBus,
        owner: Fiber,
        listener_scope: EventScope,
        dispatch_target: Option<EventScope>,
    ) -> Self {
        Self {
            context_id,
            gate,
            generation,
            events,
            owner,
            listener_scope,
            dispatch_target,
        }
    }

    fn enter(&self) -> Result<EventOperationPermit, CordisError> {
        if self.owner.context_id() != self.context_id {
            return Err(CordisError::FiberContextMismatch {
                uid: self.owner.uid(),
            });
        }
        let permit =
            self.gate
                .enter(&self.generation)
                .ok_or(CordisError::FiberContextMismatch {
                    uid: self.owner.uid(),
                })?;
        if self.owner.is_disposed() || self.owner.state() != FiberState::Active {
            return Err(CordisError::FiberDisposed {
                uid: self.owner.uid(),
            });
        }
        Ok(permit)
    }

    fn finish_listener(
        name: &str,
        result: Result<ListenerHandle, crate::event::EventBusError>,
    ) -> Result<ListenerHandle, CordisError> {
        result.map_err(|error| into_cordis_error(name, DispatchMode::Emit, error))
    }

    /// Register an infallible listener with default append/local options.
    pub fn on_emit<P, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.on_emit_with_options(key, EventOptions::default(), listener)
    }

    /// Register an infallible listener with explicit ordering/scope options.
    pub fn on_emit_with_options<P, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        let result = self.events.register_emit(
            key,
            self.owner.clone(),
            self.listener_scope.clone(),
            options,
            false,
            listener,
        );
        Self::finish_listener(key.name(), result)
    }

    /// Register an infallible listener claimed before its first callback.
    pub fn once_emit<P, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.once_emit_with_options(key, EventOptions::default(), listener)
    }

    /// Register a once listener with explicit ordering/scope options.
    pub fn once_emit_with_options<P, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        let result = self.events.register_emit(
            key,
            self.owner.clone(),
            self.listener_scope.clone(),
            options,
            true,
            listener,
        );
        Self::finish_listener(key.name(), result)
    }

    /// Register a fallible listener with default append/local options.
    pub fn try_on_emit<P, E, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        self.try_on_emit_with_options(key, EventOptions::default(), listener)
    }

    /// Register a fallible listener with explicit ordering/scope options.
    pub fn try_on_emit_with_options<P, E, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        let result = self.events.register_try_emit(
            key,
            self.owner.clone(),
            self.listener_scope.clone(),
            options,
            false,
            listener,
        );
        Self::finish_listener(key.name(), result)
    }

    /// Recursively dispatch an Emit event using the captured target scope.
    pub fn emit<P>(&self, key: EventKey<Emit, P, ()>, payload: &P) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        self.events
            .emit_owned(key, payload, self.dispatch_target.as_ref(), &self.owner)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Emit, error))
    }

    /// Dispatch an observer firehose while containing each listener failure.
    pub fn emit_contained<P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: &P,
    ) -> Result<usize, CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        self.events
            .emit_contained_owned(key, payload, self.dispatch_target.as_ref(), &self.owner)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Emit, error))
    }

    /// Dispatch one internal Waterfall from a scheduler worker while retaining
    /// the exact Context generation, Fiber owner, and target scope.
    pub(crate) fn waterfall<P>(
        &self,
        key: EventKey<Waterfall, P, P>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        let _permit = self.enter()?;
        self.events
            .waterfall(key, payload, self.dispatch_target.as_ref())
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Waterfall, error))
    }

    /// Dispatch every matching Parallel listener and wait for all of them.
    ///
    /// The returned count is the exact callback snapshot selected for this
    /// dispatch. Listener failures are retained and returned only after the
    /// complete snapshot has settled.
    pub async fn parallel<P>(
        &self,
        key: EventKey<Parallel, P, ()>,
        payload: P,
    ) -> Result<usize, CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        let _permit = self.enter()?;
        self.events
            .parallel(key, payload, self.dispatch_target.as_ref())
            .await
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Parallel, error))
    }
}

impl fmt::Debug for EventReentry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventReentry")
            .field("context_id", &self.context_id)
            .field("owner_uid", &self.owner.uid())
            .field("listener_scope", &self.listener_scope)
            .field("dispatch_target", &self.dispatch_target)
            .finish_non_exhaustive()
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    #[must_use]
    pub fn new() -> Self {
        let context_id = NEXT_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = Fiber::root(context_id);
        Self {
            id: context_id,
            event_gate: Arc::new(EventOperationGate::new()),
            services: HashMap::new(),
            providers: HashMap::new(),
            next_provider_id: 1,
            vars: ConfigValue::default(),
            effects: Vec::new(),
            events: EventBus::new(),
            reserved_services: HashSet::new(),
            current_fiber: root.uid(),
            fibers: HashMap::new(),
            root,
            registry: Registry::new(),
            mounted_factories: HashMap::new(),
            activating_factories: HashSet::new(),
            notifying_pending: false,
            activation_depth: 0,
        }
    }

    /// The active root Fiber. Its uid is always zero and it is never created
    /// from a public constructor.
    #[must_use]
    pub fn root_fiber(&self) -> Fiber {
        self.root.clone()
    }

    /// Alias for [`Context::root_fiber`].
    #[must_use]
    pub fn root(&self) -> Fiber {
        self.root_fiber()
    }

    /// Allocate a child Fiber with a distinct monotonic uid.
    pub fn new_fiber(&mut self) -> Result<Fiber, CordisError> {
        let parent = self.current_fiber_handle()?;
        self.child_fiber(&parent)
    }

    /// Allocate a child Fiber below `parent`.
    pub fn child_fiber(&mut self, parent: &Fiber) -> Result<Fiber, CordisError> {
        self.child_fiber_in_namespace(parent, parent.namespace())
    }

    fn child_fiber_in_namespace(
        &mut self,
        parent: &Fiber,
        namespace: String,
    ) -> Result<Fiber, CordisError> {
        self.validate_fiber(parent)?;
        if parent.is_disposed() {
            return Err(CordisError::FiberDisposed { uid: parent.uid() });
        }
        if !self.current_scope_allows(parent) {
            return Err(CordisError::FiberScopeViolation {
                current: self.current_fiber,
                requested: parent.uid(),
            });
        }
        let fiber = Fiber::child_with_namespace(self.id, parent, namespace);
        if parent.uid() == self.root.uid() {
            fiber.replace_metadata(self.vars.clone());
        }
        let _ = fiber.activate();
        self.fibers.insert(fiber.uid(), fiber.clone());
        Ok(fiber)
    }

    /// Create an ownership view for `fiber`. A pending Fiber remains pending
    /// until its retained factory is notified; a disposed or foreign Fiber
    /// remains fail-closed.
    pub fn with_fiber<'a>(&'a mut self, fiber: &Fiber) -> ContextView<'a> {
        let context_valid = fiber.context_id() == self.id;
        let scope_valid = context_valid && self.current_scope_allows(fiber);
        let view_active = context_valid
            && scope_valid
            && !fiber.is_disposed()
            && fiber.state() == FiberState::Active;
        let metadata = if view_active {
            fiber.metadata_snapshot()
        } else {
            ConfigValue::default()
        };
        ContextView {
            context: self,
            fiber: fiber.clone(),
            namespace: fiber.namespace(),
            shared_namespaces: Vec::new(),
            service_intercepts: Vec::new(),
            metadata,
            context_valid,
            scope_valid,
        }
    }

    /// Closure-shaped counterpart to [`Context::with_fiber`] for callers that
    /// do not need to retain a view.
    pub fn in_fiber<R>(&mut self, fiber: &Fiber, f: impl FnOnce(&mut ContextView<'_>) -> R) -> R {
        let mut view = self.with_fiber(fiber);
        f(&mut view)
    }

    fn validate_fiber(&self, fiber: &Fiber) -> Result<(), CordisError> {
        if fiber.context_id() == self.id {
            Ok(())
        } else {
            Err(CordisError::FiberContextMismatch { uid: fiber.uid() })
        }
    }

    fn ensure_owner_active(&self, owner_uid: FiberUid) -> Result<(), CordisError> {
        if owner_uid == self.root.uid() {
            if self.root.is_disposed() {
                return Err(CordisError::FiberDisposed { uid: owner_uid });
            }
            return Ok(());
        }
        match self.fibers.get(&owner_uid) {
            Some(fiber) if fiber.is_disposed() => {
                Err(CordisError::FiberDisposed { uid: fiber.uid() })
            }
            Some(fiber) if fiber.state() == FiberState::Active => Ok(()),
            Some(fiber) => Err(CordisError::FiberDisposed { uid: fiber.uid() }),
            None => Err(CordisError::FiberContextMismatch { uid: owner_uid }),
        }
    }

    fn current_fiber_handle(&self) -> Result<Fiber, CordisError> {
        self.ensure_owner_active(self.current_fiber)?;
        if self.current_fiber == self.root.uid() {
            Ok(self.root.clone())
        } else {
            self.fibers
                .get(&self.current_fiber)
                .cloned()
                .ok_or(CordisError::FiberDisposed {
                    uid: self.current_fiber,
                })
        }
    }

    /// During a factory callback, ownership may move only to that Fiber or a
    /// descendant. This blocks a callback from switching to root or a sibling
    /// while retaining normal root-context behavior outside activation.
    fn current_scope_allows(&self, fiber: &Fiber) -> bool {
        if self.activation_depth == 0 || self.current_fiber == self.root.uid() {
            return true;
        }
        if fiber.context_id() != self.id || fiber.is_disposed() {
            return false;
        }
        let mut cursor = Some(fiber.uid());
        while let Some(uid) = cursor {
            if uid == self.current_fiber {
                return true;
            }
            cursor = if uid == fiber.uid() {
                fiber.parent_uid()
            } else {
                self.fibers.get(&uid).and_then(Fiber::parent_uid)
            };
        }
        false
    }

    /// Fiber currently used by direct Context mutations. Factory callbacks
    /// temporarily switch this owner to their child Fiber.
    #[must_use]
    pub fn current_fiber_uid(&self) -> FiberUid {
        self.current_fiber
    }

    fn current_namespace(&self) -> Option<String> {
        if self.current_fiber == self.root.uid() {
            Some("root".to_string())
        } else {
            self.fibers.get(&self.current_fiber).map(Fiber::namespace)
        }
    }

    /// Number of live registration records, useful for lifecycle diagnostics.
    #[must_use]
    pub fn registration_count(&self) -> usize {
        self.effects.len()
    }

    #[cfg(test)]
    pub(crate) fn provider_snapshot(&self, key: &str) -> Option<ProviderSnapshot> {
        let provider_key = ProviderKey::new("root", key);
        let record = self.providers.get(&provider_key)?;
        Some(ProviderSnapshot {
            namespace: "root".to_string(),
            key: key.to_string(),
            provider_id: record.provider_id,
            owner_uid: record.owner_uid,
            generation: record.generation,
            notify_count: record.notify_count,
            value_identity: Arc::as_ptr(&record.value).cast::<()>() as usize,
            disposer_count: usize::from(
                self.effects.iter().any(|registration| {
                    matches!(
                        registration,
                        Registration::Provider {
                            namespace,
                            key: registered_key,
                            provider_id,
                            ..
                        } if namespace == "root" && registered_key == key && *provider_id == record.provider_id.0
                    )
                }),
            ),
        })
    }

    fn with_current_fiber<R>(
        &mut self,
        owner_uid: FiberUid,
        callback: impl FnOnce(&mut Self) -> R,
    ) -> R {
        let previous = self.current_fiber;
        self.current_fiber = owner_uid;
        let result = catch_unwind(AssertUnwindSafe(|| callback(self)));
        self.current_fiber = previous;
        match result {
            Ok(result) => result,
            Err(payload) => resume_unwind(payload),
        }
    }

    fn interpolate_plugin_config_for_fiber(
        fiber: &Fiber,
        config: &ConfigValue,
    ) -> Result<ConfigValue, crate::config::InterpolateError> {
        config.interpolate(&fiber.metadata_snapshot())
    }

    fn begin_activation(&mut self, id: PluginFactoryId) {
        self.activating_factories.insert(id);
        self.activation_depth = self.activation_depth.saturating_add(1);
    }

    fn end_activation(&mut self, id: PluginFactoryId) {
        self.activation_depth = self.activation_depth.saturating_sub(1);
        self.activating_factories.remove(&id);
    }

    fn failed_activation(
        &mut self,
        id: PluginFactoryId,
        fiber: &Fiber,
        failure: CordisError,
    ) -> CordisError {
        self.end_activation(id);
        fiber.dispose();
        let source = match self.cleanup_fiber(fiber) {
            Ok(()) => failure,
            Err(cleanup) => CordisError::CleanupAfterFailure {
                failure: Box::new(failure),
                cleanup: Box::new(cleanup),
            },
        };
        CordisError::PluginActivation {
            id,
            source: Box::new(source),
        }
    }

    fn has_in_namespace(&self, namespace: &str, key: &str) -> bool {
        self.providers
            .contains_key(&ProviderKey::new(namespace, key))
    }

    fn get_in_namespace<T: Any + Send + Sync>(&self, namespace: &str, key: &str) -> Option<Arc<T>> {
        self.providers
            .get(&ProviderKey::new(namespace, key))?
            .value
            .clone()
            .downcast::<T>()
            .ok()
    }

    fn new_pending_handle(
        &mut self,
        factory: PluginFactory,
        parent: &Fiber,
        namespace: String,
    ) -> Result<PendingHandle, CordisError> {
        self.validate_fiber(parent)?;
        if parent.is_disposed() {
            return Err(CordisError::FiberDisposed { uid: parent.uid() });
        }
        if self.mounted_factories.contains_key(&factory.id())
            || self.activating_factories.contains(&factory.id())
            || self.registry.contains_factory(factory.id())
        {
            return Err(CordisError::DuplicatePluginFactory { id: factory.id() });
        }
        let fiber = Fiber::child_with_namespace(self.id, parent, namespace.clone());
        self.fibers.insert(fiber.uid(), fiber.clone());
        let handle = PendingHandle {
            id: self.registry.allocate_id(),
            factory_id: factory.id(),
            fiber: fiber.clone(),
        };
        let inject = factory.inject().to_vec();
        let missing = inject
            .iter()
            .filter(|key| !self.has_in_namespace(&namespace, key))
            .cloned()
            .collect::<Vec<_>>();
        let config = factory.config();
        if !missing.is_empty() {
            self.registry.push(PendingEntry {
                factory,
                fiber,
                namespace,
                inject,
                config,
            });
            return Ok(handle);
        }
        fiber.activate();
        self.begin_activation(handle.factory_id);
        let config = match Self::interpolate_plugin_config_for_fiber(&fiber, &config) {
            Ok(config) => config,
            Err(error) => {
                return Err(self.failed_activation(
                    handle.factory_id,
                    &fiber,
                    CordisError::from(error),
                ));
            }
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.with_current_fiber(fiber.uid(), |ctx| factory.start(config, ctx))
        }));
        let result = match result {
            Ok(result) => result,
            Err(payload) => {
                return Err(self.failed_activation(
                    handle.factory_id,
                    &fiber,
                    CordisError::PluginCallbackPanicked {
                        message: panic_payload_message(payload.as_ref()),
                    },
                ));
            }
        };
        if let Err(source) = result {
            return Err(self.failed_activation(handle.factory_id, &fiber, source));
        }
        self.end_activation(handle.factory_id);
        if fiber.is_disposed() || !self.fibers.contains_key(&fiber.uid()) {
            return Err(CordisError::FiberDisposed { uid: fiber.uid() });
        }
        self.mounted_factories
            .insert(handle.factory_id, fiber.clone());
        if let Err(source) = self.notify_pending() {
            return Err(CordisError::PendingNotification {
                handle: handle.clone(),
                source: Box::new(source),
            });
        }
        Ok(handle)
    }

    /// Mount a repeatable factory and retain it if dependencies are missing.
    pub fn mount_pending(&mut self, factory: PluginFactory) -> Result<PendingHandle, CordisError> {
        let parent = self.current_fiber_handle()?;
        let namespace = parent.namespace();
        self.new_pending_handle(factory, &parent, namespace)
    }

    fn mount_pending_in_namespace(
        &mut self,
        factory: PluginFactory,
        parent: &Fiber,
        namespace: String,
    ) -> Result<PendingHandle, CordisError> {
        self.new_pending_handle(factory, parent, namespace)
    }

    /// Number of retained unresolved factories.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.registry.len()
    }

    /// Publish a child Fiber tombstone and synchronously clean its owned
    /// registrations. Parent-owned registrations are left untouched.
    pub fn dispose_fiber(&mut self, fiber: &Fiber) -> Result<bool, CordisError> {
        self.validate_fiber(fiber)?;
        if fiber.uid() == self.root.uid() {
            if self.activation_depth != 0 {
                return Err(CordisError::FiberBusy {
                    uid: self.current_fiber,
                });
            }
            return match self.try_begin_teardown() {
                TeardownTransaction::Busy => Ok(false),
                TeardownTransaction::Acquired(permit) => {
                    self.complete_teardown(permit);
                    Ok(true)
                }
            };
        }
        if !self.current_scope_allows(fiber) {
            return Err(CordisError::FiberScopeViolation {
                current: self.current_fiber,
                requested: fiber.uid(),
            });
        }
        let disposed = self.fiber_subtree(fiber.uid());
        let changed = fiber.dispose();
        self.tombstone_fibers(&disposed);
        let cleanup = self.cleanup_fibers(&disposed);
        self.notify_pending()?;
        cleanup?;
        Ok(changed)
    }

    fn fiber_subtree(&self, root_uid: FiberUid) -> HashSet<FiberUid> {
        let mut disposed = HashSet::from([root_uid]);
        loop {
            let descendants: Vec<FiberUid> = self
                .fibers
                .values()
                .filter(|candidate| {
                    candidate
                        .parent_uid()
                        .is_some_and(|parent| disposed.contains(&parent))
                        && !disposed.contains(&candidate.uid())
                })
                .map(Fiber::uid)
                .collect();
            if descendants.is_empty() {
                break;
            }
            disposed.extend(descendants);
        }
        disposed
    }

    fn tombstone_fibers(&self, disposed: &HashSet<FiberUid>) {
        for candidate in self.fibers.values() {
            if disposed.contains(&candidate.uid()) {
                candidate.dispose();
            }
        }
    }

    /// Remove all Context-owned records for a terminal child without asking
    /// the pending registry to activate another factory. Activation failures
    /// use this form so no partial callback registration can leak.
    fn cleanup_fiber(&mut self, fiber: &Fiber) -> Result<(), CordisError> {
        let disposed = self.fiber_subtree(fiber.uid());
        fiber.dispose();
        self.tombstone_fibers(&disposed);
        self.cleanup_fibers(&disposed)
    }

    fn cleanup_fibers(&mut self, disposed: &HashSet<FiberUid>) -> Result<(), CordisError> {
        let mut first_panic = self
            .events
            .remove_owners(disposed)
            .map(|payload| panic_payload_message(payload.as_ref()));
        for uid in disposed {
            self.registry.remove_fiber(*uid);
        }
        self.mounted_factories
            .retain(|_, candidate| !disposed.contains(&candidate.uid()));
        self.fibers.retain(|uid, _| !disposed.contains(uid));

        let mut retained = Vec::with_capacity(self.effects.len());
        let mut owned = Vec::new();
        while let Some(registration) = self.effects.pop() {
            if disposed.contains(&registration.owner_uid()) {
                owned.push(registration);
            } else {
                retained.push(registration);
            }
        }
        retained.reverse();
        self.effects = retained;
        for registration in owned {
            let result = catch_unwind(AssertUnwindSafe(|| self.run_registration(registration)));
            if let Err(payload) = result
                && first_panic.is_none()
            {
                first_panic = Some(panic_payload_message(payload.as_ref()));
            }
        }
        match first_panic {
            Some(message) => Err(CordisError::CleanupPanicked { message }),
            None => Ok(()),
        }
    }

    /// Dispose a pending/active plugin handle and its Context-owned records.
    pub fn dispose_pending(&mut self, handle: &PendingHandle) -> Result<bool, CordisError> {
        self.dispose_fiber(&handle.fiber)
    }

    fn notify_pending(&mut self) -> Result<(), CordisError> {
        if self.notifying_pending || self.activation_depth != 0 {
            return Ok(());
        }
        self.notifying_pending = true;
        let result = catch_unwind(AssertUnwindSafe(|| self.notify_pending_inner()));
        self.notifying_pending = false;
        match result {
            Ok(result) => result,
            Err(payload) => Err(CordisError::PluginCallbackPanicked {
                message: panic_payload_message(payload.as_ref()),
            }),
        }
    }

    fn requeue_pending<I>(&mut self, remaining_ready: I)
    where
        I: IntoIterator<Item = PendingEntry>,
    {
        let waiting = self.registry.take_pending();
        let mut pending = remaining_ready
            .into_iter()
            .filter(|entry| !entry.fiber.is_disposed())
            .collect::<Vec<_>>();
        pending.extend(
            waiting
                .into_iter()
                .filter(|entry| !entry.fiber.is_disposed()),
        );
        self.registry.replace_pending(pending);
    }

    fn notify_pending_inner(&mut self) -> Result<(), CordisError> {
        loop {
            let mut ready = Vec::new();
            let mut waiting = Vec::new();
            for entry in self.registry.take_pending() {
                if entry.fiber.is_disposed() {
                    continue;
                }
                let is_ready = entry
                    .inject
                    .iter()
                    .all(|key| self.has_in_namespace(&entry.namespace, key));
                if is_ready {
                    ready.push(entry);
                } else {
                    waiting.push(entry);
                }
            }
            self.registry.replace_pending(waiting);
            if ready.is_empty() {
                return Ok(());
            }
            let mut ready = ready.into_iter();
            while let Some(entry) = ready.next() {
                if entry.fiber.is_disposed() {
                    continue;
                }
                if !entry.fiber.activate() {
                    continue;
                }
                let id = entry.factory.id();
                self.begin_activation(id);
                let config =
                    match Self::interpolate_plugin_config_for_fiber(&entry.fiber, &entry.config) {
                        Ok(config) => config,
                        Err(error) => {
                            let failure =
                                self.failed_activation(id, &entry.fiber, CordisError::from(error));
                            self.requeue_pending(ready);
                            return Err(failure);
                        }
                    };
                let result = catch_unwind(AssertUnwindSafe(|| {
                    self.with_current_fiber(entry.fiber.uid(), |ctx| {
                        entry.factory.start(config, ctx)
                    })
                }));
                let result = match result {
                    Ok(result) => result,
                    Err(payload) => {
                        let failure = self.failed_activation(
                            id,
                            &entry.fiber,
                            CordisError::PluginCallbackPanicked {
                                message: panic_payload_message(payload.as_ref()),
                            },
                        );
                        self.requeue_pending(ready);
                        return Err(failure);
                    }
                };
                if let Err(source) = result {
                    let failure = self.failed_activation(id, &entry.fiber, source);
                    self.requeue_pending(ready);
                    return Err(failure);
                }
                self.end_activation(id);
                if entry.fiber.is_disposed() || !self.fibers.contains_key(&entry.fiber.uid()) {
                    self.requeue_pending(ready);
                    return Err(CordisError::FiberDisposed {
                        uid: entry.fiber.uid(),
                    });
                }
                self.mounted_factories.insert(id, entry.fiber);
            }
        }
    }

    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.current_namespace()
            .is_some_and(|namespace| self.has_in_namespace(&namespace, key))
    }

    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        let namespace = self.current_namespace()?;
        self.get_in_namespace(&namespace, key)
    }

    fn metadata_for_fiber(&self, fiber_uid: FiberUid) -> Option<ConfigValue> {
        if fiber_uid == self.root.uid() {
            (!self.root.is_disposed()).then(|| self.root.metadata_snapshot())
        } else {
            self.fibers
                .get(&fiber_uid)
                .filter(|fiber| !fiber.is_disposed() && fiber.state() == FiberState::Active)
                .map(Fiber::metadata_snapshot)
        }
    }

    fn current_service_lookup(&self) -> Option<(ServiceLookup, ServiceCaller)> {
        self.ensure_owner_active(self.current_fiber).ok()?;
        let namespace = self.current_namespace()?;
        let metadata = self.metadata_for_fiber(self.current_fiber)?;
        let scope = ServiceScope::new(
            self.id,
            self.current_fiber,
            namespace,
            Vec::new(),
            metadata,
            None,
        );
        Some((
            ServiceLookup::new(scope.clone(), Vec::new()),
            ServiceCaller::new(scope),
        ))
    }

    pub(crate) fn service_from_lookup<'ctx, T>(
        &'ctx self,
        lookup: ServiceLookup,
        caller: ServiceCaller,
        key: &str,
    ) -> Option<ServiceHandle<'ctx, T>>
    where
        T: Any + Send + Sync,
    {
        let resolved = lookup.namespaces().find_map(|namespace| {
            let record = self.providers.get(&ProviderKey::new(namespace, key))?;
            let value = Arc::clone(&record.value).downcast::<T>().ok()?;
            Some((
                namespace.to_string(),
                value,
                record.provider_id,
                record.owner_uid,
                record.generation,
                record.service_options,
                record.origin.clone(),
            ))
        })?;
        let (namespace, value, provider_id, owner_uid, generation, options, provider_origin) =
            resolved;
        let shadow = if options.is_no_shadow() {
            None
        } else {
            let origin = ServiceOrigin::new(
                self.id,
                owner_uid,
                namespace.clone(),
                provider_id,
                generation,
            );
            Some(ServiceShadow::new(
                ServiceScope::new(
                    self.id,
                    owner_uid,
                    namespace,
                    provider_origin.shared_namespaces,
                    provider_origin.metadata,
                    None,
                ),
                origin,
            ))
        };
        Some(ServiceHandle::new(
            self,
            key.to_string(),
            value,
            lookup,
            caller,
            shadow,
        ))
    }

    /// Resolve a typed service from the current Fiber namespace. This is
    /// additive to [`Context::get`] and does not change its behavior.
    #[must_use]
    pub fn service<T>(&self, key: &str) -> Option<ServiceHandle<'_, T>>
    where
        T: Any + Send + Sync,
    {
        let (lookup, caller) = self.current_service_lookup()?;
        self.service_from_lookup(lookup, caller, key)
    }

    /// Resolve explicit `association.property` entries from the current
    /// Fiber namespace without adding an implicit parent/root fallback.
    #[must_use]
    pub fn association(&self, name: impl Into<String>) -> Option<ServiceAssociation<'_>> {
        let (lookup, caller) = self.current_service_lookup()?;
        Some(ServiceAssociation::new(self, name.into(), lookup, caller))
    }

    #[must_use]
    pub fn tools<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::TOOLS)
    }

    #[must_use]
    pub fn system_prompt<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::SYSTEM_PROMPT)
    }

    #[must_use]
    pub fn llm<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::LLM)
    }

    #[must_use]
    pub fn sessions<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::SESSIONS)
    }

    #[must_use]
    pub fn agents<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::AGENTS)
    }

    #[must_use]
    pub fn approval<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::APPROVAL)
    }

    #[must_use]
    pub fn domain<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::DOMAIN)
    }

    #[must_use]
    pub fn effect_broker<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::EFFECT_BROKER)
    }

    #[must_use]
    pub fn runtime<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::RUNTIME)
    }

    #[must_use]
    pub fn desktop<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::DESKTOP)
    }

    /// Provide a named ordinary service in the current Fiber namespace.
    ///
    /// Registration is unique by `(namespace, key)` and starts at generation
    /// zero. The returned opaque handle is the only ordinary replacement
    /// capability. Domain, Effect Broker, Runtime, and Desktop are reserved
    /// to the private Hartevo surface authority.
    pub fn provide<T: Any + Send + Sync>(
        &mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        let owner_uid = self.current_fiber;
        let namespace = self
            .current_namespace()
            .ok_or(CordisError::FiberDisposed { uid: owner_uid })?;
        self.ensure_owner_active(owner_uid)?;
        let origin_metadata = self
            .metadata_for_fiber(owner_uid)
            .ok_or(CordisError::FiberDisposed { uid: owner_uid })?;
        self.provide_in_namespace(
            namespace,
            owner_uid,
            key.into(),
            value,
            ProviderOriginSnapshot::new(Vec::new(), origin_metadata),
        )
    }

    /// Provide a typed service with explicit tracing options. The provider is
    /// still owned and replaced through the ordinary Fiber-bound machinery.
    pub fn provide_service<T: Any + Send + Sync>(
        &mut self,
        key: impl Into<String>,
        value: T,
        options: ServiceOptions,
    ) -> Result<ProviderHandle, CordisError> {
        let owner_uid = self.current_fiber;
        let namespace = self
            .current_namespace()
            .ok_or(CordisError::FiberDisposed { uid: owner_uid })?;
        self.ensure_owner_active(owner_uid)?;
        let origin_metadata = self
            .metadata_for_fiber(owner_uid)
            .ok_or(CordisError::FiberDisposed { uid: owner_uid })?;
        self.provide_service_in_namespace(
            namespace,
            owner_uid,
            key.into(),
            value,
            options,
            ProviderOriginSnapshot::new(Vec::new(), origin_metadata),
        )
    }

    /// Provide `association.property` through the same owner-bound provider
    /// table used for ordinary services and typed accessors.
    pub fn provide_associated<T: Any + Send + Sync>(
        &mut self,
        association: &str,
        property: &str,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        self.provide(associated_key(association, property), value)
    }

    fn provide_in_namespace<T: Any + Send + Sync>(
        &mut self,
        namespace: impl Into<String>,
        owner_uid: FiberUid,
        key: String,
        value: T,
        origin: ProviderOriginSnapshot,
    ) -> Result<ProviderHandle, CordisError> {
        self.provide_service_in_namespace(
            namespace,
            owner_uid,
            key,
            value,
            ServiceOptions::default(),
            origin,
        )
    }

    fn provide_service_in_namespace<T: Any + Send + Sync>(
        &mut self,
        namespace: impl Into<String>,
        owner_uid: FiberUid,
        key: String,
        value: T,
        service_options: ServiceOptions,
        origin: ProviderOriginSnapshot,
    ) -> Result<ProviderHandle, CordisError> {
        if authority_reserved_key(&key) || self.reserved_services.contains(&key) {
            return Err(CordisError::ReservedServiceKey { key });
        }
        self.ensure_owner_active(owner_uid)?;
        let namespace = namespace.into();
        let provider_key = ProviderKey::new(namespace.clone(), key.clone());
        if self.providers.contains_key(&provider_key) {
            return Err(CordisError::DuplicateProvider { namespace, key });
        }
        let provider_id = ProviderId(self.next_provider_id);
        self.next_provider_id = self
            .next_provider_id
            .checked_add(1)
            .ok_or(CordisError::ProviderIdentityOverflow)?;
        let handle = ProviderHandle {
            context_id: self.id,
            namespace: namespace.clone(),
            key: key.clone(),
            provider_id,
            owner_uid,
            generation: 0,
        };
        let value: Arc<dyn Any + Send + Sync> = Arc::new(value);
        if namespace == "root" {
            self.services.insert(key.clone(), Arc::clone(&value));
        }
        self.providers.insert(
            provider_key,
            ProviderRecord {
                value,
                provider_id,
                owner_uid,
                generation: 0,
                notify_count: 0,
                service_options,
                origin,
            },
        );
        self.effects.push(Registration::provider(
            owner_uid,
            namespace,
            key,
            provider_id.0,
        ));
        if let Err(source) = self.notify_pending() {
            return Err(CordisError::ProviderNotification {
                handle: handle.clone(),
                source: Box::new(source),
            });
        }
        Ok(handle)
    }

    /// Mount one owner-bound authority service exactly once. The authority is
    /// deliberately crate-private and cannot be forged by integration users.
    pub(crate) fn provide_reserved<T: Any + Send + Sync>(
        &mut self,
        authority: HartevoSurfaceAuthority,
        key: &'static str,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        if !authority.is_valid() {
            return Err(CordisError::ReservedServiceKey {
                key: key.to_string(),
            });
        }
        self.ensure_owner_active(self.root.uid())?;
        if !authority_reserved_key(key) || self.services.contains_key(key) {
            return Err(CordisError::ReservedServiceKey {
                key: key.to_string(),
            });
        }
        let namespace = "root".to_string();
        let provider_id = ProviderId(self.next_provider_id);
        self.next_provider_id = self
            .next_provider_id
            .checked_add(1)
            .ok_or(CordisError::ProviderIdentityOverflow)?;
        self.reserved_services.insert(key.to_string());
        let value: Arc<dyn Any + Send + Sync> = Arc::new(value);
        self.services.insert(key.to_string(), Arc::clone(&value));
        self.providers.insert(
            ProviderKey::new(namespace.clone(), key),
            ProviderRecord {
                value,
                provider_id,
                owner_uid: self.root.uid(),
                generation: 0,
                notify_count: 0,
                service_options: ServiceOptions::default(),
                origin: ProviderOriginSnapshot::new(Vec::new(), self.root.metadata_snapshot()),
            },
        );
        self.effects.push(Registration::provider(
            self.root.uid(),
            namespace.clone(),
            key.to_string(),
            provider_id.0,
        ));
        self.notify_pending()?;
        Ok(ProviderHandle {
            context_id: self.id,
            namespace,
            key: key.to_string(),
            provider_id,
            owner_uid: self.root.uid(),
            generation: 0,
        })
    }

    /// Replace an ordinary provider through its opaque owner-checked handle.
    /// Reserved handles are rejected before any value or generation changes.
    pub fn replace_provider<T: Any + Send + Sync>(
        &mut self,
        handle: &ProviderHandle,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        self.replace_provider_for(self.current_fiber, handle, value, false)
    }

    fn replace_provider_for<T: Any + Send + Sync>(
        &mut self,
        owner_uid: FiberUid,
        handle: &ProviderHandle,
        value: T,
        authorized_reserved: bool,
    ) -> Result<ProviderHandle, CordisError> {
        if authority_reserved_key(&handle.key) && !authorized_reserved {
            return Err(CordisError::ReservedServiceKey {
                key: handle.key.clone(),
            });
        }
        if handle.context_id != self.id {
            return Err(CordisError::FiberContextMismatch {
                uid: handle.owner_uid,
            });
        }
        self.ensure_owner_active(owner_uid)?;
        if handle.owner_uid != owner_uid {
            return Err(CordisError::ProviderOwnerMismatch {
                key: handle.key.clone(),
            });
        }
        let provider_key = ProviderKey::new(handle.namespace.clone(), handle.key.clone());
        let Some(record) = self.providers.get_mut(&provider_key) else {
            return Err(CordisError::ProviderNotFound {
                namespace: handle.namespace.clone(),
                key: handle.key.clone(),
            });
        };
        if record.provider_id != handle.provider_id || record.owner_uid != handle.owner_uid {
            return Err(CordisError::ProviderOwnerMismatch {
                key: handle.key.clone(),
            });
        }
        if record.generation != handle.generation {
            return Err(CordisError::StaleProviderHandle {
                key: handle.key.clone(),
            });
        }
        let generation = record.generation.checked_add(1).ok_or_else(|| {
            CordisError::ProviderGenerationOverflow {
                key: handle.key.clone(),
            }
        })?;
        let value: Arc<dyn Any + Send + Sync> = Arc::new(value);
        record.value = Arc::clone(&value);
        record.generation = generation;
        record.notify_count = record.notify_count.saturating_add(1);
        if handle.namespace == "root" {
            self.services.insert(handle.key.clone(), value);
        }
        let current = ProviderHandle {
            context_id: self.id,
            namespace: handle.namespace.clone(),
            key: handle.key.clone(),
            provider_id: handle.provider_id,
            owner_uid: handle.owner_uid,
            generation,
        };
        if let Err(source) = self.notify_pending() {
            return Err(CordisError::ProviderNotification {
                handle: current,
                source: Box::new(source),
            });
        }
        Ok(current)
    }

    /// Authorized Hartevo-only Domain replacement. The key and value type are
    /// fixed so Effect Broker, Runtime, and Desktop have no replacement route.
    pub(crate) fn replace_hartevo_domain(
        &mut self,
        authority: HartevoSurfaceAuthority,
        value: DomainSurface,
    ) -> Result<ProviderHandle, CordisError> {
        let key = keys::DOMAIN;
        if !authority.is_valid() {
            return Err(CordisError::ReservedServiceKey {
                key: key.to_string(),
            });
        }
        let Some(record) = self.providers.get(&ProviderKey::new("root", key)) else {
            return Err(CordisError::ProviderNotFound {
                namespace: "root".to_string(),
                key: key.to_string(),
            });
        };
        let handle = ProviderHandle {
            context_id: self.id,
            namespace: "root".to_string(),
            key: key.to_string(),
            provider_id: record.provider_id,
            owner_uid: record.owner_uid,
            generation: record.generation,
        };
        match self.replace_provider_for(self.root.uid(), &handle, value, true) {
            Err(CordisError::ProviderNotification { handle, source }) => {
                Err(CordisError::ReservedProviderNotification {
                    key: handle.key().to_string(),
                    generation: handle.generation(),
                    source,
                })
            }
            result => result,
        }
    }

    /// Set a plugin-context interpolation variable. Reversed on teardown.
    ///
    /// Used after `inject` when expanding plugin `config`. Not the loader
    /// context used for `disabled`.
    pub fn set_var(&mut self, key: impl Into<String>, value: impl Into<ConfigValue>) {
        if self.ensure_owner_active(self.current_fiber).is_err() {
            return;
        }
        let key = key.into();
        let value = value.into();
        if self.current_fiber != self.root.uid() {
            if let Some(fiber) = self.fibers.get(&self.current_fiber) {
                let mut metadata = fiber.metadata_snapshot();
                match &mut metadata {
                    ConfigValue::Object(map) => {
                        map.insert(key, value);
                    }
                    current => *current = ConfigValue::object([(key, value)]),
                }
                fiber.replace_metadata(metadata);
            }
            return;
        }
        let previous = match &mut self.vars {
            ConfigValue::Object(map) => map.insert(key.clone(), value),
            other => {
                let previous = Some(other.clone());
                *other = ConfigValue::object([(key.clone(), value)]);
                previous
            }
        };
        self.effects
            .push(Registration::var(self.current_fiber, key, previous));
        self.root.replace_metadata(self.vars.clone());
    }

    #[must_use]
    pub fn var(&self, key: &str) -> Option<ConfigValue> {
        if self.current_fiber == self.root.uid() {
            return self.vars.lookup(key).cloned();
        }
        self.fibers
            .get(&self.current_fiber)
            .and_then(|fiber| fiber.metadata_snapshot().lookup(key).cloned())
    }

    /// Interpolation source for plugin `config` (plugin context, after inject).
    #[must_use]
    pub fn plugin_interpolation_source(&self) -> ConfigValue {
        if self.current_fiber == self.root.uid() {
            return self.vars.clone();
        }
        self.fibers
            .get(&self.current_fiber)
            .map_or_else(ConfigValue::default, Fiber::metadata_snapshot)
    }

    /// Start `plugin` once every `inject` key is present. Missing deps do not start it.
    pub fn mount<S: Service>(&mut self, plugin: S) -> Result<(), CordisError> {
        let owner_uid = self.current_fiber;
        let namespace = self
            .current_namespace()
            .ok_or(CordisError::FiberDisposed { uid: owner_uid })?;
        self.ensure_owner_active(owner_uid)?;
        let missing: Vec<String> = S::inject()
            .iter()
            .copied()
            .filter(|key| !self.has_in_namespace(&namespace, key))
            .map(str::to_string)
            .collect();
        if !missing.is_empty() {
            return Err(CordisError::MissingDependencies(missing));
        }
        self.with_current_fiber(owner_uid, |ctx| plugin.apply(ctx))
    }

    pub fn effect<F>(&mut self, dispose: F) -> RegistrationHandle
    where
        F: FnOnce() + Send + 'static,
    {
        if self.ensure_owner_active(self.current_fiber).is_err() {
            return RegistrationHandle::noop();
        }
        let dispose: Disposer = Box::new(dispose);
        let registration = Registration::disposer(self.current_fiber, dispose);
        let handle = registration.handle();
        self.effects.push(registration);
        handle
    }

    fn current_event_owner(&self) -> Result<(Fiber, EventScope), CordisError> {
        self.ensure_owner_active(self.current_fiber)?;
        let owner = self.current_fiber_handle()?;
        let scope = EventScope::new(owner.namespace(), &[]);
        Ok((owner, scope))
    }

    /// Capture a cloneable typed-Emit capability for callback re-entry.
    ///
    /// Direct Context dispatch remains untargeted, matching [`Context::emit`].
    /// Use [`ContextView::event_reentry`] to retain an isolated/shared target.
    pub fn event_reentry(&self) -> Result<EventReentry, CordisError> {
        let (owner, scope) = self.current_event_owner()?;
        let generation = self
            .event_gate
            .current_generation()
            .ok_or(CordisError::FiberContextMismatch { uid: owner.uid() })?;
        Ok(EventReentry::new(
            self.id,
            Arc::clone(&self.event_gate),
            generation,
            self.events.clone(),
            owner,
            scope,
            None,
        ))
    }

    fn finish_listener(
        &mut self,
        owner_uid: FiberUid,
        name: &str,
        mode: DispatchMode,
        result: Result<ListenerHandle, crate::event::EventBusError>,
    ) -> Result<ListenerHandle, CordisError> {
        let handle = result.map_err(|error| into_cordis_error(name, mode, error))?;
        self.effects
            .push(Registration::listener(owner_uid, handle.clone()));
        Ok(handle)
    }

    /// Register a no-payload Emit listener.
    pub fn on<F>(
        &mut self,
        key: EventKey<Emit, (), ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.on_emit(key, move |(): &()| listener())
    }

    pub fn on_emit<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.on_emit_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_emit_with_options<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_emit_for(key, owner, scope, options, false, listener)
    }

    pub fn once_emit<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.once_emit_with_options(key, EventOptions::default(), listener)
    }

    pub fn once_emit_with_options<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_emit_for(key, owner, scope, options, true, listener)
    }

    fn register_emit_for<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_emit(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Emit, result)
    }

    pub fn try_on_emit<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        self.try_on_emit_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_emit_with_options<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_emit_for(key, owner, scope, options, false, listener)
    }

    pub fn try_once_emit_with_options<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_emit_for(key, owner, scope, options, true, listener)
    }

    fn register_try_emit_for<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_try_emit(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Emit, result)
    }

    pub fn on_waterfall<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        self.on_waterfall_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_waterfall_for(key, owner, scope, options, false, listener)
    }

    pub fn once_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_waterfall_for(key, owner, scope, options, true, listener)
    }

    pub fn once_waterfall<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        self.once_waterfall_with_options(key, EventOptions::default(), listener)
    }

    fn register_waterfall_for<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_waterfall(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Waterfall, result)
    }

    pub fn try_on_waterfall<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        self.try_on_waterfall_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_waterfall_for(key, owner, scope, options, false, listener)
    }

    pub fn try_once_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_waterfall_for(key, owner, scope, options, true, listener)
    }

    fn register_try_waterfall_for<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_try_waterfall(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Waterfall, result)
    }

    pub fn on_parallel<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        self.on_parallel_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_parallel_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_parallel_for(key, owner, scope, options, false, listener)
    }

    pub fn once_parallel_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_parallel_for(key, owner, scope, options, true, listener)
    }

    fn register_parallel_for<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_parallel(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Parallel, result)
    }

    pub fn on_serial<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        self.on_serial_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_serial_with_options<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_serial_for(key, owner, scope, options, false, listener)
    }

    pub fn once_serial_with_options<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_serial_for(key, owner, scope, options, true, listener)
    }

    fn register_serial_for<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_serial(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Serial, result)
    }

    pub fn on_bail<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        self.on_bail_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_bail_with_options<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_bail_for(key, owner, scope, options, false, listener)
    }

    pub fn once_bail_with_options<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_bail_for(key, owner, scope, options, true, listener)
    }

    fn register_bail_for<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_bail(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Bail, result)
    }

    pub fn try_on_bail<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        self.try_on_bail_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_bail_with_options<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_bail_for(key, owner, scope, options, false, listener)
    }

    pub fn try_once_bail_with_options<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_try_bail_for(key, owner, scope, options, true, listener)
    }

    fn register_try_bail_for<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_try_bail(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Bail, result)
    }

    pub fn on_accumulate<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        self.on_accumulate_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_accumulate_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_accumulate_for(key, owner, scope, options, false, listener)
    }

    pub fn once_accumulate_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let (owner, scope) = self.current_event_owner()?;
        self.register_accumulate_for(key, owner, scope, options, true, listener)
    }

    fn register_accumulate_for<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let owner_uid = owner.uid();
        self.ensure_owner_active(owner_uid)?;
        let result = self
            .events
            .register_accumulate(key, owner, scope, options, once, listener);
        self.finish_listener(owner_uid, key.name(), DispatchMode::Accumulate, result)
    }

    pub fn emit<P>(&mut self, key: EventKey<Emit, P, ()>, payload: &P) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        self.emit_for(key, payload, None)
    }

    fn emit_for<P>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        payload: &P,
        target: Option<&EventScope>,
    ) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .emit(key, payload, target)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Emit, error))
    }

    pub(crate) fn prepare_emit<P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: P,
    ) -> Result<PreparedEmit, CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .prepare_emit(key, payload, None)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Emit, error))
    }

    pub fn waterfall<P>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        self.waterfall_for(key, payload, None)
    }

    fn waterfall_for<P>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .waterfall(key, payload, target)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Waterfall, error))
    }

    pub fn try_waterfall<P>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .try_waterfall(key, payload, None)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Waterfall, error))
    }

    pub async fn parallel<P>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        payload: P,
    ) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .parallel(key, payload, None)
            .await
            .map(|_| ())
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Parallel, error))
    }

    pub async fn serial<P, R>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        payload: P,
    ) -> Result<BailOutcome<R>, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .serial(key, payload, None)
            .await
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Serial, error))
    }

    pub fn bail<P, R>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        payload: &P,
    ) -> Result<BailOutcome<R>, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .bail(key, payload, None)
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Bail, error))
    }

    pub async fn accumulate<P>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        self.events
            .accumulate(key, payload, None)
            .await
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Accumulate, error))
    }

    #[must_use]
    pub fn listener_count(&self, name: impl AsRef<str>) -> usize {
        self.events.listener_count(name.as_ref())
    }

    #[must_use]
    pub fn event_mode(&self, name: impl AsRef<str>) -> Option<DispatchMode> {
        self.events.mode(name.as_ref())
    }

    #[must_use]
    pub fn event_descriptor(&self, name: impl AsRef<str>) -> Option<EventDescriptor> {
        self.events.descriptor(name.as_ref())
    }

    /// Fail-closed source-compatible tombstone for the old mode-only lock.
    pub fn lock_event(&mut self, name: &str, _mode: DispatchMode) -> Result<(), CordisError> {
        self.ensure_owner_active(self.current_fiber)?;
        Err(CordisError::EventDescriptorRequired {
            name: name.to_string(),
        })
    }

    pub fn lock_event_key<M, P, Output>(
        &mut self,
        key: EventKey<M, P, Output>,
    ) -> Result<(), CordisError>
    where
        M: EventModeMarker,
        P: 'static,
        Output: 'static,
    {
        self.ensure_owner_active(self.current_fiber)?;
        let changed = self
            .events
            .lock_descriptor(key.name(), key.descriptor())
            .map_err(|error| into_cordis_error(key.name(), M::MODE, error))?;
        if changed {
            self.effects.push(Registration::event_lock(
                self.current_fiber,
                key.name().to_string(),
            ));
        }
        Ok(())
    }

    fn run_registration(&mut self, registration: Registration) {
        registration.dispose_callback();
        match registration {
            Registration::Disposer { .. } => {}
            Registration::Provider {
                namespace,
                key,
                provider_id,
                ..
            } => {
                let provider_key = ProviderKey::new(namespace.clone(), key.clone());
                let remove = self
                    .providers
                    .get(&provider_key)
                    .is_some_and(|record| record.provider_id.0 == provider_id);
                if remove {
                    self.providers.remove(&provider_key);
                    if namespace == "root" {
                        self.services.remove(&key);
                    }
                    self.reserved_services.remove(&key);
                }
            }
            Registration::Var { key, previous, .. } => {
                match &mut self.vars {
                    ConfigValue::Object(map) => match previous {
                        Some(value) => {
                            map.insert(key, value);
                        }
                        None => {
                            map.remove(&key);
                        }
                    },
                    other => match previous {
                        Some(value) => *other = value,
                        None => *other = ConfigValue::default(),
                    },
                }
                self.root.replace_metadata(self.vars.clone());
            }
            Registration::Listener { listener, .. } => {
                let _ = listener.dispose();
            }
            Registration::EventLock { name, .. } => {
                self.events.unlock(&name);
            }
        }
    }

    /// Run registrations newest-first, then drop remaining state. The root
    /// Context remains reusable and its root Fiber keeps uid zero.
    ///
    /// A listener that calls `teardown` through shared synchronization already
    /// owns an event-operation permit on its thread. Such a request is a
    /// fail-closed no-op: it does not close the current generation or wait for
    /// itself. An external caller may retry after the callback returns.
    pub fn teardown(&mut self) {
        let TeardownTransaction::Acquired(permit) = self.try_begin_teardown() else {
            return;
        };
        self.complete_teardown(permit);
    }

    /// Atomically acquire the exact reusable event generation before any
    /// caller mutates higher-layer teardown state.
    pub(crate) fn try_begin_teardown(&self) -> TeardownTransaction {
        // A callback cannot tear down the owner whose activation bookkeeping
        // is still on the stack. N1 models explicit async unload; N0 keeps this
        // synchronous request fail-closed.
        if self.activation_depth != 0 {
            return TeardownTransaction::Busy;
        }
        match self.event_gate.try_close_and_drain_reusable() {
            Some(generation) => TeardownTransaction::Acquired(TeardownPermit {
                context_id: self.id,
                gate: Arc::clone(&self.event_gate),
                generation,
            }),
            None => TeardownTransaction::Busy,
        }
    }

    /// Consume one exact closed generation, complete all structural cleanup,
    /// publish a fresh generation, and only then propagate a retained callback
    /// destructor panic. The permit never reopens itself on Drop or unwind.
    pub(crate) fn complete_teardown(&mut self, permit: TeardownPermit) {
        let TeardownPermit {
            context_id,
            gate,
            generation,
        } = permit;
        assert_eq!(
            context_id, self.id,
            "a teardown permit belongs to one exact Context"
        );
        assert!(
            Arc::ptr_eq(&gate, &self.event_gate),
            "a teardown permit belongs to one exact event gate"
        );
        let first_panic = self.teardown_closed();
        gate.reopen_after_completed_teardown(&generation);
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
    }

    /// Teardown body entered only while the current public event-capability
    /// generation is closed and every winning operation has drained.
    fn teardown_closed(&mut self) -> Option<Box<dyn Any + Send + 'static>> {
        let mut first_panic = None;
        while let Some(registration) = self.effects.pop() {
            let result = catch_unwind(AssertUnwindSafe(|| self.run_registration(registration)));
            if let Err(payload) = result
                && first_panic.is_none()
            {
                first_panic = Some(payload);
            }
        }
        self.services.clear();
        self.providers.clear();
        self.reserved_services.clear();
        self.vars = ConfigValue::default();
        if let Some(payload) = self.events.clear()
            && first_panic.is_none()
        {
            first_panic = Some(payload);
        }
        self.registry = Registry::new();
        self.mounted_factories.clear();
        self.activating_factories.clear();
        self.notifying_pending = false;
        self.activation_depth = 0;
        for fiber in self.fibers.values() {
            fiber.dispose();
        }
        self.fibers.clear();
        self.current_fiber = self.root.uid();
        self.root.replace_metadata(self.vars.clone());
        first_panic
    }
}

/// A mutable Context view carrying one Fiber owner and one service namespace.
///
/// Views intentionally do not expose the private Hartevo authority path or a
/// raw `&mut Context`.  `isolate` switches to a fresh namespace; a caller must
/// explicitly opt into another namespace with `share_label`.
///
/// This borrowed synchronous view owns the full N2 typed-event integration.
/// It remains distinct from the repeatable registry's owned
/// [`crate::LifecycleContextView`], whose N2B bridge intentionally exposes
/// lifecycle-owned typed Emit only.
pub struct ContextView<'a> {
    context: &'a mut Context,
    fiber: Fiber,
    namespace: String,
    shared_namespaces: Vec<String>,
    service_intercepts: Vec<ServiceIntercept>,
    metadata: ConfigValue,
    context_valid: bool,
    scope_valid: bool,
}

impl fmt::Debug for ContextView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextView")
            .field("fiber", &self.fiber)
            .field("namespace", &self.namespace)
            .field("shared_namespaces", &self.shared_namespaces)
            .field("service_intercepts", &self.service_intercepts)
            .finish_non_exhaustive()
    }
}

impl ContextView<'_> {
    #[must_use]
    pub fn fiber(&self) -> Fiber {
        self.fiber.clone()
    }

    #[must_use]
    pub fn fiber_uid(&self) -> FiberUid {
        self.fiber.uid()
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_active()
    }

    fn ownership_error(&self) -> CordisError {
        if !self.context_valid {
            CordisError::FiberContextMismatch {
                uid: self.fiber.uid(),
            }
        } else if !self.scope_valid {
            CordisError::FiberScopeViolation {
                current: self.context.current_fiber,
                requested: self.fiber.uid(),
            }
        } else {
            CordisError::FiberDisposed {
                uid: self.fiber.uid(),
            }
        }
    }

    fn is_active(&self) -> bool {
        self.context_valid
            && self.scope_valid
            && !self.fiber.is_disposed()
            && self.fiber.state() == FiberState::Active
    }

    /// Switch this view to a fresh namespace derived from its current one.
    /// Existing providers are not copied and no parent fallback is implicit.
    #[must_use]
    pub fn isolate(mut self, label: impl Into<String>) -> Self {
        let label = label.into();
        self.namespace = format!("{}::{label}", self.namespace);
        self.shared_namespaces.clear();
        self
    }

    /// Explicitly share a namespace label with this view.
    #[must_use]
    pub fn share_label(mut self, label: impl Into<String>) -> Self {
        self.shared_namespaces.push(label.into());
        self
    }

    /// Alias for callers that prefer the upstream terminology.
    #[must_use]
    pub fn shared_label(self, label: impl Into<String>) -> Self {
        self.share_label(label)
    }

    /// Append one service-config interception layer. Repeated declarations
    /// retain outer-to-inner call order.
    #[must_use]
    pub fn intercept(mut self, name: impl Into<String>, config: ConfigValue) -> Self {
        self.service_intercepts
            .push(ServiceIntercept::new(name.into(), config));
        self
    }

    fn lookup_namespaces(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.namespace.as_str())
            .chain(self.shared_namespaces.iter().map(String::as_str))
    }

    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        if !self.is_active() {
            return false;
        }
        self.lookup_namespaces()
            .any(|namespace| self.context.has_in_namespace(namespace, key))
    }

    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        if !self.is_active() {
            return None;
        }
        self.lookup_namespaces()
            .find_map(|namespace| self.context.get_in_namespace(namespace, key))
    }

    fn service_lookup(&self) -> Option<(ServiceLookup, ServiceCaller)> {
        if !self.is_active() {
            return None;
        }
        let scope = ServiceScope::new(
            self.context.id,
            self.fiber.uid(),
            self.namespace.clone(),
            self.shared_namespaces.clone(),
            self.metadata.clone(),
            None,
        );
        Some((
            ServiceLookup::new(scope.clone(), self.service_intercepts.clone()),
            ServiceCaller::new(scope),
        ))
    }

    /// Resolve a typed service while preserving this view's exact isolation,
    /// explicit shares, caller identity, and config interception order.
    #[must_use]
    pub fn service<T>(&self, key: &str) -> Option<ServiceHandle<'_, T>>
    where
        T: Any + Send + Sync,
    {
        let (lookup, caller) = self.service_lookup()?;
        self.context.service_from_lookup(lookup, caller, key)
    }

    #[must_use]
    pub fn association(&self, name: impl Into<String>) -> Option<ServiceAssociation<'_>> {
        let (lookup, caller) = self.service_lookup()?;
        Some(ServiceAssociation::new(
            self.context,
            name.into(),
            lookup,
            caller,
        ))
    }

    #[must_use]
    pub fn tools<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::TOOLS)
    }

    #[must_use]
    pub fn system_prompt<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::SYSTEM_PROMPT)
    }

    #[must_use]
    pub fn llm<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::LLM)
    }

    #[must_use]
    pub fn sessions<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::SESSIONS)
    }

    #[must_use]
    pub fn agents<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::AGENTS)
    }

    #[must_use]
    pub fn approval<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::APPROVAL)
    }

    #[must_use]
    pub fn domain<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::DOMAIN)
    }

    #[must_use]
    pub fn effect_broker<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::EFFECT_BROKER)
    }

    #[must_use]
    pub fn runtime<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::RUNTIME)
    }

    #[must_use]
    pub fn desktop<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::DESKTOP)
    }

    pub fn provide<T: Any + Send + Sync>(
        &mut self,
        key: impl Into<String>,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.provide_in_namespace(
            self.namespace.clone(),
            self.fiber.uid(),
            key.into(),
            value,
            ProviderOriginSnapshot::new(self.shared_namespaces.clone(), self.metadata.clone()),
        )
    }

    pub fn provide_service<T: Any + Send + Sync>(
        &mut self,
        key: impl Into<String>,
        value: T,
        options: ServiceOptions,
    ) -> Result<ProviderHandle, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.provide_service_in_namespace(
            self.namespace.clone(),
            self.fiber.uid(),
            key.into(),
            value,
            options,
            ProviderOriginSnapshot::new(self.shared_namespaces.clone(), self.metadata.clone()),
        )
    }

    pub fn provide_associated<T: Any + Send + Sync>(
        &mut self,
        association: &str,
        property: &str,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        self.provide(associated_key(association, property), value)
    }

    pub fn replace_provider<T: Any + Send + Sync>(
        &mut self,
        handle: &ProviderHandle,
        value: T,
    ) -> Result<ProviderHandle, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        if handle.namespace != self.namespace {
            return Err(CordisError::ProviderOwnerMismatch {
                key: handle.key.clone(),
            });
        }
        self.context
            .replace_provider_for(self.fiber.uid(), handle, value, false)
    }

    pub fn effect<F>(&mut self, dispose: F) -> RegistrationHandle
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.is_active() {
            return RegistrationHandle::noop();
        }
        self.context
            .with_current_fiber(self.fiber.uid(), |ctx| ctx.effect(dispose))
    }

    pub fn set_var(&mut self, key: impl Into<String>, value: impl Into<ConfigValue>) {
        if !self.is_active() {
            return;
        }
        let key = key.into();
        let value = value.into();
        match &mut self.metadata {
            ConfigValue::Object(map) => {
                map.insert(key, value);
            }
            other => *other = ConfigValue::object([(key, value)]),
        }
        self.fiber.replace_metadata(self.metadata.clone());
    }

    #[must_use]
    pub fn var(&self, key: &str) -> Option<&ConfigValue> {
        self.is_active()
            .then(|| self.metadata.lookup(key))
            .flatten()
    }

    #[must_use]
    pub fn plugin_interpolation_source(&self) -> Option<&ConfigValue> {
        self.is_active().then_some(&self.metadata)
    }

    /// Extend this view's private metadata without mutating its parent.
    #[must_use]
    pub fn extend(mut self, metadata: ConfigValue) -> Self {
        if !self.is_active() {
            return self;
        }
        if let ConfigValue::Object(extra) = metadata {
            match &mut self.metadata {
                ConfigValue::Object(current) => {
                    current.extend(extra);
                }
                current => {
                    *current = ConfigValue::Object(extra);
                }
            }
        }
        self.fiber.replace_metadata(self.metadata.clone());
        self
    }

    pub fn new_fiber(&mut self) -> Result<Fiber, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context
            .child_fiber_in_namespace(&self.fiber, self.namespace.clone())
    }

    pub fn mount_pending(&mut self, factory: PluginFactory) -> Result<PendingHandle, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context
            .mount_pending_in_namespace(factory, &self.fiber, self.namespace.clone())
    }

    fn event_scope(&self) -> EventScope {
        EventScope::new(self.namespace.clone(), &self.shared_namespaces)
    }

    /// Capture this view's exact owner and isolation labels for safe callback
    /// registration and recursive typed-Emit dispatch.
    pub fn event_reentry(&self) -> Result<EventReentry, CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        let generation = self.context.event_gate.current_generation().ok_or(
            CordisError::FiberContextMismatch {
                uid: self.fiber.uid(),
            },
        )?;
        Ok(EventReentry::new(
            self.context.id,
            Arc::clone(&self.context.event_gate),
            generation,
            self.context.events.clone(),
            self.fiber.clone(),
            scope.clone(),
            Some(scope),
        ))
    }

    pub fn on<F>(
        &mut self,
        key: EventKey<Emit, (), ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.on_emit(key, move |(): &()| listener())
    }

    pub fn on_emit<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.on_emit_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_emit_with_options<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_emit_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_emit_with_options<P, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_emit_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn try_on_emit<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        self.try_on_emit_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_emit_with_options<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_emit_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn try_once_emit_with_options<P, E, F>(
        &mut self,
        key: EventKey<Emit, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_emit_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn on_waterfall<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        self.on_waterfall_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_waterfall_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_waterfall_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn try_on_waterfall<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        self.try_on_waterfall_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_waterfall_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn try_once_waterfall_with_options<P, F>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_waterfall_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn on_parallel<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        self.on_parallel_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_parallel_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_parallel_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_parallel_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_parallel_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn on_serial<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        self.on_serial_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_serial_with_options<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_serial_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_serial_with_options<P, R, E, Fut, F>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_serial_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn on_bail<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        self.on_bail_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_bail_with_options<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_bail_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_bail_with_options<P, R, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_bail_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn try_on_bail<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        self.try_on_bail_with_options(key, EventOptions::default(), listener)
    }

    pub fn try_on_bail_with_options<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_bail_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn try_once_bail_with_options<P, R, E, F>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_try_bail_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn on_accumulate<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        self.on_accumulate_with_options(key, EventOptions::default(), listener)
    }

    pub fn on_accumulate_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_accumulate_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            false,
            listener,
        )
    }

    pub fn once_accumulate_with_options<P, E, Fut, F>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        options: EventOptions,
        listener: F,
    ) -> Result<ListenerHandle, CordisError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        self.context.register_accumulate_for(
            key,
            self.fiber.clone(),
            self.event_scope(),
            options,
            true,
            listener,
        )
    }

    pub fn emit<P>(&mut self, key: EventKey<Emit, P, ()>, payload: &P) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context.emit_for(key, payload, Some(&scope))
    }

    pub fn lock_event(&mut self, name: &str, _mode: DispatchMode) -> Result<(), CordisError> {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        Err(CordisError::EventDescriptorRequired {
            name: name.to_string(),
        })
    }

    pub fn lock_event_key<M, P, Output>(
        &mut self,
        key: EventKey<M, P, Output>,
    ) -> Result<(), CordisError>
    where
        M: EventModeMarker,
        P: 'static,
        Output: 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let changed = self
            .context
            .events
            .lock_descriptor(key.name(), key.descriptor())
            .map_err(|error| into_cordis_error(key.name(), M::MODE, error))?;
        if changed {
            self.context.effects.push(Registration::event_lock(
                self.fiber.uid(),
                key.name().to_string(),
            ));
        }
        Ok(())
    }

    pub fn waterfall<P>(
        &mut self,
        key: EventKey<Waterfall, P, P>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context.waterfall_for(key, payload, Some(&scope))
    }

    pub fn try_waterfall<P>(
        &mut self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context
            .events
            .try_waterfall(key, payload, Some(&scope))
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Waterfall, error))
    }

    pub async fn parallel<P>(
        &mut self,
        key: EventKey<Parallel, P, ()>,
        payload: P,
    ) -> Result<(), CordisError>
    where
        P: Any + Send + Sync + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context
            .events
            .parallel(key, payload, Some(&scope))
            .await
            .map(|_| ())
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Parallel, error))
    }

    pub async fn serial<P, R>(
        &mut self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        payload: P,
    ) -> Result<BailOutcome<R>, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context
            .events
            .serial(key, payload, Some(&scope))
            .await
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Serial, error))
    }

    pub fn bail<P, R>(
        &mut self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        payload: &P,
    ) -> Result<BailOutcome<R>, CordisError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context
            .events
            .bail(key, payload, Some(&scope))
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Bail, error))
    }

    pub async fn accumulate<P>(
        &mut self,
        key: EventKey<Accumulate, P, P>,
        payload: P,
    ) -> Result<P, CordisError>
    where
        P: Any + Send + 'static,
    {
        if !self.is_active() {
            return Err(self.ownership_error());
        }
        let scope = self.event_scope();
        self.context
            .events
            .accumulate(key, payload, Some(&scope))
            .await
            .map_err(|error| into_cordis_error(key.name(), DispatchMode::Accumulate, error))
    }
}

fn authority_reserved_key(key: &str) -> bool {
    matches!(
        key,
        keys::DOMAIN | keys::EFFECT_BROKER | keys::RUNTIME | keys::DESKTOP
    )
}

fn panic_payload_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod provider_tests {
    use super::*;
    use crate::surface::{DomainSurface, HartevoSurfaces, map_surfaces, rebind_hartevo_domain};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn ordinary_duplicate_is_rejected_before_mutation() {
        let mut context = Context::new();
        let handle = context.provide("ordinary", 7_u32).unwrap();
        let before = context.provider_snapshot("ordinary").unwrap();
        assert_eq!(handle.generation(), 0);
        assert_eq!(
            context.provide("ordinary", 9_u32).unwrap_err(),
            CordisError::DuplicateProvider {
                namespace: "root".to_string(),
                key: "ordinary".to_string(),
            }
        );
        assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&7));
        assert_eq!(context.provider_snapshot("ordinary").unwrap(), before);
    }

    #[test]
    fn owner_and_stale_handles_cannot_change_provider() {
        let mut context = Context::new();
        let handle = context.provide("ordinary", 7_u32).unwrap();
        let child = context.new_fiber().unwrap();
        let before = context.provider_snapshot("ordinary").unwrap();
        {
            let mut view = context.with_fiber(&child);
            assert_eq!(
                view.replace_provider(&handle, 8_u32).unwrap_err(),
                CordisError::ProviderOwnerMismatch {
                    key: "ordinary".to_string()
                }
            );
        }
        assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&7));
        assert_eq!(context.provider_snapshot("ordinary").unwrap(), before);

        let current = context.replace_provider(&handle, 8_u32).unwrap();
        assert_eq!(current.generation(), 1);
        assert_eq!(
            context.replace_provider(&handle, 9_u32).unwrap_err(),
            CordisError::StaleProviderHandle {
                key: "ordinary".to_string()
            }
        );
        assert_eq!(context.get::<u32>("ordinary").as_deref(), Some(&8));
    }

    #[test]
    fn reserved_handles_are_rejected_without_mutation() {
        let mut context = Context::new();
        map_surfaces(&mut context, HartevoSurfaces::default()).unwrap();
        let before_domain = context.provider_snapshot(keys::DOMAIN).unwrap();
        let before_broker = context.provider_snapshot(keys::EFFECT_BROKER).unwrap();
        let domain = context
            .providers
            .get(&ProviderKey::new("root", keys::DOMAIN))
            .map(|record| ProviderHandle {
                context_id: context.id,
                namespace: "root".to_string(),
                key: keys::DOMAIN.to_string(),
                provider_id: record.provider_id,
                owner_uid: record.owner_uid,
                generation: record.generation,
            })
            .expect("domain provider");
        let broker = context
            .providers
            .get(&ProviderKey::new("root", keys::EFFECT_BROKER))
            .map(|record| ProviderHandle {
                context_id: context.id,
                namespace: "root".to_string(),
                key: keys::EFFECT_BROKER.to_string(),
                provider_id: record.provider_id,
                owner_uid: record.owner_uid,
                generation: record.generation,
            })
            .expect("broker provider");
        for handle in [&domain, &broker] {
            assert!(matches!(
                context.replace_provider(handle, "forged"),
                Err(CordisError::ReservedServiceKey { .. })
            ));
        }
        assert_eq!(
            context.provider_snapshot(keys::DOMAIN).unwrap(),
            before_domain
        );
        assert_eq!(
            context.provider_snapshot(keys::EFFECT_BROKER).unwrap(),
            before_broker
        );
    }

    #[test]
    fn reserved_rebind_does_not_expose_committed_handle_on_notification_error() {
        let mut context = Context::new();
        map_surfaces(&mut context, HartevoSurfaces::default()).unwrap();

        let fiber = Fiber::child_with_namespace(context.id, &context.root, "root".to_string());
        context.fibers.insert(fiber.uid(), fiber.clone());
        context.registry.push(PendingEntry {
            factory: PluginFactory::new("reserved-rebind-failure", |_config, _ctx| {
                Err::<(), _>(CordisError::MissingDependencies(vec![
                    "failure".to_string(),
                ]))
            }),
            fiber,
            namespace: "root".to_string(),
            inject: Vec::new(),
            config: ConfigValue::default(),
        });

        let error = rebind_hartevo_domain(&mut context, DomainSurface::default()).unwrap_err();
        assert!(matches!(
            error,
            CordisError::ReservedProviderNotification {
                ref key,
                generation: 1,
                source: _,
            } if key == keys::DOMAIN
        ));
        if let CordisError::ReservedProviderNotification { source, .. } = error {
            assert!(matches!(*source, CordisError::PluginActivation { .. }));
        }
        let snapshot = context.provider_snapshot(keys::DOMAIN).unwrap();
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.notify_count, 1);
    }

    #[test]
    fn fibers_are_monotonic_isolated_and_dispose_owned_records_once() {
        let mut context = Context::new();
        let root = context.root_fiber();
        assert_eq!(root.uid(), FiberUid::ROOT);
        context.set_var("scope", "parent");
        let parent_disposals = Arc::new(AtomicUsize::new(0));
        let parent_disposals_for_effect = Arc::clone(&parent_disposals);
        let parent_handle = context.effect(move || {
            parent_disposals_for_effect.fetch_add(1, Ordering::SeqCst);
        });

        let child = context.new_fiber().unwrap();
        let grandchild = context.child_fiber(&child).unwrap();
        assert!(child.uid() > root.uid());
        assert!(grandchild.uid() > child.uid());
        assert_eq!(child.parent_uid(), Some(root.uid()));
        assert_eq!(grandchild.parent_uid(), Some(child.uid()));

        let child_disposals = Arc::new(AtomicUsize::new(0));
        let child_disposals_for_effect = Arc::clone(&child_disposals);
        {
            let mut view = context.with_fiber(&child).isolate("tenant");
            assert_eq!(view.var("scope"), Some(&ConfigValue::string("parent")));
            view.set_var("scope", "child");
            view.provide("child-only", 42_u32).unwrap();
            view.effect(move || {
                child_disposals_for_effect.fetch_add(1, Ordering::SeqCst);
            });
            assert!(view.has("child-only"));
        }
        assert_eq!(context.var("scope"), Some(ConfigValue::string("parent")));
        assert!(context.get::<u32>("child-only").is_none());
        assert_eq!(
            child.metadata_snapshot().lookup("scope"),
            Some(&ConfigValue::string("child"))
        );

        assert!(context.dispose_fiber(&child).unwrap());
        assert!(!context.dispose_fiber(&child).unwrap());
        assert_eq!(child_disposals.load(Ordering::SeqCst), 1);
        assert!(context.get::<u32>("child-only").is_none());
        assert!(!parent_handle.is_disposed());
        assert_eq!(parent_disposals.load(Ordering::SeqCst), 0);
        context.teardown();
        assert_eq!(parent_disposals.load(Ordering::SeqCst), 1);
        assert!(parent_handle.is_disposed());
        assert_eq!(child.state(), FiberState::Active);
        assert_eq!(grandchild.state(), FiberState::Active);
        assert!(child.is_disposed());
        assert!(grandchild.is_disposed());
    }

    #[test]
    fn current_fiber_owner_is_restored_when_callback_unwinds() {
        let mut context = Context::new();
        let child = context.new_fiber().unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            context.with_current_fiber(child.uid(), |_context| -> () {
                panic!("intentional owner unwind");
            });
        }));
        assert!(panic.is_err());
        assert_eq!(context.current_fiber_uid(), FiberUid::ROOT);
        assert!(context.provide("after-unwind", true).is_ok());
    }

    #[test]
    fn disposed_current_fiber_cannot_fall_back_to_root_namespace() {
        let mut context = Context::new();
        context.provide("root-only", 1_u32).unwrap();
        let child = context.new_fiber().unwrap();
        context.with_current_fiber(child.uid(), |context| {
            assert_eq!(context.get::<u32>("root-only").as_deref(), Some(&1));
            assert!(context.dispose_fiber(&child).unwrap());
            assert!(!context.has("root-only"));
            assert!(context.get::<u32>("root-only").is_none());
            assert_eq!(
                context.provide("must-not-escape", true).unwrap_err(),
                CordisError::FiberDisposed { uid: child.uid() }
            );
        });
        assert!(context.get::<bool>("must-not-escape").is_none());
    }

    #[test]
    fn registration_handles_are_idempotent_and_reentrant() {
        let mut context = Context::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let first = context.effect(move || {
            first_calls.fetch_add(1, Ordering::SeqCst);
        });
        let first_for_second = first.clone();
        let second_calls = Arc::clone(&calls);
        let second = context.effect(move || {
            assert!(first_for_second.dispose());
            second_calls.fetch_add(1, Ordering::SeqCst);
        });
        context.teardown();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(first.is_disposed());
        assert!(second.is_disposed());
        assert!(!first.dispose());
        assert!(!second.dispose());
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.event_gate.close_and_drain_for_drop();
        if let Some(payload) = self.teardown_closed() {
            resume_unwind(payload);
        }
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut services: Vec<&String> = self.services.keys().collect();
        services.sort();
        let mut listener_events = self.events.event_names();
        listener_events.sort();
        f.debug_struct("Context")
            .field("services", &services)
            .field("vars", &self.vars)
            .field("effects", &self.effects.len())
            .field("listeners", &listener_events)
            .field("next_listener_id", &self.events.next_id())
            .finish_non_exhaustive()
    }
}
