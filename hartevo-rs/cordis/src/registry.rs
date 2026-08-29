//! Pending-plugin storage plus the asynchronous N1 lifecycle runtime.

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use futures_util::future::{BoxFuture, FutureExt, Shared, join_all};
use futures_util::stream::StreamExt;
use tokio::runtime::{Handle as TokioHandle, Id as TokioRuntimeId};
use tokio::sync::{Notify, mpsc, oneshot, watch};

use crate::config::ConfigValue;
use crate::context::CordisError;
use crate::effect::{LifecycleDisposer, LifecycleEffect};
use crate::fiber::{
    ActivationEpoch, Fiber, FiberFuture, FiberLifecycle, FiberSnapshot, FiberState, FiberUid,
    LifecycleCancellation, ProviderFingerprint, TransitionTicket,
};
use crate::loader::{PluginFactory, PluginFactoryId, PluginId};

type SharedUnitOperation = Shared<BoxFuture<'static, Result<(), CordisError>>>;
type FiberTicketWait = (Arc<FiberControl>, u64);
type FiberPublication = (Arc<FiberControl>, FiberSnapshot);

struct FiberTicketBatch {
    waits: Vec<FiberTicketWait>,
    publications: Vec<FiberPublication>,
    notifications: Vec<Arc<FiberControl>>,
}

#[derive(Clone)]
struct DriverRuntimeBinding {
    state: Arc<DriverRuntimeState>,
}

struct DriverRuntimeState {
    id: TokioRuntimeId,
    alive: AtomicBool,
    handle: TokioHandle,
    death: watch::Sender<bool>,
}

impl DriverRuntimeBinding {
    fn new(handle: &TokioHandle) -> Self {
        let (death, _) = watch::channel(true);
        let state = Arc::new(DriverRuntimeState {
            id: handle.id(),
            alive: AtomicBool::new(true),
            handle: handle.clone(),
            death,
        });
        let sentinel = DriverRuntimeSentinel(state.clone());
        drop(handle.spawn(async move {
            let _sentinel = sentinel;
            std::future::pending::<()>().await;
        }));
        Self { state }
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    fn require_current(&self) -> Result<(), CordisError> {
        let current = current_async_runtime()?;
        self.require_handle(&current)
    }

    fn require_handle(&self, current: &TokioHandle) -> Result<(), CordisError> {
        if self.state.alive.load(Ordering::Acquire) && current.id() == self.state.id {
            Ok(())
        } else {
            Err(CordisError::AsyncRuntimeUnavailable)
        }
    }

    fn require_alive(&self) -> Result<(), CordisError> {
        self.state
            .alive
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(CordisError::AsyncRuntimeUnavailable)
    }

    fn death_receiver(&self) -> watch::Receiver<bool> {
        self.state.death.subscribe()
    }

    fn drive(&self, operation: SharedUnitOperation) {
        drop(self.state.handle.spawn(async move {
            let _ = operation.await;
        }));
    }
}

struct DriverRuntimeSentinel(Arc<DriverRuntimeState>);

impl Drop for DriverRuntimeSentinel {
    fn drop(&mut self) {
        self.0.alive.store(false, Ordering::Release);
        self.0.death.send_replace(false);
    }
}

struct RegistrySupervisor {
    sender: mpsc::UnboundedSender<SupervisorCommand>,
}

struct SupervisorReservation {
    operation: oneshot::Sender<SharedUnitOperation>,
}

struct SupervisorCommand {
    operation: oneshot::Receiver<SharedUnitOperation>,
    accepted: std::sync::mpsc::SyncSender<()>,
}

impl RegistrySupervisor {
    fn start() -> Result<Self, CordisError> {
        let (sender, mut receiver) = mpsc::unbounded_channel::<SupervisorCommand>();
        let (started, ready) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("cordis-lifecycle-supervisor".to_string())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = started.send(false);
                    return;
                };
                let _ = started.send(true);
                runtime.block_on(async move {
                    while let Some(command) = receiver.recv().await {
                        tokio::spawn(async move {
                            let SupervisorCommand {
                                operation,
                                accepted,
                            } = command;
                            let _ = accepted.send(());
                            if let Ok(operation) = operation.await {
                                let _ = operation.await;
                            }
                        });
                    }
                });
            })
            .map_err(|_| CordisError::AsyncRuntimeUnavailable)?;
        if ready.recv().ok() != Some(true) {
            return Err(CordisError::AsyncRuntimeUnavailable);
        }
        Ok(Self { sender })
    }

    fn reserve(&self) -> Result<SupervisorReservation, CordisError> {
        let (operation, receiver) = oneshot::channel();
        let (accepted, ready) = std::sync::mpsc::sync_channel(1);
        self.sender
            .send(SupervisorCommand {
                operation: receiver,
                accepted,
            })
            .map_err(|_| CordisError::AsyncRuntimeUnavailable)?;
        ready
            .recv()
            .map_err(|_| CordisError::AsyncRuntimeUnavailable)?;
        Ok(SupervisorReservation { operation })
    }
}

impl SupervisorReservation {
    fn submit(self, operation: SharedUnitOperation) -> SharedUnitOperation {
        // `reserve` does not return until the supervisor task owns the
        // receiver. That task cannot finish before this sender is either
        // dropped or used, so submission after the registry transaction has
        // no fallible boundary. Keep the operation as an emergency driver if
        // the supervisor thread is lost outside that invariant.
        let driver = operation.clone();
        match self.operation.send(operation) {
            Ok(()) => driver,
            Err(operation) => operation,
        }
    }
}

pub(crate) type PendingId = u64;

pub(crate) struct PendingEntry {
    pub factory: PluginFactory,
    pub fiber: Fiber,
    pub namespace: String,
    pub inject: Vec<String>,
    pub config: crate::config::ConfigValue,
}

/// Context-local pending registry.  Context is synchronous and owns the
/// registry directly, so there is no mutex for callbacks to accidentally hold.
#[derive(Default)]
pub(crate) struct Registry {
    next_id: PendingId,
    pending: Vec<PendingEntry>,
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            pending: Vec::new(),
        }
    }

    pub(crate) fn contains_factory(&self, factory_id: crate::loader::PluginFactoryId) -> bool {
        self.pending
            .iter()
            .any(|entry| !entry.fiber.is_disposed() && entry.factory.id() == factory_id)
    }

    pub(crate) fn allocate_id(&mut self) -> PendingId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    pub(crate) fn push(&mut self, entry: PendingEntry) {
        self.pending.push(entry);
    }

    pub(crate) fn take_pending(&mut self) -> Vec<PendingEntry> {
        std::mem::take(&mut self.pending)
    }

    pub(crate) fn replace_pending(&mut self, pending: Vec<PendingEntry>) {
        self.pending = pending;
    }

    pub(crate) fn remove_fiber(&mut self, uid: FiberUid) {
        self.pending.retain(|entry| entry.fiber.uid() != uid);
    }

    pub(crate) fn len(&self) -> usize {
        self.pending
            .iter()
            .filter(|entry| !entry.fiber.is_disposed())
            .count()
    }
}

static NEXT_LIFECYCLE_REGISTRY_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuntimeProviderKey {
    namespace: String,
    key: String,
}

impl RuntimeProviderKey {
    fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
        }
    }
}

type ProviderValue = Arc<dyn Any + Send + Sync>;
/// Provider guards participate in optimistic exact revalidation and may run
/// more than once. Implementations must therefore be repeatable and free of
/// externally visible side effects.
type ProviderGuard = Arc<dyn Fn(&ProviderValue) -> Result<bool, CordisError> + Send + Sync>;

#[derive(Clone)]
enum RuntimeProviderOwner {
    Root,
    Managed {
        control: Weak<FiberControl>,
        runtime_generation: u64,
    },
}

#[derive(Clone)]
struct RuntimeProviderRecord {
    value: ProviderValue,
    provider_id: u64,
    owner: Fiber,
    owner_binding: RuntimeProviderOwner,
    generation: u64,
    removing: bool,
    guard: Option<ProviderGuard>,
}

/// One linearizable fact source for a provider key.  Slots survive absence so
/// remove/reprovide cannot let an old completion compare-remove a replacement.
/// Fresh ordinary registrations deliberately start at generation zero; slot
/// revision/removal serial, not generation, provide the ABA fence.
struct RuntimeProviderSlot {
    record: Option<RuntimeProviderRecord>,
    revision: u64,
    removal_serial: u64,
}

struct ProviderRemovalPlan {
    removal_serial: u64,
    marked_revision: u64,
    completed_revision: u64,
    batch: FiberTicketBatch,
    drivers: Vec<DriverRuntimeBinding>,
}

#[derive(Clone)]
enum ProviderRemovalMode {
    Strict,
    OwnerTeardown {
        driver_runtime: DriverRuntimeBinding,
    },
}

#[derive(Clone)]
struct ProviderRecordFact {
    value: ProviderValue,
    provider_id: u64,
    owner_uid: FiberUid,
    owner_binding: RuntimeProviderOwner,
    generation: u64,
    removing: bool,
    guard: Option<ProviderGuard>,
}

#[derive(Clone)]
struct ProviderSlotFact {
    revision: u64,
    removal_serial: u64,
    record: Option<ProviderRecordFact>,
}

#[derive(Clone)]
enum ProviderMutationRequest {
    Provide {
        owner: Fiber,
        key: RuntimeProviderKey,
        value: ProviderValue,
        guard: Option<ProviderGuard>,
    },
    Replace {
        handle: LifecycleProviderHandle,
        value: ProviderValue,
    },
}

struct ProviderMutationPlan {
    key: RuntimeProviderKey,
    expected_slot: Option<ProviderSlotFact>,
    expected_next_provider_id: Option<u64>,
    next_provider_id: Option<u64>,
    revision: u64,
    removal_serial: u64,
    record: RuntimeProviderRecord,
    handle: LifecycleProviderHandle,
}

struct ProviderControlDraft {
    control: Arc<FiberControl>,
    config_revision: u64,
    tombstone: bool,
    observations: Option<Vec<ProviderObservation>>,
}

struct ProviderControlOutcome {
    draft: ProviderControlDraft,
    desired: Option<ActivationEpoch>,
    diagnostic: Option<CordisError>,
}

impl RuntimeProviderSlot {
    fn vacant() -> Self {
        Self {
            record: None,
            revision: 0,
            removal_serial: 0,
        }
    }
}

#[derive(Clone)]
struct ProviderObservation {
    key: RuntimeProviderKey,
    value: ProviderValue,
    guard: Option<ProviderGuard>,
    provider_id: u64,
    owner_uid: FiberUid,
    owner: ProviderObservationOwner,
    generation: u64,
    revision: u64,
    removal_serial: u64,
}

#[derive(Clone)]
enum ProviderObservationOwner {
    Root,
    Managed {
        control: Arc<FiberControl>,
        runtime_generation: u64,
        activation_owner: bool,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct LifecycleProviderHandle {
    registry_id: u64,
    namespace: String,
    key: String,
    provider_id: u64,
    owner_uid: FiberUid,
    generation: u64,
}

impl LifecycleProviderHandle {
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub const fn provider_id(&self) -> u64 {
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
}

impl fmt::Debug for LifecycleProviderHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleProviderHandle")
            .field("registry_id", &self.registry_id)
            .field("namespace", &self.namespace)
            .field("key", &self.key)
            .field("provider_id", &self.provider_id)
            .field("owner_uid", &self.owner_uid)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeStatus {
    Open,
    Deleting,
}

struct FactoryRuntime {
    generation: u64,
    factory: PluginFactory,
    status: RuntimeStatus,
    fibers: HashMap<FiberUid, Arc<FiberControl>>,
}

struct LifecycleRegistryState {
    next_runtime_generation: u64,
    next_provider_id: u64,
    runtimes: HashMap<PluginFactoryId, FactoryRuntime>,
    catalog: HashMap<PluginId, PluginFactoryId>,
    providers: HashMap<RuntimeProviderKey, RuntimeProviderSlot>,
    shutting_down: bool,
}

struct LifecycleRegistryInner {
    id: u64,
    root: Fiber,
    state: Mutex<LifecycleRegistryState>,
    driver_bindings: Mutex<HashMap<TokioRuntimeId, Weak<DriverRuntimeState>>>,
    supervisor: Mutex<Option<RegistrySupervisor>>,
    shutdown_operation: Mutex<Option<SharedUnitOperation>>,
    #[cfg(test)]
    supervisor_reservation_failures: AtomicU64,
}

/// Cloneable asynchronous Cordis runtime.
///
/// All user callbacks, guards, streams, and disposers run after the registry
/// and Fiber state locks have been released.
#[derive(Clone)]
pub struct LifecycleRegistry {
    inner: Arc<LifecycleRegistryInner>,
}

/// Unforgeable mutation capability for one child Fiber.
///
/// The permit is bound to the issuing parent uid, factory runtime generation,
/// and child uid. A bare [`Fiber`] is read-only and cannot mutate a sibling,
/// ancestor, or the root runtime.
#[derive(Clone)]
pub struct LifecycleHandle {
    registry: Weak<LifecycleRegistryInner>,
    factory_id: PluginFactoryId,
    runtime_generation: u64,
    driver_runtime: DriverRuntimeBinding,
    caller_uid: FiberUid,
    fiber: Fiber,
}

impl fmt::Debug for LifecycleHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleHandle")
            .field("factory_id", &self.factory_id)
            .field("runtime_generation", &self.runtime_generation)
            .field("caller_uid", &self.caller_uid)
            .field("fiber", &self.fiber)
            .finish_non_exhaustive()
    }
}

impl LifecycleHandle {
    #[must_use]
    pub fn fiber(&self) -> Fiber {
        self.fiber.clone()
    }

    #[must_use]
    pub fn snapshot(&self) -> FiberSnapshot {
        self.fiber.snapshot()
    }

    pub async fn await_current(&self) -> Result<FiberSnapshot, CordisError> {
        self.fiber.await_current().await
    }

    pub async fn restart(&self) -> Result<FiberSnapshot, CordisError> {
        self.driver_runtime.require_current()?;
        self.control()?.restart_and_wait().await
    }

    pub async fn update(&self, config: ConfigValue) -> Result<FiberSnapshot, CordisError> {
        self.driver_runtime.require_current()?;
        self.control()?.update_and_wait(config).await
    }

    pub async fn dispose_async(&self) -> Result<FiberSnapshot, CordisError> {
        self.driver_runtime.require_current()?;
        self.control()?.dispose_and_wait().await
    }

    fn control(&self) -> Result<Arc<FiberControl>, CordisError> {
        let Some(registry) = self.registry.upgrade() else {
            return Err(CordisError::FiberRuntimeUnavailable {
                uid: self.fiber.uid(),
            });
        };
        let state = lock(&registry.state);
        let Some(runtime) = state.runtimes.get(&self.factory_id) else {
            return Err(CordisError::FiberDisposed {
                uid: self.fiber.uid(),
            });
        };
        if runtime.generation != self.runtime_generation {
            return Err(CordisError::FiberDisposed {
                uid: self.fiber.uid(),
            });
        }
        let Some(control) = runtime.fibers.get(&self.fiber.uid()) else {
            return Err(CordisError::FiberDisposed {
                uid: self.fiber.uid(),
            });
        };
        if control.parent_uid != self.caller_uid {
            return Err(CordisError::FiberScopeViolation {
                current: self.caller_uid,
                requested: self.fiber.uid(),
            });
        }
        Ok(control.clone())
    }
}

impl fmt::Debug for LifecycleRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.inner.state);
        formatter
            .debug_struct("LifecycleRegistry")
            .field("id", &self.inner.id)
            .field("runtimes", &state.runtimes.len())
            .field("providers", &state.providers.len())
            .field("shutting_down", &state.shutting_down)
            .finish()
    }
}

impl Default for LifecycleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleRegistry {
    #[must_use]
    pub fn new() -> Self {
        let id = NEXT_LIFECYCLE_REGISTRY_ID.fetch_add(1, Ordering::Relaxed);
        let root = Fiber::root(id);
        Self {
            inner: Arc::new(LifecycleRegistryInner {
                id,
                root,
                state: Mutex::new(LifecycleRegistryState {
                    next_runtime_generation: 1,
                    next_provider_id: 1,
                    runtimes: HashMap::new(),
                    catalog: HashMap::new(),
                    providers: HashMap::new(),
                    shutting_down: false,
                }),
                driver_bindings: Mutex::new(HashMap::new()),
                supervisor: Mutex::new(None),
                shutdown_operation: Mutex::new(None),
                #[cfg(test)]
                supervisor_reservation_failures: AtomicU64::new(0),
            }),
        }
    }

    #[must_use]
    pub fn root_fiber(&self) -> Fiber {
        self.inner.root.clone()
    }

    #[must_use]
    pub fn runtime_count(&self) -> usize {
        lock(&self.inner.state).runtimes.len()
    }

    fn driver_binding(&self, handle: &TokioHandle) -> DriverRuntimeBinding {
        let id = handle.id();
        let mut bindings = lock(&self.inner.driver_bindings);
        bindings.retain(|_, binding| {
            binding
                .upgrade()
                .is_some_and(|state| state.alive.load(Ordering::Acquire))
        });
        if let Some(state) = bindings.get(&id).and_then(Weak::upgrade)
            && state.alive.load(Ordering::Acquire)
        {
            return DriverRuntimeBinding { state };
        }
        let binding = DriverRuntimeBinding::new(handle);
        bindings.insert(id, Arc::downgrade(&binding.state));
        binding
    }

    fn ensure_supervisor(&self) -> Result<SupervisorReservation, CordisError> {
        #[cfg(test)]
        if self
            .inner
            .supervisor_reservation_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(CordisError::AsyncRuntimeUnavailable);
        }
        let mut supervisor = lock(&self.inner.supervisor);
        if supervisor
            .as_ref()
            .is_some_and(|supervisor| supervisor.sender.is_closed())
        {
            *supervisor = None;
        }
        if supervisor.is_none() {
            *supervisor = Some(RegistrySupervisor::start()?);
        }
        supervisor
            .as_ref()
            .ok_or(CordisError::AsyncRuntimeUnavailable)?
            .reserve()
    }

    fn fence_owner_provider_without_supervisor(&self, handle: &LifecycleProviderHandle) {
        let mut state = lock(&self.inner.state);
        let key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
        let Some(slot) = state.providers.get(&key) else {
            return;
        };
        let exact = slot.record.as_ref().is_some_and(|record| {
            record.provider_id == handle.provider_id
                && record.owner.uid() == handle.owner_uid
                && record.generation == handle.generation
        });
        if !exact {
            return;
        }
        let next_revision = slot.revision.checked_add(2);
        let next_removal = slot.removal_serial.checked_add(1);
        if let (Some(revision), Some(removal_serial)) = (next_revision, next_removal) {
            if let Some(slot) = state.providers.get_mut(&key) {
                // Exact provider identity plus the slot counters fence this
                // synchronous owner-teardown fallback from any delayed older
                // completion. Consumers are intentionally left untouched:
                // without a reserved supervisor there is no durable waiter,
                // while a later provide/reconcile can safely recover them.
                slot.revision = revision;
                slot.removal_serial = removal_serial;
                slot.record = None;
            }
        } else {
            // Global provider ids never repeat, so dropping an exhausted exact
            // slot cannot let an old completion delete a later replacement.
            state.providers.remove(&key);
        }
    }

    pub fn mount(
        &self,
        factory: PluginFactory,
        config: ConfigValue,
    ) -> Result<LifecycleHandle, CordisError> {
        self.mount_in(&self.inner.root, factory, config)
    }

    fn mount_in(
        &self,
        parent: &Fiber,
        factory: PluginFactory,
        config: ConfigValue,
    ) -> Result<LifecycleHandle, CordisError> {
        let driver_handle = current_async_runtime()?;
        if !factory.supports_lifecycle() {
            return Err(CordisError::LifecycleFactoryRequired {
                id: factory.plugin_id().clone(),
            });
        }
        if parent.context_id() != self.inner.id {
            return Err(CordisError::FiberContextMismatch { uid: parent.uid() });
        }
        if parent.is_disposed() || parent.state() != FiberState::Active {
            return Err(CordisError::FiberDisposed { uid: parent.uid() });
        }
        let factory_id = factory.id();
        let plugin_id = factory.plugin_id().clone();

        let (runtime_generation, fiber) = {
            let mut state = lock(&self.inner.state);
            if state.shutting_down {
                return Err(CordisError::RuntimeDeleting {
                    id: factory.plugin_id().clone(),
                });
            }
            if let Some(bound) = state.catalog.get(factory.plugin_id())
                && *bound != factory.id()
            {
                return Err(CordisError::PluginCatalogConflict {
                    id: factory.plugin_id().clone(),
                });
            }
            let runtime_generation = match state.runtimes.get(&factory.id()) {
                Some(runtime) if runtime.status == RuntimeStatus::Deleting => {
                    return Err(CordisError::RuntimeDeleting {
                        id: factory.plugin_id().clone(),
                    });
                }
                Some(runtime) => runtime.generation,
                None => {
                    let generation = state.next_runtime_generation;
                    state.next_runtime_generation = state
                        .next_runtime_generation
                        .checked_add(1)
                        .ok_or(CordisError::RuntimeGenerationOverflow)?;
                    state
                        .catalog
                        .insert(factory.plugin_id().clone(), factory.id());
                    state.runtimes.insert(
                        factory.id(),
                        FactoryRuntime {
                            generation,
                            factory: factory.clone(),
                            status: RuntimeStatus::Open,
                            fibers: HashMap::new(),
                        },
                    );
                    generation
                }
            };
            let fiber = Fiber::child_with_namespace(self.inner.id, parent, parent.namespace());
            (runtime_generation, fiber)
        };

        let control = FiberControl::new(
            Arc::downgrade(&self.inner),
            fiber.clone(),
            parent.uid(),
            factory,
            runtime_generation,
            self.driver_binding(&driver_handle),
            config,
        );
        let lifecycle: Arc<dyn FiberLifecycle> = control.clone();
        fiber.attach_lifecycle(Arc::downgrade(&lifecycle));
        {
            let mut state = lock(&self.inner.state);
            let Some(runtime) = state.runtimes.get_mut(&factory_id) else {
                return Err(CordisError::RuntimeDeleting { id: plugin_id });
            };
            if runtime.generation != runtime_generation || runtime.status != RuntimeStatus::Open {
                return Err(CordisError::RuntimeDeleting { id: plugin_id });
            }
            runtime.fibers.insert(fiber.uid(), control.clone());
        }
        tokio::spawn(run_fiber(control.clone()));
        self.reconcile_control(&control)?;
        Ok(LifecycleHandle {
            registry: Arc::downgrade(&self.inner),
            factory_id,
            runtime_generation,
            driver_runtime: control.driver_runtime.clone(),
            caller_uid: parent.uid(),
            fiber,
        })
    }

    pub fn provide<T: Any + Send + Sync>(
        &self,
        key: impl Into<String>,
        value: T,
    ) -> Result<LifecycleProviderHandle, CordisError> {
        self.provide_for(
            &self.inner.root,
            "root".to_string(),
            key.into(),
            value,
            None,
        )
    }

    /// Registers a root provider whose guard is evaluated optimistically.
    ///
    /// The guard can be invoked more than once during exact revalidation, so
    /// it must be repeatable and free of externally visible side effects.
    pub fn provide_guarded<T, F>(
        &self,
        key: impl Into<String>,
        value: T,
        guard: F,
    ) -> Result<LifecycleProviderHandle, CordisError>
    where
        T: Any + Send + Sync,
        F: Fn(&T) -> Result<bool, CordisError> + Send + Sync + 'static,
    {
        let guard: ProviderGuard =
            Arc::new(move |value| {
                let typed = value.as_ref().downcast_ref::<T>().ok_or_else(|| {
                    CordisError::ProviderGuard {
                        namespace: "root".to_string(),
                        key: "type".to_string(),
                        source: Box::new(CordisError::PayloadType {
                            name: "provider guard".to_string(),
                        }),
                    }
                })?;
                guard(typed)
            });
        self.provide_for(
            &self.inner.root,
            "root".to_string(),
            key.into(),
            value,
            Some(guard),
        )
    }

    fn provide_for<T: Any + Send + Sync>(
        &self,
        owner: &Fiber,
        namespace: String,
        key: String,
        value: T,
        guard: Option<ProviderGuard>,
    ) -> Result<LifecycleProviderHandle, CordisError> {
        if owner.context_id() != self.inner.id {
            return Err(CordisError::FiberContextMismatch { uid: owner.uid() });
        }
        if owner.is_disposed() {
            return Err(CordisError::FiberDisposed { uid: owner.uid() });
        }
        self.commit_provider_mutation(&ProviderMutationRequest::Provide {
            owner: owner.clone(),
            key: RuntimeProviderKey::new(namespace, key),
            value: Arc::new(value),
            guard,
        })
    }

    pub fn replace_provider<T: Any + Send + Sync>(
        &self,
        handle: &LifecycleProviderHandle,
        value: T,
    ) -> Result<LifecycleProviderHandle, CordisError> {
        self.validate_provider_handle(handle)?;
        self.commit_provider_mutation(&ProviderMutationRequest::Replace {
            handle: handle.clone(),
            value: Arc::new(value),
        })
    }

    fn commit_provider_mutation(
        &self,
        request: &ProviderMutationRequest,
    ) -> Result<LifecycleProviderHandle, CordisError> {
        loop {
            let (plan, drafts) = {
                let state = lock(&self.inner.state);
                let plan = plan_provider_mutation(&state, self.inner.id, request)?;
                let controls = affected_controls_locked(&state, &plan.key);
                let drafts = controls
                    .into_iter()
                    .map(|control| {
                        let observations =
                            provider_observations_with_plan_locked(&state, &control, &plan);
                        let (config_revision, tombstone) = {
                            let machine = lock(&control.machine);
                            (machine.config_revision, machine.tombstone)
                        };
                        ProviderControlDraft {
                            control,
                            config_revision,
                            tombstone,
                            observations,
                        }
                    })
                    .collect::<Vec<_>>();
                (plan, drafts)
            };
            let outcomes = evaluate_provider_control_drafts(self.inner.id, drafts);
            if let Some(handle) =
                commit_provider_mutation_if_current(&self.inner, &plan, &outcomes)?
            {
                return Ok(handle);
            }
        }
    }

    pub fn begin_remove_provider(
        &self,
        handle: &LifecycleProviderHandle,
    ) -> Result<BoxFuture<'static, Result<(), CordisError>>, CordisError> {
        require_async_runtime()?;
        self.validate_provider_handle(handle)?;
        self.begin_provider_removal_with_mode(handle, ProviderRemovalMode::Strict)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep owner-teardown reservation, recovery, and exact compare-delete in one path"
    )]
    fn begin_provider_removal_with_mode(
        &self,
        handle: &LifecycleProviderHandle,
        mode: ProviderRemovalMode,
    ) -> Result<BoxFuture<'static, Result<(), CordisError>>, CordisError> {
        self.validate_provider_handle(handle)?;
        let owner_teardown = matches!(&mode, ProviderRemovalMode::OwnerTeardown { .. });
        let supervisor = match self.ensure_supervisor() {
            Ok(supervisor) => supervisor,
            Err(error) if owner_teardown => {
                self.fence_owner_provider_without_supervisor(handle);
                return Ok(async move { Err(error) }.boxed());
            }
            Err(error) => return Err(error),
        };
        let mut recovery = RecoveryPlan::default();
        if let ProviderRemovalMode::OwnerTeardown { driver_runtime } = &mode {
            if let Err(error) = driver_runtime.require_alive() {
                recovery.extend(quarantine_dead_bindings_transaction(
                    &self.inner,
                    vec![driver_runtime.clone()],
                    Vec::new(),
                    std::slice::from_ref(handle),
                    &error,
                ));
                let drivers = recovery.driver_runtimes();
                let inner = self.inner.clone();
                let operation = async move {
                    let first_error = settle_recovery_plan(inner, recovery, Some(error)).await;
                    first_error.map_or(Ok(()), Err)
                }
                .boxed()
                .shared();
                return Ok(spawn_unit_operation_on(supervisor, operation, drivers));
            }
            let dead_bindings = {
                let state = lock(&self.inner.state);
                let key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
                dead_driver_bindings_for_controls(&affected_controls_locked(&state, &key))
            };
            if !dead_bindings.is_empty() {
                recovery.extend(quarantine_dead_bindings_transaction(
                    &self.inner,
                    dead_bindings,
                    Vec::new(),
                    std::slice::from_ref(handle),
                    &CordisError::AsyncRuntimeUnavailable,
                ));
                let error = CordisError::AsyncRuntimeUnavailable;
                let drivers = recovery.driver_runtimes();
                let inner = self.inner.clone();
                let operation = async move {
                    let first_error = settle_recovery_plan(inner, recovery, Some(error)).await;
                    first_error.map_or(Ok(()), Err)
                }
                .boxed()
                .shared();
                return Ok(spawn_unit_operation_on(supervisor, operation, drivers));
            }
        }
        let plan = match self.prepare_provider_removal(handle, mode) {
            Ok(plan) => plan,
            Err(error) if owner_teardown => {
                recovery.extend(quarantine_dead_bindings_transaction(
                    &self.inner,
                    Vec::new(),
                    Vec::new(),
                    std::slice::from_ref(handle),
                    &error,
                ));
                let drivers = recovery.driver_runtimes();
                let inner = self.inner.clone();
                let operation = async move {
                    let first_error = settle_recovery_plan(inner, recovery, Some(error)).await;
                    first_error.map_or(Ok(()), Err)
                }
                .boxed()
                .shared();
                return Ok(spawn_unit_operation_on(supervisor, operation, drivers));
            }
            Err(error) => return Err(error),
        };
        let ProviderRemovalPlan {
            removal_serial,
            marked_revision,
            completed_revision,
            batch:
                FiberTicketBatch {
                    waits,
                    publications,
                    notifications,
                },
            drivers,
        } = plan;
        let mut drivers = drivers;
        for driver in recovery.driver_runtimes() {
            push_binding_once(&mut drivers, driver);
        }
        publish_deferred_batch(publications, notifications);
        let weak = Arc::downgrade(&self.inner);
        let handle = handle.clone();
        let operation = async move {
            let mut summary = await_ticket_batch_or_driver_death(waits).await;
            let Some(inner) = weak.upgrade() else {
                return Ok(());
            };
            if !summary.dead_bindings.is_empty() {
                recovery.extend(quarantine_dead_bindings_transaction(
                    &inner,
                    summary.dead_bindings,
                    Vec::new(),
                    &[],
                    &CordisError::AsyncRuntimeUnavailable,
                ));
            }
            summary.first_error =
                settle_recovery_plan(inner.clone(), recovery, summary.first_error).await;
            {
                let mut state = lock(&inner.state);
                let provider_key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
                if let Some(slot) = state.providers.get_mut(&provider_key) {
                    let remove = slot.removal_serial == removal_serial
                        && slot.revision == marked_revision
                        && slot.record.as_ref().is_some_and(|record| {
                            record.provider_id == handle.provider_id && record.removing
                        });
                    if remove {
                        slot.record = None;
                        slot.revision = completed_revision;
                    }
                }
            }
            summary.first_error.map_or(Ok(()), Err)
        }
        .boxed()
        .shared();
        Ok(spawn_unit_operation_on(supervisor, operation, drivers))
    }

    fn prepare_provider_removal(
        &self,
        handle: &LifecycleProviderHandle,
        mode: ProviderRemovalMode,
    ) -> Result<ProviderRemovalPlan, CordisError> {
        let mut state = lock(&self.inner.state);
        let provider_key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
        let (removal_serial, marked_revision, completed_revision) =
            preflight_provider_removal(&state, &provider_key, handle)?;
        let mut controls = affected_controls_locked(&state, &provider_key);
        controls.sort_by_key(|control| control.fiber.uid());
        let mut machines = controls
            .iter()
            .map(|control| lock(&control.machine))
            .collect::<Vec<_>>();
        for control in &controls {
            control.driver_runtime.require_alive()?;
        }
        let next_tickets = machines
            .iter()
            .map(|machine| FiberControl::preflight_desired_locked(machine, None))
            .collect::<Result<Vec<_>, _>>()?;
        let mut drivers = driver_runtimes_for_controls(&controls);
        match mode {
            ProviderRemovalMode::Strict => {}
            ProviderRemovalMode::OwnerTeardown { driver_runtime } => {
                driver_runtime.require_alive()?;
                if !drivers.iter().any(|driver| driver.ptr_eq(&driver_runtime)) {
                    drivers.push(driver_runtime);
                }
            }
        }

        // Slot absence and every dependent ticket publish in one registry ->
        // uid-ordered machine critical section. No fallible operation remains
        // after the slot mutation begins.
        if let Some(slot) = state.providers.get_mut(&provider_key) {
            slot.removal_serial = removal_serial;
            slot.revision = marked_revision;
            if let Some(record) = slot.record.as_mut() {
                record.removing = true;
            }
        }
        let mut waits = Vec::with_capacity(controls.len());
        let mut publications = Vec::new();
        let mut notifications = Vec::new();
        for ((control, machine), next_ticket) in
            controls.iter().zip(&mut machines).zip(next_tickets)
        {
            let (changed, serial) =
                FiberControl::apply_desired_locked(machine, None, None, next_ticket);
            waits.push((control.clone(), serial));
            if changed {
                publications.push((control.clone(), machine.snapshot()));
                notifications.push(control.clone());
            }
        }
        drop(machines);
        drop(state);
        Ok(ProviderRemovalPlan {
            removal_serial,
            marked_revision,
            completed_revision,
            batch: FiberTicketBatch {
                waits,
                publications,
                notifications,
            },
            drivers,
        })
    }

    pub async fn remove_provider(
        &self,
        handle: &LifecycleProviderHandle,
    ) -> Result<(), CordisError> {
        self.begin_remove_provider(handle)?.await
    }

    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        self.get_in_namespace("root", key)
    }

    fn get_in_namespace<T: Any + Send + Sync>(&self, namespace: &str, key: &str) -> Option<Arc<T>> {
        let observation = {
            let state = lock(&self.inner.state);
            provider_observation_locked(&state, namespace, key)?
        };
        if !provider_guard_allows(self.inner.id, &observation) {
            return None;
        }
        let state = lock(&self.inner.state);
        if !provider_observations_are_current(&state, std::slice::from_ref(&observation)) {
            return None;
        }
        observation.value.downcast::<T>().ok()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep delete preflight, durable recovery, and exact runtime removal together"
    )]
    pub fn begin_delete_factory(
        &self,
        factory: &PluginFactory,
    ) -> Result<BoxFuture<'static, Result<(), CordisError>>, CordisError> {
        require_async_runtime()?;
        let supervisor = self.ensure_supervisor()?;
        let (dead_bindings, recovery_controls) = {
            let state = lock(&self.inner.state);
            state
                .runtimes
                .get(&factory.id())
                .map(|runtime| {
                    let controls = runtime.fibers.values().cloned().collect::<Vec<_>>();
                    (dead_driver_bindings_for_controls(&controls), controls)
                })
                .unwrap_or_default()
        };
        let mut recovery = RecoveryPlan::default();
        if !dead_bindings.is_empty() {
            recovery.extend(quarantine_dead_bindings_transaction(
                &self.inner,
                dead_bindings,
                recovery_controls,
                &[],
                &CordisError::AsyncRuntimeUnavailable,
            ));
        }
        if !lock(&self.inner.state).runtimes.contains_key(&factory.id()) {
            let drivers = recovery.driver_runtimes();
            let inner = self.inner.clone();
            let operation = async move {
                let first_error = settle_recovery_plan(inner, recovery, None).await;
                first_error.map_or(Ok(()), Err)
            }
            .boxed()
            .shared();
            return Ok(spawn_unit_operation_on(supervisor, operation, drivers));
        }
        let (generation, batch, drivers) = {
            let mut state = lock(&self.inner.state);
            let Some(runtime) = state.runtimes.get(&factory.id()) else {
                drop(state);
                let drivers = recovery.driver_runtimes();
                let inner = self.inner.clone();
                let operation = async move {
                    let first_error = settle_recovery_plan(inner, recovery, None).await;
                    first_error.map_or(Ok(()), Err)
                }
                .boxed()
                .shared();
                return Ok(spawn_unit_operation_on(supervisor, operation, drivers));
            };
            let generation = runtime.generation;
            let mut controls = runtime.fibers.values().cloned().collect::<Vec<_>>();
            controls.sort_by_key(|control| control.fiber.uid());
            let mut machines = controls
                .iter()
                .map(|control| lock(&control.machine))
                .collect::<Vec<_>>();
            let next_tickets = preflight_dispose_batch(&machines)?;
            for control in &controls {
                control.driver_runtime.require_alive()?;
            }
            let drivers = driver_runtimes_for_controls(&controls);
            if let Some(runtime) = state.runtimes.get_mut(&factory.id()) {
                runtime.status = RuntimeStatus::Deleting;
            }
            let batch = publish_dispose_batch(&controls, &mut machines, next_tickets);
            drop(machines);
            drop(state);
            (generation, batch, drivers)
        };
        let FiberTicketBatch {
            waits,
            publications,
            notifications,
        } = batch;
        let mut drivers = drivers;
        for driver in recovery.driver_runtimes() {
            push_binding_once(&mut drivers, driver);
        }
        publish_deferred_batch(publications, notifications);
        let weak = Arc::downgrade(&self.inner);
        let factory = factory.clone();
        let operation = async move {
            let mut summary = await_ticket_batch_or_driver_death(waits).await;
            if let Some(inner) = weak.upgrade() {
                if !summary.dead_bindings.is_empty() {
                    recovery.extend(quarantine_dead_bindings_transaction(
                        &inner,
                        summary.dead_bindings,
                        Vec::new(),
                        &[],
                        &CordisError::AsyncRuntimeUnavailable,
                    ));
                }
                summary.first_error =
                    settle_recovery_plan(inner.clone(), recovery, summary.first_error).await;
                let mut state = lock(&inner.state);
                let remove = state.runtimes.get(&factory.id()).is_some_and(|runtime| {
                    runtime.generation == generation && runtime.status == RuntimeStatus::Deleting
                });
                if remove {
                    state.runtimes.remove(&factory.id());
                    if state.catalog.get(factory.plugin_id()) == Some(&factory.id()) {
                        state.catalog.remove(factory.plugin_id());
                    }
                }
            }
            summary.first_error.map_or(Ok(()), Err)
        }
        .boxed()
        .shared();
        Ok(spawn_unit_operation_on(supervisor, operation, drivers))
    }

    pub async fn delete_factory(&self, factory: &PluginFactory) -> Result<(), CordisError> {
        self.begin_delete_factory(factory)?.await
    }

    pub async fn restart_root(&self) -> Result<Vec<FiberSnapshot>, CordisError> {
        let driver_handle = current_async_runtime()?;
        let batch = {
            let state = lock(&self.inner.state);
            let mut controls = state
                .runtimes
                .values()
                .flat_map(|runtime| runtime.fibers.values())
                .filter(|control| control.parent_uid == FiberUid::ROOT)
                .cloned()
                .collect::<Vec<_>>();
            controls.sort_by_key(|control| control.fiber.uid());
            for control in &controls {
                control.driver_runtime.require_handle(&driver_handle)?;
            }
            let mut offenders = controls
                .iter()
                .filter(|control| !control.factory.is_repeatable())
                .map(|control| control.factory.plugin_id().clone())
                .collect::<Vec<_>>();
            offenders.sort();
            offenders.dedup();
            if !offenders.is_empty() {
                return Err(CordisError::NonRepeatableFactory { ids: offenders });
            }
            // The registry lock plus uid-ordered machine guards exclude
            // mount/delete and already-resolved LifecycleHandle commands.
            // Every fallible condition is checked before the first mutation.
            let mut machines = controls
                .iter()
                .map(|control| lock(&control.machine))
                .collect::<Vec<_>>();
            let mut next_tickets = Vec::with_capacity(machines.len());
            for (control, machine) in controls.iter().zip(&machines) {
                if machine.tombstone {
                    return Err(CordisError::FiberDisposed {
                        uid: control.fiber.uid(),
                    });
                }
                next_tickets.push(machine.preflight_next_ticket()?);
            }
            let mut waits = Vec::with_capacity(controls.len());
            let mut publications = Vec::with_capacity(controls.len());
            let mut notifications = Vec::with_capacity(controls.len());
            for ((control, machine), next_ticket) in
                controls.iter().zip(&mut machines).zip(next_tickets)
            {
                machine.force_restart = true;
                let ticket = machine.publish_ticket(next_ticket);
                let serial = ticket.serial();
                waits.push((control.clone(), serial));
                publications.push((control.clone(), machine.snapshot()));
                notifications.push(control.clone());
            }
            drop(machines);
            drop(state);
            FiberTicketBatch {
                waits,
                publications,
                notifications,
            }
        };
        let FiberTicketBatch {
            waits,
            publications,
            notifications,
        } = batch;
        publish_deferred_batch(publications, notifications);
        let results = join_all(
            waits
                .into_iter()
                .map(|(control, serial)| async move { control.await_ticket(serial).await }),
        )
        .await;
        results.into_iter().collect()
    }

    pub fn begin_shutdown(
        &self,
    ) -> Result<BoxFuture<'static, Result<(), CordisError>>, CordisError> {
        require_async_runtime()?;
        let mut operation_slot = lock(&self.inner.shutdown_operation);
        if let Some(operation) = operation_slot.as_ref() {
            let operation = operation.clone();
            return Ok(operation.boxed());
        }
        let supervisor = self.ensure_supervisor()?;
        let (dead_bindings, recovery_controls) = {
            let state = lock(&self.inner.state);
            let controls = controls_locked(&state);
            (dead_driver_bindings_for_controls(&controls), controls)
        };
        let mut recovery = RecoveryPlan::default();
        if !dead_bindings.is_empty() {
            recovery.extend(quarantine_dead_bindings_transaction(
                &self.inner,
                dead_bindings,
                recovery_controls,
                &[],
                &CordisError::AsyncRuntimeUnavailable,
            ));
        }
        let (batch, drivers) = {
            let mut state = lock(&self.inner.state);
            let mut controls = state
                .runtimes
                .values()
                .flat_map(|runtime| runtime.fibers.values().cloned())
                .collect::<Vec<_>>();
            controls.sort_by_key(|control| control.fiber.uid());
            let mut machines = controls
                .iter()
                .map(|control| lock(&control.machine))
                .collect::<Vec<_>>();
            let next_tickets = preflight_dispose_batch(&machines)?;
            for control in &controls {
                control.driver_runtime.require_alive()?;
            }
            let drivers = driver_runtimes_for_controls(&controls);
            state.shutting_down = true;
            for runtime in state.runtimes.values_mut() {
                runtime.status = RuntimeStatus::Deleting;
            }
            let result = publish_dispose_batch(&controls, &mut machines, next_tickets);
            drop(machines);
            drop(state);
            (result, drivers)
        };
        let FiberTicketBatch {
            waits,
            publications,
            notifications,
        } = batch;
        let mut drivers = drivers;
        for driver in recovery.driver_runtimes() {
            push_binding_once(&mut drivers, driver);
        }
        let weak = Arc::downgrade(&self.inner);
        let operation = async move {
            let mut summary = await_ticket_batch_or_driver_death(waits).await;
            if let Some(inner) = weak.upgrade() {
                if !summary.dead_bindings.is_empty() {
                    recovery.extend(quarantine_dead_bindings_transaction(
                        &inner,
                        summary.dead_bindings,
                        Vec::new(),
                        &[],
                        &CordisError::AsyncRuntimeUnavailable,
                    ));
                }
                summary.first_error =
                    settle_recovery_plan(inner.clone(), recovery, summary.first_error).await;
                let mut state = lock(&inner.state);
                state.runtimes.clear();
                state.catalog.clear();
                state.providers.clear();
            }
            summary.first_error.map_or(Ok(()), Err)
        }
        .boxed()
        .shared();
        *operation_slot = Some(operation.clone());
        drop(operation_slot);
        publish_deferred_batch(publications, notifications);
        Ok(spawn_unit_operation_on(supervisor, operation, drivers))
    }

    pub async fn shutdown(&self) -> Result<(), CordisError> {
        self.begin_shutdown()?.await
    }

    fn validate_provider_handle(
        &self,
        handle: &LifecycleProviderHandle,
    ) -> Result<(), CordisError> {
        if handle.registry_id == self.inner.id {
            Ok(())
        } else {
            Err(CordisError::ProviderOwnerMismatch {
                key: handle.key.clone(),
            })
        }
    }

    fn reconcile_control(&self, control: &Arc<FiberControl>) -> Result<(), CordisError> {
        self.reconcile_controls_atomically(std::slice::from_ref(control))
    }

    fn reconcile_controls_atomically(
        &self,
        requested: &[Arc<FiberControl>],
    ) -> Result<(), CordisError> {
        loop {
            let drafts = stage_reconciliation(&self.inner, requested);
            let outcomes = evaluate_provider_control_drafts(self.inner.id, drafts);
            if commit_reconciliation_if_current(&self.inner, requested, &outcomes)? {
                return Ok(());
            }
        }
    }

    fn remove_terminal_child(
        &self,
        factory_id: PluginFactoryId,
        runtime_generation: u64,
        fiber_uid: FiberUid,
    ) {
        let mut state = lock(&self.inner.state);
        let mut remove_runtime = None;
        if let Some(runtime) = state.runtimes.get_mut(&factory_id)
            && runtime.generation == runtime_generation
        {
            runtime.fibers.remove(&fiber_uid);
            if runtime.fibers.is_empty() && runtime.status == RuntimeStatus::Open {
                remove_runtime = Some(runtime.factory.plugin_id().clone());
            }
        }
        if let Some(plugin_id) = remove_runtime {
            state.runtimes.remove(&factory_id);
            if state.catalog.get(&plugin_id) == Some(&factory_id) {
                state.catalog.remove(&plugin_id);
            }
        }
    }
}

fn plan_provider_mutation(
    state: &LifecycleRegistryState,
    registry_id: u64,
    request: &ProviderMutationRequest,
) -> Result<ProviderMutationPlan, CordisError> {
    if state.shutting_down {
        return Err(CordisError::RuntimeShuttingDown);
    }
    match request {
        ProviderMutationRequest::Provide {
            owner,
            key,
            value,
            guard,
        } => plan_provider_registration(state, registry_id, owner, key, value, guard.as_ref()),
        ProviderMutationRequest::Replace { handle, value } => {
            plan_provider_replacement(state, handle, value)
        }
    }
}

fn plan_provider_registration(
    state: &LifecycleRegistryState,
    registry_id: u64,
    owner: &Fiber,
    key: &RuntimeProviderKey,
    value: &ProviderValue,
    guard: Option<&ProviderGuard>,
) -> Result<ProviderMutationPlan, CordisError> {
    let owner_binding = resolve_provider_owner_locked(state, owner)?;
    let expected_slot = state.providers.get(key).map(provider_slot_fact);
    if let Some(existing) = state
        .providers
        .get(key)
        .and_then(|slot| slot.record.as_ref())
    {
        if !existing.removing {
            return Err(CordisError::DuplicateProvider {
                namespace: key.namespace.clone(),
                key: key.key.clone(),
            });
        }
        if existing.owner.uid() != owner.uid() {
            return Err(CordisError::ProviderOwnerMismatch {
                key: key.key.clone(),
            });
        }
    }
    let provider_id = state.next_provider_id;
    let next_provider_id = provider_id
        .checked_add(1)
        .ok_or(CordisError::ProviderIdentityOverflow)?;
    let revision = state
        .providers
        .get(key)
        .map_or(0, |slot| slot.revision)
        .checked_add(1)
        .ok_or_else(|| CordisError::ProviderGenerationOverflow {
            key: key.key.clone(),
        })?;
    let removal_serial = state
        .providers
        .get(key)
        .map_or(0, |slot| slot.removal_serial);
    let generation = 0;
    Ok(ProviderMutationPlan {
        key: key.clone(),
        expected_slot,
        expected_next_provider_id: Some(provider_id),
        next_provider_id: Some(next_provider_id),
        revision,
        removal_serial,
        record: RuntimeProviderRecord {
            value: value.clone(),
            provider_id,
            owner: owner.clone(),
            owner_binding,
            generation,
            removing: false,
            guard: guard.cloned(),
        },
        handle: LifecycleProviderHandle {
            registry_id,
            namespace: key.namespace.clone(),
            key: key.key.clone(),
            provider_id,
            owner_uid: owner.uid(),
            generation,
        },
    })
}

fn plan_provider_replacement(
    state: &LifecycleRegistryState,
    handle: &LifecycleProviderHandle,
    value: &ProviderValue,
) -> Result<ProviderMutationPlan, CordisError> {
    let key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
    let Some(slot) = state.providers.get(&key) else {
        return Err(CordisError::ProviderNotFound {
            namespace: handle.namespace.clone(),
            key: handle.key.clone(),
        });
    };
    let Some(record) = slot.record.as_ref() else {
        return Err(CordisError::ProviderNotFound {
            namespace: handle.namespace.clone(),
            key: handle.key.clone(),
        });
    };
    if record.provider_id != handle.provider_id
        || record.owner.uid() != handle.owner_uid
        || record.removing
    {
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
    let revision =
        slot.revision
            .checked_add(1)
            .ok_or_else(|| CordisError::ProviderGenerationOverflow {
                key: handle.key.clone(),
            })?;
    Ok(ProviderMutationPlan {
        key,
        expected_slot: Some(provider_slot_fact(slot)),
        expected_next_provider_id: None,
        next_provider_id: None,
        revision,
        removal_serial: slot.removal_serial,
        record: RuntimeProviderRecord {
            value: value.clone(),
            provider_id: record.provider_id,
            owner: record.owner.clone(),
            owner_binding: record.owner_binding.clone(),
            generation,
            removing: false,
            guard: record.guard.clone(),
        },
        handle: LifecycleProviderHandle {
            generation,
            ..handle.clone()
        },
    })
}

fn resolve_provider_owner_locked(
    state: &LifecycleRegistryState,
    owner: &Fiber,
) -> Result<RuntimeProviderOwner, CordisError> {
    if owner.uid() == FiberUid::ROOT {
        return Ok(RuntimeProviderOwner::Root);
    }
    state
        .runtimes
        .values()
        .flat_map(|runtime| runtime.fibers.values())
        .find(|control| control.fiber.uid() == owner.uid())
        .map(|control| RuntimeProviderOwner::Managed {
            control: Arc::downgrade(control),
            runtime_generation: control.runtime_generation,
        })
        .ok_or(CordisError::FiberDisposed { uid: owner.uid() })
}

fn commit_provider_mutation_if_current(
    inner: &LifecycleRegistryInner,
    plan: &ProviderMutationPlan,
    outcomes: &[ProviderControlOutcome],
) -> Result<Option<LifecycleProviderHandle>, CordisError> {
    let mut state = lock(&inner.state);
    if !provider_mutation_base_is_current(&state, plan) {
        return Ok(None);
    }
    let controls = affected_controls_locked(&state, &plan.key);
    if !same_provider_controls(&controls, outcomes)
        || outcomes.iter().any(|outcome| {
            !provider_observations_equivalent(
                outcome.draft.observations.as_deref(),
                provider_observations_with_plan_locked(&state, &outcome.draft.control, plan)
                    .as_deref(),
            )
        })
    {
        return Ok(None);
    }

    let owner_control = runtime_provider_owner_control(&plan.record.owner_binding);
    let transaction_controls = transaction_controls(&controls, outcomes, owner_control);
    let mut machines = transaction_controls
        .iter()
        .map(|control| lock(&control.machine))
        .collect::<Vec<_>>();
    if outcomes.iter().any(|outcome| {
        control_index(&transaction_controls, &outcome.draft.control).is_none_or(|index| {
            machines[index].config_revision != outcome.draft.config_revision
                || machines[index].tombstone != outcome.draft.tombstone
        })
    }) {
        return Ok(None);
    }
    if !runtime_provider_owner_is_active_locked(
        &state,
        &plan.record.owner_binding,
        &transaction_controls,
        &machines,
    ) {
        return Err(CordisError::FiberDisposed {
            uid: plan.record.owner.uid(),
        });
    }
    if !provider_outcome_owners_are_current_locked(
        &state,
        &transaction_controls,
        &machines,
        outcomes,
    ) {
        return Ok(None);
    }
    for control in &transaction_controls {
        control.driver_runtime.require_alive()?;
    }
    let next_tickets = outcomes
        .iter()
        .map(|outcome| {
            let index = control_index(&transaction_controls, &outcome.draft.control)
                .expect("affected control must be transaction-locked");
            if outcome.draft.tombstone {
                Ok(None)
            } else {
                FiberControl::preflight_desired_locked(&machines[index], outcome.desired.as_ref())
            }
        })
        .collect::<Result<Vec<_>, CordisError>>()?;

    commit_provider_plan(&mut state, plan);
    let (publications, notifications) =
        apply_provider_outcomes(&transaction_controls, &mut machines, outcomes, next_tickets);
    let handle = plan.handle.clone();
    drop(machines);
    drop(state);
    publish_deferred_batch(publications, notifications);
    Ok(Some(handle))
}

fn apply_provider_outcomes(
    controls: &[Arc<FiberControl>],
    machines: &mut [std::sync::MutexGuard<'_, FiberMachine>],
    outcomes: &[ProviderControlOutcome],
    next_tickets: Vec<Option<u64>>,
) -> (Vec<FiberPublication>, Vec<Arc<FiberControl>>) {
    let mut publications = Vec::new();
    let mut notifications = Vec::new();
    for (outcome, next_ticket) in outcomes.iter().zip(next_tickets) {
        let control = &outcome.draft.control;
        let index = control_index(controls, control).expect("affected control must be locked");
        let machine = &mut machines[index];
        if outcome.draft.tombstone {
            continue;
        }
        let before = machine.snapshot();
        let (changed, _) = FiberControl::apply_desired_locked(
            machine,
            outcome.desired.clone(),
            outcome.diagnostic.clone(),
            next_ticket,
        );
        let after = machine.snapshot();
        if after != before {
            publications.push((control.clone(), after));
        }
        if changed {
            notifications.push(control.clone());
        }
    }
    (publications, notifications)
}

fn provider_slot_fact(slot: &RuntimeProviderSlot) -> ProviderSlotFact {
    ProviderSlotFact {
        revision: slot.revision,
        removal_serial: slot.removal_serial,
        record: slot.record.as_ref().map(|record| ProviderRecordFact {
            value: record.value.clone(),
            provider_id: record.provider_id,
            owner_uid: record.owner.uid(),
            owner_binding: record.owner_binding.clone(),
            generation: record.generation,
            removing: record.removing,
            guard: record.guard.clone(),
        }),
    }
}

fn provider_slot_matches(
    slot: Option<&RuntimeProviderSlot>,
    fact: Option<&ProviderSlotFact>,
) -> bool {
    match (slot, fact) {
        (None, None) => true,
        (Some(slot), Some(fact)) => {
            slot.revision == fact.revision
                && slot.removal_serial == fact.removal_serial
                && match (slot.record.as_ref(), fact.record.as_ref()) {
                    (None, None) => true,
                    (Some(record), Some(expected)) => {
                        record.provider_id == expected.provider_id
                            && record.owner.uid() == expected.owner_uid
                            && runtime_provider_owners_ptr_eq(
                                &record.owner_binding,
                                &expected.owner_binding,
                            )
                            && record.generation == expected.generation
                            && record.removing == expected.removing
                            && Arc::ptr_eq(&record.value, &expected.value)
                            && provider_guards_ptr_eq(
                                record.guard.as_ref(),
                                expected.guard.as_ref(),
                            )
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

fn runtime_provider_owners_ptr_eq(
    left: &RuntimeProviderOwner,
    right: &RuntimeProviderOwner,
) -> bool {
    match (left, right) {
        (RuntimeProviderOwner::Root, RuntimeProviderOwner::Root) => true,
        (
            RuntimeProviderOwner::Managed {
                control: left_control,
                runtime_generation: left_generation,
            },
            RuntimeProviderOwner::Managed {
                control: right_control,
                runtime_generation: right_generation,
            },
        ) => left_generation == right_generation && left_control.ptr_eq(right_control),
        _ => false,
    }
}

fn provider_guards_ptr_eq(left: Option<&ProviderGuard>, right: Option<&ProviderGuard>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

fn provider_mutation_base_is_current(
    state: &LifecycleRegistryState,
    plan: &ProviderMutationPlan,
) -> bool {
    !state.shutting_down
        && plan
            .expected_next_provider_id
            .is_none_or(|expected| state.next_provider_id == expected)
        && provider_slot_matches(state.providers.get(&plan.key), plan.expected_slot.as_ref())
}

fn affected_controls_locked(
    state: &LifecycleRegistryState,
    key: &RuntimeProviderKey,
) -> Vec<Arc<FiberControl>> {
    let mut controls = state
        .runtimes
        .values()
        .flat_map(|runtime| runtime.fibers.values())
        .filter(|control| {
            control.namespace == key.namespace
                && control
                    .factory
                    .inject()
                    .iter()
                    .any(|inject| inject == &key.key)
        })
        .cloned()
        .collect::<Vec<_>>();
    controls.sort_by_key(|control| control.fiber.uid());
    controls
}

fn controls_locked(state: &LifecycleRegistryState) -> Vec<Arc<FiberControl>> {
    let mut controls = state
        .runtimes
        .values()
        .flat_map(|runtime| runtime.fibers.values().cloned())
        .collect::<Vec<_>>();
    controls.sort_by_key(|control| control.fiber.uid());
    controls
}

fn detach_control_locked(state: &mut LifecycleRegistryState, control: &Arc<FiberControl>) {
    let mut empty_runtime = None;
    if let Some(runtime) = state.runtimes.get_mut(&control.factory.id())
        && runtime.generation == control.runtime_generation
        && runtime
            .fibers
            .get(&control.fiber.uid())
            .is_some_and(|registered| Arc::ptr_eq(registered, control))
    {
        runtime.fibers.remove(&control.fiber.uid());
        if runtime.fibers.is_empty() {
            empty_runtime = Some(runtime.factory.plugin_id().clone());
        }
    }
    if let Some(plugin_id) = empty_runtime {
        state.runtimes.remove(&control.factory.id());
        if state.catalog.get(&plugin_id) == Some(&control.factory.id()) {
            state.catalog.remove(&plugin_id);
        }
    }
}

fn selected_controls_locked(
    state: &LifecycleRegistryState,
    requested: &[Arc<FiberControl>],
) -> Vec<Arc<FiberControl>> {
    let mut controls = requested
        .iter()
        .filter(|control| control_is_registered_locked(state, control))
        .cloned()
        .collect::<Vec<_>>();
    controls.sort_by_key(|control| control.fiber.uid());
    controls
}

fn transaction_controls(
    affected: &[Arc<FiberControl>],
    outcomes: &[ProviderControlOutcome],
    extra: impl IntoIterator<Item = Arc<FiberControl>>,
) -> Vec<Arc<FiberControl>> {
    let mut controls = affected.to_vec();
    controls.extend(extra);
    controls.extend(
        outcomes
            .iter()
            .flat_map(|outcome| outcome.draft.observations.iter().flatten())
            .filter_map(|observation| match &observation.owner {
                ProviderObservationOwner::Root => None,
                ProviderObservationOwner::Managed { control, .. } => Some(control.clone()),
            }),
    );
    controls.sort_by_key(|control| control.fiber.uid());
    controls.dedup_by(|left, right| Arc::ptr_eq(left, right));
    controls
}

fn control_index(controls: &[Arc<FiberControl>], target: &Arc<FiberControl>) -> Option<usize> {
    controls
        .iter()
        .position(|control| Arc::ptr_eq(control, target))
}

fn provider_outcome_owners_are_current_locked(
    state: &LifecycleRegistryState,
    controls: &[Arc<FiberControl>],
    machines: &[std::sync::MutexGuard<'_, FiberMachine>],
    outcomes: &[ProviderControlOutcome],
) -> bool {
    outcomes
        .iter()
        .flat_map(|outcome| outcome.draft.observations.iter().flatten())
        .all(|observation| match &observation.owner {
            ProviderObservationOwner::Root => true,
            ProviderObservationOwner::Managed {
                control,
                runtime_generation,
                activation_owner,
            } => {
                control.runtime_generation == *runtime_generation
                    && control_is_registered_locked(state, control)
                    && control_index(controls, control).is_some_and(|index| {
                        !machines[index].tombstone
                            && if *activation_owner {
                                machines[index].state == FiberState::Loading
                            } else {
                                machines[index].state == FiberState::Active
                            }
                    })
            }
        })
}

fn runtime_provider_owner_control(owner: &RuntimeProviderOwner) -> Option<Arc<FiberControl>> {
    match owner {
        RuntimeProviderOwner::Root => None,
        RuntimeProviderOwner::Managed { control, .. } => control.upgrade(),
    }
}

fn runtime_provider_owner_is_active_locked(
    state: &LifecycleRegistryState,
    owner: &RuntimeProviderOwner,
    controls: &[Arc<FiberControl>],
    machines: &[std::sync::MutexGuard<'_, FiberMachine>],
) -> bool {
    match owner {
        RuntimeProviderOwner::Root => true,
        RuntimeProviderOwner::Managed {
            control,
            runtime_generation,
        } => control.upgrade().is_some_and(|control| {
            control.runtime_generation == *runtime_generation
                && control_is_registered_locked(state, &control)
                && control_index(controls, &control).is_some_and(|index| {
                    !machines[index].tombstone && machines[index].state == FiberState::Active
                })
        }),
    }
}

fn stage_reconciliation(
    inner: &LifecycleRegistryInner,
    requested: &[Arc<FiberControl>],
) -> Vec<ProviderControlDraft> {
    let state = lock(&inner.state);
    selected_controls_locked(&state, requested)
        .into_iter()
        .map(|control| {
            let observations = provider_observations_locked(&state, &control);
            let (config_revision, tombstone) = {
                let machine = lock(&control.machine);
                (machine.config_revision, machine.tombstone)
            };
            ProviderControlDraft {
                control,
                config_revision,
                tombstone,
                observations,
            }
        })
        .collect()
}

fn commit_reconciliation_if_current(
    inner: &LifecycleRegistryInner,
    requested: &[Arc<FiberControl>],
    outcomes: &[ProviderControlOutcome],
) -> Result<bool, CordisError> {
    let state = lock(&inner.state);
    let controls = selected_controls_locked(&state, requested);
    if !same_provider_controls(&controls, outcomes)
        || outcomes.iter().any(|outcome| {
            !provider_observations_equivalent(
                outcome.draft.observations.as_deref(),
                provider_observations_locked(&state, &outcome.draft.control).as_deref(),
            )
        })
    {
        return Ok(false);
    }

    let transaction_controls = transaction_controls(&controls, outcomes, std::iter::empty());
    let mut machines = transaction_controls
        .iter()
        .map(|control| lock(&control.machine))
        .collect::<Vec<_>>();
    if outcomes.iter().any(|outcome| {
        control_index(&transaction_controls, &outcome.draft.control).is_none_or(|index| {
            machines[index].config_revision != outcome.draft.config_revision
                || machines[index].tombstone != outcome.draft.tombstone
        })
    }) || !provider_outcome_owners_are_current_locked(
        &state,
        &transaction_controls,
        &machines,
        outcomes,
    ) {
        return Ok(false);
    }
    for control in &transaction_controls {
        control.driver_runtime.require_alive()?;
    }
    let next_tickets = outcomes
        .iter()
        .map(|outcome| {
            let index = control_index(&transaction_controls, &outcome.draft.control)
                .expect("affected control must be transaction-locked");
            if outcome.draft.tombstone {
                Ok(None)
            } else {
                FiberControl::preflight_desired_locked(&machines[index], outcome.desired.as_ref())
            }
        })
        .collect::<Result<Vec<_>, CordisError>>()?;
    let (publications, notifications) =
        apply_provider_outcomes(&transaction_controls, &mut machines, outcomes, next_tickets);
    drop(machines);
    drop(state);
    publish_deferred_batch(publications, notifications);
    Ok(true)
}

fn control_is_registered_locked(
    state: &LifecycleRegistryState,
    control: &Arc<FiberControl>,
) -> bool {
    state
        .runtimes
        .get(&control.factory.id())
        .filter(|runtime| runtime.generation == control.runtime_generation)
        .and_then(|runtime| runtime.fibers.get(&control.fiber.uid()))
        .is_some_and(|registered| Arc::ptr_eq(registered, control))
}

fn provider_observations_locked(
    state: &LifecycleRegistryState,
    control: &FiberControl,
) -> Option<Vec<ProviderObservation>> {
    control
        .factory
        .inject()
        .iter()
        .map(|key| provider_observation_locked(state, &control.namespace, key))
        .collect()
}

fn provider_observations_with_plan_locked(
    state: &LifecycleRegistryState,
    control: &FiberControl,
    plan: &ProviderMutationPlan,
) -> Option<Vec<ProviderObservation>> {
    control
        .factory
        .inject()
        .iter()
        .map(|key| {
            let provider_key = RuntimeProviderKey::new(&control.namespace, key);
            if provider_key == plan.key {
                let record = &plan.record;
                let owner =
                    resolve_provider_observation_owner_locked(state, &record.owner_binding, false)?;
                Some(ProviderObservation {
                    key: provider_key,
                    value: record.value.clone(),
                    guard: record.guard.clone(),
                    provider_id: record.provider_id,
                    owner_uid: record.owner.uid(),
                    owner,
                    generation: record.generation,
                    revision: plan.revision,
                    removal_serial: plan.removal_serial,
                })
            } else {
                provider_observation_locked(state, &control.namespace, key)
            }
        })
        .collect()
}

fn evaluate_provider_control_drafts(
    registry_id: u64,
    drafts: Vec<ProviderControlDraft>,
) -> Vec<ProviderControlOutcome> {
    drafts
        .into_iter()
        .map(|draft| {
            if draft.tombstone {
                return ProviderControlOutcome {
                    draft,
                    desired: None,
                    diagnostic: None,
                };
            }
            let (available, diagnostic) = draft.observations.as_ref().map_or((false, None), |o| {
                evaluate_provider_guards(registry_id, &draft.control, o)
            });
            let desired = available.then(|| {
                ActivationEpoch::new(
                    draft.config_revision,
                    draft.observations.iter().flatten().map(|observation| {
                        ProviderFingerprint::new(
                            observation.key.namespace.clone(),
                            observation.key.key.clone(),
                            observation.owner_uid,
                            observation.generation,
                        )
                    }),
                )
            });
            ProviderControlOutcome {
                draft,
                desired,
                diagnostic,
            }
        })
        .collect()
}

fn same_provider_controls(
    controls: &[Arc<FiberControl>],
    outcomes: &[ProviderControlOutcome],
) -> bool {
    controls.len() == outcomes.len()
        && controls
            .iter()
            .zip(outcomes)
            .all(|(control, outcome)| Arc::ptr_eq(control, &outcome.draft.control))
}

fn provider_observations_equivalent(
    left: Option<&[ProviderObservation]>,
    right: Option<&[ProviderObservation]>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.len() == right.len()
                && left.iter().zip(right).all(|(left, right)| {
                    left.key == right.key
                        && left.provider_id == right.provider_id
                        && left.owner_uid == right.owner_uid
                        && provider_observation_owners_ptr_eq(&left.owner, &right.owner)
                        && left.generation == right.generation
                        && left.revision == right.revision
                        && left.removal_serial == right.removal_serial
                        && Arc::ptr_eq(&left.value, &right.value)
                        && provider_guards_ptr_eq(left.guard.as_ref(), right.guard.as_ref())
                })
        }
        _ => false,
    }
}

fn provider_observation_owners_ptr_eq(
    left: &ProviderObservationOwner,
    right: &ProviderObservationOwner,
) -> bool {
    match (left, right) {
        (ProviderObservationOwner::Root, ProviderObservationOwner::Root) => true,
        (
            ProviderObservationOwner::Managed {
                control: left_control,
                runtime_generation: left_generation,
                activation_owner: left_activation,
            },
            ProviderObservationOwner::Managed {
                control: right_control,
                runtime_generation: right_generation,
                activation_owner: right_activation,
            },
        ) => {
            left_generation == right_generation
                && left_activation == right_activation
                && Arc::ptr_eq(left_control, right_control)
        }
        _ => false,
    }
}

fn commit_provider_plan(state: &mut LifecycleRegistryState, plan: &ProviderMutationPlan) {
    if let Some(next_provider_id) = plan.next_provider_id {
        state.next_provider_id = next_provider_id;
    }
    let slot = state
        .providers
        .entry(plan.key.clone())
        .or_insert_with(RuntimeProviderSlot::vacant);
    slot.revision = plan.revision;
    slot.record = Some(plan.record.clone());
}

fn provisional_activation_base_is_current(
    state: &LifecycleRegistryState,
    prepared: &PreparedActivation,
) -> bool {
    !state.shutting_down
        && state.next_provider_id == prepared.expected_next_provider_id
        && state.next_runtime_generation == prepared.expected_next_runtime_generation
        && prepared.provider_plans.iter().all(|plan| {
            provider_slot_matches(state.providers.get(&plan.key), plan.expected_slot.as_ref())
        })
}

fn prepared_activations_equivalent(left: &PreparedActivation, right: &PreparedActivation) -> bool {
    left.expected_next_provider_id == right.expected_next_provider_id
        && left.expected_next_runtime_generation == right.expected_next_runtime_generation
        && left.next_provider_id == right.next_provider_id
        && left.next_runtime_generation == right.next_runtime_generation
        && left.runtime_generations == right.runtime_generations
        && left.provider_plans.len() == right.provider_plans.len()
        && left
            .provider_plans
            .iter()
            .zip(&right.provider_plans)
            .all(|(left, right)| {
                left.key == right.key
                    && left.revision == right.revision
                    && left.removal_serial == right.removal_serial
                    && left.handle == right.handle
                    && provider_slot_facts_equivalent(
                        left.expected_slot.as_ref(),
                        right.expected_slot.as_ref(),
                    )
                    && left.record.provider_id == right.record.provider_id
                    && left.record.owner.uid() == right.record.owner.uid()
                    && runtime_provider_owners_ptr_eq(
                        &left.record.owner_binding,
                        &right.record.owner_binding,
                    )
                    && left.record.generation == right.record.generation
                    && left.record.removing == right.record.removing
                    && Arc::ptr_eq(&left.record.value, &right.record.value)
                    && provider_guards_ptr_eq(
                        left.record.guard.as_ref(),
                        right.record.guard.as_ref(),
                    )
            })
}

fn provider_slot_facts_equivalent(
    left: Option<&ProviderSlotFact>,
    right: Option<&ProviderSlotFact>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.revision == right.revision
                && left.removal_serial == right.removal_serial
                && match (left.record.as_ref(), right.record.as_ref()) {
                    (None, None) => true,
                    (Some(left), Some(right)) => {
                        left.provider_id == right.provider_id
                            && left.owner_uid == right.owner_uid
                            && runtime_provider_owners_ptr_eq(
                                &left.owner_binding,
                                &right.owner_binding,
                            )
                            && left.generation == right.generation
                            && left.removing == right.removing
                            && Arc::ptr_eq(&left.value, &right.value)
                            && provider_guards_ptr_eq(left.guard.as_ref(), right.guard.as_ref())
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

fn affected_controls_for_provisional_locked(
    state: &LifecycleRegistryState,
    control: &Arc<FiberControl>,
    provider_plans: &[ProvisionalProviderPlan],
) -> Vec<Arc<FiberControl>> {
    let mut controls = controls_locked(state)
        .into_iter()
        .filter(|candidate| {
            !Arc::ptr_eq(candidate, control)
                && provider_plans.iter().any(|plan| {
                    candidate.namespace == plan.key.namespace
                        && candidate
                            .factory
                            .inject()
                            .iter()
                            .any(|inject| inject == &plan.key.key)
                })
        })
        .collect::<Vec<_>>();
    controls.sort_by_key(|control| control.fiber.uid());
    controls
}

fn provider_observations_with_provisional_locked(
    state: &LifecycleRegistryState,
    control: &FiberControl,
    provider_plans: &[ProvisionalProviderPlan],
) -> Option<Vec<ProviderObservation>> {
    control
        .factory
        .inject()
        .iter()
        .map(|key| {
            let provider_key = RuntimeProviderKey::new(&control.namespace, key);
            if let Some(plan) = provider_plans.iter().find(|plan| plan.key == provider_key) {
                let owner = resolve_provider_observation_owner_locked(
                    state,
                    &plan.record.owner_binding,
                    true,
                )?;
                Some(ProviderObservation {
                    key: provider_key,
                    value: plan.record.value.clone(),
                    guard: plan.record.guard.clone(),
                    provider_id: plan.record.provider_id,
                    owner_uid: plan.record.owner.uid(),
                    owner,
                    generation: plan.record.generation,
                    revision: plan.revision,
                    removal_serial: plan.removal_serial,
                })
            } else {
                provider_observation_locked(state, &control.namespace, key)
            }
        })
        .collect()
}

fn evaluate_provider_guards(
    registry_id: u64,
    control: &FiberControl,
    observations: &[ProviderObservation],
) -> (bool, Option<CordisError>) {
    for observation in observations {
        match invoke_provider_guard(registry_id, observation) {
            ProviderGuardOutcome::Allowed => {}
            ProviderGuardOutcome::Rejected => return (false, None),
            ProviderGuardOutcome::Error(source) => {
                return (
                    false,
                    Some(CordisError::ProviderGuard {
                        namespace: control.namespace.clone(),
                        key: observation.key.key.clone(),
                        source: Box::new(source),
                    }),
                );
            }
            ProviderGuardOutcome::Panicked(message) => {
                return (
                    false,
                    Some(CordisError::ProviderGuard {
                        namespace: control.namespace.clone(),
                        key: observation.key.key.clone(),
                        source: Box::new(CordisError::PluginCallbackPanicked { message }),
                    }),
                );
            }
            ProviderGuardOutcome::Recursive => {
                return (
                    false,
                    Some(CordisError::ProviderGuard {
                        namespace: control.namespace.clone(),
                        key: observation.key.key.clone(),
                        source: Box::new(CordisError::PayloadType {
                            name: "recursive provider guard".to_string(),
                        }),
                    }),
                );
            }
        }
    }
    (true, None)
}

fn provider_guard_allows(registry_id: u64, observation: &ProviderObservation) -> bool {
    matches!(
        invoke_provider_guard(registry_id, observation),
        ProviderGuardOutcome::Allowed
    )
}

enum ProviderGuardOutcome {
    Allowed,
    Rejected,
    Error(CordisError),
    Panicked(String),
    Recursive,
}

#[derive(Clone, PartialEq, Eq)]
struct ProviderGuardKey {
    registry_id: u64,
    key: RuntimeProviderKey,
}

thread_local! {
    static PROVIDER_GUARD_STACK: RefCell<ProviderGuardStack> = const {
        RefCell::new(ProviderGuardStack {
            keys: Vec::new(),
            recursive: false,
        })
    };
}

struct ProviderGuardStack {
    keys: Vec<ProviderGuardKey>,
    recursive: bool,
}

struct ProviderGuardScope(ProviderGuardKey);

impl ProviderGuardScope {
    fn enter(registry_id: u64, key: &RuntimeProviderKey) -> Option<Self> {
        let guard_key = ProviderGuardKey {
            registry_id,
            key: key.clone(),
        };
        PROVIDER_GUARD_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.keys.contains(&guard_key) {
                stack.recursive = true;
                None
            } else {
                stack.keys.push(guard_key.clone());
                Some(Self(guard_key))
            }
        })
    }
}

impl Drop for ProviderGuardScope {
    fn drop(&mut self) {
        PROVIDER_GUARD_STACK.with(|stack| {
            let mut stack = stack.borrow_mut();
            if stack.keys.last() == Some(&self.0) {
                stack.keys.pop();
            } else if let Some(position) = stack.keys.iter().rposition(|key| key == &self.0) {
                stack.keys.remove(position);
            }
            if stack.keys.is_empty() {
                stack.recursive = false;
            }
        });
    }
}

fn invoke_provider_guard(
    registry_id: u64,
    observation: &ProviderObservation,
) -> ProviderGuardOutcome {
    let Some(guard) = &observation.guard else {
        return ProviderGuardOutcome::Allowed;
    };
    let Some(_scope) = ProviderGuardScope::enter(registry_id, &observation.key) else {
        return ProviderGuardOutcome::Recursive;
    };
    let outcome = match catch_unwind(AssertUnwindSafe(|| guard(&observation.value))) {
        Ok(Ok(true)) => ProviderGuardOutcome::Allowed,
        Ok(Ok(false)) => ProviderGuardOutcome::Rejected,
        Ok(Err(error)) => ProviderGuardOutcome::Error(error),
        Err(payload) => ProviderGuardOutcome::Panicked(panic_payload_message(payload.as_ref())),
    };
    if PROVIDER_GUARD_STACK.with(|stack| stack.borrow().recursive) {
        ProviderGuardOutcome::Recursive
    } else {
        outcome
    }
}

fn preflight_provider_removal(
    state: &LifecycleRegistryState,
    provider_key: &RuntimeProviderKey,
    handle: &LifecycleProviderHandle,
) -> Result<(u64, u64, u64), CordisError> {
    let Some(slot) = state.providers.get(provider_key) else {
        return Err(CordisError::ProviderNotFound {
            namespace: handle.namespace.clone(),
            key: handle.key.clone(),
        });
    };
    let Some(record) = slot.record.as_ref() else {
        return Err(CordisError::ProviderNotFound {
            namespace: handle.namespace.clone(),
            key: handle.key.clone(),
        });
    };
    if record.provider_id != handle.provider_id
        || record.owner.uid() != handle.owner_uid
        || record.generation != handle.generation
    {
        return Err(CordisError::StaleProviderHandle {
            key: handle.key.clone(),
        });
    }
    let overflow = || CordisError::ProviderGenerationOverflow {
        key: handle.key.clone(),
    };
    let removal_serial = slot.removal_serial.checked_add(1).ok_or_else(&overflow)?;
    let marked_revision = slot.revision.checked_add(1).ok_or_else(&overflow)?;
    let completed_revision = marked_revision.checked_add(1).ok_or_else(overflow)?;
    Ok((removal_serial, marked_revision, completed_revision))
}

fn provider_owner_is_one_of(owner: &RuntimeProviderOwner, controls: &[Arc<FiberControl>]) -> bool {
    match owner {
        RuntimeProviderOwner::Root => false,
        RuntimeProviderOwner::Managed { control, .. } => control.upgrade().is_some_and(|owner| {
            controls
                .iter()
                .any(|candidate| Arc::ptr_eq(candidate, &owner))
        }),
    }
}

fn provider_observation_locked(
    state: &LifecycleRegistryState,
    namespace: &str,
    key: &str,
) -> Option<ProviderObservation> {
    if state.shutting_down {
        return None;
    }
    let provider_key = RuntimeProviderKey::new(namespace, key);
    let slot = state.providers.get(&provider_key)?;
    let record = slot.record.as_ref()?;
    if record.removing {
        return None;
    }
    let owner = resolve_provider_observation_owner_locked(state, &record.owner_binding, false)?;
    Some(ProviderObservation {
        key: provider_key,
        value: record.value.clone(),
        guard: record.guard.clone(),
        provider_id: record.provider_id,
        owner_uid: record.owner.uid(),
        owner,
        generation: record.generation,
        revision: slot.revision,
        removal_serial: slot.removal_serial,
    })
}

fn resolve_provider_observation_owner_locked(
    state: &LifecycleRegistryState,
    owner: &RuntimeProviderOwner,
    activation_owner: bool,
) -> Option<ProviderObservationOwner> {
    match owner {
        RuntimeProviderOwner::Root => Some(ProviderObservationOwner::Root),
        RuntimeProviderOwner::Managed {
            control,
            runtime_generation,
        } => {
            let control = control.upgrade()?;
            if control.runtime_generation != *runtime_generation
                || !control_is_registered_locked(state, &control)
                || control.driver_runtime.require_alive().is_err()
            {
                return None;
            }
            let machine = lock(&control.machine);
            let valid = !machine.tombstone
                && if activation_owner {
                    machine.state == FiberState::Loading
                } else {
                    machine.state == FiberState::Active
                };
            drop(machine);
            valid.then_some(ProviderObservationOwner::Managed {
                control,
                runtime_generation: *runtime_generation,
                activation_owner,
            })
        }
    }
}

fn provider_observations_are_current(
    state: &LifecycleRegistryState,
    observations: &[ProviderObservation],
) -> bool {
    !state.shutting_down
        && observations.iter().all(|observation| {
            state.providers.get(&observation.key).is_some_and(|slot| {
                slot.revision == observation.revision
                    && slot.removal_serial == observation.removal_serial
                    && slot.record.as_ref().is_some_and(|record| {
                        !record.removing
                            && record.provider_id == observation.provider_id
                            && record.owner.uid() == observation.owner_uid
                            && record.generation == observation.generation
                            && provider_record_matches_observation_owner(record, observation)
                            && provider_observation_owner_is_current_locked(state, observation)
                    })
            })
        })
}

fn provider_record_matches_observation_owner(
    record: &RuntimeProviderRecord,
    observation: &ProviderObservation,
) -> bool {
    match (&record.owner_binding, &observation.owner) {
        (RuntimeProviderOwner::Root, ProviderObservationOwner::Root) => true,
        (
            RuntimeProviderOwner::Managed {
                control: record_control,
                runtime_generation: record_generation,
            },
            ProviderObservationOwner::Managed {
                control,
                runtime_generation,
                ..
            },
        ) => {
            record_generation == runtime_generation
                && record_control
                    .upgrade()
                    .is_some_and(|registered| Arc::ptr_eq(&registered, control))
        }
        _ => false,
    }
}

fn provider_observation_owner_is_current_locked(
    state: &LifecycleRegistryState,
    observation: &ProviderObservation,
) -> bool {
    match &observation.owner {
        ProviderObservationOwner::Root => true,
        ProviderObservationOwner::Managed {
            control,
            runtime_generation,
            activation_owner,
        } => {
            if control.runtime_generation != *runtime_generation
                || !control_is_registered_locked(state, control)
                || control.driver_runtime.require_alive().is_err()
            {
                return false;
            }
            let machine = lock(&control.machine);
            !machine.tombstone
                && if *activation_owner {
                    machine.state == FiberState::Loading
                } else {
                    machine.state == FiberState::Active
                }
        }
    }
}

struct ActivationCollectorState {
    ticket_serial: u64,
    closed: bool,
    pending: Vec<LifecycleEffect>,
    groups: Vec<Vec<LifecycleDisposer>>,
    metadata: ConfigValue,
    providers: Vec<ProvisionalProvider>,
    mounts: Vec<ProvisionalMount>,
}

struct ActivationCollector {
    fiber_uid: FiberUid,
    epoch: ActivationEpoch,
    state: Mutex<ActivationCollectorState>,
}

#[derive(Clone)]
struct ProvisionalProvider {
    namespace: String,
    key: String,
    value: ProviderValue,
    guard: Option<ProviderGuard>,
}

#[derive(Clone)]
struct ProvisionalMount {
    fiber: Fiber,
    factory: PluginFactory,
    config: ConfigValue,
}

struct FinishedActivation {
    ticket_serial: u64,
    groups: Vec<Vec<LifecycleDisposer>>,
    metadata: ConfigValue,
    providers: Vec<ProvisionalProvider>,
    mounts: Vec<ProvisionalMount>,
}

impl ActivationCollector {
    fn new(
        fiber_uid: FiberUid,
        epoch: ActivationEpoch,
        ticket_serial: u64,
        metadata: ConfigValue,
    ) -> Self {
        Self {
            fiber_uid,
            epoch,
            state: Mutex::new(ActivationCollectorState {
                ticket_serial,
                closed: false,
                pending: Vec::new(),
                groups: Vec::new(),
                metadata,
                providers: Vec::new(),
                mounts: Vec::new(),
            }),
        }
    }

    fn enqueue_driver(&self, effect: LifecycleEffect) -> Result<(), CordisError> {
        let mut state = lock(&self.state);
        if state.closed {
            return Err(CordisError::StaleLifecycleView {
                uid: self.fiber_uid,
            });
        }
        state.pending.push(effect);
        Ok(())
    }

    fn drain_or_close(&self) -> Option<Vec<LifecycleEffect>> {
        let mut state = lock(&self.state);
        if state.pending.is_empty() {
            state.closed = true;
            None
        } else {
            Some(std::mem::take(&mut state.pending))
        }
    }

    fn push_group(&self, group: Vec<LifecycleDisposer>) {
        if !group.is_empty() {
            lock(&self.state).groups.push(group);
        }
    }

    fn finish(&self) -> FinishedActivation {
        let mut state = lock(&self.state);
        state.closed = true;
        FinishedActivation {
            ticket_serial: state.ticket_serial,
            groups: std::mem::take(&mut state.groups),
            metadata: state.metadata.clone(),
            providers: std::mem::take(&mut state.providers),
            mounts: std::mem::take(&mut state.mounts),
        }
    }
}

/// Owned activation view. Clones are valid only for the current activation
/// collector and fail closed once that activation commits or unloads.
#[derive(Clone)]
pub struct LifecycleContextView {
    registry: Weak<LifecycleRegistryInner>,
    control: Weak<FiberControl>,
    fiber: Fiber,
    namespace: String,
    runtime_generation: u64,
    collector: Arc<ActivationCollector>,
}

impl fmt::Debug for LifecycleContextView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleContextView")
            .field("fiber", &self.fiber)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl LifecycleContextView {
    #[must_use]
    pub fn fiber(&self) -> Fiber {
        self.fiber.clone()
    }

    #[must_use]
    pub fn var(&self, key: &str) -> Option<ConfigValue> {
        self.with_activation_read(|collector| collector.metadata.lookup(key).cloned())
            .ok()
            .flatten()
    }

    pub fn set_var(
        &self,
        key: impl Into<String>,
        value: impl Into<ConfigValue>,
    ) -> Result<(), CordisError> {
        let key = key.into();
        let value = value.into();
        self.with_activation_write(|_, _, state| {
            match &mut state.metadata {
                ConfigValue::Object(map) => {
                    map.insert(key, value);
                }
                metadata => *metadata = ConfigValue::object([(key, value)]),
            }
            Ok(())
        })
    }

    pub fn effect(&self, effect: LifecycleEffect) -> Result<(), CordisError> {
        self.with_activation_write(|_, _, state| {
            state.pending.push(effect);
            Ok(())
        })
    }

    pub fn provide<T: Any + Send + Sync>(
        &self,
        key: impl Into<String>,
        value: T,
    ) -> Result<(), CordisError> {
        let key = key.into();
        let namespace = self.namespace.clone();
        let value: ProviderValue = Arc::new(value);
        self.with_activation_write(move |registry, _, state| {
            let provider_key = RuntimeProviderKey::new(&namespace, &key);
            if state
                .providers
                .iter()
                .any(|provider| provider.namespace == namespace && provider.key == key)
                || registry
                    .providers
                    .get(&provider_key)
                    .and_then(|slot| slot.record.as_ref())
                    .is_some()
            {
                return Err(CordisError::DuplicateProvider { namespace, key });
            }
            state.providers.push(ProvisionalProvider {
                namespace,
                key,
                value,
                guard: None,
            });
            Ok(())
        })
    }

    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        let (inner, control) = self.authority().ok()?;
        let observation = {
            let registry = lock(&inner.state);
            let observation = provider_observation_locked(&registry, &self.namespace, key)?;
            let machine = lock(&control.machine);
            let collector = lock(&self.collector.state);
            self.activation_is_valid_locked(&registry, &control, &machine, &collector)
                .then_some(observation)?
        };
        if !provider_guard_allows(inner.id, &observation) {
            return None;
        }
        let registry = lock(&inner.state);
        if !provider_observations_are_current(&registry, std::slice::from_ref(&observation)) {
            return None;
        }
        let machine = lock(&control.machine);
        let collector = lock(&self.collector.state);
        if !self.activation_is_valid_locked(&registry, &control, &machine, &collector) {
            return None;
        }
        observation.value.downcast::<T>().ok()
    }

    pub fn mount(&self, factory: PluginFactory, config: ConfigValue) -> Result<Fiber, CordisError> {
        if !factory.supports_lifecycle() {
            return Err(CordisError::LifecycleFactoryRequired {
                id: factory.plugin_id().clone(),
            });
        }
        let child = Fiber::child_with_namespace(
            self.fiber.context_id(),
            &self.fiber,
            self.namespace.clone(),
        );
        let provisional = ProvisionalMount {
            fiber: child.clone(),
            factory,
            config,
        };
        self.with_activation_write(move |_, _, state| {
            state.mounts.push(provisional);
            Ok(())
        })?;
        Ok(child)
    }

    fn authority(&self) -> Result<(Arc<LifecycleRegistryInner>, Arc<FiberControl>), CordisError> {
        let inner = self
            .registry
            .upgrade()
            .ok_or(CordisError::StaleLifecycleView {
                uid: self.fiber.uid(),
            })?;
        let control = self
            .control
            .upgrade()
            .ok_or(CordisError::StaleLifecycleView {
                uid: self.fiber.uid(),
            })?;
        if inner.id != self.fiber.context_id()
            || control.fiber.uid() != self.fiber.uid()
            || control.namespace != self.namespace
            || control.runtime_generation != self.runtime_generation
        {
            return Err(CordisError::StaleLifecycleView {
                uid: self.fiber.uid(),
            });
        }
        Ok((inner, control))
    }

    fn activation_is_valid_locked(
        &self,
        registry: &LifecycleRegistryState,
        control: &Arc<FiberControl>,
        machine: &FiberMachine,
        collector: &ActivationCollectorState,
    ) -> bool {
        !registry.shutting_down
            && registry
                .runtimes
                .get(&control.factory.id())
                .filter(|runtime| runtime.generation == self.runtime_generation)
                .and_then(|runtime| runtime.fibers.get(&self.fiber.uid()))
                .is_some_and(|registered| Arc::ptr_eq(registered, control))
            && !machine.tombstone
            && machine.state == FiberState::Loading
            && machine.desired.as_ref() == Some(&self.collector.epoch)
            && machine
                .current_ticket
                .as_ref()
                .is_some_and(|ticket| ticket.serial() == collector.ticket_serial)
            && machine
                .active_activation
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, &self.collector))
            && !collector.closed
    }

    fn with_activation_read<R>(
        &self,
        read: impl FnOnce(&ActivationCollectorState) -> R,
    ) -> Result<R, CordisError> {
        let (inner, control) = self.authority()?;
        let registry = lock(&inner.state);
        let machine = lock(&control.machine);
        let collector = lock(&self.collector.state);
        if !self.activation_is_valid_locked(&registry, &control, &machine, &collector) {
            return Err(CordisError::StaleLifecycleView {
                uid: self.fiber.uid(),
            });
        }
        Ok(read(&collector))
    }

    fn with_activation_write<R>(
        &self,
        write: impl FnOnce(
            &mut LifecycleRegistryState,
            &mut FiberMachine,
            &mut ActivationCollectorState,
        ) -> Result<R, CordisError>,
    ) -> Result<R, CordisError> {
        let (inner, control) = self.authority()?;

        // Global lock order is registry -> machine -> collector.  Runtime
        // membership, ticket/state validity, and the write therefore
        // linearize together; no validate-then-write gap is exposed.
        let mut registry = lock(&inner.state);
        let mut machine = lock(&control.machine);
        let mut collector = lock(&self.collector.state);
        if !self.activation_is_valid_locked(&registry, &control, &machine, &collector) {
            return Err(CordisError::StaleLifecycleView {
                uid: self.fiber.uid(),
            });
        }
        write(&mut registry, &mut machine, &mut collector)
    }
}

struct FiberMachine {
    config: ConfigValue,
    config_revision: u64,
    desired: Option<ActivationEpoch>,
    committed: Option<ActivationEpoch>,
    next_ticket: u64,
    current_ticket: Option<TransitionTicket>,
    settled_ticket: u64,
    state: FiberState,
    error: Option<CordisError>,
    diagnostics: Vec<CordisError>,
    effects: Vec<Vec<LifecycleDisposer>>,
    effects_epoch: Option<ActivationEpoch>,
    force_restart: bool,
    tombstone: bool,
    history: Vec<FiberState>,
    baseline_metadata: ConfigValue,
    metadata: ConfigValue,
    active_activation: Option<Arc<ActivationCollector>>,
}

impl FiberMachine {
    fn snapshot(&self) -> FiberSnapshot {
        FiberSnapshot::new(
            self.state,
            self.current_ticket.clone(),
            self.committed.clone(),
            self.error.clone(),
            self.diagnostics.clone(),
        )
    }

    fn preflight_next_ticket(&self) -> Result<u64, CordisError> {
        self.next_ticket
            .checked_add(1)
            .ok_or(CordisError::TransitionTicketOverflow)
    }

    fn publish_ticket(&mut self, serial: u64) -> TransitionTicket {
        self.next_ticket = serial;
        let ticket = TransitionTicket::new(serial, self.desired.clone());
        self.current_ticket = Some(ticket.clone());
        ticket
    }
}

struct FiberControl {
    self_weak: Weak<FiberControl>,
    registry: Weak<LifecycleRegistryInner>,
    fiber: Fiber,
    parent_uid: FiberUid,
    factory: PluginFactory,
    runtime_generation: u64,
    driver_runtime: DriverRuntimeBinding,
    namespace: String,
    machine: Mutex<FiberMachine>,
    wake: Notify,
    snapshots: watch::Sender<FiberSnapshot>,
}

impl FiberControl {
    fn new(
        registry: Weak<LifecycleRegistryInner>,
        fiber: Fiber,
        parent_uid: FiberUid,
        factory: PluginFactory,
        runtime_generation: u64,
        driver_runtime: DriverRuntimeBinding,
        config: ConfigValue,
    ) -> Arc<Self> {
        let initial = FiberSnapshot::new(FiberState::Pending, None, None, None, Vec::new());
        let (snapshots, _) = watch::channel(initial);
        Arc::new_cyclic(|self_weak| Self {
            self_weak: self_weak.clone(),
            registry,
            namespace: fiber.namespace(),
            fiber,
            parent_uid,
            factory,
            runtime_generation,
            driver_runtime,
            machine: Mutex::new(FiberMachine {
                config,
                config_revision: 0,
                desired: None,
                committed: None,
                next_ticket: 0,
                current_ticket: None,
                settled_ticket: 0,
                state: FiberState::Pending,
                error: None,
                diagnostics: Vec::new(),
                effects: Vec::new(),
                effects_epoch: None,
                force_restart: false,
                tombstone: false,
                history: vec![FiberState::Pending],
                baseline_metadata: ConfigValue::default(),
                metadata: ConfigValue::default(),
                active_activation: None,
            }),
            wake: Notify::new(),
            snapshots,
        })
    }

    #[cfg(test)]
    fn set_desired_locked(
        &self,
        machine: &mut FiberMachine,
        desired: Option<ActivationEpoch>,
        diagnostic: Option<CordisError>,
    ) -> Result<(bool, u64), CordisError> {
        let next_ticket = Self::preflight_desired_locked(machine, desired.as_ref())?;
        Ok(self.publish_desired_locked(machine, desired, diagnostic, next_ticket))
    }

    fn preflight_desired_locked(
        machine: &FiberMachine,
        desired: Option<&ActivationEpoch>,
    ) -> Result<Option<u64>, CordisError> {
        (machine.desired.as_ref() != desired)
            .then(|| machine.preflight_next_ticket())
            .transpose()
    }

    #[cfg(test)]
    fn publish_desired_locked(
        &self,
        machine: &mut FiberMachine,
        desired: Option<ActivationEpoch>,
        diagnostic: Option<CordisError>,
        next_ticket: Option<u64>,
    ) -> (bool, u64) {
        let result = Self::apply_desired_locked(machine, desired, diagnostic, next_ticket);
        self.publish_locked(machine);
        result
    }

    fn apply_desired_locked(
        machine: &mut FiberMachine,
        desired: Option<ActivationEpoch>,
        diagnostic: Option<CordisError>,
        next_ticket: Option<u64>,
    ) -> (bool, u64) {
        if let Some(diagnostic) = diagnostic
            && !machine.diagnostics.contains(&diagnostic)
        {
            machine.diagnostics.push(diagnostic);
        }
        let changed = next_ticket.is_some();
        if let Some(next_ticket) = next_ticket {
            machine.desired = desired;
            let ticket = machine.publish_ticket(next_ticket);
            if machine.state == FiberState::Loading
                && let Some(active) = machine.active_activation.as_ref()
                && machine.desired.as_ref() == Some(&active.epoch)
            {
                let mut collector = lock(&active.state);
                if !collector.closed {
                    collector.ticket_serial = ticket.serial();
                }
            }
        }
        let serial = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        (changed, serial)
    }

    fn transition_locked(&self, machine: &mut FiberMachine, state: FiberState) {
        Self::apply_transition_state_locked(machine, state);
        self.publish_locked(machine);
    }

    fn apply_transition_state_locked(machine: &mut FiberMachine, state: FiberState) {
        if machine.state != state {
            machine.state = state;
            machine.history.push(state);
        }
    }

    fn publish_locked(&self, machine: &FiberMachine) {
        self.snapshots.send_replace(machine.snapshot());
    }

    fn publish_deferred(&self, candidate: FiberSnapshot) {
        let candidate_serial = candidate.ticket().map_or(0, TransitionTicket::serial);
        self.snapshots.send_if_modified(move |current| {
            let current_serial = current.ticket().map_or(0, TransitionTicket::serial);
            let same_ticket_completion = candidate_serial == current_serial
                && current.state() == FiberState::Loading
                && matches!(candidate.state(), FiberState::Active | FiberState::Failed);
            if candidate_serial < current_serial
                || (candidate_serial == current_serial && !same_ticket_completion)
            {
                return false;
            }
            *current = candidate;
            true
        });
    }

    fn publish_terminal(&self, terminal: FiberSnapshot) {
        debug_assert_eq!(terminal.state(), FiberState::Disposed);
        // Quarantine sets the exact machine to Disposed and detaches it from
        // registry command authority while holding the registry + machine
        // guards. No newer ticket can be issued after that linearization
        // point, so a direct terminal watch publication is monotonic and
        // wakes waiters even when it settles the current ticket in place.
        self.snapshots.send_replace(terminal);
    }

    fn publish_recovery_state(&self, snapshot: FiberSnapshot) {
        debug_assert!(matches!(
            snapshot.state(),
            FiberState::Unloading | FiberState::Disposed
        ));
        // Recovery has already set the exact machine tombstone while holding
        // registry + uid-ordered machine guards. That permanently closes the
        // command side of this control, so publishing an in-place terminal
        // transition at the current ticket cannot be overtaken by a newer
        // ticket. `publish_deferred` intentionally rejects this same-ticket
        // shape, hence the dedicated monotonic terminal-recovery channel.
        self.snapshots.send_replace(snapshot);
    }

    fn request_restart(&self) -> Result<u64, CordisError> {
        if !self.factory.is_repeatable() {
            return Err(CordisError::NonRepeatableFactory {
                ids: vec![self.factory.plugin_id().clone()],
            });
        }
        let serial = {
            let mut machine = lock(&self.machine);
            if machine.tombstone {
                return Err(CordisError::FiberDisposed {
                    uid: self.fiber.uid(),
                });
            }
            let next_ticket = machine.preflight_next_ticket()?;
            machine.force_restart = true;
            machine.publish_ticket(next_ticket).serial()
        };
        self.wake.notify_one();
        Ok(serial)
    }

    fn request_update(&self, config: ConfigValue) -> Result<u64, CordisError> {
        if !self.factory.is_repeatable() {
            return Err(CordisError::NonRepeatableFactory {
                ids: vec![self.factory.plugin_id().clone()],
            });
        }
        let serial = {
            let mut machine = lock(&self.machine);
            if machine.tombstone {
                return Err(CordisError::FiberDisposed {
                    uid: self.fiber.uid(),
                });
            }
            let config_revision = machine
                .config_revision
                .checked_add(1)
                .ok_or(CordisError::ConfigRevisionOverflow)?;
            let next_ticket = machine.preflight_next_ticket()?;
            machine.config_revision = config_revision;
            machine.config = config;
            machine.error = None;
            machine.force_restart = true;
            if let Some(desired) = &machine.desired {
                machine.desired = Some(ActivationEpoch::new(
                    config_revision,
                    desired.dependencies().iter().cloned(),
                ));
            }
            let serial = machine.publish_ticket(next_ticket).serial();
            self.publish_locked(&machine);
            serial
        };
        self.wake.notify_one();
        Ok(serial)
    }

    fn request_dispose(&self) -> Result<u64, CordisError> {
        let (changed, serial) = {
            let mut machine = lock(&self.machine);
            let next_ticket = Self::preflight_dispose_locked(&machine)?;
            self.publish_dispose_locked(&mut machine, next_ticket)
        };
        if changed {
            self.wake.notify_one();
        }
        Ok(serial)
    }

    fn preflight_dispose_locked(machine: &FiberMachine) -> Result<Option<u64>, CordisError> {
        (!machine.tombstone)
            .then(|| machine.preflight_next_ticket())
            .transpose()
    }

    fn publish_dispose_locked(
        &self,
        machine: &mut FiberMachine,
        next_ticket: Option<u64>,
    ) -> (bool, u64) {
        let result = self.apply_dispose_locked(machine, next_ticket);
        if result.0 {
            self.publish_locked(machine);
        }
        result
    }

    fn apply_dispose_locked(
        &self,
        machine: &mut FiberMachine,
        next_ticket: Option<u64>,
    ) -> (bool, u64) {
        let changed = next_ticket.is_some();
        if let Some(next_ticket) = next_ticket {
            machine.tombstone = true;
            machine.desired = None;
            self.fiber.publish_tombstone();
            machine.publish_ticket(next_ticket);
        }
        let serial = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        (changed, serial)
    }

    async fn await_ticket(&self, serial: u64) -> Result<FiberSnapshot, CordisError> {
        let mut snapshots = self.snapshots.subscribe();
        loop {
            let result = {
                let machine = lock(&self.machine);
                (machine.settled_ticket >= serial).then(|| machine.snapshot())
            };
            if let Some(snapshot) = result {
                if let Some(error) = snapshot.error() {
                    return Err(error.clone());
                }
                return Ok(snapshot);
            }
            if snapshots.changed().await.is_err() {
                return Ok(self.snapshot());
            }
        }
    }

    async fn await_current_inner(&self) -> Result<FiberSnapshot, CordisError> {
        let (serial, immediate) = {
            let machine = lock(&self.machine);
            let serial = machine
                .current_ticket
                .as_ref()
                .map_or(0, TransitionTicket::serial);
            let immediate = machine.current_ticket.is_none()
                || machine.settled_ticket >= serial
                || machine.state == FiberState::Disposed;
            (serial, immediate.then(|| machine.snapshot()))
        };
        if let Some(snapshot) = immediate {
            if let Some(error) = snapshot.error() {
                return Err(error.clone());
            }
            return Ok(snapshot);
        }
        self.await_ticket(serial).await
    }
}

impl FiberLifecycle for FiberControl {
    fn snapshot(&self) -> FiberSnapshot {
        lock(&self.machine).snapshot()
    }

    fn is_tombstoned(&self) -> bool {
        lock(&self.machine).tombstone
    }

    fn state_history(&self) -> Vec<FiberState> {
        lock(&self.machine).history.clone()
    }

    fn await_current(&self) -> FiberFuture<Result<FiberSnapshot, CordisError>> {
        let control = self.self_weak.clone();
        let uid = self.fiber.uid();
        Box::pin(async move {
            let control = control
                .upgrade()
                .ok_or(CordisError::FiberRuntimeUnavailable { uid })?;
            control.await_current_inner().await
        })
    }

    fn wait_until_active(
        &self,
        cancellation: LifecycleCancellation,
    ) -> FiberFuture<Result<FiberSnapshot, CordisError>> {
        let control = self.self_weak.clone();
        let uid = self.fiber.uid();
        Box::pin(async move {
            let control = control
                .upgrade()
                .ok_or(CordisError::FiberRuntimeUnavailable { uid })?;
            let mut snapshots = control.snapshots.subscribe();
            loop {
                let snapshot = control.snapshot();
                match snapshot.state() {
                    FiberState::Active => return Ok(snapshot),
                    FiberState::Failed => {
                        return Err(snapshot.error().cloned().unwrap_or(
                            CordisError::PluginActivation {
                                id: control.factory.id(),
                                source: Box::new(CordisError::FiberDisposed {
                                    uid: control.fiber.uid(),
                                }),
                            },
                        ));
                    }
                    FiberState::Disposed => {
                        return Err(CordisError::FiberDisposed {
                            uid: control.fiber.uid(),
                        });
                    }
                    FiberState::Pending | FiberState::Loading | FiberState::Unloading => {}
                }
                tokio::select! {
                    changed = snapshots.changed() => {
                        if changed.is_err() {
                            return Err(CordisError::FiberDisposed { uid: control.fiber.uid() });
                        }
                    }
                    () = cancellation.cancelled() => {
                        return Err(CordisError::WaitCancelled { uid: control.fiber.uid() });
                    }
                }
            }
        })
    }
}

impl FiberControl {
    async fn restart_and_wait(self: &Arc<Self>) -> Result<FiberSnapshot, CordisError> {
        let serial = self.request_restart()?;
        self.await_ticket(serial).await
    }

    async fn update_and_wait(
        self: &Arc<Self>,
        config: ConfigValue,
    ) -> Result<FiberSnapshot, CordisError> {
        let serial = self.request_update(config)?;
        self.await_ticket(serial).await
    }

    async fn dispose_and_wait(self: &Arc<Self>) -> Result<FiberSnapshot, CordisError> {
        let serial = self.request_dispose()?;
        self.await_ticket(serial).await
    }
}

fn preflight_dispose_batch(
    machines: &[std::sync::MutexGuard<'_, FiberMachine>],
) -> Result<Vec<Option<u64>>, CordisError> {
    machines
        .iter()
        .map(|machine| FiberControl::preflight_dispose_locked(machine))
        .collect()
}

fn publish_dispose_batch(
    controls: &[Arc<FiberControl>],
    machines: &mut [std::sync::MutexGuard<'_, FiberMachine>],
    next_tickets: Vec<Option<u64>>,
) -> FiberTicketBatch {
    let mut waits = Vec::with_capacity(controls.len());
    let mut publications = Vec::new();
    let mut notifications = Vec::new();
    for ((control, machine), next_ticket) in controls.iter().zip(machines).zip(next_tickets) {
        let (changed, serial) = control.apply_dispose_locked(machine, next_ticket);
        waits.push((control.clone(), serial));
        if changed {
            publications.push((control.clone(), machine.snapshot()));
            notifications.push(control.clone());
        }
    }
    FiberTicketBatch {
        waits,
        publications,
        notifications,
    }
}

fn publish_deferred_batch(
    publications: Vec<FiberPublication>,
    notifications: Vec<Arc<FiberControl>>,
) {
    for (control, snapshot) in publications {
        control.publish_deferred(snapshot);
    }
    for control in notifications {
        control.wake.notify_one();
    }
}

enum DriveAction {
    Cleanup(Vec<Vec<LifecycleDisposer>>),
    Start {
        epoch: ActivationEpoch,
        config: ConfigValue,
        collector: Arc<ActivationCollector>,
    },
    Idle,
    Terminal,
}

fn run_fiber(control: Arc<FiberControl>) -> BoxFuture<'static, ()> {
    async move {
        loop {
            control.wake.notified().await;
            loop {
                let action = next_action(&control);
                match action {
                    DriveAction::Cleanup(groups) => {
                        let errors = cleanup_groups(groups).await;
                        if !errors.is_empty() {
                            let mut machine = lock(&control.machine);
                            machine.diagnostics.extend(errors);
                            control.publish_locked(&machine);
                        }
                    }
                    DriveAction::Start {
                        epoch,
                        config,
                        collector,
                    } => {
                        let result = start_activation(&control, &collector, config, &epoch).await;
                        let finished = collector.finish();
                        let spawned =
                            finish_activation(&control, &collector, &epoch, result, finished);
                        for child in spawned {
                            tokio::spawn(run_fiber(child.clone()));
                            if let Some(inner) = child.registry.upgrade() {
                                let _ = LifecycleRegistry { inner }.reconcile_control(&child);
                            }
                        }
                    }
                    DriveAction::Idle => break,
                    DriveAction::Terminal => {
                        let (snapshot, history) = {
                            let machine = lock(&control.machine);
                            (machine.snapshot(), machine.history.clone())
                        };
                        control.fiber.freeze_terminal(snapshot, history);
                        if let Some(inner) = control.registry.upgrade() {
                            LifecycleRegistry { inner }.remove_terminal_child(
                                control.factory.id(),
                                control.runtime_generation,
                                control.fiber.uid(),
                            );
                        }
                        return;
                    }
                }
            }
        }
    }
    .boxed()
}

fn finish_activation(
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    result: Result<(), CordisError>,
    finished: FinishedActivation,
) -> Vec<Arc<FiberControl>> {
    let Some(inner) = control.registry.upgrade() else {
        let FinishedActivation { groups, mounts, .. } = finished;
        let mut machine = lock(&control.machine);
        retain_effect_groups(&mut machine, epoch, groups);
        machine.active_activation = None;
        machine.tombstone = true;
        control.transition_locked(&mut machine, FiberState::Disposed);
        drop(machine);
        dispose_provisional_mounts(mounts);
        return Vec::new();
    };

    let mut registry = lock(&inner.state);
    let mut machine = lock(&control.machine);
    if !activation_finish_is_exact(&registry, control, &machine, collector, epoch, &finished) {
        let FinishedActivation { groups, mounts, .. } = finished;
        record_stale_activation(control, collector, epoch, &mut machine, groups);
        drop(machine);
        drop(registry);
        dispose_provisional_mounts(mounts);
        return Vec::new();
    }

    if let Err(error) = result {
        let FinishedActivation {
            ticket_serial,
            groups,
            mounts,
            ..
        } = finished;
        record_failed_activation(control, epoch, &mut machine, groups, error, ticket_serial);
        drop(machine);
        drop(registry);
        dispose_provisional_mounts(mounts);
        return Vec::new();
    }

    if !finished.providers.is_empty() {
        drop(machine);
        drop(registry);
        return finish_provider_activation_transaction(&inner, control, collector, epoch, finished);
    }

    let prepared = prepare_activation_commit(&registry, control, &finished);
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let FinishedActivation {
                ticket_serial,
                groups,
                mounts,
                ..
            } = finished;
            record_failed_activation(control, epoch, &mut machine, groups, error, ticket_serial);
            drop(machine);
            drop(registry);
            dispose_provisional_mounts(mounts);
            return Vec::new();
        }
    };

    let spawned = commit_prepared_activation(
        &inner,
        control,
        epoch,
        &mut registry,
        &mut machine,
        finished,
        prepared,
    );
    drop(machine);
    drop(registry);
    spawned
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the registry and uid-ordered machine transaction visibly contiguous"
)]
fn finish_provider_activation_transaction(
    inner: &Arc<LifecycleRegistryInner>,
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    finished: FinishedActivation,
) -> Vec<Arc<FiberControl>> {
    loop {
        let (prepared, drafts) = {
            let registry = lock(&inner.state);
            let machine = lock(&control.machine);
            if !activation_finish_is_exact(
                &registry, control, &machine, collector, epoch, &finished,
            ) {
                drop(machine);
                drop(registry);
                return finish_stale_provider_activation(control, collector, epoch, finished);
            }
            let prepared = match prepare_activation_commit(&registry, control, &finished) {
                Ok(prepared) => prepared,
                Err(error) => {
                    drop(machine);
                    drop(registry);
                    return finish_failed_provider_activation(
                        control, collector, epoch, finished, error,
                    );
                }
            };
            // Staging follows the global registry -> uid-ordered machine
            // order. In particular, provider observation may consult this
            // owner again, so its validation guard cannot remain held here.
            drop(machine);
            let controls = affected_controls_for_provisional_locked(
                &registry,
                control,
                &prepared.provider_plans,
            );
            let drafts = controls
                .into_iter()
                .map(|candidate| {
                    let observations = provider_observations_with_provisional_locked(
                        &registry,
                        &candidate,
                        &prepared.provider_plans,
                    );
                    let (config_revision, tombstone) = {
                        let machine = lock(&candidate.machine);
                        (machine.config_revision, machine.tombstone)
                    };
                    ProviderControlDraft {
                        control: candidate,
                        config_revision,
                        tombstone,
                        observations,
                    }
                })
                .collect::<Vec<_>>();
            (prepared, drafts)
        };
        let outcomes = evaluate_provider_control_drafts(inner.id, drafts);

        let mut registry = lock(&inner.state);
        if !provisional_activation_base_is_current(&registry, &prepared) {
            continue;
        }
        let current_prepared = match prepare_activation_commit(&registry, control, &finished) {
            Ok(current) if prepared_activations_equivalent(&prepared, &current) => current,
            Ok(_) => continue,
            Err(error) => {
                drop(registry);
                return finish_failed_provider_activation(
                    control, collector, epoch, finished, error,
                );
            }
        };
        let affected = affected_controls_for_provisional_locked(
            &registry,
            control,
            &current_prepared.provider_plans,
        );
        if !same_provider_controls(&affected, &outcomes)
            || outcomes.iter().any(|outcome| {
                !provider_observations_equivalent(
                    outcome.draft.observations.as_deref(),
                    provider_observations_with_provisional_locked(
                        &registry,
                        &outcome.draft.control,
                        &current_prepared.provider_plans,
                    )
                    .as_deref(),
                )
            })
        {
            continue;
        }

        let controls = transaction_controls(&affected, &outcomes, std::iter::once(control.clone()));
        let mut machines = controls
            .iter()
            .map(|candidate| lock(&candidate.machine))
            .collect::<Vec<_>>();
        let owner_index = controls
            .iter()
            .position(|candidate| Arc::ptr_eq(candidate, control))
            .expect("activation owner must be part of its commit batch");
        if !activation_finish_is_exact(
            &registry,
            control,
            &machines[owner_index],
            collector,
            epoch,
            &finished,
        ) {
            drop(machines);
            drop(registry);
            return finish_stale_provider_activation(control, collector, epoch, finished);
        }
        if !provider_outcome_owners_are_current_locked(&registry, &controls, &machines, &outcomes) {
            drop(machines);
            drop(registry);
            continue;
        }
        if outcomes.iter().any(|outcome| {
            let Some(index) = controls
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, &outcome.draft.control))
            else {
                return true;
            };
            machines[index].config_revision != outcome.draft.config_revision
                || machines[index].tombstone != outcome.draft.tombstone
        }) {
            drop(machines);
            drop(registry);
            continue;
        }

        let preflight = (|| {
            for candidate in &controls {
                candidate.driver_runtime.require_alive()?;
            }
            outcomes
                .iter()
                .map(|outcome| {
                    let index = controls
                        .iter()
                        .position(|candidate| Arc::ptr_eq(candidate, &outcome.draft.control))
                        .expect("affected control must be part of activation commit batch");
                    if outcome.draft.tombstone {
                        Ok(None)
                    } else {
                        FiberControl::preflight_desired_locked(
                            &machines[index],
                            outcome.desired.as_ref(),
                        )
                    }
                })
                .collect::<Result<Vec<_>, CordisError>>()
        })();
        let next_tickets = match preflight {
            Ok(next_tickets) => next_tickets,
            Err(error) => {
                apply_failed_activation(
                    control,
                    epoch,
                    &mut machines[owner_index],
                    &finished,
                    error,
                );
                let owner_snapshot = machines[owner_index].snapshot();
                drop(machines);
                drop(registry);
                control.publish_deferred(owner_snapshot);
                dispose_provisional_mounts(finished.mounts);
                return Vec::new();
            }
        };

        registry.next_provider_id = current_prepared.next_provider_id;
        registry.next_runtime_generation = current_prepared.next_runtime_generation;
        let mut owner_groups =
            commit_provisional_providers(inner, &mut registry, current_prepared.provider_plans);
        let (mount_groups, spawned) = commit_provisional_mounts(
            inner,
            control,
            &mut registry,
            finished.mounts,
            &current_prepared.runtime_generations,
        );
        owner_groups.extend(mount_groups);

        let mut publications = Vec::new();
        let mut notifications = Vec::new();
        for ((outcome, next_ticket), affected_control) in
            outcomes.iter().zip(next_tickets).zip(&affected)
        {
            let index = controls
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, affected_control))
                .expect("affected control must be part of activation commit batch");
            if outcome.draft.tombstone {
                continue;
            }
            let before = machines[index].snapshot();
            let (changed, _) = FiberControl::apply_desired_locked(
                &mut machines[index],
                outcome.desired.clone(),
                outcome.diagnostic.clone(),
                next_ticket,
            );
            let after = machines[index].snapshot();
            if after != before {
                publications.push((affected_control.clone(), after));
            }
            if changed {
                notifications.push(affected_control.clone());
            }
        }

        let FinishedActivation {
            ticket_serial,
            groups,
            metadata,
            providers: _,
            mounts: _,
        } = finished;
        let owner_machine = &mut machines[owner_index];
        retain_effect_groups(owner_machine, epoch, groups);
        retain_effect_groups(owner_machine, epoch, owner_groups);
        owner_machine.committed = Some(epoch.clone());
        owner_machine.error = None;
        owner_machine.metadata = metadata;
        owner_machine.active_activation = None;
        owner_machine.settled_ticket = ticket_serial;
        FiberControl::apply_transition_state_locked(owner_machine, FiberState::Active);
        let owner_snapshot = owner_machine.snapshot();

        drop(machines);
        drop(registry);
        publications.push((control.clone(), owner_snapshot));
        publish_deferred_batch(publications, notifications);
        return spawned;
    }
}

fn activation_finish_is_exact(
    registry: &LifecycleRegistryState,
    control: &Arc<FiberControl>,
    machine: &FiberMachine,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    finished: &FinishedActivation,
) -> bool {
    activation_finish_parts_are_exact(
        registry,
        control,
        machine,
        collector,
        epoch,
        finished.ticket_serial,
    )
}

fn activation_finish_parts_are_exact(
    registry: &LifecycleRegistryState,
    control: &Arc<FiberControl>,
    machine: &FiberMachine,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    ticket_serial: u64,
) -> bool {
    registry
        .runtimes
        .get(&control.factory.id())
        .filter(|runtime| runtime.generation == control.runtime_generation)
        .and_then(|runtime| runtime.fibers.get(&control.fiber.uid()))
        .is_some_and(|registered| Arc::ptr_eq(registered, control))
        && !machine.tombstone
        && machine.state == FiberState::Loading
        && machine.desired.as_ref() == Some(epoch)
        && machine
            .current_ticket
            .as_ref()
            .is_some_and(|ticket| ticket.serial() == ticket_serial)
        && machine
            .active_activation
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, collector))
}

fn record_stale_activation(
    control: &FiberControl,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    machine: &mut FiberMachine,
    groups: Vec<Vec<LifecycleDisposer>>,
) {
    retain_effect_groups(machine, epoch, groups);
    if machine
        .active_activation
        .as_ref()
        .is_some_and(|active| Arc::ptr_eq(active, collector))
    {
        machine.active_activation = None;
    }
    control.publish_locked(machine);
}

fn finish_stale_provider_activation(
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    finished: FinishedActivation,
) -> Vec<Arc<FiberControl>> {
    let FinishedActivation { groups, mounts, .. } = finished;
    let snapshot = {
        let mut machine = lock(&control.machine);
        retain_effect_groups(&mut machine, epoch, groups);
        if machine
            .active_activation
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, collector))
        {
            machine.active_activation = None;
        }
        machine.snapshot()
    };
    control.publish_deferred(snapshot);
    dispose_provisional_mounts(mounts);
    Vec::new()
}

fn finish_failed_provider_activation(
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
    finished: FinishedActivation,
    error: CordisError,
) -> Vec<Arc<FiberControl>> {
    let Some(inner) = control.registry.upgrade() else {
        return finish_stale_provider_activation(control, collector, epoch, finished);
    };
    let FinishedActivation {
        ticket_serial,
        groups,
        mounts,
        ..
    } = finished;
    let snapshot = {
        let registry = lock(&inner.state);
        let mut machine = lock(&control.machine);
        if activation_finish_parts_are_exact(
            &registry,
            control,
            &machine,
            collector,
            epoch,
            ticket_serial,
        ) {
            apply_failed_activation_parts(epoch, &mut machine, groups, error, ticket_serial);
        } else {
            retain_effect_groups(&mut machine, epoch, groups);
            if machine
                .active_activation
                .as_ref()
                .is_some_and(|active| Arc::ptr_eq(active, collector))
            {
                machine.active_activation = None;
            }
        }
        machine.snapshot()
    };
    control.publish_deferred(snapshot);
    dispose_provisional_mounts(mounts);
    Vec::new()
}

fn apply_failed_activation(
    _control: &FiberControl,
    epoch: &ActivationEpoch,
    machine: &mut FiberMachine,
    finished: &FinishedActivation,
    error: CordisError,
) {
    apply_failed_activation_parts(
        epoch,
        machine,
        finished.groups.clone(),
        error,
        finished.ticket_serial,
    );
}

fn apply_failed_activation_parts(
    epoch: &ActivationEpoch,
    machine: &mut FiberMachine,
    groups: Vec<Vec<LifecycleDisposer>>,
    error: CordisError,
    ticket_serial: u64,
) {
    retain_effect_groups(machine, epoch, groups);
    machine.active_activation = None;
    if machine.error.is_none() {
        machine.error = Some(error);
    } else if !machine.diagnostics.contains(&error) {
        machine.diagnostics.push(error);
    }
    machine.committed = None;
    machine.force_restart = false;
    machine.settled_ticket = ticket_serial;
    FiberControl::apply_transition_state_locked(machine, FiberState::Failed);
}

fn record_failed_activation(
    control: &FiberControl,
    epoch: &ActivationEpoch,
    machine: &mut FiberMachine,
    groups: Vec<Vec<LifecycleDisposer>>,
    error: CordisError,
    ticket_serial: u64,
) {
    retain_effect_groups(machine, epoch, groups);
    machine.active_activation = None;
    if machine.error.is_none() {
        machine.error = Some(error);
    } else if !machine.diagnostics.contains(&error) {
        machine.diagnostics.push(error);
    }
    machine.committed = None;
    machine.force_restart = false;
    machine.settled_ticket = ticket_serial;
    control.transition_locked(machine, FiberState::Failed);
}

fn dispose_provisional_mounts(mounts: Vec<ProvisionalMount>) {
    for mount in mounts {
        mount.fiber.dispose();
    }
}

fn commit_prepared_activation(
    inner: &Arc<LifecycleRegistryInner>,
    control: &Arc<FiberControl>,
    epoch: &ActivationEpoch,
    registry: &mut LifecycleRegistryState,
    machine: &mut FiberMachine,
    finished: FinishedActivation,
    prepared: PreparedActivation,
) -> Vec<Arc<FiberControl>> {
    let FinishedActivation {
        ticket_serial,
        groups,
        metadata,
        providers: _,
        mounts,
    } = finished;
    registry.next_provider_id = prepared.next_provider_id;
    registry.next_runtime_generation = prepared.next_runtime_generation;
    let mut owner_groups = commit_provisional_providers(inner, registry, prepared.provider_plans);
    let (mount_groups, spawned) = commit_provisional_mounts(
        inner,
        control,
        registry,
        mounts,
        &prepared.runtime_generations,
    );
    owner_groups.extend(mount_groups);
    retain_effect_groups(machine, epoch, groups);
    retain_effect_groups(machine, epoch, owner_groups);
    machine.committed = Some(epoch.clone());
    machine.error = None;
    machine.metadata = metadata;
    machine.active_activation = None;
    machine.settled_ticket = ticket_serial;
    control.transition_locked(machine, FiberState::Active);
    spawned
}

fn commit_provisional_providers(
    inner: &Arc<LifecycleRegistryInner>,
    registry: &mut LifecycleRegistryState,
    provider_plans: Vec<ProvisionalProviderPlan>,
) -> Vec<Vec<LifecycleDisposer>> {
    let mut owner_groups = Vec::new();
    for plan in provider_plans {
        let owner_driver = runtime_provider_owner_control(&plan.record.owner_binding)
            .map(|control| control.driver_runtime.clone());
        let slot = registry
            .providers
            .entry(plan.key)
            .or_insert_with(RuntimeProviderSlot::vacant);
        slot.revision = plan.revision;
        slot.record = Some(plan.record);
        let handle = plan.handle;
        let weak = Arc::downgrade(inner);
        owner_groups.push(vec![LifecycleDisposer::new(move || async move {
            let Some(inner) = weak.upgrade() else {
                return Ok(());
            };
            let Some(driver_runtime) = owner_driver else {
                return Err(CordisError::AsyncRuntimeUnavailable);
            };
            LifecycleRegistry { inner }
                .begin_provider_removal_with_mode(
                    &handle,
                    ProviderRemovalMode::OwnerTeardown { driver_runtime },
                )?
                .await
        })]);
    }
    owner_groups
}

fn commit_provisional_mounts(
    inner: &Arc<LifecycleRegistryInner>,
    control: &Arc<FiberControl>,
    registry: &mut LifecycleRegistryState,
    mounts: Vec<ProvisionalMount>,
    runtime_generations: &HashMap<PluginFactoryId, u64>,
) -> (Vec<Vec<LifecycleDisposer>>, Vec<Arc<FiberControl>>) {
    let mut owner_groups = Vec::new();
    let mut spawned = Vec::with_capacity(mounts.len());
    for mount in mounts {
        let Some(&generation) = runtime_generations.get(&mount.factory.id()) else {
            mount.fiber.dispose();
            continue;
        };
        if !registry.runtimes.contains_key(&mount.factory.id()) {
            registry
                .catalog
                .insert(mount.factory.plugin_id().clone(), mount.factory.id());
            registry.runtimes.insert(
                mount.factory.id(),
                FactoryRuntime {
                    generation,
                    factory: mount.factory.clone(),
                    status: RuntimeStatus::Open,
                    fibers: HashMap::new(),
                },
            );
        }
        let child = FiberControl::new(
            Arc::downgrade(inner),
            mount.fiber.clone(),
            control.fiber.uid(),
            mount.factory.clone(),
            generation,
            control.driver_runtime.clone(),
            mount.config,
        );
        let lifecycle: Arc<dyn FiberLifecycle> = child.clone();
        mount.fiber.attach_lifecycle(Arc::downgrade(&lifecycle));
        let Some(runtime) = registry.runtimes.get_mut(&mount.factory.id()) else {
            mount.fiber.dispose();
            continue;
        };
        runtime.fibers.insert(mount.fiber.uid(), child.clone());
        let child_weak = Arc::downgrade(&child);
        owner_groups.push(vec![LifecycleDisposer::new(move || async move {
            let Some(child) = child_weak.upgrade() else {
                return Ok(());
            };
            child.dispose_and_wait().await.map(|_| ())
        })]);
        spawned.push(child);
    }
    (owner_groups, spawned)
}

fn retain_effect_groups(
    machine: &mut FiberMachine,
    epoch: &ActivationEpoch,
    groups: Vec<Vec<LifecycleDisposer>>,
) {
    if !groups.is_empty() {
        machine.effects.extend(groups);
        machine.effects_epoch = Some(epoch.clone());
    }
}

struct PreparedActivation {
    expected_next_provider_id: u64,
    provider_plans: Vec<ProvisionalProviderPlan>,
    runtime_generations: HashMap<PluginFactoryId, u64>,
    next_provider_id: u64,
    expected_next_runtime_generation: u64,
    next_runtime_generation: u64,
}

struct ProvisionalProviderPlan {
    key: RuntimeProviderKey,
    expected_slot: Option<ProviderSlotFact>,
    revision: u64,
    removal_serial: u64,
    record: RuntimeProviderRecord,
    handle: LifecycleProviderHandle,
}

fn prepare_activation_commit(
    registry: &LifecycleRegistryState,
    control: &FiberControl,
    finished: &FinishedActivation,
) -> Result<PreparedActivation, CordisError> {
    if registry.shutting_down {
        return Err(CordisError::RuntimeDeleting {
            id: control.factory.plugin_id().clone(),
        });
    }
    let (expected_next_provider_id, next_provider_id, provider_plans) =
        prepare_provisional_provider_plans(registry, control, &finished.providers)?;
    let (expected_next_runtime_generation, next_runtime_generation, runtime_generations) =
        prepare_provisional_runtime_generations(registry, &finished.mounts)?;

    Ok(PreparedActivation {
        expected_next_provider_id,
        provider_plans,
        runtime_generations,
        next_provider_id,
        expected_next_runtime_generation,
        next_runtime_generation,
    })
}

fn prepare_provisional_provider_plans(
    registry: &LifecycleRegistryState,
    control: &FiberControl,
    providers: &[ProvisionalProvider],
) -> Result<(u64, u64, Vec<ProvisionalProviderPlan>), CordisError> {
    let expected_next_provider_id = registry.next_provider_id;
    let mut next_provider_id = expected_next_provider_id;
    let mut provider_plans = Vec::with_capacity(providers.len());
    for provider in providers {
        let provider_key = RuntimeProviderKey::new(&provider.namespace, &provider.key);
        let slot = registry.providers.get(&provider_key);
        if let Some(record) = slot.and_then(|slot| slot.record.as_ref())
            && (!record.removing || record.owner.uid() != control.fiber.uid())
        {
            return if record.removing {
                Err(CordisError::ProviderOwnerMismatch {
                    key: provider.key.clone(),
                })
            } else {
                Err(CordisError::DuplicateProvider {
                    namespace: provider.namespace.clone(),
                    key: provider.key.clone(),
                })
            };
        }
        let revision = slot
            .map_or(0, |slot| slot.revision)
            .checked_add(1)
            .ok_or_else(|| CordisError::ProviderGenerationOverflow {
                key: provider.key.clone(),
            })?;
        let provider_id = next_provider_id;
        next_provider_id = next_provider_id
            .checked_add(1)
            .ok_or(CordisError::ProviderIdentityOverflow)?;
        provider_plans.push(provisional_provider_plan(
            control,
            provider,
            provider_key,
            slot,
            provider_id,
            revision,
        ));
    }
    Ok((expected_next_provider_id, next_provider_id, provider_plans))
}

fn provisional_provider_plan(
    control: &FiberControl,
    provider: &ProvisionalProvider,
    key: RuntimeProviderKey,
    slot: Option<&RuntimeProviderSlot>,
    provider_id: u64,
    revision: u64,
) -> ProvisionalProviderPlan {
    let generation = 0;
    ProvisionalProviderPlan {
        key,
        expected_slot: slot.map(provider_slot_fact),
        revision,
        removal_serial: slot.map_or(0, |slot| slot.removal_serial),
        record: RuntimeProviderRecord {
            value: provider.value.clone(),
            provider_id,
            owner: control.fiber.clone(),
            owner_binding: RuntimeProviderOwner::Managed {
                control: control.self_weak.clone(),
                runtime_generation: control.runtime_generation,
            },
            generation,
            removing: false,
            guard: provider.guard.clone(),
        },
        handle: LifecycleProviderHandle {
            registry_id: control.fiber.context_id(),
            namespace: provider.namespace.clone(),
            key: provider.key.clone(),
            provider_id,
            owner_uid: control.fiber.uid(),
            generation,
        },
    }
}

fn prepare_provisional_runtime_generations(
    registry: &LifecycleRegistryState,
    mounts: &[ProvisionalMount],
) -> Result<(u64, u64, HashMap<PluginFactoryId, u64>), CordisError> {
    let expected = registry.next_runtime_generation;
    let mut next = expected;
    let mut generations = HashMap::new();
    let mut batch_catalog = HashMap::new();
    for mount in mounts {
        if let Some(bound) = registry.catalog.get(mount.factory.plugin_id())
            && *bound != mount.factory.id()
        {
            return Err(CordisError::PluginCatalogConflict {
                id: mount.factory.plugin_id().clone(),
            });
        }
        if let Some(bound) = batch_catalog.get(mount.factory.plugin_id())
            && *bound != mount.factory.id()
        {
            return Err(CordisError::PluginCatalogConflict {
                id: mount.factory.plugin_id().clone(),
            });
        }
        batch_catalog.insert(mount.factory.plugin_id().clone(), mount.factory.id());
        let generation = provisional_runtime_generation(registry, &generations, mount, &mut next)?;
        generations.insert(mount.factory.id(), generation);
    }
    Ok((expected, next, generations))
}

fn provisional_runtime_generation(
    registry: &LifecycleRegistryState,
    planned: &HashMap<PluginFactoryId, u64>,
    mount: &ProvisionalMount,
    next: &mut u64,
) -> Result<u64, CordisError> {
    if let Some(runtime) = registry.runtimes.get(&mount.factory.id()) {
        if runtime.status != RuntimeStatus::Open {
            return Err(CordisError::RuntimeDeleting {
                id: mount.factory.plugin_id().clone(),
            });
        }
        Ok(runtime.generation)
    } else if let Some(generation) = planned.get(&mount.factory.id()) {
        Ok(*generation)
    } else {
        let generation = *next;
        *next = next
            .checked_add(1)
            .ok_or(CordisError::RuntimeGenerationOverflow)?;
        Ok(generation)
    }
}

fn next_action(control: &Arc<FiberControl>) -> DriveAction {
    let mut machine = lock(&control.machine);
    if machine.tombstone {
        if !machine.effects.is_empty() || machine.committed.is_some() {
            let groups = std::mem::take(&mut machine.effects);
            machine.effects_epoch = None;
            machine.committed = None;
            control.transition_locked(&mut machine, FiberState::Unloading);
            return DriveAction::Cleanup(groups);
        }
        machine.metadata = machine.baseline_metadata.clone();
        machine.settled_ticket = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        control.transition_locked(&mut machine, FiberState::Disposed);
        return DriveAction::Terminal;
    }

    let committed_stale = machine
        .committed
        .as_ref()
        .is_some_and(|committed| Some(committed) != machine.desired.as_ref());
    let effects_stale = machine
        .effects_epoch
        .as_ref()
        .is_some_and(|effects_epoch| Some(effects_epoch) != machine.desired.as_ref());
    let needs_unload = (machine.force_restart || committed_stale || effects_stale)
        && (!machine.effects.is_empty()
            || machine.effects_epoch.is_some()
            || machine.committed.is_some());
    if needs_unload {
        let groups = std::mem::take(&mut machine.effects);
        machine.effects_epoch = None;
        machine.committed = None;
        machine.metadata = machine.baseline_metadata.clone();
        control.transition_locked(&mut machine, FiberState::Unloading);
        return DriveAction::Cleanup(groups);
    }

    let Some(epoch) = machine.desired.clone() else {
        machine.force_restart = false;
        machine.metadata = machine.baseline_metadata.clone();
        machine.settled_ticket = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        let state = if machine.error.is_some() {
            FiberState::Failed
        } else {
            FiberState::Pending
        };
        control.transition_locked(&mut machine, state);
        return DriveAction::Idle;
    };

    if machine.error.is_some() {
        machine.force_restart = false;
        machine.settled_ticket = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        control.transition_locked(&mut machine, FiberState::Failed);
        return DriveAction::Idle;
    }

    if machine.committed.as_ref() == Some(&epoch) && !machine.force_restart {
        machine.settled_ticket = machine
            .current_ticket
            .as_ref()
            .map_or(machine.settled_ticket, TransitionTicket::serial);
        let state = if machine.error.is_some() {
            FiberState::Failed
        } else {
            FiberState::Active
        };
        control.transition_locked(&mut machine, state);
        return DriveAction::Idle;
    }

    machine.force_restart = false;
    let config = machine.config.clone();
    let ticket_serial = machine
        .current_ticket
        .as_ref()
        .map_or(machine.settled_ticket, TransitionTicket::serial);
    let collector = Arc::new(ActivationCollector::new(
        control.fiber.uid(),
        epoch.clone(),
        ticket_serial,
        machine.baseline_metadata.clone(),
    ));
    machine.active_activation = Some(collector.clone());
    control.transition_locked(&mut machine, FiberState::Loading);
    DriveAction::Start {
        epoch,
        config,
        collector,
    }
}

async fn start_activation(
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    config: ConfigValue,
    epoch: &ActivationEpoch,
) -> Result<(), CordisError> {
    let view = LifecycleContextView {
        registry: control.registry.clone(),
        control: control.self_weak.clone(),
        fiber: control.fiber.clone(),
        namespace: control.namespace.clone(),
        runtime_generation: control.runtime_generation,
        collector: collector.clone(),
    };
    let callback = catch_unwind(AssertUnwindSafe(|| {
        control.factory.start_lifecycle(config, view)
    }));
    let mut first_error = match callback {
        Ok(Ok(effect)) => {
            collector.enqueue_driver(effect)?;
            None
        }
        Ok(Err(error)) => Some(error),
        Err(payload) => Some(CordisError::PluginCallbackPanicked {
            message: panic_payload_message(payload.as_ref()),
        }),
    };

    while let Some(effects) = collector.drain_or_close() {
        let results = join_all(
            effects
                .into_iter()
                .map(|effect| resolve_effect(effect, control, collector, epoch)),
        )
        .await;
        for result in results {
            match result {
                Ok(group) => collector.push_group(group),
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(error) => {
                    let mut machine = lock(&control.machine);
                    if !machine.diagnostics.contains(&error) {
                        machine.diagnostics.push(error);
                    }
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn resolve_effect(
    effect: LifecycleEffect,
    control: &Arc<FiberControl>,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
) -> Result<Vec<LifecycleDisposer>, CordisError> {
    let future = async {
        match effect {
            LifecycleEffect::None => Ok(Vec::new()),
            LifecycleEffect::Disposer(disposer) => Ok(vec![disposer]),
            LifecycleEffect::DisposerCollection(disposers) => Ok(disposers),
            LifecycleEffect::DisposerFuture(future) => Ok(future.await?.into_iter().collect()),
            LifecycleEffect::DisposerStream(mut stream) => {
                let mut disposers = Vec::new();
                while let Some(disposer) = stream.next().await {
                    disposers.push(disposer);
                    if !activation_accepts_stream_yield(control, collector, epoch) {
                        break;
                    }
                }
                Ok(disposers)
            }
        }
    };
    AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .map_err(|payload| CordisError::PluginCallbackPanicked {
            message: panic_payload_message(payload.as_ref()),
        })?
}

fn activation_accepts_stream_yield(
    control: &FiberControl,
    collector: &Arc<ActivationCollector>,
    epoch: &ActivationEpoch,
) -> bool {
    // Keep the same machine -> collector lock order used by context writes and
    // same-epoch provider ticket rebinding. A stream may continue only while
    // it still belongs to the exact Loading activation. A provider
    // remove/reprovide that restores the same epoch atomically rebinds the
    // collector ticket; restart/update/dispose leave the old ticket stale and
    // therefore cancel polling immediately after the current yield.
    let machine = lock(&control.machine);
    if machine.tombstone
        || machine.state != FiberState::Loading
        || machine.desired.as_ref() != Some(epoch)
        || collector.epoch != *epoch
        || !machine
            .active_activation
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, collector))
    {
        return false;
    }
    let collector_state = lock(&collector.state);
    !collector_state.closed
        && machine
            .current_ticket
            .as_ref()
            .is_some_and(|ticket| ticket.serial() == collector_state.ticket_serial)
}

async fn cleanup_groups(groups: Vec<Vec<LifecycleDisposer>>) -> Vec<CordisError> {
    join_all(groups.into_iter().map(|group| async move {
        let mut errors = Vec::new();
        for disposer in group.into_iter().rev() {
            if let Err(error) = disposer.dispose_async().await {
                errors.push(error);
            }
        }
        errors
    }))
    .await
    .into_iter()
    .flatten()
    .collect()
}

fn driver_runtimes_for_controls(controls: &[Arc<FiberControl>]) -> Vec<DriverRuntimeBinding> {
    let mut drivers = Vec::<DriverRuntimeBinding>::new();
    for control in controls {
        if !drivers
            .iter()
            .any(|driver| driver.ptr_eq(&control.driver_runtime))
        {
            drivers.push(control.driver_runtime.clone());
        }
    }
    drivers
}

fn dead_driver_bindings_for_controls(controls: &[Arc<FiberControl>]) -> Vec<DriverRuntimeBinding> {
    let mut bindings = Vec::new();
    for control in controls {
        if control.driver_runtime.require_alive().is_err() {
            push_binding_once(&mut bindings, control.driver_runtime.clone());
        }
    }
    bindings
}

enum FiberTicketOutcome {
    Settled(Result<FiberSnapshot, CordisError>),
    DriverDied(DriverRuntimeBinding),
}

struct FiberTicketSummary {
    dead_bindings: Vec<DriverRuntimeBinding>,
    first_error: Option<CordisError>,
}

enum RecoveryWaitOutcome {
    TicketSettled(Result<FiberSnapshot, CordisError>),
    TerminalSettled(Arc<FiberControl>),
    DriverDied(DriverRuntimeBinding),
}

#[derive(Default)]
struct RecoveryPlan {
    ticket_waits: Vec<FiberTicketWait>,
    terminal_waits: Vec<Arc<FiberControl>>,
    drivers: Vec<DriverRuntimeBinding>,
}

impl RecoveryPlan {
    fn extend(&mut self, other: Self) {
        self.ticket_waits.extend(other.ticket_waits);
        self.terminal_waits.extend(other.terminal_waits);
        for driver in other.drivers {
            push_binding_once(&mut self.drivers, driver);
        }
    }

    fn driver_runtimes(&self) -> Vec<DriverRuntimeBinding> {
        self.drivers.clone()
    }
}

async fn await_ticket_or_driver_death(
    control: Arc<FiberControl>,
    serial: u64,
) -> FiberTicketOutcome {
    let binding = control.driver_runtime.clone();
    let mut death = binding.death_receiver();
    let ticket = control.await_ticket(serial);
    tokio::pin!(ticket);
    loop {
        if !*death.borrow() {
            return FiberTicketOutcome::DriverDied(binding);
        }
        tokio::select! {
            biased;
            changed = death.changed() => {
                if changed.is_err() || !*death.borrow() {
                    return FiberTicketOutcome::DriverDied(binding);
                }
            }
            result = &mut ticket => return FiberTicketOutcome::Settled(result),
        }
    }
}

async fn await_ticket_batch_or_driver_death(waits: Vec<FiberTicketWait>) -> FiberTicketSummary {
    let outcomes = join_all(
        waits
            .into_iter()
            .map(|(control, serial)| await_ticket_or_driver_death(control, serial)),
    )
    .await;
    let mut summary = FiberTicketSummary {
        dead_bindings: Vec::new(),
        first_error: None,
    };
    for outcome in outcomes {
        match outcome {
            FiberTicketOutcome::Settled(Ok(_)) => {}
            FiberTicketOutcome::Settled(Err(error)) => {
                summary.first_error.get_or_insert(error);
            }
            FiberTicketOutcome::DriverDied(binding) => {
                push_binding_once(&mut summary.dead_bindings, binding);
                summary
                    .first_error
                    .get_or_insert(CordisError::AsyncRuntimeUnavailable);
            }
        }
    }
    summary
}

async fn await_terminal_or_driver_death(control: Arc<FiberControl>) -> RecoveryWaitOutcome {
    let binding = control.driver_runtime.clone();
    let mut death = binding.death_receiver();
    let mut snapshots = control.snapshots.subscribe();
    loop {
        if lock(&control.machine).state == FiberState::Disposed {
            return RecoveryWaitOutcome::TerminalSettled(control);
        }
        if !*death.borrow() {
            return RecoveryWaitOutcome::DriverDied(binding);
        }
        tokio::select! {
            biased;
            changed = death.changed() => {
                if changed.is_err() || !*death.borrow() {
                    return RecoveryWaitOutcome::DriverDied(binding);
                }
            }
            changed = snapshots.changed() => {
                if changed.is_err() && lock(&control.machine).state != FiberState::Disposed {
                    return RecoveryWaitOutcome::DriverDied(binding);
                }
            }
        }
    }
}

fn finalize_recovered_terminal(inner: &Arc<LifecycleRegistryInner>, control: &Arc<FiberControl>) {
    let mut state = lock(&inner.state);
    if !control_is_registered_locked(&state, control) {
        return;
    }
    let machine = lock(&control.machine);
    if machine.tombstone && machine.state == FiberState::Disposed {
        drop(machine);
        detach_control_locked(&mut state, control);
    }
}

fn enqueue_recovery_plan(
    pending: &mut futures_util::stream::FuturesUnordered<BoxFuture<'static, RecoveryWaitOutcome>>,
    seen_tickets: &mut Vec<FiberTicketWait>,
    seen_terminals: &mut Vec<Arc<FiberControl>>,
    plan: RecoveryPlan,
) {
    for (control, serial) in plan.ticket_waits {
        if seen_tickets
            .iter()
            .any(|(seen, seen_serial)| Arc::ptr_eq(seen, &control) && *seen_serial == serial)
        {
            continue;
        }
        seen_tickets.push((control.clone(), serial));
        pending.push(
            async move {
                match await_ticket_or_driver_death(control, serial).await {
                    FiberTicketOutcome::Settled(result) => {
                        RecoveryWaitOutcome::TicketSettled(result)
                    }
                    FiberTicketOutcome::DriverDied(binding) => {
                        RecoveryWaitOutcome::DriverDied(binding)
                    }
                }
            }
            .boxed(),
        );
    }
    for control in plan.terminal_waits {
        if seen_terminals
            .iter()
            .any(|seen| Arc::ptr_eq(seen, &control))
        {
            continue;
        }
        seen_terminals.push(control.clone());
        pending.push(await_terminal_or_driver_death(control).boxed());
    }
}

async fn settle_recovery_plan(
    inner: Arc<LifecycleRegistryInner>,
    plan: RecoveryPlan,
    mut first_error: Option<CordisError>,
) -> Option<CordisError> {
    let mut pending = futures_util::stream::FuturesUnordered::new();
    let mut seen_tickets = Vec::new();
    let mut seen_terminals = Vec::new();
    enqueue_recovery_plan(&mut pending, &mut seen_tickets, &mut seen_terminals, plan);
    while let Some(outcome) = pending.next().await {
        match outcome {
            RecoveryWaitOutcome::TicketSettled(Ok(_)) => {}
            RecoveryWaitOutcome::TicketSettled(Err(error)) => {
                first_error.get_or_insert(error);
            }
            RecoveryWaitOutcome::TerminalSettled(control) => {
                finalize_recovered_terminal(&inner, &control);
            }
            RecoveryWaitOutcome::DriverDied(binding) => {
                first_error.get_or_insert(CordisError::AsyncRuntimeUnavailable);
                let next = quarantine_dead_bindings_transaction(
                    &inner,
                    vec![binding],
                    Vec::new(),
                    &[],
                    &CordisError::AsyncRuntimeUnavailable,
                );
                enqueue_recovery_plan(&mut pending, &mut seen_tickets, &mut seen_terminals, next);
            }
        }
    }
    first_error
}

fn binding_is_one_of(binding: &DriverRuntimeBinding, candidates: &[DriverRuntimeBinding]) -> bool {
    candidates.iter().any(|candidate| binding.ptr_eq(candidate))
}

fn push_binding_once(bindings: &mut Vec<DriverRuntimeBinding>, binding: DriverRuntimeBinding) {
    if !binding_is_one_of(&binding, bindings) {
        bindings.push(binding);
    }
}

struct ProviderReclaimPlan {
    key: RuntimeProviderKey,
    provider_id: u64,
    owner_uid: FiberUid,
    generation: u64,
    expected_revision: u64,
    expected_removal_serial: u64,
    revision: Option<u64>,
    removal_serial: Option<u64>,
}

#[derive(Clone)]
struct ExactForcedProviderFact {
    key: RuntimeProviderKey,
    provider_id: u64,
    owner_uid: FiberUid,
    generation: u64,
    revision: u64,
    removal_serial: u64,
}

fn exact_forced_provider_facts_locked(
    state: &LifecycleRegistryState,
    handles: &[LifecycleProviderHandle],
) -> Vec<ExactForcedProviderFact> {
    let mut facts = Vec::new();
    for handle in handles {
        let key = RuntimeProviderKey::new(&handle.namespace, &handle.key);
        let Some(slot) = state.providers.get(&key) else {
            continue;
        };
        let Some(record) = slot.record.as_ref() else {
            continue;
        };
        if record.provider_id != handle.provider_id
            || record.owner.uid() != handle.owner_uid
            || record.generation != handle.generation
        {
            continue;
        }
        if facts
            .iter()
            .any(|fact: &ExactForcedProviderFact| fact.key == key)
        {
            continue;
        }
        facts.push(ExactForcedProviderFact {
            key,
            provider_id: record.provider_id,
            owner_uid: record.owner.uid(),
            generation: record.generation,
            revision: slot.revision,
            removal_serial: slot.removal_serial,
        });
    }
    facts
}

/// Fail-closed recovery for an exact dead executor plus any live controls that
/// must be terminalized because the ordinary ticket path is exhausted.
///
/// Effects are abandoned only for controls whose exact driver binding is
/// confirmed dead. Live controls retain their effects and are woken into the
/// no-new-ticket tombstone path; the returned plan keeps the supervisor from
/// completing the enclosing registry operation until their real cleanup has
/// settled (or their exact binding subsequently dies and is quarantined).
#[expect(
    clippy::too_many_lines,
    reason = "keep the bounded registry + uid-ordered quarantine transaction visibly atomic"
)]
fn quarantine_dead_bindings_transaction(
    inner: &Arc<LifecycleRegistryInner>,
    initial_bindings: Vec<DriverRuntimeBinding>,
    forced_controls: Vec<Arc<FiberControl>>,
    forced_providers: &[LifecycleProviderHandle],
    diagnostic: &CordisError,
) -> RecoveryPlan {
    let mut state = lock(&inner.state);
    let mut dead_bindings = Vec::new();
    for binding in initial_bindings {
        if binding.require_alive().is_err() {
            push_binding_once(&mut dead_bindings, binding);
        }
    }
    let mut forced_cleanup = forced_controls
        .into_iter()
        .map(|control| (control, diagnostic.clone()))
        .collect::<Vec<_>>();

    'rebuild: loop {
        let all_controls = controls_locked(&state);
        let mut cleanup = all_controls
            .iter()
            .filter(|control| binding_is_one_of(&control.driver_runtime, &dead_bindings))
            .cloned()
            .map(|control| (control, CordisError::AsyncRuntimeUnavailable))
            .collect::<Vec<_>>();
        cleanup.extend(
            forced_cleanup
                .iter()
                .filter(|(control, _)| control_is_registered_locked(&state, control))
                .cloned(),
        );
        cleanup.sort_by_key(|(control, _)| control.fiber.uid());
        cleanup.dedup_by(|(left, _), (right, _)| Arc::ptr_eq(left, right));
        loop {
            let before = cleanup.len();
            for child in &all_controls {
                let Some((_, cause)) = cleanup
                    .iter()
                    .find(|(parent, _)| parent.fiber.uid() == child.parent_uid)
                else {
                    continue;
                };
                if !cleanup
                    .iter()
                    .any(|(candidate, _)| Arc::ptr_eq(candidate, child))
                {
                    cleanup.push((child.clone(), cause.clone()));
                }
            }
            cleanup.sort_by_key(|(control, _)| control.fiber.uid());
            if cleanup.len() == before {
                break;
            }
        }

        let newly_dead = cleanup
            .iter()
            .filter(|(control, _)| control.driver_runtime.require_alive().is_err())
            .map(|(control, _)| control.driver_runtime.clone())
            .collect::<Vec<_>>();
        let before = dead_bindings.len();
        for binding in newly_dead {
            push_binding_once(&mut dead_bindings, binding);
        }
        if dead_bindings.len() != before {
            continue;
        }

        let cleanup_controls = cleanup
            .iter()
            .map(|(control, _)| control.clone())
            .collect::<Vec<_>>();
        let forced_facts = exact_forced_provider_facts_locked(&state, forced_providers);
        if forced_providers.iter().any(|handle| {
            !forced_facts.iter().any(|fact| {
                fact.key == RuntimeProviderKey::new(&handle.namespace, &handle.key)
                    && fact.provider_id == handle.provider_id
                    && fact.owner_uid == handle.owner_uid
                    && fact.generation == handle.generation
            })
        }) {
            // A forced owner-teardown handle fences the entire transaction,
            // including dead-binding closure discovery. A stale completion
            // must not perturb a replacement provider or any of its consumers.
            return RecoveryPlan::default();
        }

        let mut removed_keys = state
            .providers
            .iter()
            .filter_map(|(key, slot)| {
                slot.record.as_ref().and_then(|record| {
                    provider_owner_is_one_of(&record.owner_binding, &cleanup_controls)
                        .then_some(key.clone())
                })
            })
            .collect::<Vec<_>>();
        removed_keys.extend(forced_facts.iter().map(|fact| fact.key.clone()));
        removed_keys.sort_by(|left, right| {
            (&left.namespace, &left.key).cmp(&(&right.namespace, &right.key))
        });
        removed_keys.dedup();

        let mut affected = removed_keys
            .iter()
            .flat_map(|key| affected_controls_locked(&state, key))
            .collect::<Vec<_>>();
        affected.sort_by_key(|control| control.fiber.uid());
        affected.dedup_by(|left, right| Arc::ptr_eq(left, right));
        let newly_dead = affected
            .iter()
            .filter(|control| control.driver_runtime.require_alive().is_err())
            .map(|control| control.driver_runtime.clone())
            .collect::<Vec<_>>();
        let before = dead_bindings.len();
        for binding in newly_dead {
            push_binding_once(&mut dead_bindings, binding);
        }
        if dead_bindings.len() != before {
            continue;
        }

        let mut locked_controls = cleanup_controls.clone();
        locked_controls.extend(affected.iter().cloned());
        locked_controls.sort_by_key(|control| control.fiber.uid());
        locked_controls.dedup_by(|left, right| Arc::ptr_eq(left, right));
        let mut machines = locked_controls
            .iter()
            .map(|control| lock(&control.machine))
            .collect::<Vec<_>>();

        if dead_bindings
            .iter()
            .any(|binding| binding.require_alive().is_ok())
            || cleanup_controls
                .iter()
                .any(|control| !control_is_registered_locked(&state, control))
        {
            return RecoveryPlan::default();
        }

        let dead_controls = cleanup_controls
            .iter()
            .filter(|control| binding_is_one_of(&control.driver_runtime, &dead_bindings))
            .cloned()
            .collect::<Vec<_>>();
        let live_cleanup = cleanup_controls
            .iter()
            .filter(|control| !binding_is_one_of(&control.driver_runtime, &dead_bindings))
            .cloned()
            .collect::<Vec<_>>();
        let newly_dead = dead_driver_bindings_for_controls(&live_cleanup);
        if !newly_dead.is_empty() {
            for binding in newly_dead {
                push_binding_once(&mut dead_bindings, binding);
            }
            drop(machines);
            continue;
        }

        let live_affected = affected
            .iter()
            .filter(|control| {
                !cleanup_controls
                    .iter()
                    .any(|candidate| Arc::ptr_eq(candidate, control))
            })
            .cloned()
            .collect::<Vec<_>>();
        let newly_dead = dead_driver_bindings_for_controls(&live_affected);
        if !newly_dead.is_empty() {
            for binding in newly_dead {
                push_binding_once(&mut dead_bindings, binding);
            }
            drop(machines);
            continue;
        }
        let mut next_tickets = Vec::with_capacity(live_affected.len());
        for control in &live_affected {
            let index = control_index(&locked_controls, control).expect("affected control locked");
            if machines[index].tombstone {
                forced_cleanup.push((control.clone(), diagnostic.clone()));
                drop(machines);
                continue 'rebuild;
            }
            match FiberControl::preflight_desired_locked(&machines[index], None) {
                Ok(ticket) => next_tickets.push(ticket),
                Err(error) => {
                    forced_cleanup.push((control.clone(), error));
                    drop(machines);
                    continue 'rebuild;
                }
            }
        }

        let mut reclaim = Vec::new();
        for key in &removed_keys {
            let Some(slot) = state.providers.get(key) else {
                continue;
            };
            let Some(record) = slot.record.as_ref() else {
                continue;
            };
            let exact_forced = forced_facts
                .iter()
                .find(|fact| fact.key == *key)
                .is_some_and(|fact| {
                    fact.provider_id == record.provider_id
                        && fact.owner_uid == record.owner.uid()
                        && fact.generation == record.generation
                        && fact.revision == slot.revision
                        && fact.removal_serial == slot.removal_serial
                });
            if !exact_forced && !provider_owner_is_one_of(&record.owner_binding, &cleanup_controls)
            {
                continue;
            }
            let removal_serial = slot.removal_serial.checked_add(1);
            let revision = slot.revision.checked_add(2);
            reclaim.push(ProviderReclaimPlan {
                key: key.clone(),
                provider_id: record.provider_id,
                owner_uid: record.owner.uid(),
                generation: record.generation,
                expected_revision: slot.revision,
                expected_removal_serial: slot.removal_serial,
                revision,
                removal_serial,
            });
        }

        let mut publications = Vec::new();
        let mut notifications = Vec::new();
        let mut terminals = Vec::new();
        for control in &dead_controls {
            let index = control_index(&locked_controls, control).expect("dead control locked");
            let machine = &mut machines[index];
            let error = CordisError::AsyncRuntimeUnavailable;
            if !machine.diagnostics.contains(&error) {
                machine.diagnostics.push(error);
            }
            machine.tombstone = true;
            machine.desired = None;
            machine.committed = None;
            // The exact driver is dead, so no executor exists on which async
            // user cleanup can run. Preserve that fact as a typed diagnostic
            // and abandon only this irrecoverable control's effects.
            machine.effects.clear();
            machine.effects_epoch = None;
            machine.force_restart = false;
            machine.active_activation = None;
            machine.settled_ticket = machine
                .current_ticket
                .as_ref()
                .map_or(machine.settled_ticket, |ticket| {
                    machine.settled_ticket.max(ticket.serial())
                });
            FiberControl::apply_transition_state_locked(machine, FiberState::Disposed);
            control.fiber.publish_tombstone();
            let snapshot = machine.snapshot();
            terminals.push((
                control.clone(),
                control.fiber.clone(),
                snapshot,
                machine.history.clone(),
            ));
        }
        let mut recovery_publications = Vec::new();
        let mut terminal_waits = Vec::new();
        for control in &live_cleanup {
            let index = control_index(&locked_controls, control).expect("live cleanup locked");
            let machine = &mut machines[index];
            let cause = cleanup
                .iter()
                .find(|(candidate, _)| Arc::ptr_eq(candidate, control))
                .map_or_else(|| diagnostic.clone(), |(_, cause)| cause.clone());
            if !machine.diagnostics.contains(&cause) {
                machine.diagnostics.push(cause);
            }
            machine.tombstone = true;
            machine.desired = None;
            machine.force_restart = false;
            control.fiber.publish_tombstone();
            if machine.state != FiberState::Disposed {
                FiberControl::apply_transition_state_locked(machine, FiberState::Unloading);
            }
            recovery_publications.push((control.clone(), machine.snapshot()));
            terminal_waits.push(control.clone());
            notifications.push(control.clone());
        }
        let mut ticket_waits = Vec::with_capacity(live_affected.len());
        for (control, next_ticket) in live_affected.iter().zip(next_tickets) {
            let index = control_index(&locked_controls, control).expect("affected control locked");
            let machine = &mut machines[index];
            let before = machine.snapshot();
            let (changed, serial) =
                FiberControl::apply_desired_locked(machine, None, None, next_ticket);
            ticket_waits.push((control.clone(), serial));
            if machine.snapshot() != before {
                publications.push((control.clone(), machine.snapshot()));
            }
            if changed {
                notifications.push(control.clone());
            }
        }
        for plan in reclaim {
            let exact = state.providers.get(&plan.key).is_some_and(|slot| {
                slot.revision == plan.expected_revision
                    && slot.removal_serial == plan.expected_removal_serial
                    && slot.record.as_ref().is_some_and(|record| {
                        record.provider_id == plan.provider_id
                            && record.owner.uid() == plan.owner_uid
                            && record.generation == plan.generation
                    })
            });
            if !exact {
                continue;
            }
            if let (Some(revision), Some(removal_serial)) = (plan.revision, plan.removal_serial) {
                if let Some(slot) = state.providers.get_mut(&plan.key) {
                    slot.revision = revision;
                    slot.removal_serial = removal_serial;
                    slot.record = None;
                }
            } else {
                // Counter exhaustion is recoverable only by dropping the slot.
                // Provider ids are globally monotonic, so an old completion
                // cannot match and delete a later record created for this key.
                state.providers.remove(&plan.key);
            }
        }
        for control in &dead_controls {
            detach_control_locked(&mut state, control);
        }
        let mut drivers = driver_runtimes_for_controls(&live_affected);
        for control in &live_cleanup {
            push_binding_once(&mut drivers, control.driver_runtime.clone());
        }
        drop(machines);
        drop(state);
        for (control, snapshot) in publications {
            control.publish_deferred(snapshot);
        }
        for (control, snapshot) in recovery_publications {
            control.publish_recovery_state(snapshot);
        }
        for (control, fiber, snapshot, history) in terminals {
            control.publish_terminal(snapshot.clone());
            fiber.freeze_terminal(snapshot, history);
        }
        for control in notifications {
            control.wake.notify_one();
        }
        return RecoveryPlan {
            ticket_waits,
            terminal_waits,
            drivers,
        };
    }
}

fn spawn_unit_operation_on(
    supervisor: SupervisorReservation,
    operation: SharedUnitOperation,
    drivers: Vec<DriverRuntimeBinding>,
) -> BoxFuture<'static, Result<(), CordisError>> {
    let operation = supervisor.submit(operation);
    if drivers.is_empty() {
        // Zero-control operations contain no asynchronous cleanup wait. This
        // also completes them synchronously if the already-reserved
        // supervisor task was lost outside its handshake invariant.
        let _ = operation.clone().now_or_never();
    }
    for binding in drivers {
        binding.drive(operation.clone());
    }
    operation.boxed()
}

fn require_async_runtime() -> Result<(), CordisError> {
    current_async_runtime().map(drop)
}

fn current_async_runtime() -> Result<TokioHandle, CordisError> {
    TokioHandle::try_current().map_err(|_| CordisError::AsyncRuntimeUnavailable)
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

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod lifecycle_boundary_tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MachineBoundarySnapshot {
        config: ConfigValue,
        config_revision: u64,
        desired: Option<ActivationEpoch>,
        committed: Option<ActivationEpoch>,
        next_ticket: u64,
        current_ticket: Option<TransitionTicket>,
        settled_ticket: u64,
        state: FiberState,
        error: Option<CordisError>,
        diagnostics: Vec<CordisError>,
        effects_len: usize,
        effects_epoch: Option<ActivationEpoch>,
        history: Vec<FiberState>,
        baseline_metadata: ConfigValue,
        metadata: ConfigValue,
        flags: [bool; 4],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ProviderBoundarySnapshot {
        next_provider_id: u64,
        provider_count: usize,
        shutting_down: bool,
        slot: Option<ProviderSlotBoundarySnapshot>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ProviderSlotBoundarySnapshot {
        revision: u64,
        removal_serial: u64,
        provider_id: Option<u64>,
        generation: Option<u64>,
        owner_uid: Option<FiberUid>,
        removing: bool,
        value_identity: Option<usize>,
        has_guard: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RuntimeBoundarySnapshot {
        shutting_down: bool,
        generation: u64,
        status: RuntimeStatus,
        fiber_count: usize,
        has_shutdown_operation: bool,
    }

    fn detached_control(registry: &LifecycleRegistry, id: &str) -> Arc<FiberControl> {
        let factory = PluginFactory::new_lifecycle(id, |_config, _ctx| LifecycleEffect::none());
        let fiber = Fiber::child_with_namespace(
            registry.inner.id,
            &registry.inner.root,
            "root".to_string(),
        );
        let driver_runtime = DriverRuntimeBinding::new(&current_async_runtime().unwrap());
        FiberControl::new(
            Arc::downgrade(&registry.inner),
            fiber,
            FiberUid::ROOT,
            factory,
            1,
            driver_runtime,
            ConfigValue::string("initial"),
        )
    }

    fn machine_boundary_snapshot(control: &FiberControl) -> MachineBoundarySnapshot {
        let fiber_disposed = control.fiber.is_disposed();
        let machine = lock(&control.machine);
        MachineBoundarySnapshot {
            config: machine.config.clone(),
            config_revision: machine.config_revision,
            desired: machine.desired.clone(),
            committed: machine.committed.clone(),
            next_ticket: machine.next_ticket,
            current_ticket: machine.current_ticket.clone(),
            settled_ticket: machine.settled_ticket,
            state: machine.state,
            error: machine.error.clone(),
            diagnostics: machine.diagnostics.clone(),
            effects_len: machine.effects.len(),
            effects_epoch: machine.effects_epoch.clone(),
            history: machine.history.clone(),
            baseline_metadata: machine.baseline_metadata.clone(),
            metadata: machine.metadata.clone(),
            flags: [
                machine.force_restart,
                machine.tombstone,
                machine.active_activation.is_some(),
                fiber_disposed,
            ],
        }
    }

    fn provider_boundary_snapshot(
        registry: &LifecycleRegistry,
        namespace: &str,
        key: &str,
    ) -> ProviderBoundarySnapshot {
        let state = lock(&registry.inner.state);
        let slot = state
            .providers
            .get(&RuntimeProviderKey::new(namespace, key))
            .map(|slot| ProviderSlotBoundarySnapshot {
                revision: slot.revision,
                removal_serial: slot.removal_serial,
                provider_id: slot.record.as_ref().map(|record| record.provider_id),
                generation: slot.record.as_ref().map(|record| record.generation),
                owner_uid: slot.record.as_ref().map(|record| record.owner.uid()),
                removing: slot.record.as_ref().is_some_and(|record| record.removing),
                value_identity: slot
                    .record
                    .as_ref()
                    .map(|record| Arc::as_ptr(&record.value).cast::<()>() as usize),
                has_guard: slot
                    .record
                    .as_ref()
                    .is_some_and(|record| record.guard.is_some()),
            });
        ProviderBoundarySnapshot {
            next_provider_id: state.next_provider_id,
            provider_count: state.providers.len(),
            shutting_down: state.shutting_down,
            slot,
        }
    }

    fn runtime_boundary_snapshot(
        registry: &LifecycleRegistry,
        factory: &PluginFactory,
    ) -> RuntimeBoundarySnapshot {
        let has_shutdown_operation = lock(&registry.inner.shutdown_operation).is_some();
        let state = lock(&registry.inner.state);
        let runtime = &state.runtimes[&factory.id()];
        RuntimeBoundarySnapshot {
            shutting_down: state.shutting_down,
            generation: runtime.generation,
            status: runtime.status,
            fiber_count: runtime.fibers.len(),
            has_shutdown_operation,
        }
    }

    fn production_result_with_timeout<T: Send + 'static>(
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (complete, completed) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = complete.send(work());
        });
        completed
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("production lifecycle path timed out or panicked")
    }

    fn permanently_gated_disposer(
        entered: Arc<Mutex<Option<std::sync::mpsc::SyncSender<()>>>>,
    ) -> LifecycleDisposer {
        LifecycleDisposer::new(move || {
            let entered = entered.clone();
            async move {
                if let Some(sender) = lock(&entered).take() {
                    let _ = sender.send(());
                }
                std::future::pending::<Result<(), CordisError>>().await
            }
        })
    }

    #[tokio::test]
    async fn single_control_ticket_overflow_preserves_every_machine_field() {
        let registry = LifecycleRegistry::new();
        let control = detached_control(&registry, "single-overflow");
        lock(&control.machine).next_ticket = u64::MAX;
        let before = machine_boundary_snapshot(&control);
        let desired = Some(ActivationEpoch::new(1, []));
        let diagnostic = CordisError::PayloadType {
            name: "must-not-commit".to_string(),
        };

        let desired_result = {
            let mut machine = lock(&control.machine);
            control.set_desired_locked(&mut machine, desired, Some(diagnostic))
        };
        assert!(matches!(
            desired_result,
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(machine_boundary_snapshot(&control), before);
        assert!(matches!(
            control.request_restart(),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(machine_boundary_snapshot(&control), before);
        assert!(matches!(
            control.request_update(ConfigValue::string("must-not-commit")),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(machine_boundary_snapshot(&control), before);
        assert!(matches!(
            control.request_dispose(),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(machine_boundary_snapshot(&control), before);
    }

    #[tokio::test]
    async fn update_config_revision_overflow_preserves_every_machine_field() {
        let registry = LifecycleRegistry::new();
        let control = detached_control(&registry, "config-overflow");
        lock(&control.machine).config_revision = u64::MAX;
        let before = machine_boundary_snapshot(&control);

        assert!(matches!(
            control.request_update(ConfigValue::string("must-not-commit")),
            Err(CordisError::ConfigRevisionOverflow)
        ));
        assert_eq!(machine_boundary_snapshot(&control), before);
    }

    #[tokio::test]
    async fn remove_overflow_preserves_provider_and_every_dependent() {
        let registry = LifecycleRegistry::new();
        let provider = registry.provide("remove-overflow", 1_u32).unwrap();
        let factory = PluginFactory::new_lifecycle("remove-overflow-consumer", |_config, _ctx| {
            LifecycleEffect::none()
        })
        .with_inject(["remove-overflow"]);
        let left = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        let right = registry.mount(factory, ConfigValue::default()).unwrap();
        left.fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        right
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let left_control = left.control().unwrap();
        let right_control = right.control().unwrap();
        lock(&right_control.machine).next_ticket = u64::MAX;
        let provider_before = provider_boundary_snapshot(&registry, "root", "remove-overflow");
        let left_before = machine_boundary_snapshot(&left_control);
        let right_before = machine_boundary_snapshot(&right_control);

        assert!(matches!(
            registry.begin_remove_provider(&provider),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "remove-overflow"),
            provider_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);
        assert_eq!(registry.get::<u32>("remove-overflow").as_deref(), Some(&1));
    }

    #[tokio::test]
    async fn remove_reserves_completion_revision_before_marking() {
        let registry = LifecycleRegistry::new();
        let provider = registry.provide("remove-revision", 1_u32).unwrap();
        {
            let mut state = lock(&registry.inner.state);
            state
                .providers
                .get_mut(&RuntimeProviderKey::new("root", "remove-revision"))
                .unwrap()
                .revision = u64::MAX - 1;
        }
        let before = provider_boundary_snapshot(&registry, "root", "remove-revision");

        assert!(matches!(
            registry.begin_remove_provider(&provider),
            Err(CordisError::ProviderGenerationOverflow { .. })
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "remove-revision"),
            before
        );
    }

    #[tokio::test]
    async fn provide_and_replace_overflow_preserve_provider_and_all_dependents() {
        let registry = LifecycleRegistry::new();
        let factory = PluginFactory::new_lifecycle("provide-overflow-consumer", |_, _| {
            LifecycleEffect::none()
        })
        .with_inject(["provide-overflow"]);
        let left = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        let right = registry.mount(factory, ConfigValue::default()).unwrap();
        let left_control = left.control().unwrap();
        let right_control = right.control().unwrap();
        lock(&right_control.machine).next_ticket = u64::MAX;
        let provider_before = provider_boundary_snapshot(&registry, "root", "provide-overflow");
        let left_before = machine_boundary_snapshot(&left_control);
        let right_before = machine_boundary_snapshot(&right_control);

        assert!(matches!(
            registry.provide("provide-overflow", 1_u32),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "provide-overflow"),
            provider_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);

        let registry = LifecycleRegistry::new();
        let provider = registry.provide("replace-overflow", 7_u32).unwrap();
        let factory = PluginFactory::new_lifecycle("replace-overflow-consumer", |_, _| {
            LifecycleEffect::none()
        })
        .with_inject(["replace-overflow"]);
        let left = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        let right = registry.mount(factory, ConfigValue::default()).unwrap();
        left.fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        right
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let left_control = left.control().unwrap();
        let right_control = right.control().unwrap();
        lock(&right_control.machine).next_ticket = u64::MAX;
        let provider_before = provider_boundary_snapshot(&registry, "root", "replace-overflow");
        let left_before = machine_boundary_snapshot(&left_control);
        let right_before = machine_boundary_snapshot(&right_control);

        assert!(matches!(
            registry.replace_provider(&provider, 9_u32),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "replace-overflow"),
            provider_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);
        assert_eq!(registry.get::<u32>("replace-overflow").as_deref(), Some(&7));
        assert_eq!(provider.generation(), 0);
    }

    #[test]
    fn public_mutations_reject_dead_drivers_but_delete_and_shutdown_recover() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (registry, pending, pending_control) = runtime.block_on(async {
            let registry = LifecycleRegistry::new();
            let pending = registry
                .mount(
                    PluginFactory::new_lifecycle("dead-provide", |_, _| LifecycleEffect::none())
                        .with_inject(["dead-provide"]),
                    ConfigValue::default(),
                )
                .unwrap();
            let control = pending.control().unwrap();
            (registry, pending, control)
        });
        drop(runtime);
        let provider_before = provider_boundary_snapshot(&registry, "root", "dead-provide");
        let pending_before = machine_boundary_snapshot(&pending_control);
        assert!(matches!(
            registry.provide("dead-provide", 1_u32),
            Err(CordisError::AsyncRuntimeUnavailable)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "dead-provide"),
            provider_before
        );
        assert_eq!(machine_boundary_snapshot(&pending_control), pending_before);
        drop(pending);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (registry, provider, factory, active, active_control) = runtime.block_on(async {
            let registry = LifecycleRegistry::new();
            let provider = registry.provide("dead-replace", 3_u32).unwrap();
            let factory =
                PluginFactory::new_lifecycle("dead-replace", |_, _| LifecycleEffect::none())
                    .with_inject(["dead-replace"]);
            let active = registry
                .mount(factory.clone(), ConfigValue::default())
                .unwrap();
            active
                .fiber()
                .wait_until_active(LifecycleCancellation::default())
                .await
                .unwrap();
            let control = active.control().unwrap();
            (registry, provider, factory, active, control)
        });
        drop(runtime);
        let provider_before = provider_boundary_snapshot(&registry, "root", "dead-replace");
        let runtime_before = runtime_boundary_snapshot(&registry, &factory);
        let active_before = machine_boundary_snapshot(&active_control);
        assert!(matches!(
            registry.replace_provider(&provider, 4_u32),
            Err(CordisError::AsyncRuntimeUnavailable)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "dead-replace"),
            provider_before
        );
        assert_eq!(machine_boundary_snapshot(&active_control), active_before);

        let replacement_runtime = tokio::runtime::Runtime::new().unwrap();
        replacement_runtime.block_on(async {
            assert!(matches!(
                registry.begin_remove_provider(&provider),
                Err(CordisError::AsyncRuntimeUnavailable)
            ));
        });
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "dead-replace"),
            provider_before
        );
        assert_eq!(
            runtime_boundary_snapshot(&registry, &factory),
            runtime_before
        );
        assert_eq!(machine_boundary_snapshot(&active_control), active_before);
        assert_eq!(registry.get::<u32>("dead-replace").as_deref(), Some(&3));

        replacement_runtime
            .block_on(async { registry.begin_delete_factory(&factory).unwrap().await })
            .unwrap();
        assert!(
            !lock(&registry.inner.state)
                .runtimes
                .contains_key(&factory.id())
        );
        let recovered = machine_boundary_snapshot(&active_control);
        assert_eq!(recovered.state, FiberState::Disposed);
        assert!(
            recovered
                .diagnostics
                .contains(&CordisError::AsyncRuntimeUnavailable)
        );
        assert_eq!(registry.get::<u32>("dead-replace").as_deref(), Some(&3));

        replacement_runtime
            .block_on(async { registry.begin_shutdown().unwrap().await })
            .unwrap();
        assert!(lock(&registry.inner.state).runtimes.is_empty());
        assert!(registry.get::<u32>("dead-replace").is_none());
        drop(active);
    }

    #[tokio::test]
    async fn provisional_provider_overflow_fails_owner_without_partial_publication() {
        let registry = LifecycleRegistry::new();
        let dependent = registry
            .mount(
                PluginFactory::new_lifecycle("provisional-overflow-dependent", |_, _| {
                    LifecycleEffect::none()
                })
                .with_inject(["provisional-overflow"]),
                ConfigValue::default(),
            )
            .unwrap();
        let dependent_control = dependent.control().unwrap();
        lock(&dependent_control.machine).next_ticket = u64::MAX;
        let provider_before = provider_boundary_snapshot(&registry, "root", "provisional-overflow");
        let dependent_before = machine_boundary_snapshot(&dependent_control);
        let provider = registry
            .mount(
                PluginFactory::new_lifecycle("provisional-overflow-owner", |_, context| {
                    context.provide("provisional-overflow", 11_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();

        assert!(matches!(
            provider.await_current().await,
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(provider.snapshot().state(), FiberState::Failed);
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "provisional-overflow"),
            provider_before
        );
        assert_eq!(
            machine_boundary_snapshot(&dependent_control),
            dependent_before
        );
        assert!(registry.get::<u32>("provisional-overflow").is_none());
    }

    #[test]
    fn higher_uid_provider_owner_commits_without_inverting_dependent_lock_order() {
        let (dependent_uid, owner_uid, dependent_state, owner_state) =
            production_result_with_timeout(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    let registry = LifecycleRegistry::new();
                    let dependent = registry
                        .mount(
                            PluginFactory::new_lifecycle("uid-ordered-dependent", |_, _| {
                                LifecycleEffect::none()
                            })
                            .with_inject(["uid-ordered-provider"]),
                            ConfigValue::default(),
                        )
                        .unwrap();
                    let owner = registry
                        .mount(
                            PluginFactory::new_lifecycle("higher-uid-provider-owner", |_, view| {
                                view.provide("uid-ordered-provider", 21_u32)?;
                                Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                            }),
                            ConfigValue::default(),
                        )
                        .unwrap();
                    let owner_state = owner
                        .fiber()
                        .wait_until_active(LifecycleCancellation::default())
                        .await
                        .unwrap()
                        .state();
                    let dependent_state = dependent
                        .fiber()
                        .wait_until_active(LifecycleCancellation::default())
                        .await
                        .unwrap()
                        .state();
                    (
                        dependent.fiber().uid(),
                        owner.fiber().uid(),
                        dependent_state,
                        owner_state,
                    )
                })
            });

        assert!(owner_uid > dependent_uid);
        assert_eq!(owner_state, FiberState::Active);
        assert_eq!(dependent_state, FiberState::Active);
    }

    #[test]
    fn residual_same_owner_provider_observation_settles_without_recursive_owner_lock() {
        let (owner_state, dependent_state, residual, provisional) =
            production_result_with_timeout(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(async {
                    let registry = LifecycleRegistry::new();
                    let dependent = registry
                        .mount(
                            PluginFactory::new_lifecycle("residual-owner-dependent", |_, _| {
                                LifecycleEffect::none()
                            })
                            .with_inject(["residual-owner", "new-owner-provider"]),
                            ConfigValue::default(),
                        )
                        .unwrap();
                    let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let owner = registry
                        .mount(
                            PluginFactory::new_lifecycle("residual-provider-owner", {
                                let starts = starts.clone();
                                move |_, view| {
                                    if starts.fetch_add(1, Ordering::SeqCst) > 0 {
                                        view.provide("new-owner-provider", 34_u32)?;
                                    }
                                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                                }
                            }),
                            ConfigValue::default(),
                        )
                        .unwrap();
                    owner
                        .fiber()
                        .wait_until_active(LifecycleCancellation::default())
                        .await
                        .unwrap();
                    registry
                        .provide_for(
                            &owner.fiber(),
                            "root".to_string(),
                            "residual-owner".to_string(),
                            33_u32,
                            None,
                        )
                        .unwrap();

                    let owner_state = owner.restart().await.unwrap().state();
                    let dependent_state = dependent.await_current().await.unwrap().state();
                    (
                        owner_state,
                        dependent_state,
                        registry.get::<u32>("residual-owner").as_deref().copied(),
                        registry
                            .get::<u32>("new-owner-provider")
                            .as_deref()
                            .copied(),
                    )
                })
            });

        assert_eq!(owner_state, FiberState::Active);
        assert_eq!(dependent_state, FiberState::Pending);
        assert_eq!(residual, Some(33));
        assert_eq!(provisional, Some(34));
    }

    #[test]
    fn provisional_provider_rejects_dead_dependent_but_live_cross_runtime_batch_commits() {
        let dependent_runtime = tokio::runtime::Runtime::new().unwrap();
        let registry = LifecycleRegistry::new();
        let dependent = dependent_runtime.block_on(async {
            registry
                .mount(
                    PluginFactory::new_lifecycle("provisional-dead-dependent", |_, _| {
                        LifecycleEffect::none()
                    })
                    .with_inject(["provisional-dead"]),
                    ConfigValue::default(),
                )
                .unwrap()
        });
        let dependent_control = dependent.control().unwrap();
        let dependent_before = machine_boundary_snapshot(&dependent_control);
        let provider_before = provider_boundary_snapshot(&registry, "root", "provisional-dead");
        drop(dependent_runtime);

        let provider_runtime = tokio::runtime::Runtime::new().unwrap();
        let provider = provider_runtime.block_on(async {
            let provider = registry
                .mount(
                    PluginFactory::new_lifecycle("provisional-dead-owner", |_, context| {
                        context.provide("provisional-dead", 13_u32)?;
                        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                    }),
                    ConfigValue::default(),
                )
                .unwrap();
            assert!(matches!(
                provider.await_current().await,
                Err(CordisError::AsyncRuntimeUnavailable)
            ));
            provider
        });
        assert_eq!(provider.snapshot().state(), FiberState::Failed);
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "provisional-dead"),
            provider_before
        );
        assert_eq!(
            machine_boundary_snapshot(&dependent_control),
            dependent_before
        );
        assert!(registry.get::<u32>("provisional-dead").is_none());
        drop(provider_runtime);

        let dependent_runtime = tokio::runtime::Runtime::new().unwrap();
        let registry = LifecycleRegistry::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let dependent = dependent_runtime.block_on(async {
            registry
                .mount(
                    PluginFactory::new_lifecycle("cross-runtime-dependent", {
                        let started_tx = started_tx.clone();
                        move |_, _| {
                            if let Some(sender) = lock(&started_tx).take() {
                                let _ = sender.send(());
                            }
                            LifecycleEffect::none()
                        }
                    })
                    .with_inject(["cross-runtime-provisional"]),
                    ConfigValue::default(),
                )
                .unwrap()
        });
        let provider_runtime = tokio::runtime::Runtime::new().unwrap();
        provider_runtime.block_on(async {
            let provider = registry
                .mount(
                    PluginFactory::new_lifecycle("cross-runtime-owner", |_, context| {
                        context.provide("cross-runtime-provisional", 17_u32)?;
                        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                    }),
                    ConfigValue::default(),
                )
                .unwrap();
            provider
                .fiber()
                .wait_until_active(LifecycleCancellation::default())
                .await
                .unwrap();
            started_rx.await.unwrap();
            dependent
                .fiber()
                .wait_until_active(LifecycleCancellation::default())
                .await
                .unwrap();
        });
        assert_eq!(
            registry.get::<u32>("cross-runtime-provisional").as_deref(),
            Some(&17)
        );
    }

    #[test]
    fn recursive_provider_guards_fail_closed_for_same_key_and_indirect_cycles() {
        let registry = LifecycleRegistry::new();
        registry
            .provide_guarded("guard-self", 1_u32, {
                let registry = registry.clone();
                move |_| {
                    let _ = registry.get::<u32>("guard-self");
                    Ok(true)
                }
            })
            .unwrap();
        assert!(registry.get::<u32>("guard-self").is_none());

        registry
            .provide_guarded("guard-a", 2_u32, {
                let registry = registry.clone();
                move |_| {
                    let _ = registry.get::<u32>("guard-b");
                    Ok(true)
                }
            })
            .unwrap();
        registry
            .provide_guarded("guard-b", 3_u32, {
                let registry = registry.clone();
                move |_| {
                    let _ = registry.get::<u32>("guard-a");
                    Ok(true)
                }
            })
            .unwrap();
        assert!(registry.get::<u32>("guard-a").is_none());
        assert!(registry.get::<u32>("guard-b").is_none());
    }

    #[tokio::test]
    async fn deferred_publication_never_regresses_a_newer_ticket() {
        let registry = LifecycleRegistry::new();
        let control = detached_control(&registry, "publication-monotonicity");
        let (older, newer) = {
            let mut machine = lock(&control.machine);
            machine.desired = Some(ActivationEpoch::new(1, []));
            machine.publish_ticket(1);
            let older = machine.snapshot();
            machine.desired = Some(ActivationEpoch::new(2, []));
            machine.publish_ticket(2);
            let newer = machine.snapshot();
            (older, newer)
        };
        control.snapshots.send_replace(newer.clone());
        control.publish_deferred(older);
        assert_eq!(control.snapshots.borrow().clone(), newer);
    }

    #[tokio::test]
    async fn root_restart_delete_and_shutdown_overflow_leave_all_state_unchanged() {
        let registry = LifecycleRegistry::new();
        let factory = PluginFactory::new_lifecycle("batch-dispose-overflow", |_config, _ctx| {
            LifecycleEffect::none()
        });
        let left = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        let right = registry
            .mount(factory.clone(), ConfigValue::default())
            .unwrap();
        left.fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        right
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let left_control = left.control().unwrap();
        let right_control = right.control().unwrap();
        lock(&right_control.machine).next_ticket = u64::MAX;
        let runtime_before = runtime_boundary_snapshot(&registry, &factory);
        let left_before = machine_boundary_snapshot(&left_control);
        let right_before = machine_boundary_snapshot(&right_control);

        assert!(matches!(
            registry.restart_root().await,
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            runtime_boundary_snapshot(&registry, &factory),
            runtime_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);
        assert!(matches!(
            registry.begin_delete_factory(&factory),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            runtime_boundary_snapshot(&registry, &factory),
            runtime_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);
        assert!(matches!(
            registry.begin_shutdown(),
            Err(CordisError::TransitionTicketOverflow)
        ));
        assert_eq!(
            runtime_boundary_snapshot(&registry, &factory),
            runtime_before
        );
        assert_eq!(machine_boundary_snapshot(&left_control), left_before);
        assert_eq!(machine_boundary_snapshot(&right_control), right_before);
    }

    #[tokio::test]
    async fn shutdown_rejects_providers_before_identity_or_slot_mutation() {
        let (cleanup_tx, cleanup_rx) = tokio::sync::oneshot::channel();
        let cleanup_tx = Arc::new(Mutex::new(Some(cleanup_tx)));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let registry = LifecycleRegistry::new();
        let provider = registry.provide("kept-during-shutdown", 1_u32).unwrap();
        let factory = PluginFactory::new_lifecycle("shutdown-provider-gate", {
            let cleanup_tx = cleanup_tx.clone();
            let release = release.clone();
            move |_config, _ctx| {
                let cleanup_tx = cleanup_tx.clone();
                let release = release.clone();
                LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                    let sender = lock(&cleanup_tx).take();
                    if let Some(sender) = sender {
                        let _ = sender.send(());
                    }
                    release.wait().await;
                    Ok(())
                }))
            }
        });
        let handle = registry.mount(factory, ConfigValue::default()).unwrap();
        handle
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let shutdown = registry.begin_shutdown().unwrap();
        cleanup_rx.await.unwrap();
        let before = provider_boundary_snapshot(&registry, "root", "kept-during-shutdown");

        assert!(matches!(
            registry.provide("zombie", 2_u32),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert!(matches!(
            registry.provide_guarded("guarded-zombie", 3_u32, |_value| Ok(true)),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert!(matches!(
            registry.replace_provider(&provider, 4_u32),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "kept-during-shutdown"),
            before
        );
        release.wait().await;
        shutdown.await.unwrap();

        let completed = provider_boundary_snapshot(&registry, "root", "kept-during-shutdown");
        assert!(matches!(
            registry.provide("completed-zombie", 5_u32),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert!(matches!(
            registry.provide_guarded("completed-guarded-zombie", 6_u32, |_value| Ok(true)),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert!(matches!(
            registry.replace_provider(&provider, 7_u32),
            Err(CordisError::RuntimeShuttingDown)
        ));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "kept-during-shutdown"),
            completed
        );
    }

    #[test]
    fn provisional_owner_teardown_quarantines_dead_dependents_and_reclaims_the_key() {
        production_result_with_timeout(|| {
            let dependent_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let dependent = dependent_runtime.block_on(async {
                registry
                    .mount(
                        PluginFactory::new_lifecycle("teardown-dead-dependent", |_, _| {
                            LifecycleEffect::none()
                        })
                        .with_inject(["teardown-owned"]),
                        ConfigValue::default(),
                    )
                    .unwrap()
            });
            let dependent_control = dependent.control().unwrap();

            let owner_runtime = tokio::runtime::Runtime::new().unwrap();
            let owner = owner_runtime.block_on(async {
                let owner = registry
                    .mount(
                        PluginFactory::new_lifecycle("teardown-live-owner", |_, view| {
                            view.provide("teardown-owned", 41_u32)?;
                            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                        }),
                        ConfigValue::default(),
                    )
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                dependent
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            assert_eq!(registry.get::<u32>("teardown-owned").as_deref(), Some(&41));

            drop(dependent_runtime);
            assert!(registry.get::<u32>("teardown-owned").is_some());
            let restarted = owner_runtime.block_on(owner.restart()).unwrap();
            assert_eq!(restarted.state(), FiberState::Active);
            assert!(
                restarted
                    .diagnostics()
                    .contains(&CordisError::AsyncRuntimeUnavailable)
            );
            assert!(!control_is_registered_locked(
                &lock(&registry.inner.state),
                &dependent_control,
            ));
            assert_eq!(registry.get::<u32>("teardown-owned").as_deref(), Some(&41));

            let disposed = owner_runtime.block_on(owner.dispose_async()).unwrap();
            assert_eq!(disposed.state(), FiberState::Disposed);
            assert!(registry.get::<u32>("teardown-owned").is_none());
            let replacement = registry.provide("teardown-owned", 42_u32).unwrap();
            assert_eq!(replacement.generation(), 0);
            assert_eq!(registry.get::<u32>("teardown-owned").as_deref(), Some(&42));
        });
    }

    #[test]
    fn remove_coordinator_survives_temporary_caller_runtime_drop() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let provider = registry.provide("durable-remove", 1_u32).unwrap();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
            let release = Arc::new(tokio::sync::Barrier::new(2));
            let dependent = driver_runtime.block_on(async {
                let dependent = registry
                    .mount(
                        PluginFactory::new_lifecycle("durable-remove-dependent", {
                            let entered_tx = entered_tx.clone();
                            let release = release.clone();
                            move |_, _| {
                                let entered_tx = entered_tx.clone();
                                let release = release.clone();
                                LifecycleEffect::disposer(LifecycleDisposer::new(
                                    move || async move {
                                        if let Some(sender) = lock(&entered_tx).take() {
                                            let _ = sender.send(());
                                        }
                                        release.wait().await;
                                        Ok(())
                                    },
                                ))
                            }
                        })
                        .with_inject(["durable-remove"]),
                        ConfigValue::default(),
                    )
                    .unwrap();
                dependent
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                dependent
            });

            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_remove_provider(&provider).unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(operation);
            drop(caller_runtime);
            driver_runtime.block_on(release.wait());
            driver_runtime.block_on(async {
                dependent.await_current().await.unwrap();
                for _ in 0..128 {
                    if registry.get::<u32>("durable-remove").is_none() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("provider removal coordinator did not compare-delete");
            });
        });
    }

    #[test]
    fn delete_coordinator_survives_temporary_caller_runtime_drop() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
            let release = Arc::new(tokio::sync::Barrier::new(2));
            let factory = PluginFactory::new_lifecycle("durable-delete", {
                let entered_tx = entered_tx.clone();
                let release = release.clone();
                move |_, _| {
                    let entered_tx = entered_tx.clone();
                    let release = release.clone();
                    LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                        if let Some(sender) = lock(&entered_tx).take() {
                            let _ = sender.send(());
                        }
                        release.wait().await;
                        Ok(())
                    }))
                }
            });
            let handle = driver_runtime.block_on(async {
                let handle = registry
                    .mount(factory.clone(), ConfigValue::default())
                    .unwrap();
                handle
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                handle
            });
            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_delete_factory(&factory).unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(operation);
            drop(caller_runtime);
            driver_runtime.block_on(release.wait());
            driver_runtime.block_on(async {
                let _ = handle.await_current().await;
                for _ in 0..128 {
                    if !lock(&registry.inner.state)
                        .runtimes
                        .contains_key(&factory.id())
                    {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("factory deletion coordinator did not remove the runtime");
            });
        });
    }

    #[test]
    fn shutdown_coordinator_survives_temporary_caller_runtime_drop() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
            let release = Arc::new(tokio::sync::Barrier::new(2));
            let handle = driver_runtime.block_on(async {
                let handle = registry
                    .mount(
                        PluginFactory::new_lifecycle("durable-shutdown", {
                            let entered_tx = entered_tx.clone();
                            let release = release.clone();
                            move |_, _| {
                                let entered_tx = entered_tx.clone();
                                let release = release.clone();
                                LifecycleEffect::disposer(LifecycleDisposer::new(
                                    move || async move {
                                        if let Some(sender) = lock(&entered_tx).take() {
                                            let _ = sender.send(());
                                        }
                                        release.wait().await;
                                        Ok(())
                                    },
                                ))
                            }
                        }),
                        ConfigValue::default(),
                    )
                    .unwrap();
                handle
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                handle
            });
            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_shutdown().unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(operation);
            drop(caller_runtime);
            driver_runtime.block_on(release.wait());
            driver_runtime.block_on(async {
                let _ = handle.await_current().await;
                for _ in 0..128 {
                    if lock(&registry.inner.state).runtimes.is_empty() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("shutdown coordinator did not clear runtimes");
            });
        });
    }

    #[test]
    fn remove_quarantines_a_driver_that_dies_after_cleanup_enters() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let provider = registry.provide("death-window-remove", 1_u32).unwrap();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let dependent = driver_runtime.block_on(async {
                let dependent = registry
                    .mount(
                        PluginFactory::new_lifecycle("death-window-remove-dependent", {
                            let entered = entered.clone();
                            move |_, _| {
                                LifecycleEffect::disposer(permanently_gated_disposer(
                                    entered.clone(),
                                ))
                            }
                        })
                        .with_inject(["death-window-remove"]),
                        ConfigValue::default(),
                    )
                    .unwrap();
                dependent
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                dependent
            });
            let control = dependent.control().unwrap();
            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_remove_provider(&provider).unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            let current_waiter = caller_runtime.spawn({
                let dependent = dependent.clone();
                async move { dependent.await_current().await }
            });
            let active_waiter = caller_runtime.spawn({
                let fiber = dependent.fiber();
                async move {
                    fiber
                        .wait_until_active(LifecycleCancellation::default())
                        .await
                }
            });

            drop(driver_runtime);
            let result = caller_runtime.block_on(operation);
            assert!(matches!(result, Err(CordisError::AsyncRuntimeUnavailable)));
            let current = caller_runtime.block_on(current_waiter).unwrap().unwrap();
            assert_eq!(current.state(), FiberState::Disposed);
            let active = caller_runtime.block_on(active_waiter).unwrap();
            assert!(matches!(active, Err(CordisError::FiberDisposed { .. })));
            assert!(registry.get::<u32>("death-window-remove").is_none());
            assert!(!control_is_registered_locked(
                &lock(&registry.inner.state),
                &control,
            ));
            let terminal = machine_boundary_snapshot(&control);
            assert_eq!(terminal.state, FiberState::Disposed);
            assert!(terminal.settled_ticket >= terminal.current_ticket.unwrap().serial());
            assert!(
                terminal
                    .diagnostics
                    .contains(&CordisError::AsyncRuntimeUnavailable)
            );
        });
    }

    #[test]
    fn delete_quarantines_a_driver_that_dies_after_cleanup_enters() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let factory = PluginFactory::new_lifecycle("death-window-delete", {
                let entered = entered.clone();
                move |_, view| {
                    view.provide("death-window-delete-owned", 2_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::disposer(
                        permanently_gated_disposer(entered.clone()),
                    ))
                }
            });
            let owner = driver_runtime.block_on(async {
                let owner = registry
                    .mount(factory.clone(), ConfigValue::default())
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            let control = owner.control().unwrap();
            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_delete_factory(&factory).unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(driver_runtime);
            let result = caller_runtime.block_on(operation);
            assert!(matches!(result, Err(CordisError::AsyncRuntimeUnavailable)));
            assert!(
                !lock(&registry.inner.state)
                    .runtimes
                    .contains_key(&factory.id())
            );
            assert!(registry.get::<u32>("death-window-delete-owned").is_none());
            assert_eq!(
                machine_boundary_snapshot(&control).state,
                FiberState::Disposed
            );
            assert!(registry.provide("death-window-delete-owned", 3_u32).is_ok());
        });
    }

    #[test]
    fn shutdown_quarantines_a_driver_that_dies_after_cleanup_enters() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let caller_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let owner = driver_runtime.block_on(async {
                let owner = registry
                    .mount(
                        PluginFactory::new_lifecycle("death-window-shutdown", {
                            let entered = entered.clone();
                            move |_, view| {
                                view.provide("death-window-shutdown-owned", 4_u32)?;
                                Ok::<LifecycleEffect, CordisError>(LifecycleEffect::disposer(
                                    permanently_gated_disposer(entered.clone()),
                                ))
                            }
                        }),
                        ConfigValue::default(),
                    )
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            let control = owner.control().unwrap();
            let operation = {
                let _runtime = caller_runtime.enter();
                registry.begin_shutdown().unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(driver_runtime);
            let result = caller_runtime.block_on(operation);
            assert!(matches!(result, Err(CordisError::AsyncRuntimeUnavailable)));
            let state = lock(&registry.inner.state);
            assert!(state.shutting_down);
            assert!(state.runtimes.is_empty());
            assert!(state.providers.is_empty());
            drop(state);
            assert_eq!(
                machine_boundary_snapshot(&control).state,
                FiberState::Disposed
            );
        });
    }

    #[test]
    fn owner_teardown_quarantines_a_dependent_that_dies_mid_removal() {
        production_result_with_timeout(|| {
            let dependent_runtime = tokio::runtime::Runtime::new().unwrap();
            let owner_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let dependent = dependent_runtime.block_on(async {
                registry
                    .mount(
                        PluginFactory::new_lifecycle("mid-teardown-dependent", {
                            let entered = entered.clone();
                            move |_, _| {
                                LifecycleEffect::disposer(permanently_gated_disposer(
                                    entered.clone(),
                                ))
                            }
                        })
                        .with_inject(["mid-teardown-provider"]),
                        ConfigValue::default(),
                    )
                    .unwrap()
            });
            let dependent_control = dependent.control().unwrap();
            let owner = owner_runtime.block_on(async {
                let owner = registry
                    .mount(
                        PluginFactory::new_lifecycle("mid-teardown-owner", |_, view| {
                            view.provide("mid-teardown-provider", 5_u32)?;
                            Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                        }),
                        ConfigValue::default(),
                    )
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                dependent
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            let restart = owner_runtime.spawn({
                let owner = owner.clone();
                async move { owner.restart().await }
            });
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            drop(dependent_runtime);
            let restarted = owner_runtime.block_on(restart).unwrap().unwrap();
            assert_eq!(restarted.state(), FiberState::Active);
            assert!(
                restarted
                    .diagnostics()
                    .contains(&CordisError::AsyncRuntimeUnavailable)
            );
            assert!(!control_is_registered_locked(
                &lock(&registry.inner.state),
                &dependent_control,
            ));
            assert_eq!(
                machine_boundary_snapshot(&dependent_control).state,
                FiberState::Disposed
            );
            assert_eq!(
                registry.get::<u32>("mid-teardown-provider").as_deref(),
                Some(&5)
            );
            let disposed = owner_runtime.block_on(owner.dispose_async()).unwrap();
            assert_eq!(disposed.state(), FiberState::Disposed);
            assert!(registry.get::<u32>("mid-teardown-provider").is_none());
        });
    }

    #[test]
    fn delete_recovers_a_zero_consumer_dead_owner_key() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let recovery_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let factory = PluginFactory::new_lifecycle("zero-consumer-dead-owner", |_, view| {
                view.provide("zero-consumer-dead-key", 6_u32)?;
                Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
            });
            let owner = driver_runtime.block_on(async {
                let owner = registry
                    .mount(factory.clone(), ConfigValue::default())
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            let control = owner.control().unwrap();
            assert_eq!(
                registry.get::<u32>("zero-consumer-dead-key").as_deref(),
                Some(&6)
            );
            drop(driver_runtime);
            assert!(registry.get::<u32>("zero-consumer-dead-key").is_none());

            recovery_runtime
                .block_on(async { registry.begin_delete_factory(&factory).unwrap().await })
                .unwrap();
            assert_eq!(
                machine_boundary_snapshot(&control).state,
                FiberState::Disposed
            );
            assert!(
                !lock(&registry.inner.state)
                    .runtimes
                    .contains_key(&factory.id())
            );
            assert!(registry.get::<u32>("zero-consumer-dead-key").is_none());
            assert!(registry.provide("zero-consumer-dead-key", 7_u32).is_ok());
        });
    }

    #[test]
    fn recovery_reclaims_unrelated_sibling_and_descendant_keys_on_one_dead_binding() {
        production_result_with_timeout(|| {
            let driver_runtime = tokio::runtime::Runtime::new().unwrap();
            let recovery_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let child_factory = PluginFactory::new_lifecycle("dead-binding-child", |_, view| {
                view.provide("dead-binding-child-key", 10_u32)?;
                Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
            });
            let parent_factory = PluginFactory::new_lifecycle("dead-binding-parent", {
                let child_factory = child_factory.clone();
                move |_, view| {
                    view.provide("dead-binding-parent-key", 8_u32)?;
                    let _child = view.mount(child_factory.clone(), ConfigValue::default())?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }
            });
            let sibling_factory =
                PluginFactory::new_lifecycle("dead-binding-sibling", |_, view| {
                    view.provide("dead-binding-sibling-key", 9_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                });
            let (parent, sibling) = driver_runtime.block_on(async {
                let parent = registry
                    .mount(parent_factory.clone(), ConfigValue::default())
                    .unwrap();
                let sibling = registry
                    .mount(sibling_factory.clone(), ConfigValue::default())
                    .unwrap();
                parent
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                sibling
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                for _ in 0..128 {
                    if registry.get::<u32>("dead-binding-child-key").is_some() {
                        return (parent, sibling);
                    }
                    tokio::task::yield_now().await;
                }
                panic!("provisional child did not publish its provider");
            });
            assert_eq!(
                registry.get::<u32>("dead-binding-parent-key").as_deref(),
                Some(&8)
            );
            assert_eq!(
                registry.get::<u32>("dead-binding-sibling-key").as_deref(),
                Some(&9)
            );
            assert_eq!(
                registry.get::<u32>("dead-binding-child-key").as_deref(),
                Some(&10)
            );
            drop(driver_runtime);

            recovery_runtime
                .block_on(async {
                    registry
                        .begin_delete_factory(&parent_factory)
                        .unwrap()
                        .await
                })
                .unwrap();
            let state = lock(&registry.inner.state);
            assert!(state.runtimes.is_empty());
            assert!(state.providers.values().all(|slot| slot.record.is_none()));
            drop(state);
            assert!(registry.provide("dead-binding-parent-key", 18_u32).is_ok());
            assert!(registry.provide("dead-binding-sibling-key", 19_u32).is_ok());
            assert!(registry.provide("dead-binding-child-key", 20_u32).is_ok());
            drop((parent, sibling));
        });
    }

    #[tokio::test]
    async fn view_provider_teardown_reclaims_exhausted_slot_on_restart_and_dispose() {
        let registry = LifecycleRegistry::new();
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("teardown-counter-owner", |_, view| {
                    view.provide("teardown-counter-key", 21_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let key = RuntimeProviderKey::new("root", "teardown-counter-key");
        let first_provider_id = {
            let mut state = lock(&registry.inner.state);
            let slot = state.providers.get_mut(&key).unwrap();
            let provider_id = slot.record.as_ref().unwrap().provider_id;
            slot.revision = u64::MAX;
            slot.removal_serial = u64::MAX;
            provider_id
        };

        let restarted = owner.restart().await.unwrap();
        assert_eq!(restarted.state(), FiberState::Active);
        assert!(
            restarted
                .diagnostics()
                .contains(&CordisError::ProviderGenerationOverflow {
                    key: "teardown-counter-key".to_string(),
                })
        );
        let second_provider_id = lock(&registry.inner.state).providers[&key]
            .record
            .as_ref()
            .unwrap()
            .provider_id;
        assert_ne!(second_provider_id, first_provider_id);
        assert_eq!(
            registry.get::<u32>("teardown-counter-key").as_deref(),
            Some(&21)
        );

        {
            let mut state = lock(&registry.inner.state);
            let slot = state.providers.get_mut(&key).unwrap();
            slot.revision = u64::MAX;
            slot.removal_serial = u64::MAX;
        }
        let disposed = owner.dispose_async().await.unwrap();
        assert_eq!(disposed.state(), FiberState::Disposed);
        assert!(registry.get::<u32>("teardown-counter-key").is_none());
        assert!(
            lock(&registry.inner.state)
                .providers
                .get(&key)
                .is_none_or(|slot| slot.record.is_none())
        );
    }

    #[tokio::test]
    async fn view_provider_teardown_quarantines_a_ticket_exhausted_dependent() {
        let registry = LifecycleRegistry::new();
        let dependent = registry
            .mount(
                PluginFactory::new_lifecycle("teardown-ticket-dependent", |_, _| {
                    LifecycleEffect::none()
                })
                .with_inject(["teardown-ticket-key"]),
                ConfigValue::default(),
            )
            .unwrap();
        let dependent_control = dependent.control().unwrap();
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("teardown-ticket-owner", |_, view| {
                    view.provide("teardown-ticket-key", 22_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        dependent
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        lock(&dependent_control.machine).next_ticket = u64::MAX;

        let restarted = owner.restart().await.unwrap();
        assert_eq!(restarted.state(), FiberState::Active);
        assert!(
            restarted
                .diagnostics()
                .contains(&CordisError::TransitionTicketOverflow)
        );
        assert!(!control_is_registered_locked(
            &lock(&registry.inner.state),
            &dependent_control,
        ));
        let terminal = machine_boundary_snapshot(&dependent_control);
        assert_eq!(terminal.state, FiberState::Disposed);
        assert!(
            terminal
                .diagnostics
                .contains(&CordisError::TransitionTicketOverflow)
        );
        assert_eq!(
            registry.get::<u32>("teardown-ticket-key").as_deref(),
            Some(&22)
        );

        owner.dispose_async().await.unwrap();
        assert!(registry.get::<u32>("teardown-ticket-key").is_none());
    }

    #[tokio::test]
    async fn delayed_remove_completion_cannot_delete_a_reprovided_value() {
        let registry = LifecycleRegistry::new();
        let original = registry.provide("delayed-remove-key", 23_u32).unwrap();
        let (entered_tx, entered_rx) = oneshot::channel();
        let entered = Arc::new(Mutex::new(Some(entered_tx)));
        let release = Arc::new(tokio::sync::Barrier::new(2));
        let dependent = registry
            .mount(
                PluginFactory::new_lifecycle("delayed-remove-dependent", {
                    let entered = entered.clone();
                    let release = release.clone();
                    move |_, _| {
                        let entered = entered.clone();
                        let release = release.clone();
                        LifecycleEffect::disposer(LifecycleDisposer::new(move || async move {
                            if let Some(sender) = lock(&entered).take() {
                                let _ = sender.send(());
                            }
                            release.wait().await;
                            Ok(())
                        }))
                    }
                })
                .with_inject(["delayed-remove-key"]),
                ConfigValue::default(),
            )
            .unwrap();
        dependent
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let removal = registry.begin_remove_provider(&original).unwrap();
        entered_rx.await.unwrap();
        let replacement = registry.provide("delayed-remove-key", 24_u32).unwrap();
        assert_ne!(replacement.provider_id(), original.provider_id());
        release.wait().await;
        removal.await.unwrap();
        assert_eq!(
            registry.get::<u32>("delayed-remove-key").as_deref(),
            Some(&24)
        );
        let snapshot = provider_boundary_snapshot(&registry, "root", "delayed-remove-key");
        assert_eq!(
            snapshot.slot.as_ref().and_then(|slot| slot.provider_id),
            Some(replacement.provider_id())
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one oracle exercises the shared owner fence in public and reconcile transactions"
    )]
    async fn managed_owner_commit_gap_rejects_public_and_reconcile_epochs() {
        let registry = LifecycleRegistry::new();
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("gap-owner", |_, _| LifecycleEffect::none()),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let owner_control = owner.control().unwrap();
        let public_dependent = registry
            .mount(
                PluginFactory::new_lifecycle("gap-public-dependent", |_, _| {
                    LifecycleEffect::none()
                })
                .with_inject(["gap-public"]),
                ConfigValue::default(),
            )
            .unwrap();
        let public_control = public_dependent.control().unwrap();
        let public_before = machine_boundary_snapshot(&public_control);
        let request = ProviderMutationRequest::Provide {
            owner: owner.fiber(),
            key: RuntimeProviderKey::new("root", "gap-public"),
            value: Arc::new(1_u32),
            guard: None,
        };
        let (plan, outcomes) = {
            let state = lock(&registry.inner.state);
            let plan = plan_provider_mutation(&state, registry.inner.id, &request).unwrap();
            let drafts = affected_controls_locked(&state, &plan.key)
                .into_iter()
                .map(|control| {
                    let observations =
                        provider_observations_with_plan_locked(&state, &control, &plan);
                    let (config_revision, tombstone) = {
                        let machine = lock(&control.machine);
                        (machine.config_revision, machine.tombstone)
                    };
                    ProviderControlDraft {
                        control,
                        config_revision,
                        tombstone,
                        observations,
                    }
                })
                .collect();
            (
                plan,
                evaluate_provider_control_drafts(registry.inner.id, drafts),
            )
        };
        FiberControl::apply_transition_state_locked(
            &mut lock(&owner_control.machine),
            FiberState::Unloading,
        );
        let rejected = commit_provider_mutation_if_current(&registry.inner, &plan, &outcomes);
        assert!(matches!(
            rejected,
            Ok(None) | Err(CordisError::FiberDisposed { .. })
        ));
        assert_eq!(machine_boundary_snapshot(&public_control), public_before);
        assert!(registry.get::<u32>("gap-public").is_none());
        FiberControl::apply_transition_state_locked(
            &mut lock(&owner_control.machine),
            FiberState::Active,
        );

        registry
            .provide_for(
                &owner.fiber(),
                "root".to_string(),
                "gap-existing".to_string(),
                2_u32,
                None,
            )
            .unwrap();
        let reconcile_dependent = registry
            .mount(
                PluginFactory::new_lifecycle("gap-reconcile-dependent", |_, _| {
                    LifecycleEffect::none()
                })
                .with_inject(["gap-existing"]),
                ConfigValue::default(),
            )
            .unwrap();
        reconcile_dependent
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let reconcile_control = reconcile_dependent.control().unwrap();
        {
            let mut machine = lock(&reconcile_control.machine);
            machine.desired = None;
            machine.committed = None;
            machine.state = FiberState::Pending;
        }
        let reconcile_before = machine_boundary_snapshot(&reconcile_control);
        let drafts =
            stage_reconciliation(&registry.inner, std::slice::from_ref(&reconcile_control));
        let outcomes = evaluate_provider_control_drafts(registry.inner.id, drafts);
        FiberControl::apply_transition_state_locked(
            &mut lock(&owner_control.machine),
            FiberState::Unloading,
        );
        assert!(
            !commit_reconciliation_if_current(
                &registry.inner,
                std::slice::from_ref(&reconcile_control),
                &outcomes,
            )
            .unwrap()
        );
        assert_eq!(
            machine_boundary_snapshot(&reconcile_control),
            reconcile_before
        );
    }

    #[test]
    fn direct_get_hides_a_managed_provider_after_its_driver_dies() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let registry = LifecycleRegistry::new();
        let owner = runtime.block_on(async {
            let owner = registry
                .mount(
                    PluginFactory::new_lifecycle("dead-get-owner", |_, view| {
                        view.provide("dead-get", 55_u32)?;
                        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                    }),
                    ConfigValue::default(),
                )
                .unwrap();
            owner
                .fiber()
                .wait_until_active(LifecycleCancellation::default())
                .await
                .unwrap();
            owner
        });
        assert_eq!(registry.get::<u32>("dead-get").as_deref(), Some(&55));
        drop(runtime);
        assert!(registry.get::<u32>("dead-get").is_none());
        drop(owner);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn provisional_commit_gap_does_not_publish_a_dead_managed_owner() {
        let registry = LifecycleRegistry::new();
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("provisional-gap-existing-owner", |_, _| {
                    LifecycleEffect::none()
                }),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let owner_control = owner.control().unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let entered_tx = Arc::new(Mutex::new(Some(entered_tx)));
        let release = Arc::new(std::sync::Barrier::new(2));
        let blocked = Arc::new(AtomicBool::new(false));
        let guard: ProviderGuard = Arc::new({
            let entered_tx = entered_tx.clone();
            let release = release.clone();
            let blocked = blocked.clone();
            move |_| {
                if !blocked.swap(true, Ordering::SeqCst) {
                    if let Some(sender) = lock(&entered_tx).take() {
                        let _ = sender.send(());
                    }
                    release.wait();
                }
                Ok(true)
            }
        });
        registry
            .provide_for(
                &owner.fiber(),
                "root".to_string(),
                "provisional-gap-existing".to_string(),
                71_u32,
                Some(guard),
            )
            .unwrap();
        let dependent = registry
            .mount(
                PluginFactory::new_lifecycle("provisional-gap-dependent", |_, _| {
                    LifecycleEffect::none()
                })
                // Missing provisional key comes first so initial mount does
                // not invoke the existing provider guard.
                .with_inject(["provisional-gap-new", "provisional-gap-existing"]),
                ConfigValue::default(),
            )
            .unwrap();
        let dependent_control = dependent.control().unwrap();
        let activation_owner = registry
            .mount(
                PluginFactory::new_lifecycle("provisional-gap-new-owner", |_, view| {
                    view.provide("provisional-gap-new", 72_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();
        entered_rx.await.unwrap();
        {
            let mut machine = lock(&owner_control.machine);
            FiberControl::apply_transition_state_locked(&mut machine, FiberState::Unloading);
        }
        release.wait();
        activation_owner.await_current().await.unwrap();

        let machine = lock(&dependent_control.machine);
        for epoch in machine.desired.iter().chain(machine.committed.iter()) {
            assert!(
                epoch
                    .dependencies()
                    .iter()
                    .all(|dependency| dependency.owner_uid() != owner.fiber().uid())
            );
        }
        assert_eq!(machine.state, FiberState::Pending);
    }

    #[test]
    fn dead_owner_recovery_waits_until_a_live_consumer_settles_or_dies() {
        production_result_with_timeout(|| {
            let owner_runtime = tokio::runtime::Runtime::new().unwrap();
            let consumer_runtime = tokio::runtime::Runtime::new().unwrap();
            let recovery_runtime = tokio::runtime::Runtime::new().unwrap();
            let registry = LifecycleRegistry::new();
            let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
            let entered = Arc::new(Mutex::new(Some(entered_tx)));
            let consumer = consumer_runtime.block_on(async {
                registry
                    .mount(
                        PluginFactory::new_lifecycle("recovery-live-consumer", {
                            let entered = entered.clone();
                            move |_, _| {
                                LifecycleEffect::disposer(permanently_gated_disposer(
                                    entered.clone(),
                                ))
                            }
                        })
                        .with_inject(["recovery-live-key"]),
                        ConfigValue::default(),
                    )
                    .unwrap()
            });
            let consumer_control = consumer.control().unwrap();
            let owner_factory = PluginFactory::new_lifecycle("recovery-dead-owner", |_, view| {
                view.provide("recovery-live-key", 81_u32)?;
                Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
            });
            let owner = owner_runtime.block_on(async {
                let owner = registry
                    .mount(owner_factory.clone(), ConfigValue::default())
                    .unwrap();
                owner
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                consumer
                    .fiber()
                    .wait_until_active(LifecycleCancellation::default())
                    .await
                    .unwrap();
                owner
            });
            drop(owner_runtime);

            let operation = {
                let _entered = recovery_runtime.enter();
                registry.begin_delete_factory(&owner_factory).unwrap()
            };
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(registry.get::<u32>("recovery-live-key").is_none());
            drop(consumer_runtime);
            let result = recovery_runtime.block_on(operation);
            assert!(matches!(result, Err(CordisError::AsyncRuntimeUnavailable)));
            assert_eq!(
                machine_boundary_snapshot(&consumer_control).state,
                FiberState::Disposed
            );
            assert!(!control_is_registered_locked(
                &lock(&registry.inner.state),
                &consumer_control,
            ));
            assert!(registry.provide("recovery-live-key", 82_u32).is_ok());
            drop((consumer, owner));
        });
    }

    #[tokio::test]
    async fn ticket_exhausted_live_parent_and_child_run_real_cleanup() {
        let registry = LifecycleRegistry::new();
        let cleanup_count = Arc::new(AtomicU64::new(0));
        let child_slot = Arc::new(Mutex::new(None::<Fiber>));
        let child_factory = PluginFactory::new_lifecycle("overflow-live-child", {
            let cleanup_count = cleanup_count.clone();
            move |_, _| {
                LifecycleEffect::disposer(LifecycleDisposer::new({
                    let cleanup_count = cleanup_count.clone();
                    move || {
                        let cleanup_count = cleanup_count.clone();
                        async move {
                            cleanup_count.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        }
                    }
                }))
            }
        });
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("overflow-live-owner", |_, view| {
                    view.provide("overflow-live-key", 83_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let parent = registry
            .mount(
                PluginFactory::new_lifecycle("overflow-live-parent", {
                    let child_factory = child_factory.clone();
                    let child_slot = child_slot.clone();
                    let cleanup_count = cleanup_count.clone();
                    move |_, view| {
                        let child = view.mount(child_factory.clone(), ConfigValue::default())?;
                        *lock(&child_slot) = Some(child);
                        Ok::<LifecycleEffect, CordisError>(LifecycleEffect::disposer(
                            LifecycleDisposer::new({
                                let cleanup_count = cleanup_count.clone();
                                move || {
                                    let cleanup_count = cleanup_count.clone();
                                    async move {
                                        cleanup_count.fetch_add(1, Ordering::SeqCst);
                                        Ok(())
                                    }
                                }
                            }),
                        ))
                    }
                })
                .with_inject(["overflow-live-key"]),
                ConfigValue::default(),
            )
            .unwrap();
        parent
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let child = lock(&child_slot).clone().unwrap();
        child
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let parent_control = parent.control().unwrap();
        let child_control = {
            let state = lock(&registry.inner.state);
            state.runtimes[&child_factory.id()]
                .fibers
                .values()
                .next()
                .unwrap()
                .clone()
        };
        lock(&parent_control.machine).next_ticket = u64::MAX;

        let restarted = owner.restart().await.unwrap();
        assert_eq!(restarted.state(), FiberState::Active);
        assert_eq!(cleanup_count.load(Ordering::SeqCst), 2);
        assert_eq!(parent.snapshot().state(), FiberState::Disposed);
        assert_eq!(child.state(), FiberState::Disposed);
        let state = lock(&registry.inner.state);
        assert!(!control_is_registered_locked(&state, &parent_control));
        assert!(!control_is_registered_locked(&state, &child_control));
    }

    #[tokio::test]
    async fn stale_owner_teardown_handle_cannot_touch_replacement_or_consumers() {
        let registry = LifecycleRegistry::new();
        let original = registry.provide("stale-forced-key", 84_u32).unwrap();
        let consumer = registry
            .mount(
                PluginFactory::new_lifecycle("stale-forced-consumer", |_, _| {
                    LifecycleEffect::none()
                })
                .with_inject(["stale-forced-key"]),
                ConfigValue::default(),
            )
            .unwrap();
        consumer
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let consumer_control = consumer.control().unwrap();
        let replacement = registry.replace_provider(&original, 85_u32).unwrap();
        consumer.await_current().await.unwrap();
        let provider_before = provider_boundary_snapshot(&registry, "root", "stale-forced-key");
        let consumer_before = machine_boundary_snapshot(&consumer_control);
        consumer_control
            .driver_runtime
            .state
            .alive
            .store(false, Ordering::Release);
        consumer_control
            .driver_runtime
            .state
            .death
            .send_replace(false);

        let result = registry
            .begin_provider_removal_with_mode(
                &original,
                ProviderRemovalMode::OwnerTeardown {
                    driver_runtime: consumer_control.driver_runtime.clone(),
                },
            )
            .unwrap()
            .await;
        assert!(matches!(result, Err(CordisError::AsyncRuntimeUnavailable)));
        assert_eq!(
            provider_boundary_snapshot(&registry, "root", "stale-forced-key"),
            provider_before
        );
        assert_eq!(
            machine_boundary_snapshot(&consumer_control),
            consumer_before
        );
        assert_eq!(
            registry.get::<u32>("stale-forced-key").as_deref(),
            Some(&85)
        );
        assert_eq!(replacement.generation(), 1);
    }

    #[tokio::test]
    async fn supervisor_reservation_failure_fences_owner_but_not_public_strict_removal() {
        let registry = LifecycleRegistry::new();
        let owner = registry
            .mount(
                PluginFactory::new_lifecycle("reservation-failure-owner", |_, view| {
                    view.provide("reservation-failure-key", 86_u32)?;
                    Ok::<LifecycleEffect, CordisError>(LifecycleEffect::none())
                }),
                ConfigValue::default(),
            )
            .unwrap();
        owner
            .fiber()
            .wait_until_active(LifecycleCancellation::default())
            .await
            .unwrap();
        let first_provider_id =
            provider_boundary_snapshot(&registry, "root", "reservation-failure-key")
                .slot
                .unwrap()
                .provider_id
                .unwrap();
        registry
            .inner
            .supervisor_reservation_failures
            .store(1, Ordering::Release);
        let restarted = owner.restart().await.unwrap();
        assert_eq!(restarted.state(), FiberState::Active);
        assert!(
            restarted
                .diagnostics()
                .contains(&CordisError::AsyncRuntimeUnavailable)
        );
        let second_provider_id =
            provider_boundary_snapshot(&registry, "root", "reservation-failure-key")
                .slot
                .unwrap()
                .provider_id
                .unwrap();
        assert_ne!(first_provider_id, second_provider_id);

        let strict_registry = LifecycleRegistry::new();
        let strict = strict_registry
            .provide("reservation-strict-key", 87_u32)
            .unwrap();
        let strict_before =
            provider_boundary_snapshot(&strict_registry, "root", "reservation-strict-key");
        strict_registry
            .inner
            .supervisor_reservation_failures
            .store(1, Ordering::Release);
        assert!(matches!(
            strict_registry.begin_remove_provider(&strict),
            Err(CordisError::AsyncRuntimeUnavailable)
        ));
        assert_eq!(
            provider_boundary_snapshot(&strict_registry, "root", "reservation-strict-key"),
            strict_before
        );
        assert_eq!(
            strict_registry
                .get::<u32>("reservation-strict-key")
                .as_deref(),
            Some(&87)
        );
    }
}
