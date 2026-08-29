//! Fiber identity and lifecycle value types.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::config::ConfigValue;
use crate::context::CordisError;

pub(crate) type FiberFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

pub(crate) trait FiberLifecycle: Send + Sync {
    fn snapshot(&self) -> FiberSnapshot;
    fn is_tombstoned(&self) -> bool;
    fn state_history(&self) -> Vec<FiberState>;
    fn await_current(&self) -> FiberFuture<Result<FiberSnapshot, CordisError>>;
    fn wait_until_active(
        &self,
        cancellation: LifecycleCancellation,
    ) -> FiberFuture<Result<FiberSnapshot, CordisError>>;
}

/// Opaque monotonically allocated Fiber identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FiberUid(u64);

impl FiberUid {
    /// The root Fiber identity.  A root can only be obtained from a Context.
    pub const ROOT: Self = Self(0);

    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for FiberUid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FiberUid").field(&self.0).finish()
    }
}

impl fmt::Display for FiberUid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Complete Cordis Fiber lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FiberState {
    /// Dependencies are not ready and no callback has run yet.
    Pending,
    /// The selected activation epoch is starting.
    Loading,
    /// The Fiber has successfully activated its callback.
    Active,
    /// Plugin start failed and the typed cause is retained.
    Failed,
    /// The child Fiber has published its terminal tombstone.
    Disposed,
    /// Registrations from the previous activation are being cleaned up.
    Unloading,
}

impl FiberState {
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Loading => 1,
            Self::Active => 2,
            Self::Failed => 3,
            Self::Disposed => 4,
            Self::Unloading => 5,
        }
    }

    pub(crate) const fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Loading,
            2 => Self::Active,
            3 => Self::Failed,
            4 => Self::Disposed,
            5 => Self::Unloading,
            _ => Self::Pending,
        }
    }
}

/// Provider facts which participate in an activation epoch.
///
/// Provider authorization ids are deliberately absent: replacing a provider
/// handle without changing its active owner or generation does not create a
/// different activation epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderFingerprint {
    namespace: String,
    key: String,
    owner_uid: FiberUid,
    generation: u64,
}

impl ProviderFingerprint {
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<String>,
        owner_uid: FiberUid,
        generation: u64,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            owner_uid,
            generation,
        }
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
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

/// Stable activation target: config revision plus ordered dependency facts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActivationEpoch {
    config_revision: u64,
    dependencies: Vec<ProviderFingerprint>,
}

impl ActivationEpoch {
    #[must_use]
    pub fn new(
        config_revision: u64,
        dependencies: impl IntoIterator<Item = ProviderFingerprint>,
    ) -> Self {
        let mut dependencies = dependencies.into_iter().collect::<Vec<_>>();
        dependencies.sort();
        Self {
            config_revision,
            dependencies,
        }
    }

    #[must_use]
    pub const fn config_revision(&self) -> u64 {
        self.config_revision
    }

    #[must_use]
    pub fn dependencies(&self) -> &[ProviderFingerprint] {
        &self.dependencies
    }
}

/// Monotonic transition identity bound to one desired activation epoch.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransitionTicket {
    serial: u64,
    target: Option<ActivationEpoch>,
}

/// Observable immutable lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiberSnapshot {
    state: FiberState,
    ticket: Option<TransitionTicket>,
    committed_epoch: Option<ActivationEpoch>,
    error: Option<CordisError>,
    diagnostics: Vec<CordisError>,
}

impl FiberSnapshot {
    #[must_use]
    pub fn new(
        state: FiberState,
        ticket: Option<TransitionTicket>,
        committed_epoch: Option<ActivationEpoch>,
        error: Option<CordisError>,
        diagnostics: Vec<CordisError>,
    ) -> Self {
        Self {
            state,
            ticket,
            committed_epoch,
            error,
            diagnostics,
        }
    }

    #[must_use]
    pub const fn state(&self) -> FiberState {
        self.state
    }

    #[must_use]
    pub fn ticket(&self) -> Option<&TransitionTicket> {
        self.ticket.as_ref()
    }

    #[must_use]
    pub fn committed_epoch(&self) -> Option<&ActivationEpoch> {
        self.committed_epoch.as_ref()
    }

    #[must_use]
    pub fn error(&self) -> Option<&CordisError> {
        self.error.as_ref()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[CordisError] {
        &self.diagnostics
    }
}

/// Explicit cancellation handle for [`Fiber::wait_until_active`].
#[derive(Debug, Clone)]
pub struct LifecycleCancellation {
    cancelled: Arc<tokio::sync::watch::Sender<bool>>,
}

impl LifecycleCancellation {
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    pub(crate) async fn cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        while !*cancelled.borrow_and_update() {
            if cancelled.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for LifecycleCancellation {
    fn default() -> Self {
        let (cancelled, _) = tokio::sync::watch::channel(false);
        Self {
            cancelled: Arc::new(cancelled),
        }
    }
}

impl TransitionTicket {
    #[must_use]
    pub fn new(serial: u64, target: Option<ActivationEpoch>) -> Self {
        Self { serial, target }
    }

    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    #[must_use]
    pub fn target(&self) -> Option<&ActivationEpoch> {
        self.target.as_ref()
    }
}

static NEXT_FIBER_UID: AtomicU64 = AtomicU64::new(1);

struct FiberInner {
    context_id: u64,
    uid: FiberUid,
    parent: Option<FiberUid>,
    legacy_state: AtomicU8,
    disposed: AtomicBool,
    metadata: Mutex<ConfigValue>,
    namespace: String,
    lifecycle: Mutex<Option<Weak<dyn FiberLifecycle>>>,
    terminal: Mutex<Option<(FiberSnapshot, Vec<FiberState>)>>,
}

/// Cloneable, opaque handle to a Fiber.
///
/// A Fiber handle carries identity and state only.  It cannot mint a reserved
/// provider authority or mutate a Context by itself; those operations require
/// a Context/ContextView or [`crate::LifecycleHandle`] owned by the caller.
/// This applies equally to a captured sibling, ancestor, or root Fiber.
///
/// ```compile_fail
/// use hartevo_cordis::Fiber;
///
/// fn cannot_mutate_a_captured_relative(relative: &Fiber) {
///     let _ = relative.restart();
///     let _ = relative.dispose_async();
/// }
/// ```
#[derive(Clone)]
pub struct Fiber {
    inner: Arc<FiberInner>,
}

impl Fiber {
    pub(crate) fn root(context_id: u64) -> Self {
        Self {
            inner: Arc::new(FiberInner {
                context_id,
                uid: FiberUid::ROOT,
                parent: None,
                legacy_state: AtomicU8::new(FiberState::Active.as_byte()),
                disposed: AtomicBool::new(false),
                metadata: Mutex::new(ConfigValue::default()),
                namespace: "root".to_string(),
                lifecycle: Mutex::new(None),
                terminal: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn child_with_namespace(context_id: u64, parent: &Self, namespace: String) -> Self {
        let uid = FiberUid(NEXT_FIBER_UID.fetch_add(1, Ordering::Relaxed));
        let metadata = parent.metadata_snapshot();
        Self {
            inner: Arc::new(FiberInner {
                context_id,
                uid,
                parent: Some(parent.uid()),
                legacy_state: AtomicU8::new(FiberState::Pending.as_byte()),
                disposed: AtomicBool::new(false),
                metadata: Mutex::new(metadata),
                namespace,
                lifecycle: Mutex::new(None),
                terminal: Mutex::new(None),
            }),
        }
    }

    /// Stable identity of this Fiber.
    #[must_use]
    pub fn uid(&self) -> FiberUid {
        self.inner.uid
    }

    /// The parent identity, if this is not the root Fiber.
    #[must_use]
    pub fn parent_uid(&self) -> Option<FiberUid> {
        self.inner.parent
    }

    /// Current minimal lifecycle state.
    ///
    /// N1-managed Fibers read the single runtime control snapshot. Legacy N0
    /// Context Fibers retain their last Active/Pending compatibility snapshot
    /// after teardown; callers must use [`Self::is_disposed`] as the terminal
    /// authority for those unmanaged handles.
    #[must_use]
    pub fn state(&self) -> FiberState {
        if let Some(lifecycle) = self.lifecycle() {
            return lifecycle.snapshot().state();
        }
        self.terminal_snapshot().map_or_else(
            || FiberState::from_byte(self.inner.legacy_state.load(Ordering::Acquire)),
            |(snapshot, _)| snapshot.state(),
        )
    }

    /// Whether this Fiber has reached its terminal state.
    #[must_use]
    pub fn is_disposed(&self) -> bool {
        self.lifecycle().map_or_else(
            || self.inner.disposed.load(Ordering::Acquire),
            |lifecycle| lifecycle.is_tombstoned(),
        )
    }

    /// Mark a pending Fiber active exactly once.
    pub(crate) fn activate(&self) -> bool {
        if self.is_disposed() {
            return false;
        }
        self.inner
            .legacy_state
            .compare_exchange(
                FiberState::Pending.as_byte(),
                FiberState::Active.as_byte(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Publish the legacy N0 terminal tombstone. Repeated disposal is a no-op;
    /// the compatibility state snapshot intentionally remains Active/Pending.
    /// The root Fiber is retained as the reusable Context owner.
    pub(crate) fn dispose(&self) -> bool {
        if self.uid() == FiberUid::ROOT {
            return false;
        }
        !self.inner.disposed.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn publish_tombstone(&self) -> bool {
        if self.uid() == FiberUid::ROOT {
            return false;
        }
        !self.inner.disposed.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn context_id(&self) -> u64 {
        self.inner.context_id
    }

    pub(crate) fn namespace(&self) -> String {
        self.inner.namespace.clone()
    }

    pub(crate) fn metadata_snapshot(&self) -> ConfigValue {
        self.inner
            .metadata
            .lock()
            .map_or_else(|_| ConfigValue::default(), |metadata| metadata.clone())
    }

    pub(crate) fn replace_metadata(&self, metadata: ConfigValue) {
        if let Ok(mut current) = self.inner.metadata.lock() {
            *current = metadata;
        }
    }

    pub(crate) fn attach_lifecycle(&self, lifecycle: Weak<dyn FiberLifecycle>) {
        let mut current = match self.inner.lifecycle.lock() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = Some(lifecycle);
    }

    /// Freeze the final managed snapshot before the registry releases its last
    /// strong control reference. This is a terminal handoff, not a second
    /// concurrently mutable state source.
    pub(crate) fn freeze_terminal(&self, snapshot: FiberSnapshot, history: Vec<FiberState>) {
        let mut terminal = match self.inner.terminal.lock() {
            Ok(terminal) => terminal,
            Err(poisoned) => poisoned.into_inner(),
        };
        if terminal.is_none() {
            *terminal = Some((snapshot, history));
        }
    }

    fn lifecycle(&self) -> Option<Arc<dyn FiberLifecycle>> {
        let current = match self.inner.lifecycle.lock() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        current.as_ref()?.upgrade()
    }

    fn terminal_snapshot(&self) -> Option<(FiberSnapshot, Vec<FiberState>)> {
        let terminal = match self.inner.terminal.lock() {
            Ok(terminal) => terminal,
            Err(poisoned) => poisoned.into_inner(),
        };
        terminal.clone()
    }

    /// Immutable lifecycle snapshot. Unmanaged N0 Fibers expose only their
    /// current synchronous state.
    #[must_use]
    pub fn snapshot(&self) -> FiberSnapshot {
        if let Some(lifecycle) = self.lifecycle() {
            return lifecycle.snapshot();
        }
        self.terminal_snapshot().map_or_else(
            || FiberSnapshot::new(self.state(), None, None, None, Vec::new()),
            |(snapshot, _)| snapshot,
        )
    }

    #[must_use]
    pub fn state_history(&self) -> Vec<FiberState> {
        if let Some(lifecycle) = self.lifecycle() {
            return lifecycle.state_history();
        }
        self.terminal_snapshot()
            .map_or_else(|| vec![self.state()], |(_, history)| history)
    }

    pub async fn await_current(&self) -> Result<FiberSnapshot, CordisError> {
        match self.lifecycle() {
            Some(lifecycle) => lifecycle.await_current().await,
            None => Ok(self.snapshot()),
        }
    }

    pub async fn wait_until_active(
        &self,
        cancellation: LifecycleCancellation,
    ) -> Result<FiberSnapshot, CordisError> {
        match self.lifecycle() {
            Some(lifecycle) => lifecycle.wait_until_active(cancellation).await,
            None if self.state() == FiberState::Active => Ok(self.snapshot()),
            None => Err(CordisError::FiberRuntimeUnavailable { uid: self.uid() }),
        }
    }
}

impl fmt::Debug for Fiber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Fiber")
            .field("uid", &self.uid())
            .field("parent", &self.parent_uid())
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}
