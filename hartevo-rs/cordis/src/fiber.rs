//! Fiber identity and lifecycle value types.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::ConfigValue;

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
    state: AtomicU8,
    disposed: AtomicBool,
    metadata: Mutex<ConfigValue>,
    namespace: String,
}

/// Cloneable, opaque handle to a Fiber.
///
/// A Fiber handle carries identity and state only.  It cannot mint a reserved
/// provider authority or mutate a Context by itself; those operations require
/// a Context/ContextView owned by the caller.
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
                state: AtomicU8::new(FiberState::Active.as_byte()),
                disposed: AtomicBool::new(false),
                metadata: Mutex::new(ConfigValue::default()),
                namespace: "root".to_string(),
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
                state: AtomicU8::new(FiberState::Pending.as_byte()),
                disposed: AtomicBool::new(false),
                metadata: Mutex::new(metadata),
                namespace,
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
    #[must_use]
    pub fn state(&self) -> FiberState {
        FiberState::from_byte(self.inner.state.load(Ordering::Acquire))
    }

    /// Whether this Fiber has reached its terminal state.
    #[must_use]
    pub fn is_disposed(&self) -> bool {
        self.inner.disposed.load(Ordering::Acquire)
    }

    /// Mark a pending Fiber active exactly once.
    pub(crate) fn activate(&self) -> bool {
        if self.is_disposed() {
            return false;
        }
        self.inner
            .state
            .compare_exchange(
                FiberState::Pending.as_byte(),
                FiberState::Active.as_byte(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Publish the terminal tombstone. Repeated disposal is a no-op; the root
    /// Fiber is retained as the reusable Context owner and cannot be disposed.
    pub(crate) fn dispose(&self) -> bool {
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
