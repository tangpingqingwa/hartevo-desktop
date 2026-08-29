//! Minimal synchronous Fiber ownership used by the N0 Cordis foundation.
//!
//! N0 deliberately implements only the small state surface needed to make
//! provider ownership and pending activation safe.  The remaining lifecycle
//! states, asynchronous transitions, and restart/update semantics belong to
//! N1.

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

/// The intentionally small N0 Fiber lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiberState {
    /// Dependencies are not ready and no callback has run yet.
    Pending,
    /// The Fiber has successfully activated its callback.
    Active,
}

impl FiberState {
    pub(crate) const fn as_byte(self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Active => 1,
        }
    }

    pub(crate) const fn from_byte(value: u8) -> Self {
        match value {
            1 => Self::Active,
            _ => Self::Pending,
        }
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
