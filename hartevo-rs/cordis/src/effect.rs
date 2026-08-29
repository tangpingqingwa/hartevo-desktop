use std::fmt;
use std::sync::{Arc, Mutex};

use crate::config::ConfigValue;
use crate::fiber::FiberUid;

/// Cleanup callback registered via [`crate::Context::effect`].
pub type Disposer = Box<dyn FnOnce() + Send + 'static>;

/// Idempotent handle for one synchronous registration.
///
/// A handle owns exactly one callback. Taking the callback and dropping the
/// mutex guard happen before invocation, so a disposer may safely re-enter its
/// owning Context or register another effect.
#[derive(Clone)]
pub struct RegistrationHandle {
    callback: Arc<Mutex<Option<Disposer>>>,
}

impl RegistrationHandle {
    pub(crate) fn new(dispose: Disposer) -> Self {
        Self {
            callback: Arc::new(Mutex::new(Some(dispose))),
        }
    }

    pub(crate) fn noop() -> Self {
        Self {
            callback: Arc::new(Mutex::new(None)),
        }
    }

    /// Dispose this registration once. Repeated calls are harmless.
    pub fn dispose(&self) -> bool {
        let dispose = match self.callback.lock() {
            Ok(mut callback) => callback.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(dispose) = dispose {
            dispose();
            true
        } else {
            false
        }
    }

    /// Whether this handle has already been consumed.
    #[must_use]
    pub fn is_disposed(&self) -> bool {
        match self.callback.lock() {
            Ok(callback) => callback.is_none(),
            Err(poisoned) => poisoned.into_inner().is_none(),
        }
    }
}

impl fmt::Debug for RegistrationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationHandle")
            .field("disposed", &self.is_disposed())
            .finish()
    }
}

/// One reversible registration. Teardown visits registrations newest-first.
pub enum Registration {
    Disposer {
        owner_uid: FiberUid,
        handle: RegistrationHandle,
    },
    Provider {
        owner_uid: FiberUid,
        namespace: String,
        key: String,
        provider_id: u64,
        handle: RegistrationHandle,
    },
    Var {
        owner_uid: FiberUid,
        key: String,
        previous: Option<ConfigValue>,
        handle: RegistrationHandle,
    },
    Listener {
        owner_uid: FiberUid,
        name: String,
        id: u64,
        handle: RegistrationHandle,
    },
    EventLock {
        owner_uid: FiberUid,
        name: String,
        handle: RegistrationHandle,
    },
}

impl Registration {
    pub(crate) fn disposer(owner_uid: FiberUid, dispose: Disposer) -> Self {
        Self::Disposer {
            owner_uid,
            handle: RegistrationHandle::new(dispose),
        }
    }

    pub(crate) fn provider(
        owner_uid: FiberUid,
        namespace: String,
        key: String,
        provider_id: u64,
    ) -> Self {
        Self::Provider {
            owner_uid,
            namespace,
            key,
            provider_id,
            handle: RegistrationHandle::noop(),
        }
    }

    pub(crate) fn var(owner_uid: FiberUid, key: String, previous: Option<ConfigValue>) -> Self {
        Self::Var {
            owner_uid,
            key,
            previous,
            handle: RegistrationHandle::noop(),
        }
    }

    pub(crate) fn listener(owner_uid: FiberUid, name: String, id: u64) -> Self {
        Self::Listener {
            owner_uid,
            name,
            id,
            handle: RegistrationHandle::noop(),
        }
    }

    pub(crate) fn event_lock(owner_uid: FiberUid, name: String) -> Self {
        Self::EventLock {
            owner_uid,
            name,
            handle: RegistrationHandle::noop(),
        }
    }

    pub(crate) const fn owner_uid(&self) -> FiberUid {
        match self {
            Self::Disposer { owner_uid, .. }
            | Self::Provider { owner_uid, .. }
            | Self::Var { owner_uid, .. }
            | Self::Listener { owner_uid, .. }
            | Self::EventLock { owner_uid, .. } => *owner_uid,
        }
    }

    pub(crate) fn dispose_callback(&self) {
        match self {
            Self::Disposer { handle, .. }
            | Self::Provider { handle, .. }
            | Self::Var { handle, .. }
            | Self::Listener { handle, .. }
            | Self::EventLock { handle, .. } => {
                let _ = handle.dispose();
            }
        }
    }

    pub(crate) fn handle(&self) -> RegistrationHandle {
        match self {
            Self::Disposer { handle, .. }
            | Self::Provider { handle, .. }
            | Self::Var { handle, .. }
            | Self::Listener { handle, .. }
            | Self::EventLock { handle, .. } => handle.clone(),
        }
    }
}
