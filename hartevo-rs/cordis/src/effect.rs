use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_core::Stream;
use tokio::sync::Notify;

use crate::config::ConfigValue;
use crate::context::CordisError;
use crate::fiber::FiberUid;

/// Cleanup callback registered via [`crate::Context::effect`].
pub type Disposer = Box<dyn FnOnce() + Send + 'static>;

/// Owned async cleanup future used by Fiber lifecycle effects.
pub type LifecycleDisposeFuture =
    Pin<Box<dyn Future<Output = Result<(), CordisError>> + Send + 'static>>;

type LifecycleDisposeCallback = Box<dyn FnOnce() -> LifecycleDisposeFuture + Send + 'static>;

enum LifecycleDisposerState {
    Ready(Option<LifecycleDisposeCallback>),
    Running,
    Done(Result<(), CordisError>),
}

struct LifecycleDisposerInner {
    state: Mutex<LifecycleDisposerState>,
    completed: Notify,
}

/// Idempotent async cleanup handle owned by exactly one Fiber effect.
///
/// Concurrent callers share completion. Dropping the handle is deliberately
/// nonblocking and never invokes user cleanup.
#[derive(Clone)]
pub struct LifecycleDisposer {
    inner: Arc<LifecycleDisposerInner>,
}

impl LifecycleDisposer {
    #[must_use]
    pub fn new<F, Fut>(dispose: F) -> Self
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), CordisError>> + Send + 'static,
    {
        let callback: LifecycleDisposeCallback = Box::new(move || Box::pin(dispose()));
        Self {
            inner: Arc::new(LifecycleDisposerInner {
                state: Mutex::new(LifecycleDisposerState::Ready(Some(callback))),
                completed: Notify::new(),
            }),
        }
    }

    #[must_use]
    pub fn sync<F>(dispose: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self::new(move || async move {
            dispose();
            Ok(())
        })
    }

    #[must_use]
    pub fn fallible_sync<F>(dispose: F) -> Self
    where
        F: FnOnce() -> Result<(), CordisError> + Send + 'static,
    {
        Self::new(move || async move { dispose() })
    }

    pub async fn dispose_async(&self) -> Result<(), CordisError> {
        loop {
            let notified = self.inner.completed.notified();
            let callback = {
                let mut state = match self.inner.state.lock() {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match &mut *state {
                    LifecycleDisposerState::Ready(callback) => {
                        let callback = callback.take();
                        *state = LifecycleDisposerState::Running;
                        callback
                    }
                    LifecycleDisposerState::Running => None,
                    LifecycleDisposerState::Done(result) => return result.clone(),
                }
            };
            if let Some(callback) = callback {
                let result = callback().await;
                let mut state = match self.inner.state.lock() {
                    Ok(state) => state,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *state = LifecycleDisposerState::Done(result.clone());
                drop(state);
                self.inner.completed.notify_waiters();
                return result;
            }
            notified.await;
        }
    }

    #[must_use]
    pub fn is_disposed(&self) -> bool {
        let state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        matches!(*state, LifecycleDisposerState::Done(_))
    }
}

impl fmt::Debug for LifecycleDisposer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LifecycleDisposer")
            .field("disposed", &self.is_disposed())
            .finish()
    }
}

/// Future which resolves to zero or one disposer.
pub type LifecycleDisposerFuture =
    Pin<Box<dyn Future<Output = Result<Option<LifecycleDisposer>, CordisError>> + Send + 'static>>;

/// Finite async stream of disposer items.
pub type LifecycleDisposerStream = Pin<Box<dyn Stream<Item = LifecycleDisposer> + Send + 'static>>;

/// Typed lifecycle result returned by repeatable plugin factories.
pub enum LifecycleEffect {
    None,
    Disposer(LifecycleDisposer),
    DisposerCollection(Vec<LifecycleDisposer>),
    DisposerFuture(LifecycleDisposerFuture),
    DisposerStream(LifecycleDisposerStream),
}

impl LifecycleEffect {
    #[must_use]
    pub const fn none() -> Self {
        Self::None
    }

    #[must_use]
    pub fn disposer(disposer: LifecycleDisposer) -> Self {
        Self::Disposer(disposer)
    }

    #[must_use]
    pub fn collection(disposers: impl IntoIterator<Item = LifecycleDisposer>) -> Self {
        Self::DisposerCollection(disposers.into_iter().collect())
    }

    #[must_use]
    pub fn future<Fut>(future: Fut) -> Self
    where
        Fut: Future<Output = Result<Option<LifecycleDisposer>, CordisError>> + Send + 'static,
    {
        Self::DisposerFuture(Box::pin(future))
    }

    #[must_use]
    pub fn stream<S>(stream: S) -> Self
    where
        S: Stream<Item = LifecycleDisposer> + Send + 'static,
    {
        Self::DisposerStream(Box::pin(stream))
    }

    #[must_use]
    pub const fn is_async(&self) -> bool {
        matches!(self, Self::DisposerFuture(_) | Self::DisposerStream(_))
    }
}

impl fmt::Debug for LifecycleEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => formatter.write_str("LifecycleEffect::None"),
            Self::Disposer(disposer) => formatter.debug_tuple("Disposer").field(disposer).finish(),
            Self::DisposerCollection(disposers) => formatter
                .debug_tuple("DisposerCollection")
                .field(disposers)
                .finish(),
            Self::DisposerFuture(_) => formatter.write_str("LifecycleEffect::DisposerFuture(..)"),
            Self::DisposerStream(_) => formatter.write_str("LifecycleEffect::DisposerStream(..)"),
        }
    }
}

/// Normalize source-compatible plugin returns into a typed lifecycle effect.
pub trait IntoLifecycleEffect {
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError>;
}

impl IntoLifecycleEffect for () {
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError> {
        Ok(LifecycleEffect::None)
    }
}

impl IntoLifecycleEffect for LifecycleEffect {
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError> {
        Ok(self)
    }
}

impl IntoLifecycleEffect for LifecycleDisposer {
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError> {
        Ok(LifecycleEffect::Disposer(self))
    }
}

impl IntoLifecycleEffect for Vec<LifecycleDisposer> {
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError> {
        Ok(LifecycleEffect::DisposerCollection(self))
    }
}

impl<T> IntoLifecycleEffect for Result<T, CordisError>
where
    T: IntoLifecycleEffect,
{
    fn into_lifecycle_effect(self) -> Result<LifecycleEffect, CordisError> {
        self?.into_lifecycle_effect()
    }
}

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
