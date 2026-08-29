//! Typed Cordis events with complete runtime descriptor locks.

use std::any::{Any, TypeId, type_name};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::ThreadId;

use futures_util::FutureExt;
use futures_util::future::join_all;
use tokio::sync::watch;

use crate::context::CordisError;
use crate::fiber::{Fiber, FiberState, FiberUid};

/// How listeners for one event name are dispatched.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchMode {
    /// Synchronous observation in listener order.
    Emit,
    /// Synchronous around-middleware.
    Waterfall,
    /// Start every listener and await all of them.
    Parallel,
    /// Await listeners in order with one immutable original payload.
    Serial,
    /// Synchronous first-explicit-bail dispatch.
    Bail,
    /// Hartevo transform extension that threads each result to the next listener.
    Accumulate,
}

impl DispatchMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emit => "emit",
            Self::Waterfall => "waterfall",
            Self::Parallel => "parallel",
            Self::Serial => "serial",
            Self::Bail => "bail",
            Self::Accumulate => "accumulate",
        }
    }
}

impl fmt::Display for DispatchMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Explicit stable logical identity for an event schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventSchemaId(&'static str);

impl EventSchemaId {
    #[must_use]
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for EventSchemaId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// Marker implemented by the six typed dispatch modes.
pub trait EventModeMarker: sealed::Sealed + Send + Sync + 'static {
    const MODE: DispatchMode;
}

macro_rules! event_mode_marker {
    ($name:ident, $mode:ident) => {
        #[doc = concat!(stringify!($mode), " event-key marker.")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl EventModeMarker for $name {
            const MODE: DispatchMode = DispatchMode::$mode;
        }
    };
}

event_mode_marker!(Emit, Emit);
event_mode_marker!(Parallel, Parallel);
event_mode_marker!(Serial, Serial);
event_mode_marker!(Bail, Bail);
event_mode_marker!(Waterfall, Waterfall);
event_mode_marker!(Accumulate, Accumulate);

/// A typed event key carrying its stable schema, mode, payload, and full output.
///
/// The payload and output are part of the runtime descriptor lock. This also
/// makes cross-mode use fail at compile time:
///
/// ```compile_fail
/// use hartevo_cordis::{Context, Emit, EventKey, EventSchemaId};
///
/// let mut context = Context::new();
/// let key = EventKey::<Emit, u32, ()>::new(EventSchemaId::new("example"), "example");
/// context.on_serial(key, |_| async { unreachable!() });
/// ```
///
/// Infallible and fallible Waterfall keys are also intentionally incompatible:
///
/// ```compile_fail
/// use hartevo_cordis::{Context, EventKey, EventSchemaId, Waterfall, WaterfallFailure};
///
/// let mut context = Context::new();
/// let key = EventKey::<Waterfall, u32, Result<u32, WaterfallFailure>>::new(
///     EventSchemaId::new("fallible-example"),
///     "example",
/// );
/// context.on_waterfall(key, |value, next| next(value));
/// ```
///
/// ```compile_fail
/// use hartevo_cordis::{Context, EventKey, EventSchemaId, Waterfall};
///
/// let mut context = Context::new();
/// let key = EventKey::<Waterfall, u32, u32>::new(
///     EventSchemaId::new("infallible-example"),
///     "example",
/// );
/// context.try_waterfall(key, 1);
/// ```
///
/// Bail callbacks are synchronous and cannot smuggle in a Future:
///
/// ```compile_fail
/// use hartevo_cordis::{Bail, BailOutcome, Context, EventKey, EventSchemaId, NonBail};
///
/// let mut context = Context::new();
/// let key = EventKey::<Bail, (), BailOutcome<()>>::new(
///     EventSchemaId::new("bail-example"),
///     "example",
/// );
/// context.on_bail(key, |_| async { BailOutcome::Continue(NonBail::Undefined) });
/// ```
type EventKeyMarker<M, P, Output> = fn() -> (M, P, Output);

pub struct EventKey<M, P, Output> {
    schema_id: EventSchemaId,
    name: &'static str,
    marker: PhantomData<EventKeyMarker<M, P, Output>>,
}

impl<M, P, Output> EventKey<M, P, Output> {
    #[must_use]
    pub const fn new(schema_id: EventSchemaId, name: &'static str) -> Self {
        Self {
            schema_id,
            name,
            marker: PhantomData,
        }
    }

    #[must_use]
    pub const fn schema_id(self) -> EventSchemaId {
        self.schema_id
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }
}

impl<M, P, Output> EventKey<M, P, Output>
where
    M: EventModeMarker,
    P: 'static,
    Output: 'static,
{
    #[must_use]
    pub fn descriptor(self) -> EventDescriptor {
        EventDescriptor::new(EventDescriptorInner {
            schema_id: self.schema_id,
            mode: M::MODE,
            payload_type: TypeId::of::<P>(),
            result_type: TypeId::of::<Output>(),
            payload_type_name: type_name::<P>(),
            result_type_name: type_name::<Output>(),
        })
    }
}

impl<M, P, Output> Copy for EventKey<M, P, Output> {}

impl<M, P, Output> Clone for EventKey<M, P, Output> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M, P, Output> PartialEq for EventKey<M, P, Output> {
    fn eq(&self, other: &Self) -> bool {
        self.schema_id == other.schema_id && self.name == other.name
    }
}

impl<M, P, Output> Eq for EventKey<M, P, Output> {}

impl<M, P, Output> Hash for EventKey<M, P, Output> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.schema_id.hash(state);
        self.name.hash(state);
    }
}

impl<M, P, Output> AsRef<str> for EventKey<M, P, Output> {
    fn as_ref(&self) -> &str {
        self.name
    }
}

impl<M, P, Output> fmt::Display for EventKey<M, P, Output> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name)
    }
}

impl<M, P, Output> fmt::Debug for EventKey<M, P, Output> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventKey")
            .field("schema_id", &self.schema_id)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Complete runtime event lock.
#[derive(Clone, PartialEq, Eq)]
pub struct EventDescriptor {
    inner: Arc<EventDescriptorInner>,
}

#[derive(PartialEq, Eq)]
struct EventDescriptorInner {
    schema_id: EventSchemaId,
    mode: DispatchMode,
    payload_type: TypeId,
    result_type: TypeId,
    payload_type_name: &'static str,
    result_type_name: &'static str,
}

impl EventDescriptor {
    fn new(inner: EventDescriptorInner) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    #[must_use]
    pub fn schema_id(&self) -> EventSchemaId {
        self.inner.schema_id
    }

    #[must_use]
    pub fn mode(&self) -> DispatchMode {
        self.inner.mode
    }

    #[must_use]
    pub fn payload_type(&self) -> TypeId {
        self.inner.payload_type
    }

    #[must_use]
    pub fn result_type(&self) -> TypeId {
        self.inner.result_type
    }

    #[must_use]
    pub fn payload_type_name(&self) -> &'static str {
        self.inner.payload_type_name
    }

    #[must_use]
    pub fn result_type_name(&self) -> &'static str {
        self.inner.result_type_name
    }
}

impl fmt::Debug for EventDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventDescriptor")
            .field("schema_id", &self.inner.schema_id)
            .field("mode", &self.inner.mode)
            .field("payload_type", &self.inner.payload_type)
            .field("payload_type_name", &self.inner.payload_type_name)
            .field("result_type", &self.inner.result_type)
            .field("result_type_name", &self.inner.result_type_name)
            .finish()
    }
}

impl fmt::Display for EventDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}({}->{})",
            self.inner.schema_id,
            self.inner.mode,
            self.inner.payload_type_name,
            self.inner.result_type_name
        )
    }
}

/// Explicit non-bailing JavaScript-compatible results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NonBail {
    Undefined,
    Null,
    False,
}

/// An explicit bail decision. Rust truthiness is never inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BailOutcome<T> {
    Continue(NonBail),
    Bail(T),
}

impl<T> BailOutcome<T> {
    #[must_use]
    pub const fn is_bailed(&self) -> bool {
        matches!(self, Self::Bail(_))
    }
}

/// Immutable diagnostic identity of one retained concrete error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventSourceFingerprint {
    concrete_type: TypeId,
    concrete_type_name: &'static str,
    display: String,
}

impl EventSourceFingerprint {
    #[must_use]
    pub fn concrete_type(&self) -> TypeId {
        self.concrete_type
    }

    #[must_use]
    pub const fn concrete_type_name(&self) -> &'static str {
        self.concrete_type_name
    }

    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }
}

/// Cloneable event cause that retains the original concrete error.
#[derive(Clone)]
pub struct SharedEventSource {
    source: Arc<dyn Error + Send + Sync + 'static>,
    fingerprint: EventSourceFingerprint,
}

impl SharedEventSource {
    #[must_use]
    pub fn new<E>(source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        let fingerprint = EventSourceFingerprint {
            concrete_type: TypeId::of::<E>(),
            concrete_type_name: type_name::<E>(),
            display: source.to_string(),
        };
        Self {
            source: Arc::new(source),
            fingerprint,
        }
    }

    #[must_use]
    pub fn fingerprint(&self) -> &EventSourceFingerprint {
        &self.fingerprint
    }

    #[must_use]
    pub fn as_error(&self) -> &(dyn Error + Send + Sync + 'static) {
        self.source.as_ref()
    }
}

impl fmt::Debug for SharedEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedEventSource")
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SharedEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.fingerprint.display)
    }
}

impl Error for SharedEventSource {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl PartialEq for SharedEventSource {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}

impl Eq for SharedEventSource {}

/// One listener-attributed event failure.
#[derive(Clone, PartialEq, Eq)]
pub struct EventError {
    inner: Arc<EventErrorInner>,
}

#[derive(PartialEq, Eq)]
struct EventErrorInner {
    listener_id: u64,
    registration_index: u64,
    source: SharedEventSource,
}

impl EventError {
    fn new(listener_id: u64, registration_index: u64, source: SharedEventSource) -> Self {
        Self {
            inner: Arc::new(EventErrorInner {
                listener_id,
                registration_index,
                source,
            }),
        }
    }

    #[must_use]
    pub fn listener_id(&self) -> u64 {
        self.inner.listener_id
    }

    #[must_use]
    pub fn registration_index(&self) -> u64 {
        self.inner.registration_index
    }

    #[must_use]
    pub fn event_source(&self) -> &SharedEventSource {
        &self.inner.source
    }
}

impl fmt::Debug for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventError")
            .field("listener_id", &self.inner.listener_id)
            .field("registration_index", &self.inner.registration_index)
            .field("source", &self.inner.source)
            .finish()
    }
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "listener {} (registration {}) failed: {}",
            self.inner.listener_id, self.inner.registration_index, self.inner.source
        )
    }
}

impl Error for EventError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.inner.source)
    }
}

/// Ordered source-preserving aggregate for Parallel dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventErrors(Vec<EventError>);

impl EventErrors {
    pub(crate) fn new(errors: Vec<EventError>) -> Self {
        Self(errors)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[EventError] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for EventErrors {
    type Target = [EventError];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl IntoIterator for EventErrors {
    type Item = EventError;
    type IntoIter = std::vec::IntoIter<EventError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a EventErrors {
    type Item = &'a EventError;
    type IntoIter = std::slice::Iter<'a, EventError>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for EventErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, error) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str("; ")?;
            }
            error.fmt(formatter)?;
        }
        Ok(())
    }
}

impl Error for EventErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.first().map(|error| error as &(dyn Error + 'static))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WaterfallFailureKind {
    Source(SharedEventSource),
    Attributed(EventError),
}

/// Opaque fallible-Waterfall error channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaterfallFailure {
    kind: WaterfallFailureKind,
}

impl WaterfallFailure {
    #[must_use]
    pub fn source<E>(source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            kind: WaterfallFailureKind::Source(SharedEventSource::new(source)),
        }
    }

    fn attribute(self, listener_id: u64, registration_index: u64) -> Self {
        match self.kind {
            WaterfallFailureKind::Source(source) => Self {
                kind: WaterfallFailureKind::Attributed(EventError::new(
                    listener_id,
                    registration_index,
                    source,
                )),
            },
            WaterfallFailureKind::Attributed(error) => Self {
                kind: WaterfallFailureKind::Attributed(error),
            },
        }
    }

    #[must_use]
    pub fn event_error(&self) -> Option<&EventError> {
        match &self.kind {
            WaterfallFailureKind::Source(_) => None,
            WaterfallFailureKind::Attributed(error) => Some(error),
        }
    }

    #[must_use]
    pub fn event_source(&self) -> &SharedEventSource {
        match &self.kind {
            WaterfallFailureKind::Source(source) => source,
            WaterfallFailureKind::Attributed(error) => error.event_source(),
        }
    }

    pub(crate) fn into_event_error(self) -> Option<EventError> {
        match self.kind {
            WaterfallFailureKind::Source(_) => None,
            WaterfallFailureKind::Attributed(error) => Some(error),
        }
    }
}

impl fmt::Display for WaterfallFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            WaterfallFailureKind::Source(source) => source.fmt(formatter),
            WaterfallFailureKind::Attributed(error) => error.fmt(formatter),
        }
    }
}

impl Error for WaterfallFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.kind {
            WaterfallFailureKind::Source(source) => Some(source),
            WaterfallFailureKind::Attributed(error) => Some(error),
        }
    }
}

/// Registration ordering and isolation options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EventOptions {
    pub prepend: bool,
    pub global: bool,
}

/// Continuation passed to an infallible Waterfall listener.
pub type WaterfallNext<T> = Box<dyn FnOnce(T) -> T + Send>;

/// Continuation passed to a fallible Waterfall listener.
pub type TryWaterfallNext<T> = Box<dyn FnOnce(T) -> Result<T, WaterfallFailure> + Send>;

type AnyRef = dyn Any + Send + Sync;
type ArcPayload = Arc<dyn Any + Send + Sync>;
type BoxedPayload = Box<dyn Any + Send>;
type CallbackFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Debug)]
pub(crate) enum EventBusError {
    Schema {
        locked: EventDescriptor,
        requested: EventDescriptor,
    },
    ListenerIdentityOverflow,
    OwnerInactive {
        uid: FiberUid,
    },
    Payload,
    Listener(EventError),
    Parallel(EventErrors),
}

enum CallbackFailure {
    Source(SharedEventSource),
    Payload,
}

struct ErasedBail {
    bailed: bool,
    output: BoxedPayload,
}

type EmitFn = Arc<dyn Fn(&AnyRef) -> Result<(), CallbackFailure> + Send + Sync>;
type ParallelFn =
    Arc<dyn Fn(ArcPayload) -> CallbackFuture<Result<(), CallbackFailure>> + Send + Sync>;
type SerialFn =
    Arc<dyn Fn(ArcPayload) -> CallbackFuture<Result<ErasedBail, CallbackFailure>> + Send + Sync>;
type BailFn = Arc<dyn Fn(&AnyRef) -> Result<ErasedBail, CallbackFailure> + Send + Sync>;
type WaterfallContinuation = Box<dyn FnOnce(BoxedPayload) -> BoxedPayload + Send>;
type WaterfallFn =
    Arc<dyn Fn(BoxedPayload, WaterfallContinuation) -> Result<BoxedPayload, ()> + Send + Sync>;
type TryWaterfallContinuation =
    Box<dyn FnOnce(BoxedPayload) -> Result<BoxedPayload, WaterfallFailure> + Send>;
type TryWaterfallFn = Arc<
    dyn Fn(BoxedPayload, TryWaterfallContinuation) -> Result<BoxedPayload, WaterfallFailure>
        + Send
        + Sync,
>;
type AccumulateFn = Arc<
    dyn Fn(BoxedPayload) -> CallbackFuture<Result<BoxedPayload, CallbackFailure>> + Send + Sync,
>;

#[derive(Clone)]
enum Callback {
    Emit(EmitFn),
    Parallel(ParallelFn),
    Serial(SerialFn),
    Bail(BailFn),
    Waterfall(WaterfallFn),
    TryWaterfall(TryWaterfallFn),
    Accumulate(AccumulateFn),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleEventEpochPhase {
    Preparing = 0,
    Active = 1,
    Closing = 2,
    Closed = 3,
}

impl LifecycleEventEpochPhase {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Preparing,
            1 => Self::Active,
            2 => Self::Closing,
            _ => Self::Closed,
        }
    }
}

struct LifecycleEventEpochState {
    active: usize,
    active_by_thread: HashMap<ThreadId, usize>,
}

/// Sealed operation gate for one exact lifecycle activation attempt.
///
/// The phase mirror is read lock-free only while the EventBus table lock is
/// held, so lifecycle snapshots never invert the lifecycle lock order by
/// consulting a Fiber, registry, machine, or epoch mutex from that lock.
pub(crate) struct LifecycleEventEpoch {
    phase: AtomicU8,
    state: Mutex<LifecycleEventEpochState>,
    drained: Condvar,
    changed: watch::Sender<u64>,
}

/// Opaque RAII proof that one lifecycle event operation linearized before
/// close. The permit deliberately exposes no registry or Fiber authority.
pub(crate) struct LifecycleEventPermit {
    epoch: Arc<LifecycleEventEpoch>,
    thread_id: ThreadId,
    active_entry: bool,
}

impl LifecycleEventEpoch {
    pub(crate) fn new() -> Arc<Self> {
        let (changed, _) = watch::channel(0);
        Arc::new(Self {
            phase: AtomicU8::new(LifecycleEventEpochPhase::Preparing as u8),
            state: Mutex::new(LifecycleEventEpochState {
                active: 0,
                active_by_thread: HashMap::new(),
            }),
            drained: Condvar::new(),
            changed,
        })
    }

    pub(crate) fn ptr_eq(left: &Arc<Self>, right: &Arc<Self>) -> bool {
        Arc::ptr_eq(left, right)
    }

    /// Promote an exact successful activation. Every fallible activation
    /// preflight must have completed before this infallible commit step.
    pub(crate) fn activate(&self) {
        self.phase
            .compare_exchange(
                LifecycleEventEpochPhase::Preparing as u8,
                LifecycleEventEpochPhase::Active as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .expect("only an exact Preparing lifecycle event epoch can activate");
        self.notify_changed();
    }

    /// Nonblocking, idempotent close. New permits fail immediately; winning
    /// permits drain independently after lifecycle locks are released.
    pub(crate) fn close(&self) -> bool {
        let state = lock_recover(&self.state);
        let phase = self.phase();
        let changed = matches!(
            phase,
            LifecycleEventEpochPhase::Preparing | LifecycleEventEpochPhase::Active
        );
        if changed {
            self.phase
                .store(LifecycleEventEpochPhase::Closing as u8, Ordering::Release);
        }
        if state.active == 0 && self.phase() == LifecycleEventEpochPhase::Closing {
            self.phase
                .store(LifecycleEventEpochPhase::Closed as u8, Ordering::Release);
        }
        drop(state);
        if changed {
            self.drained.notify_all();
            self.notify_changed();
        }
        changed
    }

    /// Loading registration may enter while Preparing; callback re-entry may
    /// enter while Active. Close wins atomically against both.
    pub(crate) fn try_registration_permit(self: &Arc<Self>) -> Option<LifecycleEventPermit> {
        self.try_permit(true, true)
    }

    fn try_preparing_permit(self: &Arc<Self>) -> Option<LifecycleEventPermit> {
        self.try_permit(true, false)
    }

    /// Active dispatch and listener invocation require an exact Active entry.
    pub(crate) fn try_active_permit(self: &Arc<Self>) -> Option<LifecycleEventPermit> {
        self.try_permit(false, true)
    }

    pub(crate) async fn drain(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            let complete = {
                let state = lock_recover(&self.state);
                if state.active == 0 && self.phase() == LifecycleEventEpochPhase::Closing {
                    self.phase
                        .store(LifecycleEventEpochPhase::Closed as u8, Ordering::Release);
                }
                self.phase() == LifecycleEventEpochPhase::Closed
            };
            if complete {
                return;
            }
            // `watch` retains the latest revision, so a last permit drop
            // between the state check and this await cannot be lost.
            if changed.changed().await.is_err() {
                return;
            }
        }
    }

    /// Permanent last-owner teardown waits for operations on every other
    /// thread but never self-waits when invoked from a callback that still
    /// owns this thread's permits.
    pub(crate) fn close_and_drain_for_drop(&self) {
        let thread_id = std::thread::current().id();
        let mut state = lock_recover(&self.state);
        if matches!(
            self.phase(),
            LifecycleEventEpochPhase::Preparing | LifecycleEventEpochPhase::Active
        ) {
            self.phase
                .store(LifecycleEventEpochPhase::Closing as u8, Ordering::Release);
        }
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
        if state.active == 0 {
            self.phase
                .store(LifecycleEventEpochPhase::Closed as u8, Ordering::Release);
        }
        drop(state);
        self.notify_changed();
    }

    fn try_permit(
        self: &Arc<Self>,
        allow_preparing: bool,
        allow_active: bool,
    ) -> Option<LifecycleEventPermit> {
        let mut state = lock_recover(&self.state);
        let phase = self.phase();
        if !matches!(
            phase,
            LifecycleEventEpochPhase::Preparing if allow_preparing
        ) && !matches!(phase, LifecycleEventEpochPhase::Active if allow_active)
        {
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
        Some(LifecycleEventPermit {
            epoch: Arc::clone(self),
            thread_id,
            active_entry: phase == LifecycleEventEpochPhase::Active,
        })
    }

    fn phase(&self) -> LifecycleEventEpochPhase {
        LifecycleEventEpochPhase::from_byte(self.phase.load(Ordering::Acquire))
    }

    fn is_active_snapshot(&self) -> bool {
        self.phase() == LifecycleEventEpochPhase::Active
    }

    fn notify_changed(&self) {
        self.changed.send_modify(|revision| {
            *revision = revision.wrapping_add(1);
        });
    }
}

impl LifecycleEventPermit {
    fn epoch_matches(&self, epoch: &Arc<LifecycleEventEpoch>) -> bool {
        Arc::ptr_eq(&self.epoch, epoch)
    }

    fn belongs_to(&self, epoch: &Arc<LifecycleEventEpoch>) -> bool {
        self.active_entry && self.epoch_matches(epoch)
    }
}

impl Drop for LifecycleEventPermit {
    fn drop(&mut self) {
        let mut state = lock_recover(&self.epoch.state);
        state.active = state
            .active
            .checked_sub(1)
            .expect("a lifecycle event permit owns one active count");
        let remove_thread = {
            let thread_active = state
                .active_by_thread
                .get_mut(&self.thread_id)
                .expect("a lifecycle event permit owns one thread-local count");
            *thread_active = thread_active
                .checked_sub(1)
                .expect("a lifecycle event permit owns one thread-local count");
            *thread_active == 0
        };
        if remove_thread {
            state.active_by_thread.remove(&self.thread_id);
        }
        if state.active == 0 && self.epoch.phase() == LifecycleEventEpochPhase::Closing {
            self.epoch
                .phase
                .store(LifecycleEventEpochPhase::Closed as u8, Ordering::Release);
        }
        drop(state);
        self.epoch.drained.notify_all();
        self.epoch.notify_changed();
    }
}

/// Namespace/isolation labels captured by one listener or targeted dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EventScope {
    labels: Arc<[String]>,
}

impl EventScope {
    pub(crate) fn new(namespace: String, shared: &[String]) -> Self {
        let mut labels = Vec::with_capacity(shared.len() + 1);
        labels.push(namespace);
        for label in shared {
            if !labels.contains(label) {
                labels.push(label.clone());
            }
        }
        Self {
            labels: labels.into(),
        }
    }

    fn intersects(&self, other: &Self) -> bool {
        self.labels
            .iter()
            .any(|label| other.labels.iter().any(|other| other == label))
    }
}

struct Listener {
    id: u64,
    registration_index: u64,
    owner: Fiber,
    lifecycle_epoch: Option<Arc<LifecycleEventEpoch>>,
    scope: EventScope,
    options: EventOptions,
    once: bool,
    callback: Callback,
}

impl Clone for Listener {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            registration_index: self.registration_index,
            owner: self.owner.clone(),
            lifecycle_epoch: self.lifecycle_epoch.clone(),
            scope: self.scope.clone(),
            options: self.options,
            once: self.once,
            callback: self.callback.clone(),
        }
    }
}

struct ListenerInvocationPermit {
    _lifecycle: Option<LifecycleEventPermit>,
}

struct LifecycleListenerSnapshot {
    listener: Listener,
    _lifecycle: Option<LifecycleEventPermit>,
}

struct Slot {
    descriptor: EventDescriptor,
    listeners: Vec<Listener>,
    explicit_lock: bool,
    dispatch_lock: bool,
}

struct EventBusState {
    slots: HashMap<String, Slot>,
    next_id: u64,
}

pub(crate) type CallbackDropPanic = Box<dyn Any + Send + 'static>;

/// Idempotent handle for one exact Fiber-owned listener registration.
#[derive(Clone)]
pub struct ListenerHandle {
    bus: Weak<Mutex<EventBusState>>,
    name: Arc<str>,
    id: u64,
    owner_uid: FiberUid,
}

impl ListenerHandle {
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub const fn owner_uid(&self) -> FiberUid {
        self.owner_uid
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Remove this exact listener once. Later calls are harmless.
    pub fn dispose(&self) -> bool {
        let Some(bus) = self.bus.upgrade() else {
            return false;
        };
        remove_listener_locked(&bus, &self.name, self.id)
    }

    #[must_use]
    pub fn is_disposed(&self) -> bool {
        let Some(bus) = self.bus.upgrade() else {
            return true;
        };
        let state = lock_recover(&bus);
        !state
            .slots
            .get(self.name.as_ref())
            .is_some_and(|slot| slot.listeners.iter().any(|listener| listener.id == self.id))
    }
}

impl fmt::Debug for ListenerHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListenerHandle")
            .field("name", &self.name)
            .field("id", &self.id)
            .field("owner_uid", &self.owner_uid)
            .field("disposed", &self.is_disposed())
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct EventBus {
    inner: Arc<Mutex<EventBusState>>,
}

struct RegistrationSpec {
    name: &'static str,
    descriptor: EventDescriptor,
    owner: Fiber,
    scope: EventScope,
    options: EventOptions,
    once: bool,
    callback: Callback,
}

/// One typed Emit registration staged by an exact lifecycle activation.
///
/// The callback remains private to the activation collector until a complete
/// activation transaction has preflighted every event descriptor and listener
/// identity. It deliberately exposes neither a listener handle nor EventBus
/// mutation authority.
pub(crate) struct PendingLifecycleListener {
    epoch: Arc<LifecycleEventEpoch>,
    spec: RegistrationSpec,
}

impl PendingLifecycleListener {
    pub(crate) fn emit<P, F>(
        epoch: Arc<LifecycleEventEpoch>,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Self
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        Self::try_emit(epoch, key, owner, scope, options, once, move |payload| {
            listener(payload);
            Ok::<(), std::convert::Infallible>(())
        })
    }

    pub(crate) fn try_emit<P, E, F>(
        epoch: Arc<LifecycleEventEpoch>,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Self
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let callback = Arc::new(move |payload: &AnyRef| {
            let value = payload
                .downcast_ref::<P>()
                .ok_or(CallbackFailure::Payload)?;
            listener(value).map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))
        });
        Self {
            epoch,
            spec: RegistrationSpec {
                name: key.name(),
                descriptor: key.descriptor(),
                owner,
                scope,
                options,
                once,
                callback: Callback::Emit(callback),
            },
        }
    }

    fn listener(&self, id: u64) -> Listener {
        Listener {
            id,
            registration_index: id,
            owner: self.spec.owner.clone(),
            lifecycle_epoch: Some(self.epoch.clone()),
            scope: self.spec.scope.clone(),
            options: self.spec.options,
            once: self.spec.once,
            callback: self.spec.callback.clone(),
        }
    }
}

enum LifecycleBatchPermit<'permit> {
    Owned(LifecycleEventPermit),
    Borrowed(&'permit LifecycleEventPermit),
}

impl LifecycleBatchPermit<'_> {
    fn permit(&self) -> &LifecycleEventPermit {
        match self {
            Self::Owned(permit) => permit,
            Self::Borrowed(permit) => permit,
        }
    }
}

struct PreparedLifecycleInsertion {
    name: &'static str,
    descriptor: EventDescriptor,
    prepend: bool,
    listener: Listener,
}

/// Fully preflighted lifecycle listener batch. Lifecycle callers retain the
/// registry transaction lock, so cleanup may remove an old epoch between
/// preflight and insertion but no competing registration can change the
/// descriptor or identity reservation.
pub(crate) struct PreparedLifecycleBatch<'permit> {
    bus: EventBus,
    insertions: Vec<PreparedLifecycleInsertion>,
    previous_next_id: u64,
    next_id: u64,
    permit: Option<LifecycleBatchPermit<'permit>>,
}

impl<'permit> PreparedLifecycleBatch<'permit> {
    /// Insert an invisible, epoch-tagged batch. Dropping the returned guard
    /// before `commit` restores the exact table and identity-counter snapshot.
    pub(crate) fn insert(mut self) -> LifecycleBatchCommitGuard<'permit> {
        let permit = self.permit.take();
        let mut state = lock_recover(&self.bus.inner);
        assert_eq!(
            state.next_id, self.previous_next_id,
            "the lifecycle registry transaction excludes competing identity allocation"
        );
        let mut commit = LifecycleBatchCommitGuard {
            bus: self.bus.clone(),
            inserted: Vec::with_capacity(self.insertions.len()),
            previous_next_id: self.previous_next_id,
            committed_next_id: self.next_id,
            permit,
            committed: false,
        };
        for insertion in std::mem::take(&mut self.insertions) {
            commit.insert(&mut state, insertion);
        }
        state.next_id = self.next_id;
        drop(state);
        commit
    }
}

impl Drop for PreparedLifecycleBatch<'_> {
    fn drop(&mut self) {
        drop(self.permit.take());
        let mut first_panic = None;
        for insertion in std::mem::take(&mut self.insertions) {
            drop_one_catching(insertion, &mut first_panic);
        }
    }
}

/// Rollback guard for an inserted lifecycle batch. Activation commit is the
/// only path that may make these listeners visible by promoting their epoch.
pub(crate) struct LifecycleBatchCommitGuard<'permit> {
    bus: EventBus,
    inserted: Vec<(String, u64)>,
    previous_next_id: u64,
    committed_next_id: u64,
    permit: Option<LifecycleBatchPermit<'permit>>,
    committed: bool,
}

impl LifecycleBatchCommitGuard<'_> {
    fn insert(&mut self, state: &mut EventBusState, insertion: PreparedLifecycleInsertion) {
        let PreparedLifecycleInsertion {
            name,
            descriptor,
            prepend,
            listener,
        } = insertion;
        let id = listener.id;
        if let Some(slot) = state.slots.get(name) {
            assert_eq!(
                slot.descriptor, descriptor,
                "the lifecycle registry transaction excludes a conflicting descriptor"
            );
        }
        let slot = state.slots.entry(name.to_string()).or_insert_with(|| Slot {
            descriptor,
            listeners: Vec::new(),
            explicit_lock: false,
            dispatch_lock: false,
        });
        if prepend {
            slot.listeners.insert(0, listener);
        } else {
            slot.listeners.push(listener);
        }
        self.inserted.push((name.to_string(), id));
    }

    /// Mark the already-inserted batch permanent before releasing its epoch
    /// reservation.
    pub(crate) fn commit(mut self) {
        self.committed = true;
        drop(self.permit.take());
    }
}

impl Drop for LifecycleBatchCommitGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            drop(self.permit.take());
            return;
        }

        let mut removed = Vec::new();
        let mut removed_slots = Vec::new();
        let mut state = lock_recover(&self.bus.inner);
        for (name, id) in self.inserted.iter().rev() {
            let Some(slot) = state.slots.get_mut(name) else {
                continue;
            };
            if let Some(index) = slot
                .listeners
                .iter()
                .position(|listener| listener.id == *id)
            {
                removed.push(slot.listeners.remove(index));
            }
        }
        let names = self
            .inserted
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<HashSet<_>>();
        for name in names {
            if let Some(slot) = take_empty_slot(&mut state, &name) {
                removed_slots.push(slot);
            }
        }
        // The registry transaction excludes later allocation. Stay
        // non-panicking during rollback nonetheless, because this Drop may be
        // running while an unrelated invariant panic is already unwinding.
        if state.next_id == self.committed_next_id {
            state.next_id = self.previous_next_id;
        }
        drop(state);
        drop(self.permit.take());
        // Rollback can run during unwind. Catch each callback-capture drop and
        // finish the structural rollback without starting a second panic.
        let _ = drop_detached(removed, removed_slots);
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBusState {
                slots: HashMap::new(),
                next_id: 1,
            })),
        }
    }

    pub(crate) fn listener_count(&self, name: &str) -> usize {
        lock_recover(&self.inner)
            .slots
            .get(name)
            .map_or(0, |slot| slot.listeners.len())
    }

    pub(crate) fn mode(&self, name: &str) -> Option<DispatchMode> {
        lock_recover(&self.inner)
            .slots
            .get(name)
            .map(|slot| slot.descriptor.mode())
    }

    pub(crate) fn descriptor(&self, name: &str) -> Option<EventDescriptor> {
        lock_recover(&self.inner)
            .slots
            .get(name)
            .map(|slot| slot.descriptor.clone())
    }

    pub(crate) fn event_names(&self) -> Vec<String> {
        lock_recover(&self.inner).slots.keys().cloned().collect()
    }

    pub(crate) fn next_id(&self) -> u64 {
        lock_recover(&self.inner).next_id
    }

    pub(crate) fn lock_descriptor(
        &self,
        name: &'static str,
        descriptor: EventDescriptor,
    ) -> Result<bool, EventBusError> {
        let mut state = lock_recover(&self.inner);
        if let Some(slot) = state.slots.get_mut(name) {
            if slot.descriptor != descriptor {
                return Err(EventBusError::Schema {
                    locked: slot.descriptor.clone(),
                    requested: descriptor,
                });
            }
            let changed = !slot.explicit_lock;
            slot.explicit_lock = true;
            return Ok(changed);
        }
        state.slots.insert(
            name.to_string(),
            Slot {
                descriptor,
                listeners: Vec::new(),
                explicit_lock: true,
                dispatch_lock: false,
            },
        );
        Ok(true)
    }

    pub(crate) fn unlock(&self, name: &str) {
        let removed_slot = {
            let mut state = lock_recover(&self.inner);
            if let Some(slot) = state.slots.get_mut(name) {
                slot.explicit_lock = false;
            }
            take_empty_slot(&mut state, name)
        };
        resume_first_drop_panic(drop_detached(Vec::new(), removed_slot));
    }

    /// Clear the table structurally, then destroy every callback capture one at
    /// a time outside the table lock. The caller decides when to propagate the
    /// first destructor panic after completing its wider cleanup transaction.
    pub(crate) fn clear(&self) -> Option<CallbackDropPanic> {
        let removed_slots = {
            let mut state = lock_recover(&self.inner);
            std::mem::take(&mut state.slots)
        };
        drop_detached(Vec::new(), removed_slots.into_values())
    }

    /// Remove every listener owned by a terminal Fiber. The owner tombstone is
    /// published before this sweep, while registration rechecks that same
    /// tombstone under the event-table lock. Consequently a cloneable event
    /// capability cannot race cleanup and leave an inactive listener behind.
    pub(crate) fn remove_owners(&self, owners: &HashSet<FiberUid>) -> Option<CallbackDropPanic> {
        let (removed_listeners, removed_slots) = {
            let mut state = lock_recover(&self.inner);
            let mut removed_listeners = Vec::new();
            for slot in state.slots.values_mut() {
                let listeners = std::mem::take(&mut slot.listeners);
                let mut retained = Vec::with_capacity(listeners.len());
                for listener in listeners {
                    if owners.contains(&listener.owner.uid()) {
                        removed_listeners.push(listener);
                    } else {
                        retained.push(listener);
                    }
                }
                slot.listeners = retained;
            }
            let empty = state
                .slots
                .iter()
                .filter(|(_, slot)| {
                    slot.listeners.is_empty() && !slot.explicit_lock && !slot.dispatch_lock
                })
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            let removed_slots = empty
                .into_iter()
                .filter_map(|name| state.slots.remove(&name))
                .collect::<Vec<_>>();
            (removed_listeners, removed_slots)
        };
        drop_detached(removed_listeners, removed_slots)
    }

    /// Preflight a Loading activation's complete typed-Emit batch without
    /// changing descriptors, listener identities, or listener visibility.
    pub(crate) fn prepare_lifecycle_batch(
        &self,
        epoch: &Arc<LifecycleEventEpoch>,
        pending: &[PendingLifecycleListener],
    ) -> Result<PreparedLifecycleBatch<'static>, CordisError> {
        if pending.is_empty() {
            let previous_next_id = lock_recover(&self.inner).next_id;
            return Ok(PreparedLifecycleBatch {
                bus: self.clone(),
                insertions: Vec::new(),
                previous_next_id,
                next_id: previous_next_id,
                permit: None,
            });
        }
        let permit =
            epoch
                .try_preparing_permit()
                .ok_or_else(|| CordisError::StaleLifecycleView {
                    uid: pending[0].spec.owner.uid(),
                })?;
        self.prepare_lifecycle_batch_with_permit(
            epoch,
            pending,
            LifecycleBatchPermit::Owned(permit),
        )
    }

    /// Preflight one callback-time registration using the Active permit won
    /// while the registry and exact owner machine were still validated.
    pub(crate) fn prepare_lifecycle_emit<'permit>(
        &self,
        epoch: &Arc<LifecycleEventEpoch>,
        permit: &'permit LifecycleEventPermit,
        pending: &PendingLifecycleListener,
    ) -> Result<PreparedLifecycleBatch<'permit>, CordisError> {
        if !permit.belongs_to(epoch) || !Arc::ptr_eq(&pending.epoch, epoch) {
            return Err(CordisError::StaleLifecycleView {
                uid: pending.spec.owner.uid(),
            });
        }
        self.prepare_lifecycle_batch_with_permit(
            epoch,
            std::slice::from_ref(pending),
            LifecycleBatchPermit::Borrowed(permit),
        )
    }

    fn prepare_lifecycle_batch_with_permit<'permit>(
        &self,
        epoch: &Arc<LifecycleEventEpoch>,
        pending: &[PendingLifecycleListener],
        permit: LifecycleBatchPermit<'permit>,
    ) -> Result<PreparedLifecycleBatch<'permit>, CordisError> {
        if !permit.permit().epoch_matches(epoch) {
            return Err(CordisError::StaleLifecycleView {
                uid: pending
                    .first()
                    .map_or(FiberUid::ROOT, |pending| pending.spec.owner.uid()),
            });
        }
        for registration in pending {
            if !Arc::ptr_eq(&registration.epoch, epoch) {
                return Err(CordisError::StaleLifecycleView {
                    uid: registration.spec.owner.uid(),
                });
            }
        }

        let state = lock_recover(&self.inner);
        let mut batch_descriptors = HashMap::<&'static str, EventDescriptor>::new();
        for registration in pending {
            if let Some(slot) = state.slots.get(registration.spec.name)
                && slot.descriptor != registration.spec.descriptor
            {
                return Err(CordisError::SchemaConflict {
                    name: registration.spec.name.to_string(),
                    locked: slot.descriptor.clone(),
                    requested: registration.spec.descriptor.clone(),
                });
            }
            if let Some(locked) = batch_descriptors.get(registration.spec.name) {
                if *locked != registration.spec.descriptor {
                    return Err(CordisError::SchemaConflict {
                        name: registration.spec.name.to_string(),
                        locked: locked.clone(),
                        requested: registration.spec.descriptor.clone(),
                    });
                }
            } else {
                batch_descriptors
                    .insert(registration.spec.name, registration.spec.descriptor.clone());
            }
        }

        let previous_next_id = state.next_id;
        let count =
            u64::try_from(pending.len()).map_err(|_| CordisError::ListenerIdentityOverflow)?;
        let next_id = state
            .next_id
            .checked_add(count)
            .ok_or(CordisError::ListenerIdentityOverflow)?;
        let insertions = pending
            .iter()
            .enumerate()
            .map(|(offset, pending)| PreparedLifecycleInsertion {
                name: pending.spec.name,
                descriptor: pending.spec.descriptor.clone(),
                prepend: pending.spec.options.prepend,
                listener: pending.listener(
                    state.next_id
                        + u64::try_from(offset)
                            .expect("a preflighted listener offset fits into u64"),
                ),
            })
            .collect();
        drop(state);
        Ok(PreparedLifecycleBatch {
            bus: self.clone(),
            insertions,
            previous_next_id,
            next_id,
            permit: Some(permit),
        })
    }

    /// Structurally sweep every exact listener for one drained lifecycle
    /// epoch, then destroy callback captures independently outside the table
    /// lock. The first destructor panic is returned only after the full sweep.
    pub(crate) fn remove_lifecycle_epoch(
        &self,
        epoch: &Arc<LifecycleEventEpoch>,
    ) -> Option<CallbackDropPanic> {
        let (removed_listeners, removed_slots) = {
            let mut state = lock_recover(&self.inner);
            let mut removed_listeners = Vec::new();
            for slot in state.slots.values_mut() {
                let listeners = std::mem::take(&mut slot.listeners);
                let mut retained = Vec::with_capacity(listeners.len());
                for listener in listeners {
                    if listener
                        .lifecycle_epoch
                        .as_ref()
                        .is_some_and(|owner_epoch| Arc::ptr_eq(owner_epoch, epoch))
                    {
                        removed_listeners.push(listener);
                    } else {
                        retained.push(listener);
                    }
                }
                slot.listeners = retained;
            }
            let empty = state
                .slots
                .iter()
                .filter(|(_, slot)| {
                    slot.listeners.is_empty() && !slot.explicit_lock && !slot.dispatch_lock
                })
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            let removed_slots = empty
                .into_iter()
                .filter_map(|name| state.slots.remove(&name))
                .collect::<Vec<_>>();
            (removed_listeners, removed_slots)
        };
        drop_detached(removed_listeners, removed_slots)
    }

    pub(crate) fn register_emit<P, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        F: Fn(&P) + Send + Sync + 'static,
    {
        self.register_try_emit(key, owner, scope, options, once, move |payload| {
            listener(payload);
            Ok::<(), std::convert::Infallible>(())
        })
    }

    pub(crate) fn register_try_emit<P, E, F>(
        &self,
        key: EventKey<Emit, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<(), E> + Send + Sync + 'static,
    {
        let callback = Arc::new(move |payload: &AnyRef| {
            let value = payload
                .downcast_ref::<P>()
                .ok_or(CallbackFailure::Payload)?;
            listener(value).map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))
        });
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Emit(callback),
        })
    }

    pub(crate) fn register_parallel<P, E, Fut, F>(
        &self,
        key: EventKey<Parallel, P, ()>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Clone + Any + Send + Sync + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let listener = Arc::new(listener);
        let callback = Arc::new(move |payload: ArcPayload| {
            let value = payload.downcast_ref::<P>().cloned();
            let listener = Arc::clone(&listener);
            Box::pin(async move {
                let value = value.ok_or(CallbackFailure::Payload)?;
                listener(value)
                    .await
                    .map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))
            }) as CallbackFuture<Result<(), CallbackFailure>>
        });
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Parallel(callback),
        })
    }

    pub(crate) fn register_serial<P, R, E, Fut, F>(
        &self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<BailOutcome<R>, E>> + Send + 'static,
        F: Fn(Arc<P>) -> Fut + Send + Sync + 'static,
    {
        let listener = Arc::new(listener);
        let callback = Arc::new(move |payload: ArcPayload| {
            let value = Arc::downcast::<P>(payload).ok();
            let listener = Arc::clone(&listener);
            Box::pin(async move {
                let value = value.ok_or(CallbackFailure::Payload)?;
                let outcome = listener(value)
                    .await
                    .map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))?;
                let bailed = outcome.is_bailed();
                Ok(ErasedBail {
                    bailed,
                    output: Box::new(outcome),
                })
            }) as CallbackFuture<Result<ErasedBail, CallbackFailure>>
        });
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Serial(callback),
        })
    }

    pub(crate) fn register_bail<P, R, F>(
        &self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        F: Fn(&P) -> BailOutcome<R> + Send + Sync + 'static,
    {
        self.register_try_bail(key, owner, scope, options, once, move |payload| {
            Ok::<_, std::convert::Infallible>(listener(payload))
        })
    }

    pub(crate) fn register_try_bail<P, R, E, F>(
        &self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        F: Fn(&P) -> Result<BailOutcome<R>, E> + Send + Sync + 'static,
    {
        let callback = Arc::new(move |payload: &AnyRef| {
            let value = payload
                .downcast_ref::<P>()
                .ok_or(CallbackFailure::Payload)?;
            let outcome = listener(value)
                .map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))?;
            let bailed = outcome.is_bailed();
            Ok(ErasedBail {
                bailed,
                output: Box::new(outcome),
            })
        });
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Bail(callback),
        })
    }

    pub(crate) fn register_waterfall<P, F>(
        &self,
        key: EventKey<Waterfall, P, P>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + 'static,
        F: Fn(P, WaterfallNext<P>) -> P + Send + Sync + 'static,
    {
        let callback = Arc::new(
            move |payload: BoxedPayload, next: WaterfallContinuation| -> Result<BoxedPayload, ()> {
                let value = payload.downcast::<P>().map_err(|_| ())?;
                let typed_next: WaterfallNext<P> = Box::new(move |value| {
                    *next(Box::new(value))
                        .downcast::<P>()
                        .expect("typed Waterfall continuation preserves its payload")
                });
                Ok(Box::new(listener(*value, typed_next)))
            },
        );
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Waterfall(callback),
        })
    }

    pub(crate) fn register_try_waterfall<P, F>(
        &self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + 'static,
        F: Fn(P, TryWaterfallNext<P>) -> Result<P, WaterfallFailure> + Send + Sync + 'static,
    {
        let callback = Arc::new(
            move |payload: BoxedPayload,
                  next: TryWaterfallContinuation|
                  -> Result<BoxedPayload, WaterfallFailure> {
                let value = payload.downcast::<P>().unwrap_or_else(|_| {
                    panic!("typed fallible Waterfall descriptor preserves its payload")
                });
                let typed_next: TryWaterfallNext<P> = Box::new(move |value| {
                    next(Box::new(value)).map(|next| {
                        *next
                            .downcast::<P>()
                            .expect("typed fallible Waterfall continuation preserves its payload")
                    })
                });
                listener(*value, typed_next).map(|output| Box::new(output) as BoxedPayload)
            },
        );
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::TryWaterfall(callback),
        })
    }

    pub(crate) fn register_accumulate<P, E, Fut, F>(
        &self,
        key: EventKey<Accumulate, P, P>,
        owner: Fiber,
        scope: EventScope,
        options: EventOptions,
        once: bool,
        listener: F,
    ) -> Result<ListenerHandle, EventBusError>
    where
        P: Any + Send + 'static,
        E: Error + Send + Sync + 'static,
        Fut: Future<Output = Result<P, E>> + Send + 'static,
        F: Fn(P) -> Fut + Send + Sync + 'static,
    {
        let listener = Arc::new(listener);
        let callback = Arc::new(move |payload: BoxedPayload| {
            let value = payload.downcast::<P>().ok();
            let listener = Arc::clone(&listener);
            Box::pin(async move {
                let value = value.ok_or(CallbackFailure::Payload)?;
                let next = listener(*value)
                    .await
                    .map_err(|error| CallbackFailure::Source(SharedEventSource::new(error)))?;
                Ok(Box::new(next) as BoxedPayload)
            }) as CallbackFuture<Result<BoxedPayload, CallbackFailure>>
        });
        self.register(RegistrationSpec {
            name: key.name(),
            descriptor: key.descriptor(),
            owner,
            scope,
            options,
            once,
            callback: Callback::Accumulate(callback),
        })
    }

    fn register(&self, spec: RegistrationSpec) -> Result<ListenerHandle, EventBusError> {
        let mut state = lock_recover(&self.inner);
        if spec.owner.is_disposed() || spec.owner.state() != FiberState::Active {
            let error = EventBusError::OwnerInactive {
                uid: spec.owner.uid(),
            };
            drop(state);
            return Err(error);
        }
        if let Some(slot) = state.slots.get(spec.name)
            && slot.descriptor != spec.descriptor
        {
            let error = EventBusError::Schema {
                locked: slot.descriptor.clone(),
                requested: spec.descriptor.clone(),
            };
            drop(state);
            return Err(error);
        }
        let Some(next_id) = state.next_id.checked_add(1) else {
            drop(state);
            return Err(EventBusError::ListenerIdentityOverflow);
        };
        let id = state.next_id;
        let owner_uid = spec.owner.uid();
        let listener = Listener {
            id,
            registration_index: id,
            owner: spec.owner,
            lifecycle_epoch: None,
            scope: spec.scope,
            options: spec.options,
            once: spec.once,
            callback: spec.callback,
        };
        let slot = state
            .slots
            .entry(spec.name.to_string())
            .or_insert_with(|| Slot {
                descriptor: spec.descriptor,
                listeners: Vec::new(),
                explicit_lock: false,
                dispatch_lock: false,
            });
        if spec.options.prepend {
            slot.listeners.insert(0, listener);
        } else {
            slot.listeners.push(listener);
        }
        state.next_id = next_id;
        Ok(ListenerHandle {
            bus: Arc::downgrade(&self.inner),
            name: Arc::from(spec.name),
            id,
            owner_uid,
        })
    }

    fn snapshots(
        &self,
        name: &'static str,
        descriptor: EventDescriptor,
        target: Option<&EventScope>,
        emitter: Option<&Fiber>,
    ) -> Result<Vec<Listener>, EventBusError> {
        let snapshots = {
            let mut state = lock_recover(&self.inner);
            if let Some(emitter) = emitter
                && (emitter.is_disposed() || emitter.state() != FiberState::Active)
            {
                return Err(EventBusError::OwnerInactive { uid: emitter.uid() });
            }
            if let Some(slot) = state.slots.get(name) {
                if slot.descriptor != descriptor {
                    return Err(EventBusError::Schema {
                        locked: slot.descriptor.clone(),
                        requested: descriptor,
                    });
                }
                slot.listeners
                    .iter()
                    .filter(|listener| {
                        listener
                            .lifecycle_epoch
                            .as_ref()
                            .is_none_or(|epoch| epoch.is_active_snapshot())
                    })
                    .cloned()
                    .collect()
            } else {
                state.slots.insert(
                    name.to_string(),
                    Slot {
                        descriptor,
                        listeners: Vec::new(),
                        explicit_lock: false,
                        dispatch_lock: true,
                    },
                );
                Vec::new()
            }
        };
        Ok(snapshots
            .into_iter()
            .filter(|listener| {
                listener.options.global
                    || target.is_none()
                    || target.is_some_and(|target| listener.scope.intersects(target))
            })
            .collect())
    }

    fn lifecycle_snapshots(
        &self,
        name: &'static str,
        descriptor: EventDescriptor,
        target: Option<&EventScope>,
        emitter: &LifecycleEventPermit,
    ) -> Result<Vec<LifecycleListenerSnapshot>, EventBusError> {
        if !emitter.active_entry {
            return Err(EventBusError::Payload);
        }
        let listeners = {
            let mut state = lock_recover(&self.inner);
            if let Some(slot) = state.slots.get(name) {
                if slot.descriptor != descriptor {
                    return Err(EventBusError::Schema {
                        locked: slot.descriptor.clone(),
                        requested: descriptor,
                    });
                }
                slot.listeners
                    .iter()
                    .filter(|listener| {
                        listener
                            .lifecycle_epoch
                            .as_ref()
                            .is_none_or(|epoch| epoch.is_active_snapshot())
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                state.slots.insert(
                    name.to_string(),
                    Slot {
                        descriptor,
                        listeners: Vec::new(),
                        explicit_lock: false,
                        dispatch_lock: true,
                    },
                );
                Vec::new()
            }
        };

        Ok(listeners
            .into_iter()
            .filter(|listener| {
                listener.options.global
                    || target.is_none()
                    || target.is_some_and(|target| listener.scope.intersects(target))
            })
            .filter_map(|listener| {
                let lifecycle = if let Some(epoch) = &listener.lifecycle_epoch {
                    Some(epoch.try_active_permit()?)
                } else {
                    if listener.owner.is_disposed() || listener.owner.state() != FiberState::Active
                    {
                        return None;
                    }
                    None
                };
                Some(LifecycleListenerSnapshot {
                    listener,
                    _lifecycle: lifecycle,
                })
            })
            .collect())
    }

    fn begin_invoke(&self, listener: &Listener) -> Option<ListenerInvocationPermit> {
        let lifecycle = if let Some(epoch) = &listener.lifecycle_epoch {
            Some(epoch.try_active_permit()?)
        } else {
            if listener.owner.is_disposed() || listener.owner.state() != FiberState::Active {
                return None;
            }
            None
        };
        if listener.once && !claim_once_by_id(&self.inner, listener.id) {
            return None;
        }
        Some(ListenerInvocationPermit {
            _lifecycle: lifecycle,
        })
    }

    pub(crate) fn emit<P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: &P,
        target: Option<&EventScope>,
    ) -> Result<(), EventBusError>
    where
        P: Any + Send + Sync + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, None)?;
        self.run_emit_snapshots(payload, snapshots)
    }

    /// Emit on behalf of one exact callback-reentry owner. Owner validity is
    /// checked while the snapshot linearization lock is held, before an empty
    /// slot or callback snapshot can be published.
    pub(crate) fn emit_owned<P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: &P,
        target: Option<&EventScope>,
        owner: &Fiber,
    ) -> Result<(), EventBusError>
    where
        P: Any + Send + Sync + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, Some(owner))?;
        self.run_emit_snapshots(payload, snapshots)
    }

    fn run_emit_snapshots(
        &self,
        payload: &AnyRef,
        snapshots: Vec<Listener>,
    ) -> Result<(), EventBusError> {
        for listener in snapshots {
            let Some(_invocation) = self.begin_invoke(&listener) else {
                continue;
            };
            let Callback::Emit(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            callback(payload).map_err(|failure| listener_failure(&listener, failure))?;
        }
        Ok(())
    }

    fn run_lifecycle_emit_snapshots(
        &self,
        payload: &AnyRef,
        snapshots: Vec<LifecycleListenerSnapshot>,
    ) -> Result<(), EventBusError> {
        for snapshot in snapshots {
            let listener = &snapshot.listener;
            if listener.once && !claim_once_by_id(&self.inner, listener.id) {
                continue;
            }
            let Callback::Emit(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            callback(payload).map_err(|failure| listener_failure(listener, failure))?;
        }
        Ok(())
    }

    pub(crate) fn prepare_emit<P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<PreparedEmit, EventBusError>
    where
        P: Any + Send + Sync + 'static,
    {
        let listeners = self.snapshots(key.name(), key.descriptor(), target, None)?;
        Ok(PreparedEmit {
            bus: self.clone(),
            name: key.name(),
            payload: Arc::new(payload),
            listeners,
        })
    }

    /// Snapshot an exact lifecycle-owned Emit while the caller still holds
    /// registry/machine authority. The returned value borrows both payload and
    /// emitter permit, but dispatch itself runs only after those outer locks
    /// have been released.
    pub(crate) fn prepare_lifecycle_emit_owned<'permit, 'payload, P>(
        &self,
        key: EventKey<Emit, P, ()>,
        payload: &'payload P,
        target: Option<&EventScope>,
        emitter: &'permit LifecycleEventPermit,
    ) -> Result<PreparedLifecycleEmit<'permit, 'payload>, EventBusError>
    where
        P: Any + Send + Sync + 'static,
    {
        let listeners = self.lifecycle_snapshots(key.name(), key.descriptor(), target, emitter)?;
        Ok(PreparedLifecycleEmit {
            bus: self.clone(),
            name: key.name(),
            payload,
            listeners,
            _emitter: emitter,
        })
    }

    pub(crate) async fn parallel<P>(
        &self,
        key: EventKey<Parallel, P, ()>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<(), EventBusError>
    where
        P: Any + Send + Sync + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, None)?;
        let payload: ArcPayload = Arc::new(payload);
        let futures = snapshots.into_iter().map(|listener| {
            let bus = self.clone();
            let payload = Arc::clone(&payload);
            async move {
                let Some(_invocation) = bus.begin_invoke(&listener) else {
                    return Ok(());
                };
                let Callback::Parallel(callback) = &listener.callback else {
                    return Err(EventBusError::Payload);
                };
                callback(payload)
                    .await
                    .map_err(|failure| listener_failure(&listener, failure))
            }
        });
        let mut errors = Vec::new();
        let mut first_panic = None;
        for outcome in join_all(futures.map(|future| AssertUnwindSafe(future).catch_unwind())).await
        {
            match outcome {
                Ok(Err(EventBusError::Listener(error))) => errors.push(error),
                Ok(Err(error)) => return Err(error),
                Err(payload) if first_panic.is_none() => first_panic = Some(payload),
                Ok(Ok(())) | Err(_) => {}
            }
        }
        if let Some(payload) = first_panic {
            resume_unwind(payload);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(EventBusError::Parallel(EventErrors::new(errors)))
        }
    }

    pub(crate) async fn serial<P, R>(
        &self,
        key: EventKey<Serial, P, BailOutcome<R>>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<BailOutcome<R>, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, None)?;
        let payload: ArcPayload = Arc::new(payload);
        for listener in snapshots {
            let Some(_invocation) = self.begin_invoke(&listener) else {
                continue;
            };
            let Callback::Serial(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            let outcome = callback(Arc::clone(&payload))
                .await
                .map_err(|failure| listener_failure(&listener, failure))?;
            if outcome.bailed {
                return outcome
                    .output
                    .downcast::<BailOutcome<R>>()
                    .map(|outcome| *outcome)
                    .map_err(|_| EventBusError::Payload);
            }
        }
        Ok(BailOutcome::Continue(NonBail::Undefined))
    }

    pub(crate) fn bail<P, R>(
        &self,
        key: EventKey<Bail, P, BailOutcome<R>>,
        payload: &P,
        target: Option<&EventScope>,
    ) -> Result<BailOutcome<R>, EventBusError>
    where
        P: Any + Send + Sync + 'static,
        R: Any + Send + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, None)?;
        for listener in snapshots {
            let Some(_invocation) = self.begin_invoke(&listener) else {
                continue;
            };
            let Callback::Bail(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            let outcome =
                callback(payload).map_err(|failure| listener_failure(&listener, failure))?;
            if outcome.bailed {
                return outcome
                    .output
                    .downcast::<BailOutcome<R>>()
                    .map(|outcome| *outcome)
                    .map_err(|_| EventBusError::Payload);
            }
        }
        Ok(BailOutcome::Continue(NonBail::Undefined))
    }

    pub(crate) fn waterfall<P>(
        &self,
        key: EventKey<Waterfall, P, P>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<P, EventBusError>
    where
        P: Any + Send + 'static,
    {
        let chain = Arc::new(self.snapshots(key.name(), key.descriptor(), target, None)?);
        run_waterfall(self.clone(), 0, chain, Box::new(payload))?
            .downcast::<P>()
            .map(|payload| *payload)
            .map_err(|_| EventBusError::Payload)
    }

    pub(crate) fn try_waterfall<P>(
        &self,
        key: EventKey<Waterfall, P, Result<P, WaterfallFailure>>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<P, EventBusError>
    where
        P: Any + Send + 'static,
    {
        let chain = Arc::new(self.snapshots(key.name(), key.descriptor(), target, None)?);
        run_try_waterfall(self.clone(), 0, chain, Box::new(payload))
            .map_err(|failure| {
                failure
                    .into_event_error()
                    .map_or(EventBusError::Payload, EventBusError::Listener)
            })?
            .downcast::<P>()
            .map(|payload| *payload)
            .map_err(|_| EventBusError::Payload)
    }

    pub(crate) async fn accumulate<P>(
        &self,
        key: EventKey<Accumulate, P, P>,
        payload: P,
        target: Option<&EventScope>,
    ) -> Result<P, EventBusError>
    where
        P: Any + Send + 'static,
    {
        let snapshots = self.snapshots(key.name(), key.descriptor(), target, None)?;
        let mut payload: BoxedPayload = Box::new(payload);
        for listener in snapshots {
            let Some(_invocation) = self.begin_invoke(&listener) else {
                continue;
            };
            let Callback::Accumulate(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            payload = callback(payload)
                .await
                .map_err(|failure| listener_failure(&listener, failure))?;
        }
        payload
            .downcast::<P>()
            .map(|payload| *payload)
            .map_err(|_| EventBusError::Payload)
    }
}

fn run_waterfall(
    bus: EventBus,
    index: usize,
    chain: Arc<Vec<Listener>>,
    payload: BoxedPayload,
) -> Result<BoxedPayload, EventBusError> {
    let Some(listener) = chain.get(index).cloned() else {
        return Ok(payload);
    };
    let Some(_invocation) = bus.begin_invoke(&listener) else {
        return run_waterfall(bus, index + 1, chain, payload);
    };
    let Callback::Waterfall(callback) = &listener.callback else {
        return Err(EventBusError::Payload);
    };
    let next_bus = bus.clone();
    let next_chain = Arc::clone(&chain);
    let next: WaterfallContinuation = Box::new(move |payload| {
        run_waterfall(next_bus, index + 1, next_chain, payload)
            .expect("typed infallible Waterfall cannot produce a dispatch error")
    });
    callback(payload, next).map_err(|()| EventBusError::Payload)
}

fn run_try_waterfall(
    bus: EventBus,
    index: usize,
    chain: Arc<Vec<Listener>>,
    payload: BoxedPayload,
) -> Result<BoxedPayload, WaterfallFailure> {
    let Some(listener) = chain.get(index).cloned() else {
        return Ok(payload);
    };
    let Some(_invocation) = bus.begin_invoke(&listener) else {
        return run_try_waterfall(bus, index + 1, chain, payload);
    };
    let Callback::TryWaterfall(callback) = &listener.callback else {
        panic!("fallible Waterfall descriptor contains an incompatible callback");
    };
    let next_bus = bus.clone();
    let next_chain = Arc::clone(&chain);
    let next: TryWaterfallContinuation =
        Box::new(move |payload| run_try_waterfall(next_bus, index + 1, next_chain, payload));
    callback(payload, next)
        .map_err(|failure| failure.attribute(listener.id, listener.registration_index))
}

fn listener_failure(listener: &Listener, failure: CallbackFailure) -> EventBusError {
    match failure {
        CallbackFailure::Source(source) => EventBusError::Listener(EventError::new(
            listener.id,
            listener.registration_index,
            source,
        )),
        CallbackFailure::Payload => EventBusError::Payload,
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn take_empty_slot(state: &mut EventBusState, name: &str) -> Option<Slot> {
    let remove = state.slots.get(name).is_some_and(|slot| {
        slot.listeners.is_empty() && !slot.explicit_lock && !slot.dispatch_lock
    });
    if remove {
        state.slots.remove(name)
    } else {
        None
    }
}

/// Drop all callback-bearing values independently after their table mutation
/// has committed. A destructor panic cannot prevent later callbacks from
/// being released; only the first panic payload is retained for diagnostics.
fn drop_detached(
    listeners: impl IntoIterator<Item = Listener>,
    slots: impl IntoIterator<Item = Slot>,
) -> Option<CallbackDropPanic> {
    let mut first_panic = None;
    for listener in listeners {
        drop_one_catching(listener, &mut first_panic);
    }
    for slot in slots {
        let Slot {
            descriptor,
            listeners,
            explicit_lock: _,
            dispatch_lock: _,
        } = slot;
        for listener in listeners {
            drop_one_catching(listener, &mut first_panic);
        }
        drop(descriptor);
    }
    first_panic
}

/// Destroy staged lifecycle callbacks independently after collector and
/// lifecycle locks have been released. The caller can retain the first panic
/// as a cleanup diagnostic without preventing later captures from dropping.
pub(crate) fn drop_pending_lifecycle_listeners(
    pending: Vec<PendingLifecycleListener>,
) -> Option<CallbackDropPanic> {
    let mut first_panic = None;
    for listener in pending {
        drop_one_catching(listener, &mut first_panic);
    }
    first_panic
}

fn drop_one_catching<T>(value: T, first_panic: &mut Option<CallbackDropPanic>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(value)))
        && first_panic.is_none()
    {
        *first_panic = Some(payload);
    }
}

fn resume_first_drop_panic(first_panic: Option<CallbackDropPanic>) {
    if let Some(payload) = first_panic {
        resume_unwind(payload);
    }
}

fn remove_listener_locked(bus: &Mutex<EventBusState>, name: &str, id: u64) -> bool {
    let (removed_listener, removed_slot) = {
        let mut state = lock_recover(bus);
        let Some(slot) = state.slots.get_mut(name) else {
            return false;
        };
        let Some(index) = slot.listeners.iter().position(|listener| listener.id == id) else {
            return false;
        };
        let removed_listener = slot.listeners.remove(index);
        let removed_slot = take_empty_slot(&mut state, name);
        (removed_listener, removed_slot)
    };
    resume_first_drop_panic(drop_detached([removed_listener], removed_slot));
    true
}

fn claim_once_by_id(bus: &Mutex<EventBusState>, id: u64) -> bool {
    let (removed_listener, removed_slot) = {
        let mut state = lock_recover(bus);
        let found = state.slots.iter().find_map(|(name, slot)| {
            slot.listeners
                .iter()
                .position(|listener| listener.id == id)
                .map(|index| (name.clone(), index))
        });
        let Some((name, index)) = found else {
            return false;
        };
        let slot = state.slots.get_mut(&name).expect("located slot exists");
        let removed_listener = slot.listeners.remove(index);
        let removed_slot = take_empty_slot(&mut state, &name);
        (removed_listener, removed_slot)
    };
    resume_first_drop_panic(drop_detached([removed_listener], removed_slot));
    true
}

/// Owned emit snapshot dispatched after an outer coordination lock is released.
pub(crate) struct PreparedEmit {
    bus: EventBus,
    name: &'static str,
    payload: ArcPayload,
    listeners: Vec<Listener>,
}

impl PreparedEmit {
    pub(crate) fn dispatch(self) -> Result<(), CordisError> {
        self.bus
            .run_emit_snapshots(self.payload.as_ref(), self.listeners)
            .map_err(|error| into_cordis_error(self.name, DispatchMode::Emit, error))
    }
}

impl fmt::Debug for PreparedEmit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEmit")
            .field("name", &self.name)
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

/// Borrowed lifecycle Emit snapshot. The emitter permit and payload remain
/// alive for the complete synchronous callback dispatch without requiring a
/// payload clone or retaining an outer registry/machine guard.
pub(crate) struct PreparedLifecycleEmit<'permit, 'payload> {
    bus: EventBus,
    name: &'static str,
    payload: &'payload AnyRef,
    listeners: Vec<LifecycleListenerSnapshot>,
    _emitter: &'permit LifecycleEventPermit,
}

impl PreparedLifecycleEmit<'_, '_> {
    pub(crate) fn dispatch(self) -> Result<(), CordisError> {
        self.bus
            .run_lifecycle_emit_snapshots(self.payload, self.listeners)
            .map_err(|error| into_cordis_error(self.name, DispatchMode::Emit, error))
    }
}

impl fmt::Debug for PreparedLifecycleEmit<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedLifecycleEmit")
            .field("name", &self.name)
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

pub(crate) fn into_cordis_error(
    name: &str,
    mode: DispatchMode,
    error: EventBusError,
) -> CordisError {
    match error {
        EventBusError::Schema { locked, requested } => CordisError::SchemaConflict {
            name: name.to_string(),
            locked,
            requested,
        },
        EventBusError::ListenerIdentityOverflow => CordisError::ListenerIdentityOverflow,
        EventBusError::OwnerInactive { uid } => CordisError::FiberDisposed { uid },
        EventBusError::Payload => CordisError::PayloadType {
            name: name.to_string(),
        },
        EventBusError::Listener(error) => match mode {
            DispatchMode::Emit => CordisError::Emit {
                name: name.to_string(),
                error,
            },
            DispatchMode::Waterfall => CordisError::Waterfall {
                name: name.to_string(),
                error,
            },
            DispatchMode::Parallel => CordisError::ParallelJoin {
                name: name.to_string(),
                errors: EventErrors::new(vec![error]),
            },
            DispatchMode::Serial => CordisError::Serial {
                name: name.to_string(),
                error,
            },
            DispatchMode::Bail => CordisError::Bail {
                name: name.to_string(),
                error,
            },
            DispatchMode::Accumulate => CordisError::Accumulate {
                name: name.to_string(),
                error,
            },
        },
        EventBusError::Parallel(errors) => CordisError::ParallelJoin {
            name: name.to_string(),
            errors,
        },
    }
}

impl fmt::Debug for EventBus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock_recover(&self.inner);
        let mut names: Vec<&String> = state.slots.keys().collect();
        names.sort();
        formatter
            .debug_struct("EventBus")
            .field("events", &names)
            .field("next_id", &state.next_id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const ONCE_REENTRANT: EventKey<Emit, (), ()> = EventKey::new(
        EventSchemaId::new("cordis.event.once-reentrant.v1"),
        "once-reentrant",
    );
    const SNAPSHOT: EventKey<Emit, (), ()> =
        EventKey::new(EventSchemaId::new("cordis.event.snapshot.v1"), "snapshot");
    const OVERFLOW: EventKey<Emit, (), ()> =
        EventKey::new(EventSchemaId::new("cordis.event.overflow.v1"), "overflow");
    const PREPARED: EventKey<Emit, usize, ()> =
        EventKey::new(EventSchemaId::new("cordis.event.prepared.v1"), "prepared");
    const PREPARED_ONCE: EventKey<Emit, (), ()> = EventKey::new(
        EventSchemaId::new("cordis.event.prepared-once.v1"),
        "prepared-once",
    );
    const PREPARED_ERROR: EventKey<Emit, (), ()> = EventKey::new(
        EventSchemaId::new("cordis.event.prepared-error.v1"),
        "prepared-error",
    );
    const LIFECYCLE_BATCH: EventKey<Emit, u32, ()> = EventKey::new(
        EventSchemaId::new("cordis.event.lifecycle-batch.v1"),
        "lifecycle-batch",
    );
    const LIFECYCLE_BATCH_CONFLICT: EventKey<Emit, String, ()> = EventKey::new(
        EventSchemaId::new("cordis.event.lifecycle-batch-conflict.v1"),
        "lifecycle-batch",
    );

    #[derive(Debug)]
    struct PreparedError;

    impl fmt::Display for PreparedError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("prepared source")
        }
    }

    impl Error for PreparedError {}

    fn root_and_scope() -> (Fiber, EventScope) {
        let root = Fiber::root(1);
        let scope = EventScope::new(root.namespace(), &[]);
        (root, scope)
    }

    #[test]
    fn once_is_claimed_before_a_reentrant_dispatch() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        let calls = Arc::new(AtomicUsize::new(0));
        let reentrant_bus = bus.clone();
        let calls_for_listener = Arc::clone(&calls);
        bus.register_emit(
            ONCE_REENTRANT,
            root,
            scope,
            EventOptions::default(),
            true,
            move |()| {
                calls_for_listener.fetch_add(1, Ordering::SeqCst);
                reentrant_bus.emit(ONCE_REENTRANT, &(), None).unwrap();
            },
        )
        .unwrap();

        bus.emit(ONCE_REENTRANT, &(), None).unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(bus.listener_count(ONCE_REENTRANT.name()), 0);
    }

    #[test]
    fn registration_during_dispatch_is_lock_free_and_joins_only_the_next_snapshot() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        let installed = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let callback_bus = bus.clone();
        let callback_root = root.clone();
        let callback_scope = scope.clone();
        let installed_for_listener = Arc::clone(&installed);
        let calls_for_listener = Arc::clone(&calls);
        bus.register_emit(
            SNAPSHOT,
            root,
            scope,
            EventOptions::default(),
            false,
            move |()| {
                lock_recover(&calls_for_listener).push("original");
                if !installed_for_listener.swap(true, Ordering::SeqCst) {
                    let calls = Arc::clone(&calls_for_listener);
                    callback_bus
                        .register_emit(
                            SNAPSHOT,
                            callback_root.clone(),
                            callback_scope.clone(),
                            EventOptions::default(),
                            false,
                            move |()| lock_recover(&calls).push("added"),
                        )
                        .unwrap();
                }
            },
        )
        .unwrap();

        bus.emit(SNAPSHOT, &(), None).unwrap();
        assert_eq!(&*lock_recover(&calls), &["original"]);
        lock_recover(&calls).clear();
        bus.emit(SNAPSHOT, &(), None).unwrap();
        assert_eq!(&*lock_recover(&calls), &["original", "added"]);
    }

    #[test]
    fn listener_identity_overflow_is_zero_mutation() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        lock_recover(&bus.inner).next_id = u64::MAX;
        let before_names = bus.event_names();
        let before_next_id = bus.next_id();

        let result = bus.register_emit(
            OVERFLOW,
            root,
            scope,
            EventOptions::default(),
            false,
            |()| {},
        );

        assert!(matches!(
            result,
            Err(EventBusError::ListenerIdentityOverflow)
        ));
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.listener_count(OVERFLOW.name()), 0);
        assert_eq!(bus.next_id(), before_next_id);
    }

    #[test]
    fn lifecycle_batch_preflight_and_rollback_are_exact_zero_mutation() {
        let bus = EventBus::new();
        let epoch = LifecycleEventEpoch::new();
        let (root, scope) = root_and_scope();
        let calls = Arc::new(AtomicUsize::new(0));
        let valid = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            {
                let calls = calls.clone();
                move |value| {
                    calls.fetch_add(*value as usize, Ordering::SeqCst);
                }
            },
        );
        let conflict = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH_CONFLICT,
            root,
            scope,
            EventOptions::default(),
            false,
            |_: &String| {},
        );
        let before_names = bus.event_names();
        let before_next_id = bus.next_id();

        assert!(matches!(
            bus.prepare_lifecycle_batch(&epoch, &[valid, conflict]),
            Err(CordisError::SchemaConflict { .. })
        ));
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.next_id(), before_next_id);
        assert_eq!(epoch.phase(), LifecycleEventEpochPhase::Preparing);

        let valid = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH,
            Fiber::root(1),
            EventScope::new("root".to_string(), &[]),
            EventOptions::default(),
            false,
            {
                let calls = calls.clone();
                move |value| {
                    calls.fetch_add(*value as usize, Ordering::SeqCst);
                }
            },
        );
        lock_recover(&bus.inner).next_id = u64::MAX;
        assert!(matches!(
            bus.prepare_lifecycle_batch(&epoch, std::slice::from_ref(&valid)),
            Err(CordisError::ListenerIdentityOverflow)
        ));
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.next_id(), u64::MAX);
        assert_eq!(epoch.phase(), LifecycleEventEpochPhase::Preparing);

        lock_recover(&bus.inner).next_id = before_next_id;
        let rollback = bus
            .prepare_lifecycle_batch(&epoch, std::slice::from_ref(&valid))
            .unwrap()
            .insert();
        assert_eq!(bus.listener_count(LIFECYCLE_BATCH.name()), 1);
        bus.emit(LIFECYCLE_BATCH, &3, None).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(rollback);
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.next_id(), before_next_id);

        let commit = bus
            .prepare_lifecycle_batch(&epoch, std::slice::from_ref(&valid))
            .unwrap()
            .insert();
        epoch.activate();
        commit.commit();
        bus.emit(LIFECYCLE_BATCH, &3, None).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn lifecycle_dynamic_schema_and_identity_failures_leave_a_later_registration_valid() {
        let bus = EventBus::new();
        let epoch = LifecycleEventEpoch::new();
        let (root, scope) = root_and_scope();
        let calls = Arc::new(AtomicUsize::new(0));
        let initial = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        let commit = bus
            .prepare_lifecycle_batch(&epoch, std::slice::from_ref(&initial))
            .unwrap()
            .insert();
        epoch.activate();
        commit.commit();
        let permit = epoch.try_registration_permit().unwrap();
        let before_names = bus.event_names();
        let before_count = bus.listener_count(LIFECYCLE_BATCH.name());
        let before_next_id = bus.next_id();

        let conflict = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH_CONFLICT,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            |_: &String| {},
        );
        assert!(matches!(
            bus.prepare_lifecycle_emit(&epoch, &permit, &conflict),
            Err(CordisError::SchemaConflict { .. })
        ));
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.listener_count(LIFECYCLE_BATCH.name()), before_count);
        assert_eq!(bus.next_id(), before_next_id);
        drop_pending_lifecycle_listeners(vec![conflict]);

        lock_recover(&bus.inner).next_id = u64::MAX;
        let overflow = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            |_| {},
        );
        assert!(matches!(
            bus.prepare_lifecycle_emit(&epoch, &permit, &overflow),
            Err(CordisError::ListenerIdentityOverflow)
        ));
        assert_eq!(bus.event_names(), before_names);
        assert_eq!(bus.listener_count(LIFECYCLE_BATCH.name()), before_count);
        assert_eq!(bus.next_id(), u64::MAX);
        drop_pending_lifecycle_listeners(vec![overflow]);

        lock_recover(&bus.inner).next_id = before_next_id;
        let later = PendingLifecycleListener::emit(
            epoch.clone(),
            LIFECYCLE_BATCH,
            root,
            scope,
            EventOptions::default(),
            false,
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        bus.prepare_lifecycle_emit(&epoch, &permit, &later)
            .unwrap()
            .insert()
            .commit();
        drop(later);
        drop(permit);
        bus.emit(LIFECYCLE_BATCH, &1, None).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn prepared_emit_owns_one_exact_snapshot() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let first_calls = Arc::clone(&calls);
        bus.register_emit(
            PREPARED,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            move |value| lock_recover(&first_calls).push(("first", *value)),
        )
        .unwrap();
        let prepared = bus.prepare_emit(PREPARED, 1, None).unwrap();
        let second_calls = Arc::clone(&calls);
        bus.register_emit(
            PREPARED,
            root,
            scope,
            EventOptions::default(),
            false,
            move |value| lock_recover(&second_calls).push(("second", *value)),
        )
        .unwrap();

        prepared.dispatch().unwrap();
        bus.prepare_emit(PREPARED, 2, None)
            .unwrap()
            .dispatch()
            .unwrap();

        assert_eq!(
            &*lock_recover(&calls),
            &[("first", 1), ("first", 2), ("second", 2)]
        );
    }

    #[test]
    fn two_prepared_snapshots_claim_the_same_once_listener_exactly_once() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        let calls = Arc::new(AtomicUsize::new(0));
        let listener_calls = Arc::clone(&calls);
        bus.register_emit(
            PREPARED_ONCE,
            root,
            scope,
            EventOptions::default(),
            true,
            move |()| {
                listener_calls.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();
        let first = bus.prepare_emit(PREPARED_ONCE, (), None).unwrap();
        let second = bus.prepare_emit(PREPARED_ONCE, (), None).unwrap();

        first.dispatch().unwrap();
        second.dispatch().unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(bus.listener_count(PREPARED_ONCE.name()), 0);
    }

    #[test]
    fn prepared_emit_stops_at_first_typed_error_and_retains_its_source() {
        let bus = EventBus::new();
        let (root, scope) = root_and_scope();
        bus.register_try_emit(
            PREPARED_ERROR,
            root.clone(),
            scope.clone(),
            EventOptions::default(),
            false,
            |()| Err(PreparedError),
        )
        .unwrap();
        let later = Arc::new(AtomicUsize::new(0));
        let later_for_listener = Arc::clone(&later);
        bus.register_emit(
            PREPARED_ERROR,
            root,
            scope,
            EventOptions::default(),
            false,
            move |()| {
                later_for_listener.fetch_add(1, Ordering::SeqCst);
            },
        )
        .unwrap();

        let error = bus
            .prepare_emit(PREPARED_ERROR, (), None)
            .unwrap()
            .dispatch()
            .unwrap_err();

        let CordisError::Emit { error, .. } = error else {
            panic!("expected a typed prepared Emit error");
        };
        assert!(
            error
                .event_source()
                .as_error()
                .downcast_ref::<PreparedError>()
                .is_some()
        );
        assert_eq!(later.load(Ordering::SeqCst), 0);
    }
}
