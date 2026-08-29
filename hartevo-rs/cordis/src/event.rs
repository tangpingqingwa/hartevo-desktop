//! Typed Cordis events with complete runtime descriptor locks.

use std::any::{Any, TypeId, type_name};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Deref;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};

use futures_util::FutureExt;
use futures_util::future::join_all;

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
            scope: self.scope.clone(),
            options: self.options,
            once: self.once,
            callback: self.callback.clone(),
        }
    }
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
        let mut state = lock_recover(&self.inner);
        if let Some(slot) = state.slots.get_mut(name) {
            slot.explicit_lock = false;
        }
        remove_empty_slot(&mut state, name);
    }

    pub(crate) fn clear(&self) {
        lock_recover(&self.inner).slots.clear();
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
        if let Some(slot) = state.slots.get(spec.name)
            && slot.descriptor != spec.descriptor
        {
            return Err(EventBusError::Schema {
                locked: slot.descriptor.clone(),
                requested: spec.descriptor,
            });
        }
        let next_id = state
            .next_id
            .checked_add(1)
            .ok_or(EventBusError::ListenerIdentityOverflow)?;
        let id = state.next_id;
        let owner_uid = spec.owner.uid();
        let listener = Listener {
            id,
            registration_index: id,
            owner: spec.owner,
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
            let index = slot
                .listeners
                .iter()
                .position(|listener| !listener.options.prepend)
                .unwrap_or(slot.listeners.len());
            slot.listeners.insert(index, listener);
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
    ) -> Result<Vec<Listener>, EventBusError> {
        let snapshots = {
            let mut state = lock_recover(&self.inner);
            if let Some(slot) = state.slots.get(name) {
                if slot.descriptor != descriptor {
                    return Err(EventBusError::Schema {
                        locked: slot.descriptor.clone(),
                        requested: descriptor,
                    });
                }
                slot.listeners.clone()
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

    fn should_invoke(&self, listener: &Listener) -> bool {
        if listener.owner.is_disposed() || listener.owner.state() != FiberState::Active {
            return false;
        }
        !listener.once || claim_once_by_id(&self.inner, listener.id)
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
        let snapshots = self.snapshots(key.name(), key.descriptor(), target)?;
        self.run_emit_snapshots(payload, snapshots)
    }

    fn run_emit_snapshots(
        &self,
        payload: &AnyRef,
        snapshots: Vec<Listener>,
    ) -> Result<(), EventBusError> {
        for listener in snapshots {
            if !self.should_invoke(&listener) {
                continue;
            }
            let Callback::Emit(callback) = &listener.callback else {
                return Err(EventBusError::Payload);
            };
            callback(payload).map_err(|failure| listener_failure(&listener, failure))?;
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
        let listeners = self.snapshots(key.name(), key.descriptor(), target)?;
        Ok(PreparedEmit {
            bus: self.clone(),
            name: key.name(),
            payload: Arc::new(payload),
            listeners,
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
        let snapshots = self.snapshots(key.name(), key.descriptor(), target)?;
        let payload: ArcPayload = Arc::new(payload);
        let futures = snapshots.into_iter().map(|listener| {
            let bus = self.clone();
            let payload = Arc::clone(&payload);
            async move {
                if !bus.should_invoke(&listener) {
                    return Ok(());
                }
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
        let snapshots = self.snapshots(key.name(), key.descriptor(), target)?;
        let payload: ArcPayload = Arc::new(payload);
        for listener in snapshots {
            if !self.should_invoke(&listener) {
                continue;
            }
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
        let snapshots = self.snapshots(key.name(), key.descriptor(), target)?;
        for listener in snapshots {
            if !self.should_invoke(&listener) {
                continue;
            }
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
        let chain = Arc::new(self.snapshots(key.name(), key.descriptor(), target)?);
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
        let chain = Arc::new(self.snapshots(key.name(), key.descriptor(), target)?);
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
        let snapshots = self.snapshots(key.name(), key.descriptor(), target)?;
        let mut payload: BoxedPayload = Box::new(payload);
        for listener in snapshots {
            if !self.should_invoke(&listener) {
                continue;
            }
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
    if !bus.should_invoke(&listener) {
        return run_waterfall(bus, index + 1, chain, payload);
    }
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
    if !bus.should_invoke(&listener) {
        return run_try_waterfall(bus, index + 1, chain, payload);
    }
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

fn remove_empty_slot(state: &mut EventBusState, name: &str) {
    let remove = state.slots.get(name).is_some_and(|slot| {
        slot.listeners.is_empty() && !slot.explicit_lock && !slot.dispatch_lock
    });
    if remove {
        state.slots.remove(name);
    }
}

fn remove_listener_locked(bus: &Mutex<EventBusState>, name: &str, id: u64) -> bool {
    let mut state = lock_recover(bus);
    let Some(slot) = state.slots.get_mut(name) else {
        return false;
    };
    let before = slot.listeners.len();
    slot.listeners.retain(|listener| listener.id != id);
    let removed = slot.listeners.len() != before;
    remove_empty_slot(&mut state, name);
    removed
}

fn claim_once_by_id(bus: &Mutex<EventBusState>, id: u64) -> bool {
    let mut state = lock_recover(bus);
    let name = state.slots.iter().find_map(|(name, slot)| {
        slot.listeners
            .iter()
            .any(|listener| listener.id == id)
            .then(|| name.clone())
    });
    let Some(name) = name else {
        return false;
    };
    let slot = state.slots.get_mut(&name).expect("located slot exists");
    slot.listeners.retain(|listener| listener.id != id);
    remove_empty_slot(&mut state, &name);
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
