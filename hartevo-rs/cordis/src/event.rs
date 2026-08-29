//! Typed Cordis events: each name is locked to exactly one dispatch mode.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// How listeners for one event name are dispatched.
///
/// Mixing modes on the same name is a contract error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DispatchMode {
    /// Observe only: invoke listeners in registration order, do not await, no return.
    Emit,
    /// Middleware: wrap with `next()`; skipping `next` short-circuits (policy).
    Waterfall,
    /// Await every listener; join errors instead of dropping the rest.
    Parallel,
    /// Await in registration order; each listener receives the previous return.
    Serial,
}

impl DispatchMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emit => "emit",
            Self::Waterfall => "waterfall",
            Self::Parallel => "parallel",
            Self::Serial => "serial",
        }
    }
}

impl fmt::Display for DispatchMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Continuation passed to a waterfall listener. Not calling it is a short-circuit.
pub type WaterfallNext<T> = Box<dyn FnOnce(T) -> T + Send>;

pub(crate) type EmitFn = Arc<dyn Fn(&(dyn Any + Send + Sync)) + Send + Sync>;
pub(crate) type BoxedPayload = Box<dyn Any + Send>;
pub(crate) type WaterfallContinuation = Box<dyn FnOnce(BoxedPayload) -> BoxedPayload + Send>;
pub(crate) type WaterfallFn =
    Arc<dyn Fn(BoxedPayload, WaterfallContinuation) -> BoxedPayload + Send + Sync>;
pub(crate) type ParallelFn = Arc<
    dyn Fn(Arc<dyn Any + Send + Sync>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;
pub(crate) type SerialFn = Arc<
    dyn Fn(
            Box<dyn Any + Send>,
        ) -> Pin<Box<dyn Future<Output = Result<Box<dyn Any + Send>, String>> + Send>>
        + Send
        + Sync,
>;

/// Owned emit snapshot that can be dispatched after a caller releases its
/// coordination lock. Listener registration changes after preparation do not
/// affect this one notification.
pub(crate) struct PreparedEmit {
    payload: Arc<dyn Any + Send + Sync>,
    listeners: Vec<EmitFn>,
}

impl PreparedEmit {
    pub(crate) fn new<T>(payload: T, listeners: Vec<EmitFn>) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        Self {
            payload: Arc::new(payload),
            listeners,
        }
    }

    pub(crate) fn dispatch(self) {
        for listener in self.listeners {
            listener(self.payload.as_ref());
        }
    }
}

impl fmt::Debug for PreparedEmit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEmit")
            .field("listener_count", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

enum Callback {
    Emit(EmitFn),
    Waterfall(WaterfallFn),
    Parallel(ParallelFn),
    Serial(SerialFn),
}

struct Listener {
    id: u64,
    callback: Callback,
}

struct Slot {
    mode: DispatchMode,
    listeners: Vec<Listener>,
}

/// Named listener table. Mode is stored even when the listener list is empty.
pub(crate) struct EventBus {
    slots: HashMap<String, Slot>,
    next_id: u64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub(crate) fn new() -> Self {
        Self {
            slots: HashMap::new(),
            next_id: 1,
        }
    }

    pub(crate) fn listener_count(&self, name: &str) -> usize {
        self.slots.get(name).map_or(0, |slot| slot.listeners.len())
    }

    pub(crate) fn mode(&self, name: &str) -> Option<DispatchMode> {
        self.slots.get(name).map(|slot| slot.mode)
    }

    pub(crate) fn event_names(&self) -> Vec<&String> {
        self.slots.keys().collect()
    }

    pub(crate) fn next_id(&self) -> u64 {
        self.next_id
    }

    pub(crate) fn lock(&mut self, name: &str, mode: DispatchMode) -> Result<(), DispatchMode> {
        match self.slots.get(name) {
            Some(slot) if slot.mode != mode => Err(slot.mode),
            Some(_) => Ok(()),
            None => {
                self.slots.insert(
                    name.to_string(),
                    Slot {
                        mode,
                        listeners: Vec::new(),
                    },
                );
                Ok(())
            }
        }
    }

    pub(crate) fn register_emit(
        &mut self,
        name: String,
        callback: EmitFn,
    ) -> Result<u64, DispatchMode> {
        self.register(name, DispatchMode::Emit, Callback::Emit(callback))
    }

    pub(crate) fn register_waterfall(
        &mut self,
        name: String,
        callback: WaterfallFn,
    ) -> Result<u64, DispatchMode> {
        self.register(name, DispatchMode::Waterfall, Callback::Waterfall(callback))
    }

    pub(crate) fn register_parallel(
        &mut self,
        name: String,
        callback: ParallelFn,
    ) -> Result<u64, DispatchMode> {
        self.register(name, DispatchMode::Parallel, Callback::Parallel(callback))
    }

    pub(crate) fn register_serial(
        &mut self,
        name: String,
        callback: SerialFn,
    ) -> Result<u64, DispatchMode> {
        self.register(name, DispatchMode::Serial, Callback::Serial(callback))
    }

    fn register(
        &mut self,
        name: String,
        mode: DispatchMode,
        callback: Callback,
    ) -> Result<u64, DispatchMode> {
        self.lock(&name, mode)?;
        let id = self.next_id;
        self.next_id += 1;
        self.slots
            .entry(name)
            .or_insert_with(|| Slot {
                mode,
                listeners: Vec::new(),
            })
            .listeners
            .push(Listener { id, callback });
        Ok(id)
    }

    pub(crate) fn remove_listener(&mut self, name: &str, id: u64) {
        if let Some(slot) = self.slots.get_mut(name) {
            slot.listeners.retain(|listener| listener.id != id);
        }
    }

    pub(crate) fn unlock(&mut self, name: &str) {
        if let Some(slot) = self.slots.get(name)
            && slot.listeners.is_empty()
        {
            self.slots.remove(name);
        }
    }

    pub(crate) fn clear(&mut self) {
        self.slots.clear();
    }

    pub(crate) fn emit(
        &mut self,
        name: &str,
        payload: &(dyn Any + Send + Sync),
    ) -> Result<(), DispatchMode> {
        self.lock(name, DispatchMode::Emit)?;
        let listeners: Vec<EmitFn> = self
            .slots
            .get(name)
            .map(|slot| {
                slot.listeners
                    .iter()
                    .filter_map(|listener| match &listener.callback {
                        Callback::Emit(callback) => Some(Arc::clone(callback)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for listener in listeners {
            listener(payload);
        }
        Ok(())
    }

    /// Snapshot emit listeners without invoking user code. The caller can
    /// release any outer coordination lock before dispatching the snapshot.
    pub(crate) fn prepare_emit(&self, name: &str) -> Result<Vec<EmitFn>, DispatchMode> {
        let Some(slot) = self.slots.get(name) else {
            return Ok(Vec::new());
        };
        if slot.mode != DispatchMode::Emit {
            return Err(slot.mode);
        }
        Ok(slot
            .listeners
            .iter()
            .filter_map(|listener| match &listener.callback {
                Callback::Emit(callback) => Some(Arc::clone(callback)),
                _ => None,
            })
            .collect())
    }

    pub(crate) fn waterfall(
        &mut self,
        name: &str,
        payload: BoxedPayload,
    ) -> Result<BoxedPayload, DispatchMode> {
        self.lock(name, DispatchMode::Waterfall)?;
        let chain: Arc<Vec<WaterfallFn>> = Arc::new(
            self.slots
                .get(name)
                .map(|slot| {
                    slot.listeners
                        .iter()
                        .filter_map(|listener| match &listener.callback {
                            Callback::Waterfall(callback) => Some(Arc::clone(callback)),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        );
        Ok(run_waterfall(0, &chain, payload))
    }

    pub(crate) async fn parallel(
        &mut self,
        name: &str,
        payload: Arc<dyn Any + Send + Sync>,
    ) -> Result<Vec<String>, DispatchMode> {
        self.lock(name, DispatchMode::Parallel)?;
        let listeners: Vec<ParallelFn> = self
            .slots
            .get(name)
            .map(|slot| {
                slot.listeners
                    .iter()
                    .filter_map(|listener| match &listener.callback {
                        Callback::Parallel(callback) => Some(Arc::clone(callback)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut set = tokio::task::JoinSet::new();
        for listener in listeners {
            let payload = Arc::clone(&payload);
            set.spawn(async move { listener(payload).await });
        }
        let mut errors = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(message)) => errors.push(message),
                Err(join_error) => errors.push(join_error.to_string()),
            }
        }
        Ok(errors)
    }

    pub(crate) async fn serial(
        &mut self,
        name: &str,
        mut payload: Box<dyn Any + Send>,
    ) -> Result<Result<Box<dyn Any + Send>, String>, DispatchMode> {
        self.lock(name, DispatchMode::Serial)?;
        let listeners: Vec<SerialFn> = self
            .slots
            .get(name)
            .map(|slot| {
                slot.listeners
                    .iter()
                    .filter_map(|listener| match &listener.callback {
                        Callback::Serial(callback) => Some(Arc::clone(callback)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for listener in listeners {
            match listener(payload).await {
                Ok(next) => payload = next,
                Err(message) => return Ok(Err(message)),
            }
        }
        Ok(Ok(payload))
    }
}

fn run_waterfall(
    index: usize,
    chain: &Arc<Vec<WaterfallFn>>,
    payload: BoxedPayload,
) -> BoxedPayload {
    let Some(current) = chain.get(index).cloned() else {
        return payload;
    };
    let next_chain = Arc::clone(chain);
    let next: WaterfallContinuation =
        Box::new(move |value: BoxedPayload| run_waterfall(index + 1, &next_chain, value));
    current(payload, next)
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names: Vec<&String> = self.event_names();
        names.sort();
        f.debug_struct("EventBus")
            .field("events", &names)
            .field("next_id", &self.next_id)
            .finish_non_exhaustive()
    }
}
