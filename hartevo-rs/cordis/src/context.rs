use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::ConfigValue;
use crate::effect::{Disposer, Registration};
use crate::event::{BoxedPayload, DispatchMode, EventBus, WaterfallContinuation, WaterfallNext};
use crate::service::Service;

/// Conventional Cordis / Hartevo service keys. Plugins look up by these names.
pub mod keys {
    pub const TOOLS: &str = "tools";
    pub const LLM: &str = "llm";
    pub const SESSIONS: &str = "sessions";
    pub const AGENTS: &str = "agents";
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
    #[error("event `{name}` parallel listeners failed: {}", .errors.join("; "))]
    ParallelJoin { name: String, errors: Vec<String> },
    #[error("event `{name}` serial listener failed: {message}")]
    Serial { name: String, message: String },
    #[error("event `{name}` payload type mismatch")]
    PayloadType { name: String },
    #[error(transparent)]
    Interpolate(#[from] crate::config::InterpolateError),
}

/// Service container and plugin host.
pub struct Context {
    services: HashMap<String, Arc<dyn Any + Send + Sync>>,
    /// Plugin-context interpolation source. Distinct from the loader context.
    vars: ConfigValue,
    effects: Vec<Registration>,
    events: EventBus,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    #[must_use]
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            vars: ConfigValue::default(),
            effects: Vec::new(),
            events: EventBus::new(),
        }
    }

    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.services.contains_key(key)
    }

    #[must_use]
    pub fn get<T: Any + Send + Sync>(&self, key: &str) -> Option<Arc<T>> {
        self.services.get(key)?.clone().downcast::<T>().ok()
    }

    #[must_use]
    pub fn tools<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.get(keys::TOOLS)
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

    /// Provide a named service. Reversed on teardown (restores the previous value).
    pub fn provide<T: Any + Send + Sync>(&mut self, key: impl Into<String>, value: T) {
        let key = key.into();
        let previous = self.services.insert(key.clone(), Arc::new(value));
        self.effects.push(Registration::Service { key, previous });
    }

    /// Set a plugin-context interpolation variable. Reversed on teardown.
    ///
    /// Used after `inject` when expanding plugin `config`. Not the loader
    /// context used for `disabled`.
    pub fn set_var(&mut self, key: impl Into<String>, value: impl Into<ConfigValue>) {
        let key = key.into();
        let value = value.into();
        let previous = match &mut self.vars {
            ConfigValue::Object(map) => map.insert(key.clone(), value),
            other => {
                let previous = Some(other.clone());
                *other = ConfigValue::object([(key.clone(), value)]);
                previous
            }
        };
        self.effects.push(Registration::Var { key, previous });
    }

    #[must_use]
    pub fn var(&self, key: &str) -> Option<&ConfigValue> {
        self.vars.lookup(key)
    }

    /// Interpolation source for plugin `config` (plugin context, after inject).
    #[must_use]
    pub fn plugin_interpolation_source(&self) -> &ConfigValue {
        &self.vars
    }

    /// Start `plugin` once every `inject` key is present. Missing deps do not start it.
    pub fn mount<S: Service>(&mut self, plugin: S) -> Result<(), CordisError> {
        let missing: Vec<String> = S::inject()
            .iter()
            .copied()
            .filter(|key| !self.has(key))
            .map(str::to_string)
            .collect();
        if !missing.is_empty() {
            return Err(CordisError::MissingDependencies(missing));
        }
        plugin.apply(self);
        Ok(())
    }

    pub fn effect<F>(&mut self, dispose: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let dispose: Disposer = Box::new(dispose);
        self.effects.push(Registration::Disposer(dispose));
    }

    /// Store an emit listener. Locks this name to [`DispatchMode::Emit`].
    pub fn on<F>(&mut self, name: impl Into<String>, listener: F) -> Result<(), CordisError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.on_emit(name, move |(): &()| listener())
    }

    /// Observe-only listener. Locks `name` to [`DispatchMode::Emit`].
    pub fn on_emit<T, F>(&mut self, name: impl Into<String>, listener: F) -> Result<(), CordisError>
    where
        T: Any + Send + Sync + 'static,
        F: Fn(&T) + Send + Sync + 'static,
    {
        let name = name.into();
        let callback = Arc::new(move |payload: &(dyn Any + Send + Sync)| {
            if let Some(value) = payload.downcast_ref::<T>() {
                listener(value);
            }
        });
        let id = self
            .events
            .register_emit(name.clone(), callback)
            .map_err(|locked| conflict(&name, locked, DispatchMode::Emit))?;
        self.effects.push(Registration::Listener { name, id });
        Ok(())
    }

    /// Middleware listener. Locks `name` to [`DispatchMode::Waterfall`].
    ///
    /// Not calling `next` short-circuits the remaining chain (policy).
    pub fn on_waterfall<T, F>(
        &mut self,
        name: impl Into<String>,
        listener: F,
    ) -> Result<(), CordisError>
    where
        T: Any + Send + 'static,
        F: Fn(T, WaterfallNext<T>) -> T + Send + Sync + 'static,
    {
        let name = name.into();
        let callback = Arc::new(move |payload: BoxedPayload, next: WaterfallContinuation| {
            match payload.downcast::<T>() {
                Ok(value) => {
                    let typed_next: WaterfallNext<T> = Box::new(move |value: T| {
                        *next(Box::new(value))
                            .downcast::<T>()
                            .expect("waterfall payload type is homogeneous")
                    });
                    Box::new(listener(*value, typed_next)) as Box<dyn Any + Send>
                }
                Err(original) => original,
            }
        });
        let id = self
            .events
            .register_waterfall(name.clone(), callback)
            .map_err(|locked| conflict(&name, locked, DispatchMode::Waterfall))?;
        self.effects.push(Registration::Listener { name, id });
        Ok(())
    }

    /// Awaited listener with no return. Locks `name` to [`DispatchMode::Parallel`].
    pub fn on_parallel<T, E, Fut, F>(
        &mut self,
        name: impl Into<String>,
        listener: F,
    ) -> Result<(), CordisError>
    where
        T: Clone + Any + Send + Sync + 'static,
        E: Display + Send + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
    {
        let name = name.into();
        let listener = Arc::new(listener);
        let callback = Arc::new(move |payload: Arc<dyn Any + Send + Sync>| {
            let value = payload.downcast_ref::<T>().cloned();
            let listener = Arc::clone(&listener);
            Box::pin(async move {
                let Some(value) = value else {
                    return Err("payload type mismatch".to_string());
                };
                listener(value).await.map_err(|error| error.to_string())
            }) as Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        });
        let id = self
            .events
            .register_parallel(name.clone(), callback)
            .map_err(|locked| conflict(&name, locked, DispatchMode::Parallel))?;
        self.effects.push(Registration::Listener { name, id });
        Ok(())
    }

    /// Awaited listener that threads a return value. Locks `name` to [`DispatchMode::Serial`].
    pub fn on_serial<T, E, Fut, F>(
        &mut self,
        name: impl Into<String>,
        listener: F,
    ) -> Result<(), CordisError>
    where
        T: Any + Send + 'static,
        E: Display + Send + 'static,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
        F: Fn(T) -> Fut + Send + Sync + 'static,
    {
        let name = name.into();
        let listener = Arc::new(listener);
        let callback = Arc::new(move |payload: Box<dyn Any + Send>| {
            let listener = Arc::clone(&listener);
            Box::pin(async move {
                let value = payload
                    .downcast::<T>()
                    .map_err(|_| "payload type mismatch".to_string())?;
                let next = listener(*value).await.map_err(|error| error.to_string())?;
                Ok(Box::new(next) as Box<dyn Any + Send>)
            })
                as Pin<Box<dyn Future<Output = Result<Box<dyn Any + Send>, String>> + Send>>
        });
        let id = self
            .events
            .register_serial(name.clone(), callback)
            .map_err(|locked| conflict(&name, locked, DispatchMode::Serial))?;
        self.effects.push(Registration::Listener { name, id });
        Ok(())
    }

    /// Observe-only dispatch. Locks `name` to [`DispatchMode::Emit`].
    pub fn emit<T>(&mut self, name: &str, payload: &T) -> Result<(), CordisError>
    where
        T: Any + Send + Sync,
    {
        self.events
            .emit(name, payload)
            .map_err(|locked| conflict(name, locked, DispatchMode::Emit))
    }

    /// Synchronous middleware dispatch. Locks `name` to [`DispatchMode::Waterfall`].
    pub fn waterfall<T>(&mut self, name: &str, payload: T) -> Result<T, CordisError>
    where
        T: Any + Send,
    {
        let boxed = self
            .events
            .waterfall(name, Box::new(payload))
            .map_err(|locked| conflict(name, locked, DispatchMode::Waterfall))?;
        boxed
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| CordisError::PayloadType {
                name: name.to_string(),
            })
    }

    /// Await every listener. Listener errors are joined; others are not dropped.
    pub async fn parallel<T>(&mut self, name: &str, payload: T) -> Result<(), CordisError>
    where
        T: Any + Send + Sync,
    {
        let errors = self
            .events
            .parallel(name, Arc::new(payload))
            .await
            .map_err(|locked| conflict(name, locked, DispatchMode::Parallel))?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(CordisError::ParallelJoin {
                name: name.to_string(),
                errors,
            })
        }
    }

    /// Await listeners in registration order, threading the return value.
    pub async fn serial<T>(&mut self, name: &str, payload: T) -> Result<T, CordisError>
    where
        T: Any + Send,
    {
        let boxed = self
            .events
            .serial(name, Box::new(payload))
            .await
            .map_err(|locked| conflict(name, locked, DispatchMode::Serial))?
            .map_err(|message| CordisError::Serial {
                name: name.to_string(),
                message,
            })?;
        boxed
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| CordisError::PayloadType {
                name: name.to_string(),
            })
    }

    #[must_use]
    pub fn listener_count(&self, name: &str) -> usize {
        self.events.listener_count(name)
    }

    #[must_use]
    pub fn event_mode(&self, name: &str) -> Option<DispatchMode> {
        self.events.mode(name)
    }

    /// Lock `name` to one dispatch mode without installing a listener.
    ///
    /// Reversed on teardown when no listeners remain for `name`. Re-locking an
    /// already-locked name is a no-op and does not stack another disposer.
    pub fn lock_event(&mut self, name: &str, mode: DispatchMode) -> Result<(), CordisError> {
        let already = self.events.mode(name) == Some(mode);
        self.events
            .lock(name, mode)
            .map_err(|locked| conflict(name, locked, mode))?;
        if !already {
            self.effects.push(Registration::EventLock {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    /// Run disposers newest-first, then drop remaining registrations. The context is reusable.
    pub fn teardown(&mut self) {
        while let Some(registration) = self.effects.pop() {
            match registration {
                Registration::Disposer(dispose) => dispose(),
                Registration::Service { key, previous } => match previous {
                    Some(value) => {
                        self.services.insert(key, value);
                    }
                    None => {
                        self.services.remove(&key);
                    }
                },
                Registration::Var { key, previous } => match &mut self.vars {
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
                },
                Registration::Listener { name, id } => {
                    self.events.remove_listener(&name, id);
                }
                Registration::EventLock { name } => {
                    self.events.unlock(&name);
                }
            }
        }
        self.services.clear();
        self.vars = ConfigValue::default();
        self.events.clear();
    }
}

fn conflict(name: &str, locked: DispatchMode, requested: DispatchMode) -> CordisError {
    CordisError::ModeConflict {
        name: name.to_string(),
        locked,
        requested,
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut services: Vec<&String> = self.services.keys().collect();
        services.sort();
        let mut listener_events: Vec<&String> = self.events.event_names();
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
