use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::effect::{Disposer, Registration};
use crate::service::Service;

/// Conventional Cordis / Hartevo service keys. Plugins look up by these names.
pub mod keys {
    pub const TOOLS: &str = "tools";
    pub const LLM: &str = "llm";
    pub const SESSIONS: &str = "sessions";
    pub const DOMAIN: &str = "domain";
    pub const EFFECT_BROKER: &str = "effect_broker";
    pub const RUNTIME: &str = "runtime";
    pub const DESKTOP: &str = "desktop";
}

/// Failure starting a plugin because `inject` dependencies are not yet provided.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CordisError {
    #[error("missing inject dependencies: {}", .0.join(", "))]
    MissingDependencies(Vec<String>),
}

struct ListenerEntry {
    id: u64,
    /// Stored for later dispatch (PR 3). Unused in this kernel revision.
    #[allow(dead_code)]
    listener: Arc<dyn Fn() + Send + Sync>,
}

/// Service container and plugin host.
pub struct Context {
    services: HashMap<String, Arc<dyn Any + Send + Sync>>,
    effects: Vec<Registration>,
    listeners: HashMap<String, Vec<ListenerEntry>>,
    next_listener_id: u64,
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
            effects: Vec::new(),
            listeners: HashMap::new(),
            next_listener_id: 1,
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

    /// Store a named listener. No dispatch in this revision. Unregistered on teardown.
    pub fn on<F>(&mut self, name: impl Into<String>, listener: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let name = name.into();
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.listeners
            .entry(name.clone())
            .or_default()
            .push(ListenerEntry {
                id,
                listener: Arc::new(listener),
            });
        self.effects.push(Registration::Listener { name, id });
    }

    #[must_use]
    pub fn listener_count(&self, name: &str) -> usize {
        self.listeners.get(name).map_or(0, Vec::len)
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
                Registration::Listener { name, id } => {
                    if let Some(entries) = self.listeners.get_mut(&name) {
                        entries.retain(|entry| entry.id != id);
                        if entries.is_empty() {
                            self.listeners.remove(&name);
                        }
                    }
                }
            }
        }
        self.services.clear();
        self.listeners.clear();
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
        let mut listener_events: Vec<&String> = self.listeners.keys().collect();
        listener_events.sort();
        f.debug_struct("Context")
            .field("services", &services)
            .field("effects", &self.effects.len())
            .field("listeners", &listener_events)
            .field("next_listener_id", &self.next_listener_id)
            .finish_non_exhaustive()
    }
}
