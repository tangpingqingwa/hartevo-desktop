//! Synchronous pending-plugin registry for the N0 foundation.
//!
//! This registry intentionally owns only pending activation records.  N1 adds
//! runtime identity sharing, epochs, asynchronous transitions, and deletion
//! synchronization.  Keeping the N0 record small makes its no-late-activation
//! and exactly-once activation rules easy to audit.

use crate::fiber::{Fiber, FiberUid};
use crate::loader::PluginFactory;

pub(crate) type PendingId = u64;

pub(crate) struct PendingEntry {
    pub factory: PluginFactory,
    pub fiber: Fiber,
    pub namespace: String,
    pub inject: Vec<String>,
    pub config: crate::config::ConfigValue,
}

/// Context-local pending registry.  Context is synchronous and owns the
/// registry directly, so there is no mutex for callbacks to accidentally hold.
#[derive(Default)]
pub(crate) struct Registry {
    next_id: PendingId,
    pending: Vec<PendingEntry>,
}

impl Registry {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            pending: Vec::new(),
        }
    }

    pub(crate) fn contains_factory(&self, factory_id: crate::loader::PluginFactoryId) -> bool {
        self.pending
            .iter()
            .any(|entry| !entry.fiber.is_disposed() && entry.factory.id() == factory_id)
    }

    pub(crate) fn allocate_id(&mut self) -> PendingId {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    pub(crate) fn push(&mut self, entry: PendingEntry) {
        self.pending.push(entry);
    }

    pub(crate) fn take_pending(&mut self) -> Vec<PendingEntry> {
        std::mem::take(&mut self.pending)
    }

    pub(crate) fn replace_pending(&mut self, pending: Vec<PendingEntry>) {
        self.pending = pending;
    }

    pub(crate) fn remove_fiber(&mut self, uid: FiberUid) {
        self.pending.retain(|entry| entry.fiber.uid() != uid);
    }

    pub(crate) fn len(&self) -> usize {
        self.pending
            .iter()
            .filter(|entry| !entry.fiber.is_disposed())
            .count()
    }
}
