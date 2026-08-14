//! Connection-center-owned on-demand repair boundaries.
//!
//! This module is deliberately separate from the provider catalog and from
//! Mission/Application UI. It consumes an exact Mission repair request,
//! delegates authentication and probing to a provider boundary, and returns
//! only a scoped, content-free repair result.

mod events;
mod plugin;
mod repair;

pub use events::{
    ConnectionRepairEvent, ConnectionRepairEventKind, ConnectionRepairEventLog,
    ConnectionRepairEventSink,
};
pub use plugin::{
    MissionConnectionRepairPlugin, MissionConnectionRepairPluginError,
    MissionConnectionRepairState, MissionConnectionRepairSurface,
};
pub use repair::{
    ConnectionRepairError, ConnectionRepairObservation, ConnectionRepairPlugin,
    ConnectionRepairProvider, ConnectionRepairProviderFailure, ConnectionRepairProviderStatus,
    ConnectionRepairReason, ConnectionRepairRequest, ConnectionRepairResult,
    ConnectionRepairResultStatus, ConnectionRepairScope, ConnectionRepairService,
    ConnectionRepairSession, ConnectionRepairSessionState, MAX_REPAIR_SESSION_TTL_SECONDS,
    MissionConnectionRepairConsumer, MissionRepairScope, RepairAuthRequest, RepairLifecycleRequest,
    RepairMountRequest, RepairProbeRequest, RepairQuota,
};
