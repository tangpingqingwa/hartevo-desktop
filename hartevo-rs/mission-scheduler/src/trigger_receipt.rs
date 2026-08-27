//! Plugin-first scheduled-objective trigger receipts.
//!
//! This is the narrow Mission Scheduler vertical slice between a scheduled
//! Mission objective and its Mission Control consumer.  The service owns
//! durable, digest-bound records; a provider owns only the OS/Cell wake seam;
//! the consumer receives a capability-only start request.  There is no
//! Runtime, Browser, or Effect authority in this module, so a wake cannot
//! replay an uncertain action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::os::{
    MacOsWakeSleepAdapter, MacOsWakeSleepBackend, OsWakeSleepAdapter, WakeReceipt, WakeRequest,
    WakeSleepError,
};
use crate::scheduler_digest;

/// One coalesced wake is the only dispatch emitted for these logical ticks.
pub const DEFAULT_MAX_COALESCED_TICKS: u64 = 1_024;
pub const MAX_OBJECTIVE_BYTES: usize = 16 * 1_024;
pub const MAX_SCOPE_IDENTIFIER_BYTES: usize = 1_024;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScope {
    pub project_id: String,
    pub mission_id: String,
    pub mission_revision: u64,
}

impl MissionScope {
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        mission_revision: u64,
    ) -> Result<Self, SchedulingError> {
        let scope = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            mission_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), SchedulingError> {
        if !valid_identifier(&self.project_id)
            || !valid_identifier(&self.mission_id)
            || self.mission_revision == 0
        {
            return Err(SchedulingError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleState {
    Pending,
    Cancelled,
}

/// The content-free schedule binding owned by the scheduler.
///
/// The objective text is never stored in this record.  Its digest is carried
/// by [`DurableWakeRequest`] and [`TriggerReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduledObjective {
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub interval_seconds: u64,
    pub contract_valid_until: DateTime<Utc>,
    pub state: ScheduleState,
}

impl ScheduledObjective {
    pub fn new(
        schedule_id_digest: impl Into<String>,
        schedule_revision: u64,
        planned_at: DateTime<Utc>,
        interval_seconds: u64,
        contract_valid_until: DateTime<Utc>,
    ) -> Result<Self, SchedulingError> {
        let schedule = Self {
            schedule_id_digest: schedule_id_digest.into(),
            schedule_revision,
            planned_at,
            interval_seconds,
            contract_valid_until,
            state: ScheduleState::Pending,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.schedule_id_digest)
            || self.schedule_revision == 0
            || self.planned_at >= self.contract_valid_until
        {
            return Err(SchedulingError::InvalidSchedule);
        }
        Ok(())
    }
}

/// Input accepted from a Mission-specific consumer.  The objective is
/// transient and becomes a digest before any durable record is written.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionScheduleInput {
    pub objective: String,
    pub scope: MissionScope,
    pub schedule: ScheduledObjective,
}

impl MissionScheduleInput {
    pub fn validate(&self) -> Result<(), SchedulingError> {
        if self.objective.trim().is_empty() || self.objective.len() > MAX_OBJECTIVE_BYTES {
            return Err(SchedulingError::InvalidObjective);
        }
        self.scope.validate()?;
        self.schedule.validate()?;
        if self.schedule.state != ScheduleState::Pending {
            return Err(SchedulingError::ScheduleStateConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleKey {
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
}

impl ScheduleKey {
    fn new(
        scope: MissionScope,
        schedule_id_digest: impl Into<String>,
        schedule_revision: u64,
    ) -> Result<Self, SchedulingError> {
        let key = Self {
            scope,
            schedule_id_digest: schedule_id_digest.into(),
            schedule_revision,
        };
        key.scope.validate()?;
        if !validate_digest(&key.schedule_id_digest) || key.schedule_revision == 0 {
            return Err(SchedulingError::InvalidSchedule);
        }
        Ok(key)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduleSlot {
    scope: MissionScope,
    schedule_id_digest: String,
}

impl ScheduleSlot {
    fn new(scope: &MissionScope, schedule_id_digest: &str) -> Self {
        Self {
            scope: scope.clone(),
            schedule_id_digest: schedule_id_digest.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleEvent {
    Unmounted,
    Revoked,
    Crashed,
    Sleep,
    Wake,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Unmounted,
    Mounted,
    Sleeping,
    Crashed,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMountRequest {
    pub provider_id_digest: String,
    pub scope: MissionScope,
    pub provider_epoch: u64,
    pub observed_at: DateTime<Utc>,
}

impl ProviderMountRequest {
    fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.provider_id_digest) || self.provider_epoch == 0 {
            return Err(SchedulingError::InvalidProvider);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLifecycleTransition {
    pub provider_id_digest: String,
    pub scope: MissionScope,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub event: ProviderLifecycleEvent,
    pub observed_at: DateTime<Utc>,
}

impl ProviderLifecycleTransition {
    fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.provider_id_digest)
            || self.previous_epoch == 0
            || self.next_epoch == 0
            || (self.event != ProviderLifecycleEvent::Sleep
                && self.next_epoch <= self.previous_epoch)
        {
            return Err(SchedulingError::InvalidProviderEpoch);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMountReceipt {
    pub provider_id_digest: String,
    pub scope: MissionScope,
    pub provider_epoch: u64,
    pub refreshed_requests: Vec<DurableWakeRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderWakeReceipt {
    pub request_id_digest: String,
    pub request_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lifecycle_receipt: Option<WakeReceipt>,
}

impl ProviderWakeReceipt {
    fn validate_for(&self, request: &DurableWakeRequest) -> Result<(), SchedulingError> {
        if self.request_id_digest != request.request_id_digest
            || self.request_digest != request.request_digest
            || self.provider_id_digest != request.provider_id_digest
            || self.provider_epoch != request.provider_epoch
        {
            return Err(SchedulingError::ProviderReceiptConflict);
        }
        if let Some(receipt) = &self.lifecycle_receipt
            && (receipt.request_digest
                != request
                    .wake
                    .request_digest()
                    .map_err(SchedulingError::Lifecycle)?
                || receipt.wake_at != request.wake.wake_at
                || receipt.lease_generation != request.provider_epoch)
        {
            return Err(SchedulingError::ProviderReceiptConflict);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SchedulingProviderError {
    #[error("provider lifecycle epoch is stale")]
    EpochLost,
    #[error("provider wake receipt conflicts with the exact request")]
    ReceiptConflict,
    #[error("provider lifecycle adapter rejected the operation")]
    Lifecycle(#[from] WakeSleepError),
    #[error("provider backend failed")]
    Backend,
}

/// Provider lifecycle and wake boundary.  A provider can arm a wake, but it
/// never receives an Effect executor or a Mission completion authority.
pub trait SchedulingProvider: fmt::Debug {
    fn provider_id_digest(&self) -> &str;

    fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError>;
    fn unmount(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn revoke(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn crash(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn on_sleep(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn on_wake(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError>;
    fn arm_wake(
        &mut self,
        request: &DurableWakeRequest,
    ) -> Result<ProviderWakeReceipt, SchedulingProviderError>;
    fn disarm_wake(&mut self, receipt: &ProviderWakeReceipt)
    -> Result<(), SchedulingProviderError>;
}

/// Durable, content-free wake request.  The request digest covers the exact
/// Project/Mission scope, schedule revision, provider identity, provider
/// epoch and OS wake contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DurableWakeRequest {
    pub request_id_digest: String,
    pub request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule: ScheduledObjective,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub wake: WakeRequest,
}

impl DurableWakeRequest {
    fn new(
        objective_digest: String,
        scope: MissionScope,
        schedule: ScheduledObjective,
        provider_id_digest: String,
        provider_epoch: u64,
        coalesced_ticks: u64,
    ) -> Result<Self, SchedulingError> {
        scope.validate()?;
        schedule.validate()?;
        if !validate_digest(&objective_digest)
            || !validate_digest(&provider_id_digest)
            || provider_epoch == 0
            || coalesced_ticks == 0
        {
            return Err(SchedulingError::InvalidRequest);
        }
        let request_id_digest = digest_json(&RequestIdMaterial {
            objective_digest: &objective_digest,
            scope: &scope,
            schedule_id_digest: &schedule.schedule_id_digest,
            schedule_revision: schedule.schedule_revision,
            provider_id_digest: &provider_id_digest,
            provider_epoch,
        })?;
        let wake = WakeRequest {
            schedule_id_digest: schedule.schedule_id_digest.clone(),
            wake_at: schedule.planned_at,
            contract_valid_until: schedule.contract_valid_until,
            coalesced_ticks,
            lease_generation: provider_epoch,
        };
        let mut request = Self {
            request_id_digest,
            request_digest: String::new(),
            objective_digest,
            scope,
            schedule,
            provider_id_digest,
            provider_epoch,
            wake,
        };
        request.request_digest = request.expected_request_digest()?;
        request.validate()?;
        Ok(request)
    }

    fn rebind_provider_epoch(&self, provider_epoch: u64) -> Result<Self, SchedulingError> {
        Self::new(
            self.objective_digest.clone(),
            self.scope.clone(),
            self.schedule.clone(),
            self.provider_id_digest.clone(),
            provider_epoch,
            self.wake.coalesced_ticks,
        )
    }

    fn with_coalesced_ticks(&self, coalesced_ticks: u64) -> Result<Self, SchedulingError> {
        Self::new(
            self.objective_digest.clone(),
            self.scope.clone(),
            self.schedule.clone(),
            self.provider_id_digest.clone(),
            self.provider_epoch,
            coalesced_ticks,
        )
    }

    pub fn schedule_key(&self) -> Result<ScheduleKey, SchedulingError> {
        ScheduleKey::new(
            self.scope.clone(),
            self.schedule.schedule_id_digest.clone(),
            self.schedule.schedule_revision,
        )
    }

    pub fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.request_id_digest)
            || !validate_digest(&self.request_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.provider_epoch == 0
        {
            return Err(SchedulingError::InvalidRequest);
        }
        self.scope.validate()?;
        self.schedule.validate()?;
        self.wake.validate().map_err(SchedulingError::Lifecycle)?;
        if self.wake.schedule_id_digest != self.schedule.schedule_id_digest
            || self.wake.wake_at != self.schedule.planned_at
            || self.wake.contract_valid_until != self.schedule.contract_valid_until
            || self.wake.lease_generation != self.provider_epoch
            || self.expected_request_id_digest()? != self.request_id_digest
            || self.expected_request_digest()? != self.request_digest
        {
            return Err(SchedulingError::InvalidRequest);
        }
        Ok(())
    }

    pub fn expected_request_id_digest(&self) -> Result<String, SchedulingError> {
        digest_json(&RequestIdMaterial {
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule.schedule_id_digest,
            schedule_revision: self.schedule.schedule_revision,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
        })
    }

    pub fn expected_request_digest(&self) -> Result<String, SchedulingError> {
        digest_json(&RequestDigestMaterial {
            request_id_digest: &self.request_id_digest,
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule: &self.schedule,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
            wake: &self.wake,
        })
    }
}

/// One durable fact that the scheduler observed a wake for an exact schedule
/// revision.  Repeated wakes return this same record; they never append a
/// second receipt for the same logical schedule key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerReceipt {
    pub trigger_id_digest: String,
    pub request_id_digest: String,
    pub request_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u64,
    /// Digest-bound provider identity; no raw provider token is persisted.
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub receipt_digest: String,
}

impl TriggerReceipt {
    fn from_request(
        request: &DurableWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<Self, SchedulingError> {
        let mut receipt = Self {
            trigger_id_digest: scheduler_digest(
                format!(
                    "trigger:{}:{}:{}:{}:{}",
                    request.scope.project_id,
                    request.scope.mission_id,
                    request.schedule.schedule_id_digest,
                    request.schedule.schedule_revision,
                    request.objective_digest,
                )
                .as_bytes(),
            ),
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            objective_digest: request.objective_digest.clone(),
            scope: request.scope.clone(),
            schedule_id_digest: request.schedule.schedule_id_digest.clone(),
            schedule_revision: request.schedule.schedule_revision,
            planned_at: request.schedule.planned_at,
            woke_at,
            coalesced_ticks: request.wake.coalesced_ticks,
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_receipt_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn schedule_key(&self) -> Result<ScheduleKey, SchedulingError> {
        ScheduleKey::new(
            self.scope.clone(),
            self.schedule_id_digest.clone(),
            self.schedule_revision,
        )
    }

    pub fn expected_receipt_digest(&self) -> Result<String, SchedulingError> {
        digest_json(&TriggerReceiptMaterial {
            trigger_id_digest: &self.trigger_id_digest,
            request_id_digest: &self.request_id_digest,
            request_digest: &self.request_digest,
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule_id_digest,
            schedule_revision: self.schedule_revision,
            planned_at: self.planned_at,
            woke_at: self.woke_at,
            coalesced_ticks: self.coalesced_ticks,
            provider_id_digest: &self.provider_id_digest,
            provider_epoch: self.provider_epoch,
        })
    }

    pub fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.trigger_id_digest)
            || !validate_digest(&self.request_id_digest)
            || !validate_digest(&self.request_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.schedule_id_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.planned_at > self.woke_at
            || self.receipt_digest != self.expected_receipt_digest()?
        {
            return Err(SchedulingError::InvalidTriggerReceipt);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAuthority {
    CapabilityRequestOnly,
}

/// Mission Control receives a typed capability request, not an executor or
/// an Effect authority.  `start_id_digest` is stable across exact receipt
/// replay and makes downstream start handling idempotent after restart.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlStartRequest {
    pub start_id_digest: String,
    pub trigger_receipt_digest: String,
    pub objective_digest: String,
    pub scope: MissionScope,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub authority: CapabilityAuthority,
}

impl MissionControlStartRequest {
    fn from_receipt(receipt: &TriggerReceipt) -> Result<Self, SchedulingError> {
        let mut request = Self {
            start_id_digest: String::new(),
            trigger_receipt_digest: receipt.receipt_digest.clone(),
            objective_digest: receipt.objective_digest.clone(),
            scope: receipt.scope.clone(),
            schedule_id_digest: receipt.schedule_id_digest.clone(),
            schedule_revision: receipt.schedule_revision,
            planned_at: receipt.planned_at,
            woke_at: receipt.woke_at,
            coalesced_ticks: receipt.coalesced_ticks,
            provider_id_digest: receipt.provider_id_digest.clone(),
            provider_epoch: receipt.provider_epoch,
            authority: CapabilityAuthority::CapabilityRequestOnly,
        };
        request.start_id_digest = request.expected_start_id_digest()?;
        request.validate()?;
        Ok(request)
    }

    pub fn expected_start_id_digest(&self) -> Result<String, SchedulingError> {
        digest_json(&MissionControlStartMaterial {
            trigger_receipt_digest: &self.trigger_receipt_digest,
            objective_digest: &self.objective_digest,
            scope: &self.scope,
            schedule_id_digest: &self.schedule_id_digest,
            schedule_revision: self.schedule_revision,
            authority: self.authority,
        })
    }

    pub fn validate(&self) -> Result<(), SchedulingError> {
        if !validate_digest(&self.start_id_digest)
            || !validate_digest(&self.trigger_receipt_digest)
            || !validate_digest(&self.objective_digest)
            || !validate_digest(&self.schedule_id_digest)
            || !validate_digest(&self.provider_id_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.authority != CapabilityAuthority::CapabilityRequestOnly
            || self.start_id_digest != self.expected_start_id_digest()?
        {
            return Err(SchedulingError::InvalidMissionControlRequest);
        }
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissionControlConsume {
    Started(MissionControlStartRequest),
    AlreadyStarted(MissionControlStartRequest),
}

/// The durable scheduler snapshot is intentionally small and content-free.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerStoreSnapshot {
    pub requests: Vec<DurableWakeRequest>,
    pub cancelled: Vec<ScheduleKey>,
    pub receipts: Vec<TriggerReceipt>,
    pub starts: Vec<MissionControlStartRequest>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum TriggerReceiptStoreError {
    #[error("trigger receipt snapshot serialization failed: {0}")]
    Serialization(String),
    #[error("trigger receipt snapshot is corrupt")]
    Corrupt,
    #[error("trigger receipt SQLite store failed: {0}")]
    Sqlite(String),
}

/// Persistence seam for the typed trigger record.  Production can use the
/// SQLCipher-backed connection owned by the scheduler; tests can use the
/// deterministic in-memory implementation.
pub trait TriggerReceiptStore: fmt::Debug {
    fn load(&self) -> Result<TriggerStoreSnapshot, TriggerReceiptStoreError>;
    fn save(&mut self, snapshot: &TriggerStoreSnapshot) -> Result<(), TriggerReceiptStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryTriggerReceiptStore {
    snapshot: TriggerStoreSnapshot,
}

impl MemoryTriggerReceiptStore {
    pub fn snapshot(&self) -> &TriggerStoreSnapshot {
        &self.snapshot
    }
}

impl TriggerReceiptStore for MemoryTriggerReceiptStore {
    fn load(&self) -> Result<TriggerStoreSnapshot, TriggerReceiptStoreError> {
        Ok(self.snapshot.clone())
    }

    fn save(&mut self, snapshot: &TriggerStoreSnapshot) -> Result<(), TriggerReceiptStoreError> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqliteTriggerReceiptStore {
    connection: Connection,
}

impl SqliteTriggerReceiptStore {
    pub fn new(connection: Connection) -> Result<Self, TriggerReceiptStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_trigger_receipts (
                    snapshot_id INTEGER PRIMARY KEY CHECK (snapshot_id = 1),
                    snapshot_json TEXT NOT NULL
                )",
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(Self { connection })
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl TriggerReceiptStore for SqliteTriggerReceiptStore {
    fn load(&self) -> Result<TriggerStoreSnapshot, TriggerReceiptStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT snapshot_json FROM scheduler_trigger_receipts WHERE snapshot_id = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_store_error(&error))?;
        json.map_or_else(
            || Ok(TriggerStoreSnapshot::default()),
            |value| {
                serde_json::from_str(&value)
                    .map_err(|error| TriggerReceiptStoreError::Serialization(error.to_string()))
            },
        )
    }

    fn save(&mut self, snapshot: &TriggerStoreSnapshot) -> Result<(), TriggerReceiptStoreError> {
        let json = serde_json::to_string(snapshot)
            .map_err(|error| TriggerReceiptStoreError::Serialization(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO scheduler_trigger_receipts(snapshot_id, snapshot_json)
                 VALUES (1, ?1)
                 ON CONFLICT(snapshot_id) DO UPDATE SET snapshot_json = excluded.snapshot_json",
                params![json],
            )
            .map_err(|error| sqlite_store_error(&error))?;
        Ok(())
    }
}

fn sqlite_store_error(error: &rusqlite::Error) -> TriggerReceiptStoreError {
    TriggerReceiptStoreError::Sqlite(error.to_string())
}

/// Scheduling service contract consumed by Mission Control or another
/// plugin-provided consumer.
pub trait SchedulingService {
    fn provider_state(&self) -> ProviderState;
    fn provider_epoch(&self) -> u64;
    fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<ProviderMountReceipt, SchedulingError>;
    fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError>;
    fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError>;
    fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError>;
    fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError>;
    fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError>;
    fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError>;
    fn schedule_objective(
        &mut self,
        input: MissionScheduleInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableWakeRequest, SchedulingError>;
    fn coalesce_missed_ticks(
        &mut self,
        request: &DurableWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, SchedulingError>;
    fn observe_wake(
        &mut self,
        request: &DurableWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, SchedulingError>;
    fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError>;
    fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        receipt: &TriggerReceipt,
    ) -> Result<MissionControlConsume, SchedulingError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalescedWake {
    pub request: DurableWakeRequest,
    pub due_ticks: u64,
    pub coalesced_ticks: u64,
    pub dispatch_count: u8,
}

/// In-process implementation of the scheduling service.  The provider and
/// store are injected so Desktop, Cell, and tests do not share Application
/// files or acquire hidden authorities.
#[derive(Debug)]
pub struct TriggerSchedulingService<P, S = MemoryTriggerReceiptStore> {
    provider: P,
    store: S,
    provider_id_digest: String,
    state: ProviderState,
    scope: Option<MissionScope>,
    provider_epoch: u64,
    requests: BTreeMap<String, DurableWakeRequest>,
    latest_by_schedule: BTreeMap<ScheduleSlot, String>,
    armed: BTreeMap<String, ProviderWakeReceipt>,
    cancelled: BTreeSet<ScheduleKey>,
    receipts: BTreeMap<ScheduleKey, TriggerReceipt>,
    starts: BTreeMap<ScheduleKey, MissionControlStartRequest>,
}

pub type PluginSchedulingService<P, S = MemoryTriggerReceiptStore> = TriggerSchedulingService<P, S>;

impl<P> TriggerSchedulingService<P, MemoryTriggerReceiptStore>
where
    P: SchedulingProvider,
{
    pub fn new(provider: P) -> Result<Self, SchedulingError> {
        Self::with_store(provider, MemoryTriggerReceiptStore::default())
    }
}

impl<P, S> TriggerSchedulingService<P, S>
where
    P: SchedulingProvider,
    S: TriggerReceiptStore,
{
    pub fn with_store(provider: P, store: S) -> Result<Self, SchedulingError> {
        let provider_id_digest = provider.provider_id_digest().to_owned();
        if !validate_digest(&provider_id_digest) {
            return Err(SchedulingError::InvalidProvider);
        }
        let snapshot = store.load().map_err(SchedulingError::Store)?;
        let mut requests = BTreeMap::new();
        let mut provider_epoch = 0;
        for request in snapshot.requests {
            request.validate()?;
            if request.provider_id_digest != provider_id_digest {
                return Err(SchedulingError::ProviderIdentityMismatch);
            }
            provider_epoch = provider_epoch.max(request.provider_epoch);
            if requests
                .insert(request.request_id_digest.clone(), request)
                .is_some()
            {
                return Err(SchedulingError::Store(TriggerReceiptStoreError::Corrupt));
            }
        }
        let mut cancelled = BTreeSet::new();
        for key in snapshot.cancelled {
            key.scope.validate()?;
            if !validate_digest(&key.schedule_id_digest) || key.schedule_revision == 0 {
                return Err(SchedulingError::Store(TriggerReceiptStoreError::Corrupt));
            }
            cancelled.insert(key);
        }
        let mut receipts = BTreeMap::new();
        for receipt in snapshot.receipts {
            receipt.validate()?;
            if receipt.provider_id_digest != provider_id_digest {
                return Err(SchedulingError::ProviderIdentityMismatch);
            }
            provider_epoch = provider_epoch.max(receipt.provider_epoch);
            let key = receipt.schedule_key()?;
            if receipts.insert(key, receipt).is_some() {
                return Err(SchedulingError::Store(TriggerReceiptStoreError::Corrupt));
            }
        }
        let mut starts = BTreeMap::new();
        for start in snapshot.starts {
            start.validate()?;
            if start.provider_id_digest != provider_id_digest {
                return Err(SchedulingError::ProviderIdentityMismatch);
            }
            provider_epoch = provider_epoch.max(start.provider_epoch);
            let key = ScheduleKey::new(
                start.scope.clone(),
                start.schedule_id_digest.clone(),
                start.schedule_revision,
            )?;
            if starts.insert(key, start).is_some() {
                return Err(SchedulingError::Store(TriggerReceiptStoreError::Corrupt));
            }
        }

        let mut latest_by_schedule: BTreeMap<ScheduleSlot, (u64, u64, String)> = BTreeMap::new();
        for request in requests.values() {
            let slot = ScheduleSlot::new(&request.scope, &request.schedule.schedule_id_digest);
            let candidate = (
                request.schedule.schedule_revision,
                request.provider_epoch,
                request.request_id_digest.clone(),
            );
            let replace = latest_by_schedule
                .get(&slot)
                .is_none_or(|current| candidate.0 > current.0 || candidate.1 >= current.1);
            if replace {
                latest_by_schedule.insert(slot, candidate);
            }
        }

        Ok(Self {
            provider,
            store,
            provider_id_digest,
            state: ProviderState::Unmounted,
            scope: None,
            provider_epoch,
            requests,
            latest_by_schedule: latest_by_schedule
                .into_iter()
                .map(|(slot, (_, _, request_id))| (slot, request_id))
                .collect(),
            armed: BTreeMap::new(),
            cancelled,
            receipts,
            starts,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn snapshot(&self) -> TriggerStoreSnapshot {
        TriggerStoreSnapshot {
            requests: self.requests.values().cloned().collect(),
            cancelled: self.cancelled.iter().cloned().collect(),
            receipts: self.receipts.values().cloned().collect(),
            starts: self.starts.values().cloned().collect(),
        }
    }

    pub fn latest_request(&self, schedule_id_digest: &str) -> Option<&DurableWakeRequest> {
        self.latest_by_schedule
            .iter()
            .find(|(slot, _)| slot.schedule_id_digest == schedule_id_digest)
            .and_then(|(_, request_id)| self.requests.get(request_id))
    }

    pub fn receipt_for(
        &self,
        scope: &MissionScope,
        schedule_id_digest: &str,
        schedule_revision: u64,
    ) -> Option<&TriggerReceipt> {
        let key = ScheduleKey::new(
            scope.clone(),
            schedule_id_digest.to_owned(),
            schedule_revision,
        )
        .ok()?;
        self.receipts.get(&key)
    }

    pub fn started_count(&self) -> usize {
        self.starts.len()
    }

    fn sync_store(&mut self) -> Result<(), SchedulingError> {
        let snapshot = self.snapshot();
        self.store.save(&snapshot).map_err(SchedulingError::Store)
    }

    fn current_scope(&self) -> Result<&MissionScope, SchedulingError> {
        self.scope
            .as_ref()
            .ok_or(SchedulingError::ProviderNotMounted)
    }

    fn ensure_scope(&self, scope: &MissionScope) -> Result<(), SchedulingError> {
        if self.current_scope()? != scope {
            return Err(SchedulingError::ScopeMismatch);
        }
        Ok(())
    }

    fn ensure_epoch(&self, provider_epoch: u64) -> Result<(), SchedulingError> {
        if provider_epoch != self.provider_epoch {
            return Err(SchedulingError::ProviderEpochLost {
                expected: self.provider_epoch,
                actual: provider_epoch,
            });
        }
        Ok(())
    }

    fn ensure_mounted(&self, provider_epoch: u64) -> Result<(), SchedulingError> {
        match self.state {
            ProviderState::Mounted => self.ensure_epoch(provider_epoch),
            ProviderState::Sleeping => Err(SchedulingError::ProviderSleeping),
            ProviderState::Unmounted => Err(SchedulingError::ProviderNotMounted),
            ProviderState::Crashed => Err(SchedulingError::ProviderCrashed),
            ProviderState::Revoked => Err(SchedulingError::ProviderRevoked),
        }
    }

    fn next_epoch(&self) -> Result<u64, SchedulingError> {
        self.provider_epoch
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(SchedulingError::ProviderEpochExhausted)
    }

    fn transition(
        &mut self,
        event: ProviderLifecycleEvent,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
        next_state: ProviderState,
    ) -> Result<(), SchedulingError> {
        self.ensure_epoch(provider_epoch)?;
        let scope = self.current_scope()?.clone();
        let next_epoch = if event == ProviderLifecycleEvent::Sleep {
            provider_epoch
        } else {
            self.next_epoch()?
        };
        let transition = ProviderLifecycleTransition {
            provider_id_digest: self.provider_id_digest.clone(),
            scope,
            previous_epoch: provider_epoch,
            next_epoch,
            event,
            observed_at,
        };
        transition.validate()?;
        match event {
            ProviderLifecycleEvent::Unmounted => self.provider.unmount(&transition),
            ProviderLifecycleEvent::Revoked => self.provider.revoke(&transition),
            ProviderLifecycleEvent::Crashed => self.provider.crash(&transition),
            ProviderLifecycleEvent::Sleep => self.provider.on_sleep(&transition),
            ProviderLifecycleEvent::Wake => self.provider.on_wake(&transition),
        }
        .map_err(SchedulingError::Provider)?;
        self.provider_epoch = next_epoch;
        self.state = next_state;
        Ok(())
    }

    fn disarm_all(&mut self) -> Result<(), SchedulingError> {
        let armed = self
            .armed
            .iter()
            .map(|(request_id, receipt)| (request_id.clone(), receipt.clone()))
            .collect::<Vec<_>>();
        for (request_id, receipt) in armed {
            self.provider
                .disarm_wake(&receipt)
                .map_err(SchedulingError::Provider)?;
            self.armed.remove(&request_id);
        }
        Ok(())
    }

    fn request_for_exact_record(
        &self,
        request: &DurableWakeRequest,
    ) -> Result<&DurableWakeRequest, SchedulingError> {
        request.validate()?;
        let current = self
            .requests
            .get(&request.request_id_digest)
            .ok_or(SchedulingError::StaleWakeRequest)?;
        if current != request {
            return Err(SchedulingError::WakeRequestConflict);
        }
        self.ensure_scope(&request.scope)?;
        let key = request.schedule_key()?;
        if self.cancelled.contains(&key) {
            return Err(SchedulingError::ScheduleCancelled);
        }
        let slot = ScheduleSlot::new(&request.scope, &request.schedule.schedule_id_digest);
        if self.latest_by_schedule.get(&slot) != Some(&request.request_id_digest) {
            return Err(SchedulingError::StaleWakeRequest);
        }
        Ok(current)
    }

    fn arm_request(
        &mut self,
        request: &DurableWakeRequest,
    ) -> Result<ProviderWakeReceipt, SchedulingError> {
        let receipt = self
            .provider
            .arm_wake(request)
            .map_err(SchedulingError::Provider)?;
        receipt.validate_for(request)?;
        Ok(receipt)
    }

    fn replace_armed_request(
        &mut self,
        old_request_id: &str,
        request: &DurableWakeRequest,
    ) -> Result<(), SchedulingError> {
        if let Some(receipt) = self.armed.remove(old_request_id) {
            self.provider
                .disarm_wake(&receipt)
                .map_err(SchedulingError::Provider)?;
        }
        let receipt = self.arm_request(request)?;
        self.armed
            .insert(request.request_id_digest.clone(), receipt);
        Ok(())
    }

    fn due_ticks(
        schedule: &ScheduledObjective,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, SchedulingError> {
        if schedule.planned_at > observed_at {
            return Ok(0);
        }
        if schedule.interval_seconds == 0 {
            return Ok(1);
        }
        let elapsed = (observed_at - schedule.planned_at).num_seconds().max(0);
        let interval = i64::try_from(schedule.interval_seconds)
            .map_err(|_| SchedulingError::InvalidSchedule)?;
        u64::try_from(elapsed / interval)
            .ok()
            .and_then(|ticks| ticks.checked_add(1))
            .ok_or(SchedulingError::InvalidSchedule)
    }

    fn refresh_pending_requests(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<Vec<DurableWakeRequest>, SchedulingError> {
        let ids = self
            .latest_by_schedule
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut refreshed = Vec::new();
        for request_id in ids {
            let current = self
                .requests
                .get(&request_id)
                .ok_or(SchedulingError::StaleWakeRequest)?
                .clone();
            let key = current.schedule_key()?;
            if self.cancelled.contains(&key) || self.receipts.contains_key(&key) {
                continue;
            }
            let mut next = if current.provider_epoch == self.provider_epoch {
                current.clone()
            } else {
                current.rebind_provider_epoch(self.provider_epoch)?
            };
            let due_ticks = Self::due_ticks(&next.schedule, observed_at)?;
            if due_ticks > 0 && next.wake.coalesced_ticks == 1 {
                next = next.with_coalesced_ticks(due_ticks.min(DEFAULT_MAX_COALESCED_TICKS))?;
            }
            if next != current || !self.armed.contains_key(&next.request_id_digest) {
                self.replace_armed_request(&request_id, &next)?;
                self.requests
                    .insert(next.request_id_digest.clone(), next.clone());
                let slot = ScheduleSlot::new(&next.scope, &next.schedule.schedule_id_digest);
                self.latest_by_schedule
                    .insert(slot, next.request_id_digest.clone());
            }
            refreshed.push(next);
        }
        Ok(refreshed)
    }

    fn collect_due_triggers(
        &mut self,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError> {
        let ids = self
            .latest_by_schedule
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        for request_id in ids {
            let request = self
                .requests
                .get(&request_id)
                .ok_or(SchedulingError::StaleWakeRequest)?
                .clone();
            let key = request.schedule_key()?;
            if self.receipts.contains_key(&key) || request.wake.wake_at > woke_at {
                continue;
            }
            receipts.push(self.observe_wake(&request, woke_at)?);
        }
        Ok(receipts)
    }

    fn validate_current_receipt(
        &self,
        scope: &MissionScope,
        receipt: &TriggerReceipt,
    ) -> Result<ScheduleKey, SchedulingError> {
        receipt.validate()?;
        self.ensure_scope(scope)?;
        if receipt.scope != *scope || receipt.provider_id_digest != self.provider_id_digest {
            return Err(SchedulingError::ScopeMismatch);
        }
        let key = receipt.schedule_key()?;
        if self.cancelled.contains(&key) {
            return Err(SchedulingError::ScheduleCancelled);
        }
        let slot = ScheduleSlot::new(scope, &receipt.schedule_id_digest);
        let request_id = self
            .latest_by_schedule
            .get(&slot)
            .ok_or(SchedulingError::StaleTriggerReceipt)?;
        let request = self
            .requests
            .get(request_id)
            .ok_or(SchedulingError::StaleTriggerReceipt)?;
        if request.schedule.schedule_revision != receipt.schedule_revision
            || request.objective_digest != receipt.objective_digest
            || request.schedule.planned_at != receipt.planned_at
            || request.schedule.schedule_id_digest != receipt.schedule_id_digest
        {
            return Err(SchedulingError::StaleTriggerReceipt);
        }
        Ok(key)
    }

    pub fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<ProviderMountReceipt, SchedulingError> {
        scope.validate()?;
        if matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(SchedulingError::ProviderAlreadyMounted);
        }
        if self.state == ProviderState::Revoked {
            return Err(SchedulingError::ProviderRevoked);
        }
        let provider_epoch = self.next_epoch()?;
        let request = ProviderMountRequest {
            provider_id_digest: self.provider_id_digest.clone(),
            scope: scope.clone(),
            provider_epoch,
            observed_at,
        };
        request.validate()?;
        self.provider
            .mount(&request)
            .map_err(SchedulingError::Provider)?;
        self.scope = Some(scope.clone());
        self.provider_epoch = provider_epoch;
        self.state = ProviderState::Mounted;
        let refreshed_requests = self.refresh_pending_requests(observed_at)?;
        self.sync_store()?;
        Ok(ProviderMountReceipt {
            provider_id_digest: self.provider_id_digest.clone(),
            scope,
            provider_epoch,
            refreshed_requests,
        })
    }

    pub fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Unmounted,
            provider_epoch,
            observed_at,
            ProviderState::Unmounted,
        )?;
        self.sync_store()
    }

    pub fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        if self.state == ProviderState::Revoked {
            return Ok(());
        }
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Revoked,
            provider_epoch,
            observed_at,
            ProviderState::Revoked,
        )?;
        self.sync_store()
    }

    pub fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        if !matches!(self.state, ProviderState::Mounted | ProviderState::Sleeping) {
            return Err(self.state_error());
        }
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Crashed,
            provider_epoch,
            observed_at,
            ProviderState::Crashed,
        )?;
        self.armed.clear();
        self.sync_store()
    }

    pub fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        if self.state != ProviderState::Mounted {
            return Err(self.state_error());
        }
        self.transition(
            ProviderLifecycleEvent::Sleep,
            provider_epoch,
            observed_at,
            ProviderState::Sleeping,
        )?;
        self.sync_store()
    }

    pub fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError> {
        if self.state != ProviderState::Sleeping {
            return Err(self.state_error());
        }
        self.ensure_epoch(provider_epoch)?;
        self.disarm_all()?;
        self.transition(
            ProviderLifecycleEvent::Wake,
            provider_epoch,
            woke_at,
            ProviderState::Mounted,
        )?;
        self.refresh_pending_requests(woke_at)?;
        let receipts = self.collect_due_triggers(woke_at)?;
        self.sync_store()?;
        Ok(receipts)
    }

    pub fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError> {
        self.ensure_mounted(provider_epoch)?;
        self.refresh_pending_requests(woke_at)?;
        let receipts = self.collect_due_triggers(woke_at)?;
        self.sync_store()?;
        Ok(receipts)
    }

    pub fn schedule_objective(
        &mut self,
        input: MissionScheduleInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableWakeRequest, SchedulingError> {
        input.validate()?;
        self.ensure_mounted(self.provider_epoch)?;
        self.ensure_scope(&input.scope)?;
        if input.schedule.contract_valid_until <= observed_at {
            return Err(SchedulingError::ScheduleExpired);
        }
        let objective_digest = scheduler_digest(input.objective.as_bytes());
        let slot = ScheduleSlot::new(&input.scope, &input.schedule.schedule_id_digest);
        if let Some(existing_id) = self.latest_by_schedule.get(&slot).cloned() {
            let existing = self
                .requests
                .get(&existing_id)
                .ok_or(SchedulingError::StaleWakeRequest)?;
            if existing.schedule.schedule_revision > input.schedule.schedule_revision {
                return Err(SchedulingError::StaleSchedule);
            }
            if existing.schedule.schedule_revision == input.schedule.schedule_revision {
                if existing.objective_digest == objective_digest
                    && existing.schedule == input.schedule
                {
                    return Ok(existing.clone());
                }
                return Err(SchedulingError::ScheduleConflict);
            }
            if let Some(receipt) = self.armed.remove(&existing_id) {
                self.provider
                    .disarm_wake(&receipt)
                    .map_err(SchedulingError::Provider)?;
            }
        }
        let request = DurableWakeRequest::new(
            objective_digest,
            input.scope,
            input.schedule,
            self.provider_id_digest.clone(),
            self.provider_epoch,
            1,
        )?;
        let receipt = self.arm_request(&request)?;
        self.requests
            .insert(request.request_id_digest.clone(), request.clone());
        self.latest_by_schedule
            .insert(slot, request.request_id_digest.clone());
        self.armed
            .insert(request.request_id_digest.clone(), receipt);
        self.sync_store()?;
        Ok(request)
    }

    pub fn coalesce_missed_ticks(
        &mut self,
        request: &DurableWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, SchedulingError> {
        if max_coalesced_ticks == 0 || max_coalesced_ticks > DEFAULT_MAX_COALESCED_TICKS {
            return Err(SchedulingError::InvalidCoalescingLimit);
        }
        let current = self.request_for_exact_record(request)?.clone();
        self.ensure_mounted(current.provider_epoch)?;
        let key = current.schedule_key()?;
        if self.receipts.contains_key(&key) {
            return Err(SchedulingError::AlreadyTriggered);
        }
        let due_ticks = Self::due_ticks(&current.schedule, observed_at)?;
        if due_ticks == 0 {
            return Err(SchedulingError::NoDueTicks);
        }
        let coalesced_ticks = due_ticks.min(max_coalesced_ticks);
        let next = current.with_coalesced_ticks(coalesced_ticks)?;
        self.replace_armed_request(&current.request_id_digest, &next)?;
        self.requests
            .insert(next.request_id_digest.clone(), next.clone());
        self.sync_store()?;
        Ok(CoalescedWake {
            request: next,
            due_ticks,
            coalesced_ticks,
            dispatch_count: 1,
        })
    }

    pub fn observe_wake(
        &mut self,
        request: &DurableWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, SchedulingError> {
        self.ensure_mounted(request.provider_epoch)?;
        let current = self.request_for_exact_record(request)?.clone();
        if current.wake.wake_at > woke_at {
            return Err(SchedulingError::WakeNotDue);
        }
        if current.schedule.contract_valid_until <= woke_at {
            return Err(SchedulingError::ScheduleExpired);
        }
        if let Some(existing) = self.receipts.get(&current.schedule_key()?) {
            if let Some(armed) = self.armed.remove(&current.request_id_digest) {
                self.provider
                    .disarm_wake(&armed)
                    .map_err(SchedulingError::Provider)?;
            }
            return Ok(existing.clone());
        }
        if let Some(armed) = self.armed.remove(&current.request_id_digest) {
            self.provider
                .disarm_wake(&armed)
                .map_err(SchedulingError::Provider)?;
        }
        let receipt = TriggerReceipt::from_request(&current, woke_at)?;
        let key = receipt.schedule_key()?;
        self.receipts.insert(key, receipt.clone());
        self.sync_store()?;
        Ok(receipt)
    }

    pub fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        _observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        self.ensure_mounted(self.provider_epoch)?;
        let scope = self.current_scope()?.clone();
        let slot = ScheduleSlot::new(&scope, schedule_id_digest);
        let request_id = self
            .latest_by_schedule
            .get(&slot)
            .cloned()
            .ok_or(SchedulingError::ScheduleNotFound)?;
        let request = self
            .requests
            .get(&request_id)
            .ok_or(SchedulingError::ScheduleNotFound)?;
        if request.schedule.schedule_revision != schedule_revision {
            return Err(SchedulingError::StaleSchedule);
        }
        let key = request.schedule_key()?;
        if let Some(armed) = self.armed.remove(&request_id) {
            self.provider
                .disarm_wake(&armed)
                .map_err(SchedulingError::Provider)?;
        }
        self.cancelled.insert(key);
        self.latest_by_schedule.remove(&slot);
        self.sync_store()
    }

    pub fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        receipt: &TriggerReceipt,
    ) -> Result<MissionControlConsume, SchedulingError> {
        self.ensure_mounted(self.provider_epoch)?;
        let key = self.validate_current_receipt(scope, receipt)?;
        if let Some(existing) = self.starts.get(&key) {
            return Ok(MissionControlConsume::AlreadyStarted(existing.clone()));
        }
        let request = MissionControlStartRequest::from_receipt(receipt)?;
        self.starts.insert(key, request.clone());
        self.sync_store()?;
        Ok(MissionControlConsume::Started(request))
    }

    fn state_error(&self) -> SchedulingError {
        match self.state {
            ProviderState::Mounted => SchedulingError::InvalidLifecycleState,
            ProviderState::Sleeping => SchedulingError::ProviderSleeping,
            ProviderState::Unmounted => SchedulingError::ProviderNotMounted,
            ProviderState::Crashed => SchedulingError::ProviderCrashed,
            ProviderState::Revoked => SchedulingError::ProviderRevoked,
        }
    }
}

impl<P, S> SchedulingService for TriggerSchedulingService<P, S>
where
    P: SchedulingProvider,
    S: TriggerReceiptStore,
{
    fn provider_state(&self) -> ProviderState {
        self.state
    }

    fn provider_epoch(&self) -> u64 {
        self.provider_epoch
    }

    fn mount_provider(
        &mut self,
        scope: MissionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<ProviderMountReceipt, SchedulingError> {
        TriggerSchedulingService::mount_provider(self, scope, observed_at)
    }

    fn unmount_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        TriggerSchedulingService::unmount_provider(self, provider_epoch, observed_at)
    }

    fn revoke_provider(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        TriggerSchedulingService::revoke_provider(self, provider_epoch, observed_at)
    }

    fn provider_crash(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        TriggerSchedulingService::provider_crash(self, provider_epoch, observed_at)
    }

    fn os_sleep(
        &mut self,
        provider_epoch: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        TriggerSchedulingService::os_sleep(self, provider_epoch, observed_at)
    }

    fn os_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError> {
        TriggerSchedulingService::os_wake(self, provider_epoch, woke_at)
    }

    fn cell_wake(
        &mut self,
        provider_epoch: u64,
        woke_at: DateTime<Utc>,
    ) -> Result<Vec<TriggerReceipt>, SchedulingError> {
        TriggerSchedulingService::cell_wake(self, provider_epoch, woke_at)
    }

    fn schedule_objective(
        &mut self,
        input: MissionScheduleInput,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableWakeRequest, SchedulingError> {
        TriggerSchedulingService::schedule_objective(self, input, observed_at)
    }

    fn coalesce_missed_ticks(
        &mut self,
        request: &DurableWakeRequest,
        observed_at: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedWake, SchedulingError> {
        TriggerSchedulingService::coalesce_missed_ticks(
            self,
            request,
            observed_at,
            max_coalesced_ticks,
        )
    }

    fn observe_wake(
        &mut self,
        request: &DurableWakeRequest,
        woke_at: DateTime<Utc>,
    ) -> Result<TriggerReceipt, SchedulingError> {
        TriggerSchedulingService::observe_wake(self, request, woke_at)
    }

    fn cancel_schedule(
        &mut self,
        schedule_id_digest: &str,
        schedule_revision: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<(), SchedulingError> {
        TriggerSchedulingService::cancel_schedule(
            self,
            schedule_id_digest,
            schedule_revision,
            observed_at,
        )
    }

    fn consume_trigger(
        &mut self,
        scope: &MissionScope,
        receipt: &TriggerReceipt,
    ) -> Result<MissionControlConsume, SchedulingError> {
        TriggerSchedulingService::consume_trigger(self, scope, receipt)
    }
}

/// Mission Control's scope-pinned consumer.  It can only consume receipts for
/// its exact Project/Mission revision; the service persists the idempotency
/// decision so a restarted consumer cannot start the same revision twice.
#[derive(Clone, Debug)]
pub struct MissionControlConsumer {
    scope: MissionScope,
}

impl MissionControlConsumer {
    pub fn new(scope: MissionScope) -> Result<Self, SchedulingError> {
        scope.validate()?;
        Ok(Self { scope })
    }

    pub fn scope(&self) -> &MissionScope {
        &self.scope
    }

    pub fn schedule_objective<P, S>(
        &self,
        service: &mut TriggerSchedulingService<P, S>,
        objective: impl Into<String>,
        schedule: ScheduledObjective,
        observed_at: DateTime<Utc>,
    ) -> Result<DurableWakeRequest, SchedulingError>
    where
        P: SchedulingProvider,
        S: TriggerReceiptStore,
    {
        service.schedule_objective(
            MissionScheduleInput {
                objective: objective.into(),
                scope: self.scope.clone(),
                schedule,
            },
            observed_at,
        )
    }

    pub fn consume<P, S>(
        &self,
        service: &mut TriggerSchedulingService<P, S>,
        receipt: &TriggerReceipt,
    ) -> Result<MissionControlConsume, SchedulingError>
    where
        P: SchedulingProvider,
        S: TriggerReceiptStore,
    {
        if receipt.scope != self.scope {
            return Err(SchedulingError::ScopeMismatch);
        }
        service.consume_trigger(&self.scope, receipt)
    }
}

/// A macOS provider adapter using the existing OS wake/sleep contract.  The
/// native backend is injected, so this module remains free of platform calls.
#[derive(Debug)]
pub struct MacOsSchedulingProvider<B> {
    provider_id_digest: String,
    epoch: Option<u64>,
    adapter: MacOsWakeSleepAdapter<B>,
}

impl<B> MacOsSchedulingProvider<B>
where
    B: MacOsWakeSleepBackend,
{
    pub fn new(provider_id_digest: impl Into<String>, backend: B) -> Result<Self, SchedulingError> {
        let provider_id_digest = provider_id_digest.into();
        if !validate_digest(&provider_id_digest) {
            return Err(SchedulingError::InvalidProvider);
        }
        Ok(Self {
            provider_id_digest,
            epoch: None,
            adapter: MacOsWakeSleepAdapter::new(backend),
        })
    }

    pub fn adapter(&self) -> &MacOsWakeSleepAdapter<B> {
        &self.adapter
    }

    fn ensure_epoch(&self, epoch: u64) -> Result<(), SchedulingProviderError> {
        if self.epoch != Some(epoch) {
            return Err(SchedulingProviderError::EpochLost);
        }
        Ok(())
    }

    fn ensure_transition(
        &self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        transition
            .validate()
            .map_err(|_| SchedulingProviderError::EpochLost)?;
        if transition.provider_id_digest != self.provider_id_digest
            || self.epoch != Some(transition.previous_epoch)
        {
            return Err(SchedulingProviderError::EpochLost);
        }
        Ok(())
    }
}

impl<B> SchedulingProvider for MacOsSchedulingProvider<B>
where
    B: MacOsWakeSleepBackend,
{
    fn provider_id_digest(&self) -> &str {
        &self.provider_id_digest
    }

    fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError> {
        request
            .validate()
            .map_err(|_| SchedulingProviderError::EpochLost)?;
        if request.provider_id_digest != self.provider_id_digest || self.epoch.is_some() {
            return Err(SchedulingProviderError::EpochLost);
        }
        self.epoch = Some(request.provider_epoch);
        Ok(())
    }

    fn unmount(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn revoke(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn crash(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.epoch = None;
        Ok(())
    }

    fn on_sleep(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.adapter
            .record_sleep(transition.observed_at)
            .map_err(SchedulingProviderError::Lifecycle)?;
        Ok(())
    }

    fn on_wake(
        &mut self,
        transition: &ProviderLifecycleTransition,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_transition(transition)?;
        self.adapter
            .record_wake(transition.observed_at)
            .map_err(SchedulingProviderError::Lifecycle)?;
        self.epoch = Some(transition.next_epoch);
        Ok(())
    }

    fn arm_wake(
        &mut self,
        request: &DurableWakeRequest,
    ) -> Result<ProviderWakeReceipt, SchedulingProviderError> {
        self.ensure_epoch(request.provider_epoch)?;
        if request.provider_id_digest != self.provider_id_digest {
            return Err(SchedulingProviderError::EpochLost);
        }
        let lifecycle_receipt = self
            .adapter
            .arm_wake(request.wake.clone())
            .map_err(SchedulingProviderError::Lifecycle)?;
        Ok(ProviderWakeReceipt {
            request_id_digest: request.request_id_digest.clone(),
            request_digest: request.request_digest.clone(),
            provider_id_digest: self.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lifecycle_receipt: Some(lifecycle_receipt),
        })
    }

    fn disarm_wake(
        &mut self,
        receipt: &ProviderWakeReceipt,
    ) -> Result<(), SchedulingProviderError> {
        self.ensure_epoch(receipt.provider_epoch)?;
        if receipt.provider_id_digest != self.provider_id_digest {
            return Err(SchedulingProviderError::EpochLost);
        }
        if let Some(lifecycle_receipt) = &receipt.lifecycle_receipt {
            self.adapter
                .disarm_wake(lifecycle_receipt)
                .map_err(SchedulingProviderError::Lifecycle)?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct RequestIdMaterial<'a> {
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    provider_id_digest: &'a str,
    provider_epoch: u64,
}

#[derive(Serialize)]
struct RequestDigestMaterial<'a> {
    request_id_digest: &'a str,
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule: &'a ScheduledObjective,
    provider_id_digest: &'a str,
    provider_epoch: u64,
    wake: &'a WakeRequest,
}

#[derive(Serialize)]
struct TriggerReceiptMaterial<'a> {
    trigger_id_digest: &'a str,
    request_id_digest: &'a str,
    request_digest: &'a str,
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    planned_at: DateTime<Utc>,
    woke_at: DateTime<Utc>,
    coalesced_ticks: u64,
    provider_id_digest: &'a str,
    provider_epoch: u64,
}

#[derive(Serialize)]
struct MissionControlStartMaterial<'a> {
    trigger_receipt_digest: &'a str,
    objective_digest: &'a str,
    scope: &'a MissionScope,
    schedule_id_digest: &'a str,
    schedule_revision: u64,
    authority: CapabilityAuthority,
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, SchedulingError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| SchedulingError::Serialization(error.to_string()))?;
    Ok(scheduler_digest(bytes))
}

fn validate_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_IDENTIFIER_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SchedulingError {
    #[error("scheduled objective Project/Mission scope is invalid")]
    InvalidScope,
    #[error("scheduled objective is empty or exceeds the bounded input size")]
    InvalidObjective,
    #[error("scheduled objective schedule is invalid")]
    InvalidSchedule,
    #[error("scheduling provider identifier or mount contract is invalid")]
    InvalidProvider,
    #[error("scheduling provider epoch is invalid")]
    InvalidProviderEpoch,
    #[error("scheduling provider epoch is exhausted")]
    ProviderEpochExhausted,
    #[error("scheduling provider is already mounted")]
    ProviderAlreadyMounted,
    #[error("scheduling provider is not mounted")]
    ProviderNotMounted,
    #[error("scheduling provider is sleeping")]
    ProviderSleeping,
    #[error("scheduling provider is not sleeping")]
    ProviderNotSleeping,
    #[error("scheduling provider has crashed")]
    ProviderCrashed,
    #[error("scheduling provider has been revoked")]
    ProviderRevoked,
    #[error("provider epoch is stale ({expected} != {actual})")]
    ProviderEpochLost { expected: u64, actual: u64 },
    #[error("provider identity does not match durable scheduler records")]
    ProviderIdentityMismatch,
    #[error("Project/Mission scope does not match the mounted provider")]
    ScopeMismatch,
    #[error("schedule state does not permit a scheduled objective")]
    ScheduleStateConflict,
    #[error("schedule is already bound to a different objective in this revision")]
    ScheduleConflict,
    #[error("schedule revision is stale")]
    StaleSchedule,
    #[error("schedule was not found")]
    ScheduleNotFound,
    #[error("schedule has been cancelled")]
    ScheduleCancelled,
    #[error("schedule contract has expired")]
    ScheduleExpired,
    #[error("wake request is malformed or tampered")]
    InvalidRequest,
    #[error("wake request is stale or not registered")]
    StaleWakeRequest,
    #[error("wake request conflicts with the current immutable record")]
    WakeRequestConflict,
    #[error("wake request is not due")]
    WakeNotDue,
    #[error("trigger receipt is stale or not for the current schedule revision")]
    StaleTriggerReceipt,
    #[error("trigger receipt is malformed or tampered")]
    InvalidTriggerReceipt,
    #[error("Mission Control start request is malformed")]
    InvalidMissionControlRequest,
    #[error("trigger for this exact schedule revision already exists")]
    AlreadyTriggered,
    #[error("missed-tick coalescing limit is zero or exceeds the bounded contract")]
    InvalidCoalescingLimit,
    #[error("scheduled objective has no due ticks")]
    NoDueTicks,
    #[error("provider wake receipt conflicts with the exact request")]
    ProviderReceiptConflict,
    #[error("provider lifecycle state does not allow this operation")]
    InvalidLifecycleState,
    #[error("trigger receipt store failed")]
    Store(#[from] TriggerReceiptStoreError),
    #[error("provider boundary failed")]
    Provider(#[from] SchedulingProviderError),
    #[error("wake contract failed")]
    Lifecycle(#[from] WakeSleepError),
    #[error("scheduler boundary serialization failed: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn test_scope(project: &str, mission: &str, revision: u64) -> MissionScope {
        MissionScope::new(project, mission, revision).expect("scope")
    }

    fn schedule(id: u8, revision: u64, planned_at: DateTime<Utc>) -> ScheduledObjective {
        ScheduledObjective::new(
            digest(id),
            revision,
            planned_at,
            60,
            now() + Duration::hours(4),
        )
        .expect("schedule")
    }

    #[derive(Debug, Default)]
    struct RecordingProvider {
        provider_id_digest: String,
        epoch: Option<u64>,
        arms: BTreeMap<String, ProviderWakeReceipt>,
        arm_calls: usize,
        disarm_calls: usize,
    }

    impl RecordingProvider {
        fn new(provider_id_digest: String) -> Self {
            Self {
                provider_id_digest,
                ..Self::default()
            }
        }

        fn transition_epoch(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            transition
                .validate()
                .map_err(|_| SchedulingProviderError::EpochLost)?;
            if transition.provider_id_digest != self.provider_id_digest
                || self.epoch != Some(transition.previous_epoch)
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            Ok(())
        }
    }

    impl SchedulingProvider for RecordingProvider {
        fn provider_id_digest(&self) -> &str {
            &self.provider_id_digest
        }

        fn mount(&mut self, request: &ProviderMountRequest) -> Result<(), SchedulingProviderError> {
            request
                .validate()
                .map_err(|_| SchedulingProviderError::EpochLost)?;
            self.epoch = Some(request.provider_epoch);
            Ok(())
        }

        fn unmount(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.transition_epoch(transition)?;
            self.epoch = None;
            Ok(())
        }

        fn revoke(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.unmount(transition)
        }

        fn crash(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.unmount(transition)
        }

        fn on_sleep(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.transition_epoch(transition)
        }

        fn on_wake(
            &mut self,
            transition: &ProviderLifecycleTransition,
        ) -> Result<(), SchedulingProviderError> {
            self.transition_epoch(transition)?;
            self.epoch = Some(transition.next_epoch);
            Ok(())
        }

        fn arm_wake(
            &mut self,
            request: &DurableWakeRequest,
        ) -> Result<ProviderWakeReceipt, SchedulingProviderError> {
            if self.epoch != Some(request.provider_epoch)
                || request.provider_id_digest != self.provider_id_digest
            {
                return Err(SchedulingProviderError::EpochLost);
            }
            if let Some(existing) = self.arms.get(&request.request_id_digest) {
                existing
                    .validate_for(request)
                    .map_err(|_| SchedulingProviderError::ReceiptConflict)?;
                return Ok(existing.clone());
            }
            self.arm_calls += 1;
            let receipt = ProviderWakeReceipt {
                request_id_digest: request.request_id_digest.clone(),
                request_digest: request.request_digest.clone(),
                provider_id_digest: self.provider_id_digest.clone(),
                provider_epoch: request.provider_epoch,
                lifecycle_receipt: None,
            };
            self.arms
                .insert(request.request_id_digest.clone(), receipt.clone());
            Ok(receipt)
        }

        fn disarm_wake(
            &mut self,
            receipt: &ProviderWakeReceipt,
        ) -> Result<(), SchedulingProviderError> {
            if self.epoch != Some(receipt.provider_epoch) {
                return Err(SchedulingProviderError::EpochLost);
            }
            self.disarm_calls += 1;
            self.arms.remove(&receipt.request_id_digest);
            Ok(())
        }
    }

    fn mounted_service() -> (
        TriggerSchedulingService<RecordingProvider>,
        MissionScope,
        DateTime<Utc>,
    ) {
        let provider_id = digest(b'p');
        let mut service =
            TriggerSchedulingService::new(RecordingProvider::new(provider_id)).expect("service");
        let scope = test_scope("project-1", "mission-1", 7);
        let mounted = service.mount_provider(scope.clone(), now()).expect("mount");
        assert_eq!(mounted.provider_epoch, 1);
        (service, scope, now())
    }

    #[test]
    fn wake_produces_typed_receipt_and_mission_control_starts_exact_revision_once() {
        let (mut service, scope, time) = mounted_service();
        let consumer = MissionControlConsumer::new(scope.clone()).expect("consumer");
        let request = consumer
            .schedule_objective(
                &mut service,
                "send the weekly brief",
                schedule(b's', 3, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        let receipt = service
            .cell_wake(1, time + Duration::minutes(2))
            .expect("cell wake")
            .pop()
            .expect("receipt");
        assert_eq!(receipt.schedule_revision, 3);
        assert_eq!(receipt.planned_at, request.schedule.planned_at);
        assert_eq!(receipt.woke_at, time + Duration::minutes(2));
        assert_eq!(receipt.coalesced_ticks, 2);
        assert_eq!(receipt.provider_id_digest, digest(b'p'));
        receipt.validate().expect("valid receipt");

        let first = consumer
            .consume(&mut service, &receipt)
            .expect("first start");
        let second = consumer
            .consume(&mut service, &receipt)
            .expect("replay start");
        assert!(matches!(first, MissionControlConsume::Started(_)));
        assert!(matches!(second, MissionControlConsume::AlreadyStarted(_)));
        assert_eq!(service.started_count(), 1);
    }

    #[test]
    fn missed_ticks_are_bounded_to_one_capability_request() {
        let (mut service, scope, time) = mounted_service();
        let consumer = MissionControlConsumer::new(scope).expect("consumer");
        let request = consumer
            .schedule_objective(&mut service, "coalesce", schedule(b'c', 2, time), time)
            .expect("schedule");
        let coalesced = service
            .coalesce_missed_ticks(&request, time + Duration::hours(1), 3)
            .expect("coalesce");
        assert_eq!(coalesced.due_ticks, 61);
        assert_eq!(coalesced.coalesced_ticks, 3);
        assert_eq!(coalesced.dispatch_count, 1);
        let receipts = service
            .cell_wake(1, time + Duration::hours(1))
            .expect("wake");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].coalesced_ticks, 3);
    }

    #[test]
    fn sleep_resume_rebinds_epoch_and_repeated_wake_has_zero_new_receipts() {
        let (mut service, scope, time) = mounted_service();
        let consumer = MissionControlConsumer::new(scope.clone()).expect("consumer");
        let request = consumer
            .schedule_objective(
                &mut service,
                "resume safely",
                schedule(b'r', 4, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service.os_sleep(1, time).expect("sleep");
        let receipts = service
            .os_wake(1, time + Duration::minutes(2))
            .expect("resume");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].schedule_revision, 4);
        assert_eq!(service.provider_epoch(), 2);
        assert_eq!(
            service.observe_wake(&request, time + Duration::minutes(2)),
            Err(SchedulingError::ProviderEpochLost {
                expected: 2,
                actual: 1
            })
        );
        assert!(
            service
                .cell_wake(2, time + Duration::minutes(3))
                .expect("repeated wake")
                .is_empty()
        );
        let receipt = service
            .receipt_for(&scope, &digest(b'r'), 4)
            .expect("durable receipt")
            .clone();
        let replay = consumer.consume(&mut service, &receipt).expect("consume");
        assert!(matches!(replay, MissionControlConsume::Started(_)));
    }

    #[test]
    fn sqlite_restart_preserves_receipt_and_start_idempotency() {
        let connection = Connection::open_in_memory().expect("sqlite");
        let store = SqliteTriggerReceiptStore::new(connection).expect("store");
        let provider_id = digest(b'p');
        let scope = test_scope("project-restart", "mission-restart", 2);
        let consumer = MissionControlConsumer::new(scope.clone()).expect("consumer");
        let (receipt, store) = {
            let mut service = TriggerSchedulingService::with_store(
                RecordingProvider::new(provider_id.clone()),
                store,
            )
            .expect("service");
            service.mount_provider(scope.clone(), now()).expect("mount");
            consumer
                .schedule_objective(
                    &mut service,
                    "restart-safe objective",
                    schedule(b'x', 9, now()),
                    now(),
                )
                .expect("schedule");
            let receipt = service
                .cell_wake(1, now() + Duration::minutes(1))
                .expect("wake")
                .pop()
                .expect("receipt")
                .clone();
            let first = consumer.consume(&mut service, &receipt).expect("start");
            assert!(matches!(first, MissionControlConsume::Started(_)));
            (receipt, service.into_store())
        };
        let mut restarted =
            TriggerSchedulingService::with_store(RecordingProvider::new(provider_id), store)
                .expect("restart service");
        let mount = restarted
            .mount_provider(scope.clone(), now() + Duration::minutes(2))
            .expect("remount");
        assert_eq!(mount.provider_epoch, 2);
        assert!(
            restarted
                .cell_wake(2, now() + Duration::minutes(3))
                .expect("repeated wake")
                .is_empty()
        );
        let replay = consumer
            .consume(&mut restarted, &receipt)
            .expect("idempotent consume");
        assert!(matches!(replay, MissionControlConsume::AlreadyStarted(_)));
        assert_eq!(restarted.started_count(), 1);
    }

    #[test]
    fn cancel_unmount_revoke_and_scope_fences_cannot_trigger() {
        let (mut service, scope, time) = mounted_service();
        let consumer = MissionControlConsumer::new(scope.clone()).expect("consumer");
        let cancelled = consumer
            .schedule_objective(
                &mut service,
                "cancel me",
                schedule(b'a', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service
            .cancel_schedule(&digest(b'a'), 1, time)
            .expect("cancel");
        assert_eq!(
            service.observe_wake(&cancelled, time + Duration::minutes(2)),
            Err(SchedulingError::ScheduleCancelled)
        );

        let cross_scope_request = consumer
            .schedule_objective(&mut service, "scope-bound", schedule(b'c', 1, time), time)
            .expect("scope-bound schedule");
        let cross_scope_receipt = service
            .cell_wake(1, time)
            .expect("scope-bound wake")
            .into_iter()
            .find(|receipt| {
                receipt.schedule_id_digest == cross_scope_request.schedule.schedule_id_digest
            })
            .expect("scope-bound receipt");
        let other_scope = MissionScope::new("project-other", "mission-other", 2).expect("scope");
        let other_consumer = MissionControlConsumer::new(other_scope).expect("consumer");
        assert_eq!(
            other_consumer.consume(&mut service, &cross_scope_receipt),
            Err(SchedulingError::ScopeMismatch)
        );

        let unmounted = consumer
            .schedule_objective(
                &mut service,
                "unmount me",
                schedule(b'u', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        service.unmount_provider(1, time).expect("unmount");
        assert_eq!(
            service.observe_wake(&unmounted, time + Duration::minutes(2)),
            Err(SchedulingError::ProviderNotMounted)
        );

        let (mut revoked_service, revoked_scope, _) = mounted_service();
        let revoked_consumer = MissionControlConsumer::new(revoked_scope).expect("consumer");
        let revoked = revoked_consumer
            .schedule_objective(
                &mut revoked_service,
                "revoke me",
                schedule(b'v', 1, time + Duration::minutes(1)),
                time,
            )
            .expect("schedule");
        revoked_service.revoke_provider(1, time).expect("revoke");
        assert_eq!(
            revoked_service.observe_wake(&revoked, time + Duration::minutes(2)),
            Err(SchedulingError::ProviderRevoked)
        );
    }

    #[test]
    fn exact_revision_and_digest_tampering_are_rejected() {
        let (mut service, scope, time) = mounted_service();
        let consumer = MissionControlConsumer::new(scope.clone()).expect("consumer");
        let old = consumer
            .schedule_objective(&mut service, "revision one", schedule(b'z', 1, time), time)
            .expect("old schedule");
        let current = consumer
            .schedule_objective(&mut service, "revision two", schedule(b'z', 2, time), time)
            .expect("new schedule");
        assert_eq!(
            service.observe_wake(&old, time),
            Err(SchedulingError::StaleWakeRequest)
        );
        let mut tampered = current.clone();
        tampered.schedule.schedule_revision = 99;
        assert_eq!(
            service.observe_wake(&tampered, time),
            Err(SchedulingError::InvalidRequest)
        );
    }
}
