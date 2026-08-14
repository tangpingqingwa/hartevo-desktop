//! Scheduler-owned local host timer integration.
//!
//! This module is an adapter around the recurring Mission scheduler.  It does
//! not define another schedule or dispatch registry: [`LocalTimerMissionRunner`]
//! drives the existing [`MissionScheduleService`] and persists only a
//! host-bound result projection for the durable dispatch receipt it receives.
//!
//! The host timer is deliberately process-local.  A small background worker
//! waits on real wall-clock time and emits a typed wake event; it never calls a
//! Runtime, Browser, Connector, or Effect executor.  Native OS wake remains a
//! separate provider contract (and is therefore not claimed by this module).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::plugin_invocation::{DispatchAuthority, MissionScope};
use crate::recurring_schedule::{
    MissionCapabilityDispatchReceipt, MissionScheduleDraft, MissionScheduleProviderError,
    MissionScheduleService, MissionScheduleStore, MissionScheduleWakeOutcome,
    MissionScheduleWakeProvider, RecurringScheduleError, ScheduleWakeReceipt, ScheduleWakeRequest,
};
use crate::scheduler_digest;

/// A stable identity for the local host/process adapter.
///
/// The host identity is deliberately separate from a Project/Mission plugin
/// composition.  The resulting `identity_digest` is the provider identity
/// bound into the existing schedule wake request; the individual fields are
/// repeated in the durable projection so a Mission can show exactly which
/// local process revision handled a request.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalHostIdentity {
    pub host_id_digest: String,
    pub provider_version: String,
    pub provider_digest: String,
    pub current_commit_digest: String,
    pub identity_digest: String,
}

impl LocalHostIdentity {
    pub fn new(
        host_id_digest: impl Into<String>,
        provider_version: impl Into<String>,
        provider_digest: impl Into<String>,
        current_commit_digest: impl Into<String>,
    ) -> Result<Self, LocalTimerError> {
        let mut identity = Self {
            host_id_digest: host_id_digest.into(),
            provider_version: provider_version.into(),
            provider_digest: provider_digest.into(),
            current_commit_digest: current_commit_digest.into(),
            identity_digest: String::new(),
        };
        identity.identity_digest = identity.expected_digest()?;
        identity.validate()?;
        Ok(identity)
    }

    /// Build the identity used by a real local process.  The commit digest is
    /// supplied by the launcher/build environment and is never guessed.
    pub fn for_local_process(
        current_commit_digest: impl Into<String>,
    ) -> Result<Self, LocalTimerError> {
        let host_name = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".into());
        Self::new(
            scheduler_digest(host_name.as_bytes()),
            env!("CARGO_PKG_VERSION"),
            scheduler_digest(b"hartevo-mission-scheduler/local-timer/v1"),
            current_commit_digest,
        )
    }

    pub fn expected_digest(&self) -> Result<String, LocalTimerError> {
        let material = (
            &self.host_id_digest,
            &self.provider_version,
            &self.provider_digest,
            &self.current_commit_digest,
        );
        serde_json::to_vec(&material)
            .map(scheduler_digest)
            .map_err(|error| LocalTimerError::Serialization(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), LocalTimerError> {
        if !is_digest(&self.host_id_digest)
            || self.provider_version.trim().is_empty()
            || self.provider_version.len() > 128
            || !is_digest(&self.provider_digest)
            || !is_digest(&self.current_commit_digest)
            || !is_digest(&self.identity_digest)
            || self.identity_digest != self.expected_digest()?
        {
            return Err(LocalTimerError::InvalidHostIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTimerRegistrationReceipt {
    pub registration_id_digest: String,
    pub token_digest: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub scope: MissionScope,
    pub objective_digest: String,
    pub planned_at: DateTime<Utc>,
    pub contract_valid_until: DateTime<Utc>,
    pub composition_digest: String,
    pub invocation_digest: String,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub host: LocalHostIdentity,
    pub registered_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl LocalTimerRegistrationReceipt {
    fn from_request(
        request: &ScheduleWakeRequest,
        host: &LocalHostIdentity,
        registered_at: DateTime<Utc>,
    ) -> Result<Self, LocalTimerError> {
        let mut receipt = Self {
            registration_id_digest: digest_json(&(
                &request.token_digest,
                &host.identity_digest,
                request.provider_epoch,
            ))?,
            token_digest: request.token_digest.clone(),
            schedule_id_digest: request.schedule_id_digest.clone(),
            schedule_revision: request.schedule_revision,
            scope: request.scope.clone(),
            objective_digest: request.objective_digest.clone(),
            planned_at: request.planned_at,
            contract_valid_until: request.contract_valid_until,
            composition_digest: request.composition_digest.clone(),
            invocation_digest: request.invocation_digest.clone(),
            provider_id_digest: request.provider_id_digest.clone(),
            provider_epoch: request.provider_epoch,
            lease_revision: request.lease_revision,
            clock_epoch: request.clock_epoch,
            host: host.clone(),
            registered_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.expected_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn expected_digest(&self) -> Result<String, LocalTimerError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), LocalTimerError> {
        if !is_digest(&self.registration_id_digest)
            || !is_digest(&self.token_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.composition_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.provider_id_digest)
            || !is_digest(&self.receipt_digest)
            || self.schedule_revision == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.planned_at >= self.contract_valid_until
            || self.receipt_digest != self.expected_digest()?
        {
            return Err(LocalTimerError::InvalidRegistration);
        }
        self.scope
            .validate()
            .map_err(|_| LocalTimerError::InvalidRegistration)?;
        self.host.validate()?;
        if self.provider_id_digest != self.host.identity_digest
            || self.registration_id_digest
                != digest_json(&(
                    &self.token_digest,
                    &self.host.identity_digest,
                    self.provider_epoch,
                ))?
        {
            return Err(LocalTimerError::InvalidRegistration);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTimerWake {
    pub request: ScheduleWakeRequest,
    pub receipt: ScheduleWakeReceipt,
    pub registration: LocalTimerRegistrationReceipt,
    pub woke_at: DateTime<Utc>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LocalTimerError {
    #[error("local timer host identity is invalid")]
    InvalidHostIdentity,
    #[error("local timer registration is invalid")]
    InvalidRegistration,
    #[error("local timer provider is unavailable")]
    ProviderUnavailable,
    #[error("local timer provider epoch is stale")]
    ProviderEpochLost,
    #[error("local timer provider receipt conflicts")]
    ReceiptConflict,
    #[error("local timer wake is stale or does not match the schedule")]
    StaleWake,
    #[error("local timer timed out waiting for a host wake")]
    Timeout,
    #[error("local timer schedule failed: {0}")]
    Schedule(#[from] RecurringScheduleError),
    #[error("local timer schedule store failed: {0}")]
    ScheduleStore(#[from] crate::recurring_schedule::MissionScheduleStoreError),
    #[error("local timer projection store failed: {0}")]
    ProjectionStore(#[from] LocalTimerProjectionStoreError),
    #[error("local timer serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug)]
struct LocalTimerRegistration {
    request: ScheduleWakeRequest,
    receipt: ScheduleWakeReceipt,
    registration: LocalTimerRegistrationReceipt,
}

#[derive(Debug)]
struct LocalTimerState {
    mounted: bool,
    stopped: bool,
    epoch: u64,
    active: BTreeMap<String, LocalTimerRegistration>,
    known_receipts: BTreeMap<String, ScheduleWakeReceipt>,
    known_registrations: BTreeMap<String, LocalTimerRegistrationReceipt>,
    queue: VecDeque<LocalTimerWake>,
}

#[derive(Debug)]
struct LocalTimerShared {
    state: Mutex<LocalTimerState>,
    changed: Condvar,
}

/// A real process-local timer provider implementing the existing scheduler
/// wake contract.  Its worker has no plugin or Effect authority; it only
/// moves a scheduled request into a typed wake queue.
#[derive(Debug)]
pub struct LocalTimerProvider {
    identity: LocalHostIdentity,
    shared: Arc<LocalTimerShared>,
    worker: Option<JoinHandle<()>>,
}

impl LocalTimerProvider {
    pub fn new(identity: LocalHostIdentity) -> Result<Self, LocalTimerError> {
        Self::with_epoch(identity, 1)
    }

    pub fn with_epoch(identity: LocalHostIdentity, epoch: u64) -> Result<Self, LocalTimerError> {
        identity.validate()?;
        if epoch == 0 {
            return Err(LocalTimerError::ProviderEpochLost);
        }
        let shared = Arc::new(LocalTimerShared {
            state: Mutex::new(LocalTimerState {
                mounted: true,
                stopped: false,
                epoch,
                active: BTreeMap::new(),
                known_receipts: BTreeMap::new(),
                known_registrations: BTreeMap::new(),
                queue: VecDeque::new(),
            }),
            changed: Condvar::new(),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("hartevo-scheduler-local-timer".into())
            .spawn(move || timer_worker(&worker_shared))
            .map_err(|_| LocalTimerError::ProviderUnavailable)?;
        Ok(Self {
            identity,
            shared,
            worker: Some(worker),
        })
    }

    pub fn identity(&self) -> &LocalHostIdentity {
        &self.identity
    }

    pub fn active_registration_count(&self) -> usize {
        self.lock_state().active.len()
    }

    pub fn queued_wake_count(&self) -> usize {
        self.lock_state().queue.len()
    }

    pub fn registration(&self, token_digest: &str) -> Option<LocalTimerRegistrationReceipt> {
        self.lock_state()
            .known_registrations
            .get(token_digest)
            .cloned()
    }

    /// Drain one wake produced by the real host timer worker.
    pub fn poll(&self) -> Option<LocalTimerWake> {
        let mut state = self.lock_state();
        loop {
            let wake = state.queue.pop_front()?;
            if state.mounted && wake.receipt.provider_epoch == state.epoch {
                return Some(wake);
            }
        }
    }

    /// Wait on real process time for one host wake.  Tests use this journey
    /// instead of injecting a fake tick, while callers can still use `poll`
    /// from an event loop.
    pub fn wait_for_wake(
        &mut self,
        timeout: StdDuration,
    ) -> Result<LocalTimerWake, LocalTimerError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(LocalTimerError::Timeout)?;
        loop {
            if let Some(wake) = self.poll() {
                return Ok(wake);
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(LocalTimerError::Timeout)?;
            thread::sleep(remaining.min(StdDuration::from_millis(5)));
        }
    }

    /// Fence all old registrations after a provider/process restart.  The
    /// scheduler subsequently calls `rebind_provider_epoch` to arm the exact
    /// current schedule again.
    pub fn restart(&mut self) -> Result<u64, LocalTimerError> {
        self.bump_epoch(true)
    }

    /// Remove the provider mount and every active/queued host registration.
    /// Older receipts remain known so scheduler cancellation/disarm is
    /// idempotent after unmount.
    pub fn unmount(&mut self) -> Result<u64, LocalTimerError> {
        let mut state = self.lock_state();
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(LocalTimerError::ProviderEpochLost)?;
        state.mounted = false;
        state.active.clear();
        state.queue.clear();
        self.shared.changed.notify_all();
        Ok(state.epoch)
    }

    pub fn mount(&mut self) -> Result<u64, LocalTimerError> {
        let mut state = self.lock_state();
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(LocalTimerError::ProviderEpochLost)?;
        state.mounted = true;
        self.shared.changed.notify_all();
        Ok(state.epoch)
    }

    /// Simulate a crashed host process.  It is intentionally different from
    /// a successful restart: the provider is unavailable until `mount`.
    pub fn simulate_crash(&mut self) -> Result<u64, LocalTimerError> {
        let mut state = self.lock_state();
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(LocalTimerError::ProviderEpochLost)?;
        state.mounted = false;
        state.active.clear();
        state.queue.clear();
        self.shared.changed.notify_all();
        Ok(state.epoch)
    }

    fn bump_epoch(&mut self, mounted: bool) -> Result<u64, LocalTimerError> {
        let mut state = self.lock_state();
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(LocalTimerError::ProviderEpochLost)?;
        state.mounted = mounted;
        state.active.clear();
        state.queue.clear();
        self.shared.changed.notify_all();
        Ok(state.epoch)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, LocalTimerState> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for LocalTimerProvider {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.state.lock() {
            state.stopped = true;
            self.shared.changed.notify_all();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl MissionScheduleWakeProvider for LocalTimerProvider {
    fn provider_id_digest(&self) -> &str {
        &self.identity.identity_digest
    }

    fn provider_epoch(&self) -> u64 {
        self.lock_state().epoch
    }

    fn arm_wake(
        &mut self,
        request: &ScheduleWakeRequest,
    ) -> Result<ScheduleWakeReceipt, MissionScheduleProviderError> {
        validate_wake_request(request, &self.identity).map_err(|error| provider_error(&error))?;
        let mut state = self.lock_state();
        if !state.mounted {
            return Err(MissionScheduleProviderError::Unavailable);
        }
        if request.provider_epoch != state.epoch {
            return Err(MissionScheduleProviderError::EpochLost);
        }
        if let Some(existing) = state.active.get(&request.token_digest) {
            if existing.request == *request {
                return Ok(existing.receipt.clone());
            }
            return Err(MissionScheduleProviderError::ReceiptConflict);
        }
        let receipt = ScheduleWakeReceipt {
            token_digest: request.token_digest.clone(),
            provider_id_digest: self.identity.identity_digest.clone(),
            provider_epoch: state.epoch,
            woke_at: request.planned_at,
        };
        let registration =
            LocalTimerRegistrationReceipt::from_request(request, &self.identity, Utc::now())
                .map_err(|error| provider_error(&error))?;
        state
            .known_receipts
            .insert(request.token_digest.clone(), receipt.clone());
        state
            .known_registrations
            .insert(request.token_digest.clone(), registration.clone());
        state.active.insert(
            request.token_digest.clone(),
            LocalTimerRegistration {
                request: request.clone(),
                receipt: receipt.clone(),
                registration,
            },
        );
        self.shared.changed.notify_all();
        Ok(receipt)
    }

    fn disarm_wake(
        &mut self,
        receipt: &ScheduleWakeReceipt,
    ) -> Result<(), MissionScheduleProviderError> {
        if !is_digest(&receipt.token_digest)
            || receipt.provider_id_digest != self.identity.identity_digest
        {
            return Err(MissionScheduleProviderError::ReceiptConflict);
        }
        let mut state = self.lock_state();
        if receipt.provider_epoch > state.epoch {
            return Err(MissionScheduleProviderError::EpochLost);
        }
        if let Some(existing) = state.known_receipts.get(&receipt.token_digest)
            && existing != receipt
        {
            return Err(MissionScheduleProviderError::ReceiptConflict);
        }
        state.active.remove(&receipt.token_digest);
        state.queue.retain(|wake| wake.receipt != *receipt);
        self.shared.changed.notify_all();
        Ok(())
    }
}

fn timer_worker(shared: &LocalTimerShared) {
    loop {
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.stopped {
            return;
        }
        if !state.mounted || state.active.is_empty() {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            drop(state);
            continue;
        }
        let Some((token_digest, registration)) = state
            .active
            .iter()
            .min_by_key(|(_, registration)| registration.request.planned_at)
            .map(|(token, registration)| (token.clone(), registration.request.planned_at))
        else {
            drop(state);
            continue;
        };
        let delay = time_until(registration);
        if delay.is_zero() {
            let Some(registration) = state.active.remove(&token_digest) else {
                drop(state);
                continue;
            };
            state.queue.push_back(LocalTimerWake {
                request: registration.request,
                receipt: registration.receipt,
                registration: registration.registration,
                woke_at: Utc::now(),
            });
            continue;
        }
        let (next_state, _) = shared
            .changed
            .wait_timeout(state, delay)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(next_state);
    }
}

fn time_until(planned_at: DateTime<Utc>) -> StdDuration {
    let remaining = planned_at - Utc::now();
    if remaining <= Duration::zero() {
        StdDuration::ZERO
    } else {
        remaining
            .to_std()
            .unwrap_or_else(|_| StdDuration::from_hours(1))
            .min(StdDuration::from_hours(1))
    }
}

fn validate_wake_request(
    request: &ScheduleWakeRequest,
    identity: &LocalHostIdentity,
) -> Result<(), LocalTimerError> {
    if !is_digest(&request.token_digest)
        || !is_digest(&request.schedule_id_digest)
        || !is_digest(&request.objective_digest)
        || !is_digest(&request.timezone_digest)
        || !is_digest(&request.recurrence_digest)
        || !is_digest(&request.composition_digest)
        || !is_digest(&request.invocation_digest)
        || request.schedule_revision == 0
        || request.provider_epoch == 0
        || request.lease_revision == 0
        || request.clock_epoch == 0
        || request.planned_at >= request.contract_valid_until
        || request.provider_id_digest != identity.identity_digest
    {
        return Err(LocalTimerError::InvalidRegistration);
    }
    request
        .scope
        .validate()
        .map_err(|_| LocalTimerError::InvalidRegistration)?;
    Ok(())
}

fn provider_error(error: &LocalTimerError) -> MissionScheduleProviderError {
    match error {
        LocalTimerError::ProviderUnavailable => MissionScheduleProviderError::Unavailable,
        LocalTimerError::ProviderEpochLost => MissionScheduleProviderError::EpochLost,
        LocalTimerError::ReceiptConflict | LocalTimerError::StaleWake => {
            MissionScheduleProviderError::ReceiptConflict
        }
        _ => MissionScheduleProviderError::Backend,
    }
}

/// The only result state projected by the local adapter.  It records that the
/// capability request was accepted by the Mission consumer; it is not a
/// Runtime/Browser/Effect completion claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalTimerResultKind {
    CapabilityRequestAccepted,
}

/// Model-visible durable projection for one existing scheduler dispatch
/// receipt and one exact host/process identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalTimerResultProjection {
    pub projection_id_digest: String,
    pub dispatch_id_digest: String,
    pub receipt_digest: String,
    pub schedule_id_digest: String,
    pub schedule_revision: u64,
    pub scope: MissionScope,
    pub objective_digest: String,
    pub composition_digest: String,
    pub invocation_digest: String,
    pub planned_at: DateTime<Utc>,
    pub woke_at: DateTime<Utc>,
    pub coalesced_ticks: u32,
    pub next_run_at: Option<DateTime<Utc>>,
    pub provider_id_digest: String,
    pub provider_epoch: u64,
    pub lease_revision: u64,
    pub clock_epoch: u64,
    pub consumer_id_digest: String,
    pub authority: DispatchAuthority,
    pub host: LocalHostIdentity,
    pub result: LocalTimerResultKind,
    pub projection_digest: String,
}

impl LocalTimerResultProjection {
    fn from_receipt(
        receipt: &MissionCapabilityDispatchReceipt,
        host: &LocalHostIdentity,
    ) -> Result<Self, LocalTimerError> {
        receipt
            .validate()
            .map_err(|_| LocalTimerError::InvalidRegistration)?;
        host.validate()?;
        let mut projection = Self {
            projection_id_digest: digest_json(&(
                &receipt.dispatch_id_digest,
                &host.identity_digest,
            ))?,
            dispatch_id_digest: receipt.dispatch_id_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            schedule_id_digest: receipt.schedule_id_digest.clone(),
            schedule_revision: receipt.schedule_revision,
            scope: receipt.scope.clone(),
            objective_digest: receipt.objective_digest.clone(),
            composition_digest: receipt.composition.composition_digest.clone(),
            invocation_digest: receipt
                .invocation
                .digest()
                .map_err(|_| LocalTimerError::InvalidRegistration)?,
            planned_at: receipt.planned_at,
            woke_at: receipt.woke_at,
            coalesced_ticks: receipt.coalesced_ticks,
            next_run_at: receipt.next_run_at,
            provider_id_digest: receipt.provider_id_digest.clone(),
            provider_epoch: receipt.provider_epoch,
            lease_revision: receipt.lease_revision,
            clock_epoch: receipt.clock_epoch,
            consumer_id_digest: receipt.consumer_id_digest.clone(),
            authority: receipt.authority,
            host: host.clone(),
            result: LocalTimerResultKind::CapabilityRequestAccepted,
            projection_digest: String::new(),
        };
        projection.projection_digest = projection.expected_digest()?;
        projection.validate()?;
        Ok(projection)
    }

    pub fn expected_digest(&self) -> Result<String, LocalTimerError> {
        let mut material = self.clone();
        material.projection_digest.clear();
        digest_json(&material)
    }

    pub fn validate(&self) -> Result<(), LocalTimerError> {
        if !is_digest(&self.projection_id_digest)
            || !is_digest(&self.dispatch_id_digest)
            || !is_digest(&self.receipt_digest)
            || !is_digest(&self.schedule_id_digest)
            || !is_digest(&self.objective_digest)
            || !is_digest(&self.composition_digest)
            || !is_digest(&self.invocation_digest)
            || !is_digest(&self.provider_id_digest)
            || !is_digest(&self.consumer_id_digest)
            || !is_digest(&self.projection_digest)
            || self.schedule_revision == 0
            || self.coalesced_ticks == 0
            || self.provider_epoch == 0
            || self.lease_revision == 0
            || self.clock_epoch == 0
            || self.authority != DispatchAuthority::CapabilityRequestOnly
            || self.projection_id_digest
                != digest_json(&(&self.dispatch_id_digest, &self.host.identity_digest))?
            || self.projection_digest != self.expected_digest()?
        {
            return Err(LocalTimerError::InvalidRegistration);
        }
        self.scope
            .validate()
            .map_err(|_| LocalTimerError::InvalidRegistration)?;
        self.host.validate()?;
        if self.provider_id_digest != self.host.identity_digest {
            return Err(LocalTimerError::InvalidRegistration);
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LocalTimerProjectionStoreError {
    #[error("local timer projection serialization failed: {0}")]
    Serialization(String),
    #[error("local timer projection store is corrupt")]
    Corrupt,
    #[error("local timer projection conflicts with an existing projection")]
    Conflict,
    #[error("local timer projection SQLite store failed: {0}")]
    Sqlite(String),
}

pub trait LocalTimerProjectionStore: fmt::Debug {
    fn load(&self) -> Result<Vec<LocalTimerResultProjection>, LocalTimerProjectionStoreError>;
    fn save(
        &mut self,
        projection: &LocalTimerResultProjection,
    ) -> Result<(), LocalTimerProjectionStoreError>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryLocalTimerProjectionStore {
    projections: BTreeMap<String, LocalTimerResultProjection>,
}

impl MemoryLocalTimerProjectionStore {
    pub fn projections(&self) -> impl Iterator<Item = &LocalTimerResultProjection> {
        self.projections.values()
    }
}

impl LocalTimerProjectionStore for MemoryLocalTimerProjectionStore {
    fn load(&self) -> Result<Vec<LocalTimerResultProjection>, LocalTimerProjectionStoreError> {
        Ok(self.projections.values().cloned().collect())
    }

    fn save(
        &mut self,
        projection: &LocalTimerResultProjection,
    ) -> Result<(), LocalTimerProjectionStoreError> {
        projection
            .validate()
            .map_err(|_| LocalTimerProjectionStoreError::Corrupt)?;
        if let Some(existing) = self.projections.get(&projection.projection_id_digest)
            && existing != projection
        {
            return Err(LocalTimerProjectionStoreError::Conflict);
        }
        self.projections
            .insert(projection.projection_id_digest.clone(), projection.clone());
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqliteLocalTimerProjectionStore {
    connection: Connection,
}

impl SqliteLocalTimerProjectionStore {
    pub fn open_in_memory() -> Result<Self, LocalTimerProjectionStoreError> {
        Self::new(Connection::open_in_memory().map_err(|error| sqlite_error(&error))?)
    }

    pub fn new(connection: Connection) -> Result<Self, LocalTimerProjectionStoreError> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS scheduler_local_timer_projections (
                    projection_id_digest TEXT PRIMARY KEY,
                    projection_json TEXT NOT NULL
                )",
            )
            .map_err(|error| sqlite_error(&error))?;
        Ok(Self { connection })
    }

    pub fn into_connection(self) -> Connection {
        self.connection
    }
}

impl LocalTimerProjectionStore for SqliteLocalTimerProjectionStore {
    fn load(&self) -> Result<Vec<LocalTimerResultProjection>, LocalTimerProjectionStoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT projection_json
                 FROM scheduler_local_timer_projections
                 ORDER BY projection_id_digest",
            )
            .map_err(|error| sqlite_error(&error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| sqlite_error(&error))?;
        rows.map(|row| {
            let json = row.map_err(|error| sqlite_error(&error))?;
            let projection: LocalTimerResultProjection =
                serde_json::from_str(&json).map_err(|_| LocalTimerProjectionStoreError::Corrupt)?;
            projection
                .validate()
                .map_err(|_| LocalTimerProjectionStoreError::Corrupt)?;
            Ok(projection)
        })
        .collect()
    }

    fn save(
        &mut self,
        projection: &LocalTimerResultProjection,
    ) -> Result<(), LocalTimerProjectionStoreError> {
        projection
            .validate()
            .map_err(|_| LocalTimerProjectionStoreError::Corrupt)?;
        let json = serde_json::to_string(projection)
            .map_err(|error| LocalTimerProjectionStoreError::Serialization(error.to_string()))?;
        let existing = self
            .connection
            .query_row(
                "SELECT projection_json
                 FROM scheduler_local_timer_projections
                 WHERE projection_id_digest = ?1",
                params![projection.projection_id_digest],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| sqlite_error(&error))?;
        if let Some(existing) = existing {
            if existing == json {
                return Ok(());
            }
            return Err(LocalTimerProjectionStoreError::Conflict);
        }
        self.connection
            .execute(
                "INSERT INTO scheduler_local_timer_projections
                 (projection_id_digest, projection_json) VALUES (?1, ?2)",
                params![projection.projection_id_digest, json],
            )
            .map_err(|error| sqlite_error(&error))?;
        Ok(())
    }
}

fn sqlite_error(error: &rusqlite::Error) -> LocalTimerProjectionStoreError {
    LocalTimerProjectionStoreError::Sqlite(error.to_string())
}

/// One host-timer run result.  The scheduler outcome remains available for
/// callers, while the projection is the only local result persisted here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalTimerRun {
    pub outcome: MissionScheduleWakeOutcome,
    pub projection: Option<LocalTimerResultProjection>,
}

/// Adapter that composes the existing Mission schedule service with a real
/// local process timer and a durable result projection store.
#[derive(Debug)]
pub struct LocalTimerMissionRunner<
    C,
    S = crate::recurring_schedule::MemoryMissionScheduleStore,
    R = MemoryLocalTimerProjectionStore,
> where
    C: crate::recurring_schedule::MissionCapabilityConsumer,
    S: MissionScheduleStore,
    R: LocalTimerProjectionStore,
{
    service: MissionScheduleService<LocalTimerProvider, C, S>,
    projection_store: R,
    projections: BTreeMap<String, LocalTimerResultProjection>,
    pending_wake: Option<LocalTimerWake>,
}

impl<C> LocalTimerMissionRunner<C>
where
    C: crate::recurring_schedule::MissionCapabilityConsumer,
{
    pub fn new(identity: LocalHostIdentity, consumer: C) -> Result<Self, LocalTimerError> {
        Self::with_stores(
            identity,
            consumer,
            crate::recurring_schedule::MemoryMissionScheduleStore::default(),
            MemoryLocalTimerProjectionStore::default(),
        )
    }
}

impl<C, S, R> LocalTimerMissionRunner<C, S, R>
where
    C: crate::recurring_schedule::MissionCapabilityConsumer,
    S: MissionScheduleStore,
    R: LocalTimerProjectionStore,
{
    pub fn with_stores(
        identity: LocalHostIdentity,
        consumer: C,
        schedule_store: S,
        projection_store: R,
    ) -> Result<Self, LocalTimerError> {
        let projections = projection_store
            .load()?
            .into_iter()
            .map(|projection| {
                projection.validate()?;
                Ok((projection.projection_id_digest.clone(), projection))
            })
            .collect::<Result<BTreeMap<_, _>, LocalTimerError>>()?;
        let service = MissionScheduleService::with_store(
            LocalTimerProvider::new(identity)?,
            consumer,
            schedule_store,
        )?;
        Ok(Self {
            service,
            projection_store,
            projections,
            pending_wake: None,
        })
    }

    /// Recover a process using the durable schedule/provider epoch and then
    /// rebind all active wakes to a fresh local provider epoch.
    pub fn recover_with_stores(
        identity: LocalHostIdentity,
        consumer: C,
        schedule_store: S,
        projection_store: R,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, LocalTimerError> {
        let previous_snapshot = schedule_store.load()?;
        let previous_epoch = previous_snapshot.provider_epoch.max(1);
        let projections = projection_store
            .load()?
            .into_iter()
            .map(|projection| {
                projection.validate()?;
                Ok((projection.projection_id_digest.clone(), projection))
            })
            .collect::<Result<BTreeMap<_, _>, LocalTimerError>>()?;
        let provider = LocalTimerProvider::with_epoch(identity, previous_epoch)?;
        let mut service = MissionScheduleService::with_store(provider, consumer, schedule_store)?;
        let next_epoch = service.provider_mut().restart()?;
        if service.snapshot().schedules.iter().any(|schedule| {
            schedule.status == crate::recurring_schedule::MissionScheduleStatus::Active
        }) {
            service.rebind_provider_epoch(next_epoch, observed_at)?;
        }
        Ok(Self {
            service,
            projection_store,
            projections,
            pending_wake: None,
        })
    }

    pub fn service(&self) -> &MissionScheduleService<LocalTimerProvider, C, S> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut MissionScheduleService<LocalTimerProvider, C, S> {
        &mut self.service
    }

    pub fn projection_store(&self) -> &R {
        &self.projection_store
    }

    pub fn into_recovery_stores(self) -> (S, R) {
        let Self {
            service,
            projection_store,
            ..
        } = self;
        (service.into_store(), projection_store)
    }

    pub fn projections(&self) -> impl Iterator<Item = &LocalTimerResultProjection> {
        self.projections.values()
    }

    pub fn result_projection_for_dispatch(
        &self,
        dispatch_id_digest: &str,
    ) -> Option<&LocalTimerResultProjection> {
        self.projections
            .values()
            .find(|projection| projection.dispatch_id_digest == dispatch_id_digest)
    }

    pub fn create(
        &mut self,
        draft: &MissionScheduleDraft,
        observed_at: DateTime<Utc>,
    ) -> Result<crate::recurring_schedule::MissionScheduleModelReceipt, LocalTimerError> {
        Ok(self.service.create(draft, observed_at)?)
    }

    pub fn wait_and_dispatch(
        &mut self,
        timeout: StdDuration,
    ) -> Result<LocalTimerRun, LocalTimerError> {
        let wake = if let Some(pending) = self.pending_wake.take() {
            pending
        } else {
            self.service.provider_mut().wait_for_wake(timeout)?
        };
        match self.dispatch_wake(&wake) {
            Ok(run) => Ok(run),
            Err(error) => {
                self.pending_wake = Some(wake);
                Err(error)
            }
        }
    }

    pub fn restart_and_rebind(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, LocalTimerError> {
        let epoch = self.service.provider_mut().restart()?;
        self.service.rebind_provider_epoch(epoch, observed_at)?;
        Ok(epoch)
    }

    pub fn unmount_host(&mut self) -> Result<u64, LocalTimerError> {
        self.service.provider_mut().unmount()
    }

    pub fn mount_and_rebind(&mut self, observed_at: DateTime<Utc>) -> Result<u64, LocalTimerError> {
        let epoch = self.service.provider_mut().mount()?;
        self.service.rebind_provider_epoch(epoch, observed_at)?;
        Ok(epoch)
    }

    pub fn crash_and_recover(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<u64, LocalTimerError> {
        let _ = self.service.provider_mut().simulate_crash()?;
        let epoch = self.service.provider_mut().mount()?;
        self.service.rebind_provider_epoch(epoch, observed_at)?;
        Ok(epoch)
    }

    fn dispatch_wake(&mut self, wake: &LocalTimerWake) -> Result<LocalTimerRun, LocalTimerError> {
        if let Some(receipt) =
            self.service
                .snapshot()
                .dispatch_receipts
                .into_iter()
                .find(|receipt| {
                    receipt.wake_token_digest == wake.request.token_digest
                        && receipt.schedule_id_digest == wake.request.schedule_id_digest
                        && receipt.schedule_revision == wake.request.schedule_revision
                        && receipt.planned_at == wake.request.planned_at
                })
        {
            let outcome = MissionScheduleWakeOutcome::AlreadyDispatched(receipt.clone());
            return self.project_dispatch(&receipt, outcome);
        }
        let token = self
            .service
            .wake_token_for(&wake.request.schedule_id_digest)?
            .ok_or(LocalTimerError::StaleWake)?;
        if token.token_digest != wake.request.token_digest
            || wake.registration.token_digest != wake.request.token_digest
            || wake.registration.host.identity_digest
                != self.service.provider().identity().identity_digest
        {
            return Err(LocalTimerError::StaleWake);
        }
        let outcome = self.service.wake_once(&token, wake.woke_at)?;
        match outcome {
            MissionScheduleWakeOutcome::Dispatched(receipt) => {
                let outcome = MissionScheduleWakeOutcome::Dispatched(receipt.clone());
                self.project_dispatch(&receipt, outcome)
            }
            MissionScheduleWakeOutcome::AlreadyDispatched(receipt) => self.project_dispatch(
                &receipt,
                MissionScheduleWakeOutcome::AlreadyDispatched(receipt.clone()),
            ),
            MissionScheduleWakeOutcome::LateRejected(receipt) => Ok(LocalTimerRun {
                outcome: MissionScheduleWakeOutcome::LateRejected(receipt),
                projection: None,
            }),
        }
    }

    fn project_dispatch(
        &mut self,
        receipt: &crate::recurring_schedule::MissionCapabilityDispatchReceipt,
        outcome: MissionScheduleWakeOutcome,
    ) -> Result<LocalTimerRun, LocalTimerError> {
        let projection =
            LocalTimerResultProjection::from_receipt(receipt, self.service.provider().identity())?;
        self.projection_store.save(&projection)?;
        self.projections
            .insert(projection.projection_id_digest.clone(), projection.clone());
        Ok(LocalTimerRun {
            outcome,
            projection: Some(projection),
        })
    }
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, LocalTimerError> {
    serde_json::to_vec(value)
        .map(scheduler_digest)
        .map_err(|error| LocalTimerError::Serialization(error.to_string()))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_cloud_storage::DataCell;

    use super::*;
    use crate::plugin_invocation::{PluginComposition, PluginInvocation, PluginManifest};
    use crate::recurring_schedule::{
        LateWakePolicy, MissionCapabilityAck, MissionCapabilityConsumer,
        MissionCapabilityConsumerError, RecurrenceRule, ScheduleLease, ScheduleTimezone,
        SqliteMissionScheduleStore,
    };

    #[derive(Clone, Debug, Default)]
    struct RecordingConsumer {
        consumer_id_digest: String,
        requests: Vec<crate::recurring_schedule::MissionCapabilityRequest>,
    }

    impl RecordingConsumer {
        fn new() -> Self {
            Self {
                consumer_id_digest: digest(b'c'),
                requests: Vec::new(),
            }
        }
    }

    impl MissionCapabilityConsumer for RecordingConsumer {
        fn consumer_id_digest(&self) -> &str {
            &self.consumer_id_digest
        }

        fn request_capability(
            &mut self,
            request: &crate::recurring_schedule::MissionCapabilityRequest,
        ) -> Result<MissionCapabilityAck, MissionCapabilityConsumerError> {
            self.requests.push(request.clone());
            let mut ack = MissionCapabilityAck {
                dispatch_id_digest: request.dispatch_id_digest.clone(),
                consumer_id_digest: self.consumer_id_digest.clone(),
                requested_at: request.woke_at,
                authority: DispatchAuthority::CapabilityRequestOnly,
                ack_digest: String::new(),
            };
            ack.ack_digest = ack
                .expected_digest()
                .map_err(|_| MissionCapabilityConsumerError::Backend)?;
            Ok(ack)
        }
    }

    #[derive(Debug, Default)]
    struct FailOnceProjectionStore {
        inner: MemoryLocalTimerProjectionStore,
        fail_next: bool,
    }

    impl LocalTimerProjectionStore for FailOnceProjectionStore {
        fn load(&self) -> Result<Vec<LocalTimerResultProjection>, LocalTimerProjectionStoreError> {
            self.inner.load()
        }

        fn save(
            &mut self,
            projection: &LocalTimerResultProjection,
        ) -> Result<(), LocalTimerProjectionStoreError> {
            if self.fail_next {
                self.fail_next = false;
                return Err(LocalTimerProjectionStoreError::Serialization(
                    "injected projection failure".into(),
                ));
            }
            self.inner.save(projection)
        }
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn identity(commit: u8) -> LocalHostIdentity {
        LocalHostIdentity::new(digest(b'h'), "0.1.0", digest(b'p'), digest(commit))
            .expect("host identity")
    }

    fn scope() -> MissionScope {
        MissionScope::new(
            DataCell::Us,
            "tenant-local-timer",
            "project-local-timer",
            "mission-local-timer",
            7,
        )
        .expect("scope")
    }

    fn draft(
        schedule_byte: u8,
        start: DateTime<Utc>,
        plugin_version: &str,
    ) -> MissionScheduleDraft {
        let scope = scope();
        let composition = PluginComposition::new(
            scope.clone(),
            3,
            vec![
                PluginManifest::new("summary-plugin", plugin_version, digest(b'v'))
                    .expect("plugin"),
            ],
        )
        .expect("composition");
        MissionScheduleDraft {
            schedule_id_digest: digest(schedule_byte),
            objective_digest: digest(b'o'),
            scope: scope.clone(),
            recurrence: RecurrenceRule::daily(start.naive_utc(), 1).expect("recurrence"),
            timezone: ScheduleTimezone::utc(),
            dst_policy: crate::recurring_schedule::DstPolicy::default(),
            late_wake_policy: LateWakePolicy::Coalesce {
                max_missed_ticks: 4,
            },
            wake_contract_seconds: 300,
            composition,
            invocation: PluginInvocation::new("summary-plugin", "summarize").expect("invocation"),
            lease: ScheduleLease::new(digest(b'l'), 1, 1, start + Duration::days(30))
                .expect("lease"),
        }
    }

    #[test]
    fn host_identity_is_separate_from_mission_composition() {
        let first_host = identity(b'a');
        let second_host = identity(b'b');
        let now = Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0).unwrap();
        let first = draft(b's', now + Duration::seconds(2), "1.0.0");
        let same_composition = draft(b't', now + Duration::seconds(2), "1.0.0");
        let second = draft(b't', now + Duration::seconds(2), "2.0.0");
        assert_eq!(
            first.composition.composition_digest,
            same_composition.composition.composition_digest
        );
        assert_ne!(first_host.identity_digest, second_host.identity_digest);
        assert_ne!(
            first.composition.plugins[0].version,
            second.composition.plugins[0].version
        );
        assert_ne!(
            first.composition.composition_digest,
            second.composition.composition_digest
        );
    }

    #[test]
    fn registration_binds_scope_plugin_digests_and_current_commit() {
        let host = identity(b'a');
        let request = ScheduleWakeRequest {
            token_digest: digest(b't'),
            schedule_id_digest: digest(b's'),
            objective_digest: digest(b'o'),
            scope: scope(),
            schedule_revision: 4,
            planned_at: Utc::now() + Duration::seconds(60),
            contract_valid_until: Utc::now() + Duration::seconds(120),
            timezone_digest: digest(b'z'),
            recurrence_digest: digest(b'r'),
            composition_digest: digest(b'c'),
            invocation_digest: digest(b'i'),
            provider_id_digest: host.identity_digest.clone(),
            provider_epoch: 1,
            lease_revision: 3,
            clock_epoch: 2,
        };
        let receipt = LocalTimerRegistrationReceipt::from_request(&request, &host, Utc::now())
            .expect("registration");
        assert_eq!(receipt.scope, request.scope);
        assert_eq!(receipt.composition_digest, request.composition_digest);
        assert_eq!(receipt.host.current_commit_digest, digest(b'a'));
        assert_eq!(receipt.provider_id_digest, host.identity_digest);
        assert!(receipt.validate().is_ok());
    }

    #[test]
    fn local_timer_real_process_journey_dispatches_once_and_projects_result() {
        let start = Utc::now() + Duration::milliseconds(120);
        let host = identity(b'a');
        let mut runner = LocalTimerMissionRunner::with_stores(
            host.clone(),
            RecordingConsumer::new(),
            SqliteMissionScheduleStore::open_in_memory().expect("schedule store"),
            MemoryLocalTimerProjectionStore::default(),
        )
        .expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        let first = runner
            .wait_and_dispatch(StdDuration::from_secs(2))
            .expect("real host timer dispatch");
        let first_receipt = match &first.outcome {
            MissionScheduleWakeOutcome::Dispatched(receipt) => receipt,
            other => panic!("expected first dispatch, got {other:?}"),
        };
        assert_eq!(
            first.projection.as_ref().unwrap().dispatch_id_digest,
            first_receipt.dispatch_id_digest
        );
        assert_eq!(runner.projections().count(), 1);
        let request_count = runner.service().consumer().requests.len();
        assert_eq!(request_count, 1);
        assert_eq!(runner.service().provider().active_registration_count(), 1);

        let token = runner
            .service()
            .wake_token_for(&first_receipt.schedule_id_digest)
            .expect("token query")
            .expect("next occurrence token");
        let replay = runner
            .service_mut()
            .wake_once(&token, Utc::now() + Duration::seconds(1));
        assert!(replay.is_err(), "the next recurrence is not due yet");
        assert_eq!(runner.service().consumer().requests.len(), 1);
    }

    #[test]
    fn missed_ticks_coalesce_and_exact_dispatch_receipt_is_restart_idempotent() {
        let planned = Utc.with_ymd_and_hms(2026, 8, 14, 9, 0, 0).unwrap();
        let host = identity(b'a');
        let mut runner =
            LocalTimerMissionRunner::new(host, RecordingConsumer::new()).expect("runner");
        runner
            .create(&draft(b's', planned, "1.0.0"), planned - Duration::hours(1))
            .expect("schedule");
        let wake = runner
            .service()
            .provider()
            .registration(
                &runner
                    .service()
                    .schedule(&digest(b's'))
                    .unwrap()
                    .armed_wake
                    .as_ref()
                    .unwrap()
                    .token_digest,
            )
            .expect("registration");
        assert_eq!(wake.schedule_revision, 1);
        let token = runner
            .service()
            .wake_token_for(&digest(b's'))
            .expect("token")
            .expect("armed token");
        let first = runner
            .service_mut()
            .wake_once(&token, planned + Duration::days(3))
            .expect("coalesced dispatch");
        let receipt = match first {
            MissionScheduleWakeOutcome::Dispatched(receipt) => receipt,
            other => panic!("expected dispatch, got {other:?}"),
        };
        assert_eq!(receipt.coalesced_ticks, 4);
        let projection = LocalTimerResultProjection::from_receipt(
            &receipt,
            runner.service().provider().identity(),
        )
        .expect("projection");
        runner
            .projection_store
            .save(&projection)
            .expect("projection save");
        runner
            .projections
            .insert(projection.projection_id_digest.clone(), projection.clone());
        assert_eq!(runner.service().consumer().requests.len(), 1);
        let replay = runner
            .service_mut()
            .wake_once(&token, planned + Duration::days(3))
            .expect("idempotent service replay");
        assert!(matches!(
            replay,
            MissionScheduleWakeOutcome::AlreadyDispatched(_)
        ));
        assert_eq!(runner.service().consumer().requests.len(), 1);
    }

    #[test]
    fn restart_rebinds_lease_and_never_replays_old_epoch() {
        let start = Utc::now() + Duration::milliseconds(150);
        let mut runner =
            LocalTimerMissionRunner::new(identity(b'a'), RecordingConsumer::new()).expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        let old_epoch = runner.service().provider().provider_epoch();
        let new_epoch = runner
            .restart_and_rebind(Utc::now())
            .expect("restart/rebind");
        assert!(new_epoch > old_epoch);
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        let run = runner
            .wait_and_dispatch(StdDuration::from_secs(2))
            .expect("rebound dispatch");
        assert!(matches!(
            run.outcome,
            MissionScheduleWakeOutcome::Dispatched(_)
        ));
        assert_eq!(runner.service().consumer().requests.len(), 1);
        assert_eq!(runner.projections().count(), 1);
    }

    #[test]
    fn process_restart_rebinds_durable_schedule_and_dispatches_once() {
        let start = Utc::now() + Duration::milliseconds(120);
        let host = identity(b'a');
        let mut runner =
            LocalTimerMissionRunner::new(host.clone(), RecordingConsumer::new()).expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        let (schedule_store, projection_store) = runner.into_recovery_stores();
        let mut recovered = LocalTimerMissionRunner::recover_with_stores(
            host,
            RecordingConsumer::new(),
            schedule_store,
            projection_store,
            Utc::now(),
        )
        .expect("recover runner");
        assert_eq!(recovered.service().provider().provider_epoch(), 2);
        let run = recovered
            .wait_and_dispatch(StdDuration::from_secs(2))
            .expect("recovered dispatch");
        assert!(matches!(
            run.outcome,
            MissionScheduleWakeOutcome::Dispatched(_)
        ));
        assert_eq!(recovered.service().consumer().requests.len(), 1);
        assert_eq!(recovered.projections().count(), 1);
    }

    #[test]
    fn projection_retry_reuses_dispatch_receipt_without_second_consumer_call() {
        let start = Utc::now() + Duration::milliseconds(100);
        let mut runner = LocalTimerMissionRunner::with_stores(
            identity(b'a'),
            RecordingConsumer::new(),
            crate::recurring_schedule::MemoryMissionScheduleStore::default(),
            FailOnceProjectionStore {
                inner: MemoryLocalTimerProjectionStore::default(),
                fail_next: true,
            },
        )
        .expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        let first = runner.wait_and_dispatch(StdDuration::from_secs(2));
        assert!(matches!(
            first,
            Err(LocalTimerError::ProjectionStore(
                LocalTimerProjectionStoreError::Serialization(_)
            ))
        ));
        assert_eq!(runner.service().consumer().requests.len(), 1);
        let retry = runner
            .wait_and_dispatch(StdDuration::from_secs(2))
            .expect("projection retry");
        assert!(matches!(
            retry.outcome,
            MissionScheduleWakeOutcome::AlreadyDispatched(_)
        ));
        assert_eq!(runner.service().consumer().requests.len(), 1);
        assert_eq!(runner.projections().count(), 1);
    }

    #[test]
    fn revoke_unmount_and_crash_cleanup_leave_no_active_host_wake() {
        let start = Utc::now() + Duration::seconds(5);
        let mut runner =
            LocalTimerMissionRunner::new(identity(b'a'), RecordingConsumer::new()).expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        let schedule = runner.service().schedule(&digest(b's')).unwrap().clone();
        runner
            .service_mut()
            .revoke_plugin(&schedule.composition.plugins[0], Utc::now())
            .expect("revoke");
        assert_eq!(runner.service().provider().active_registration_count(), 0);
        assert!(runner.service().provider().poll().is_none());

        let second_start = Utc::now() + Duration::seconds(5);
        runner
            .create(&draft(b't', second_start, "2.0.0"), Utc::now())
            .expect("second schedule");
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        runner.unmount_host().expect("unmount");
        assert_eq!(runner.service().provider().active_registration_count(), 0);
        assert!(runner.service().provider().poll().is_none());

        runner.mount_and_rebind(Utc::now()).expect("mount/rebind");
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        runner
            .crash_and_recover(Utc::now())
            .expect("crash recovery");
        assert_eq!(runner.service().provider().active_registration_count(), 1);
        assert!(runner.service().provider().poll().is_none());
    }

    #[test]
    fn sqlite_projection_restart_preserves_exact_result_without_second_consumer_call() {
        let start = Utc::now() + Duration::milliseconds(100);
        let host = identity(b'a');
        let mut runner =
            LocalTimerMissionRunner::new(host.clone(), RecordingConsumer::new()).expect("runner");
        runner
            .create(&draft(b's', start, "1.0.0"), Utc::now())
            .expect("schedule");
        let run = runner
            .wait_and_dispatch(StdDuration::from_secs(2))
            .expect("dispatch");
        let projection = run.projection.expect("projection");
        let mut store = SqliteLocalTimerProjectionStore::open_in_memory().expect("store");
        store.save(&projection).expect("save");
        let connection = store.into_connection();
        let recovered = SqliteLocalTimerProjectionStore::new(connection).expect("reopen");
        let rows = recovered.load().expect("load");
        assert_eq!(rows, vec![projection]);
    }
}
