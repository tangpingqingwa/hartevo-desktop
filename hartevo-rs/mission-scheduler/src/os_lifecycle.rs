//! Lifecycle-owned scheduler contracts for OS wake and sleep/resume.
//!
//! This module is intentionally separate from the Cell persistence plane. It
//! owns the local lifecycle state machine, exact owner/token/generation
//! fencing, interval coalescing, and replay decisions at the OS boundary. A
//! native macOS implementation can be injected through [`MacOsWakeSleepDriver`];
//! Windows and Linux are explicit unsupported capabilities until their native
//! contracts are designed and tested.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::scheduler_digest;

pub const MAX_LIFECYCLE_LEASE_SECONDS: i64 = 15 * 60;
pub const DEFAULT_MAX_COALESCED_TICKS: u64 = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsPlatform {
    MacOs,
    Windows,
    Linux,
    Other,
}

impl OsPlatform {
    pub const fn current() -> Self {
        current_platform()
    }

    pub const fn supports_wake_sleep(self) -> bool {
        matches!(self, Self::MacOs)
    }
}

#[cfg(target_os = "macos")]
const fn current_platform() -> OsPlatform {
    OsPlatform::MacOs
}

#[cfg(target_os = "windows")]
const fn current_platform() -> OsPlatform {
    OsPlatform::Windows
}

#[cfg(target_os = "linux")]
const fn current_platform() -> OsPlatform {
    OsPlatform::Linux
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
const fn current_platform() -> OsPlatform {
    OsPlatform::Other
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct LeaseFence {
    pub owner_digest: String,
    pub token_digest: String,
    pub generation: u64,
}

impl LeaseFence {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.owner_digest) || !is_digest(&self.token_digest) || self.generation == 0
        {
            return Err(LifecycleError::InvalidLeaseFence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleLease {
    pub schedule_id_digest: String,
    pub fence: LeaseFence,
    pub claimed_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl LifecycleLease {
    fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.schedule_id_digest)
            || self.heartbeat_at < self.claimed_at
            || self.expires_at <= self.heartbeat_at
        {
            return Err(LifecycleError::InvalidLease);
        }
        self.fence.validate()
    }

    fn is_current(&self, fence: &LeaseFence, now: DateTime<Utc>) -> bool {
        self.fence == *fence && self.expires_at > now
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleScheduleState {
    Pending,
    Paused,
    Uncertain,
    Completed,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleSchedule {
    pub schedule_id_digest: String,
    pub interval_seconds: u64,
    pub next_due_at: DateTime<Utc>,
    pub contract_valid_until: DateTime<Utc>,
    pub state: LifecycleScheduleState,
    pub missed_ticks: u64,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl LifecycleSchedule {
    pub fn new(
        schedule_id_digest: impl Into<String>,
        interval_seconds: u64,
        next_due_at: DateTime<Utc>,
        contract_valid_until: DateTime<Utc>,
        created_at: DateTime<Utc>,
    ) -> Result<Self, LifecycleError> {
        let schedule = Self {
            schedule_id_digest: schedule_id_digest.into(),
            interval_seconds,
            next_due_at,
            contract_valid_until,
            state: LifecycleScheduleState::Pending,
            missed_ticks: 0,
            revision: 1,
            created_at,
            updated_at: created_at,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.schedule_id_digest)
            || self.interval_seconds == 0
            || self.interval_seconds > i64::MAX as u64
            || self.contract_valid_until <= self.created_at
            || self.next_due_at >= self.contract_valid_until
            || self.updated_at < self.created_at
            || self.revision == 0
        {
            return Err(LifecycleError::InvalidSchedule);
        }
        Ok(())
    }

    pub fn due_ticks(&self, now: DateTime<Utc>) -> Result<u64, LifecycleError> {
        self.validate()?;
        if self.state != LifecycleScheduleState::Pending
            || now >= self.contract_valid_until
            || self.next_due_at > now
        {
            return Ok(0);
        }
        let elapsed_seconds = (now - self.next_due_at).num_seconds().max(0);
        let interval_seconds =
            i64::try_from(self.interval_seconds).map_err(|_| LifecycleError::InvalidSchedule)?;
        let intervals = u64::try_from(elapsed_seconds / interval_seconds)
            .map_err(|_| LifecycleError::InvalidSchedule)?;
        intervals
            .checked_add(1)
            .ok_or(LifecycleError::InvalidSchedule)
    }

    fn coalesce(
        &mut self,
        now: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedDispatch, LifecycleError> {
        if max_coalesced_ticks == 0 {
            return Err(LifecycleError::InvalidCoalescingLimit);
        }
        let due_ticks = self.due_ticks(now)?;
        if due_ticks == 0 {
            return Err(LifecycleError::NoDueTicks);
        }
        let interval_seconds =
            i64::try_from(self.interval_seconds).map_err(|_| LifecycleError::InvalidSchedule)?;
        let elapsed_seconds = interval_seconds
            .checked_mul(i64::try_from(due_ticks).map_err(|_| LifecycleError::InvalidSchedule)?)
            .ok_or(LifecycleError::InvalidSchedule)?;
        let next_due_at = self
            .next_due_at
            .checked_add_signed(Duration::seconds(elapsed_seconds))
            .ok_or(LifecycleError::InvalidSchedule)?;
        let mut candidate = self.clone();
        candidate.next_due_at = next_due_at;
        candidate.missed_ticks = candidate
            .missed_ticks
            .checked_add(due_ticks)
            .ok_or(LifecycleError::InvalidSchedule)?;
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or(LifecycleError::InvalidSchedule)?;
        candidate.updated_at = now;
        candidate.validate()?;
        *self = candidate;
        Ok(CoalescedDispatch {
            schedule_id_digest: self.schedule_id_digest.clone(),
            due_ticks,
            coalesced_ticks: due_ticks.min(max_coalesced_ticks),
            dispatch_count: 1,
            next_due_at,
            revision: self.revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoalescedDispatch {
    pub schedule_id_digest: String,
    pub due_ticks: u64,
    pub coalesced_ticks: u64,
    pub dispatch_count: u8,
    pub next_due_at: DateTime<Utc>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptSurface {
    Runtime,
    Browser,
    Effect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDecision {
    Allowed,
    SuppressedUncertain,
    SuppressedCompleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttemptRecord {
    pub attempt_id_digest: String,
    pub schedule_id_digest: String,
    pub surface: AttemptSurface,
    pub decision: ReplayDecision,
    pub fence: LeaseFence,
    pub observed_at: DateTime<Utc>,
}

impl AttemptRecord {
    fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.attempt_id_digest) || !is_digest(&self.schedule_id_digest) {
            return Err(LifecycleError::InvalidAttempt);
        }
        self.fence.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleWakeRequest {
    pub schedule_id_digest: String,
    pub wake_at: DateTime<Utc>,
    pub contract_valid_until: DateTime<Utc>,
    pub coalesced_ticks: u64,
    pub lifecycle_generation: u64,
    pub fence: LeaseFence,
}

impl LifecycleWakeRequest {
    pub fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.schedule_id_digest)
            || self.coalesced_ticks == 0
            || self.wake_at >= self.contract_valid_until
        {
            return Err(LifecycleError::InvalidWakeRequest);
        }
        self.fence.validate()
    }

    pub fn request_digest(&self) -> Result<String, LifecycleError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(scheduler_digest)
            .map_err(|_| LifecycleError::Serialization)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleWakeReceipt {
    pub request_digest: String,
    pub schedule_id_digest: String,
    pub wake_at: DateTime<Utc>,
    pub lifecycle_generation: u64,
    pub fence: LeaseFence,
}

impl LifecycleWakeReceipt {
    fn validate(&self) -> Result<(), LifecycleError> {
        if !is_digest(&self.request_digest) || !is_digest(&self.schedule_id_digest) {
            return Err(LifecycleError::InvalidWakeReceipt);
        }
        self.fence.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    Awake,
    Asleep,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SleepObservation {
    pub slept_at: DateTime<Utc>,
    pub lifecycle_generation: u64,
    pub armed_wake_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeObservation {
    pub woke_at: DateTime<Utc>,
    pub slept_for: Duration,
    pub lifecycle_generation: u64,
    pub armed_wake_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WakePlan {
    pub request: LifecycleWakeRequest,
    pub receipt: LifecycleWakeReceipt,
}

/// The native boundary for the macOS implementation. The scheduler owns all
/// validation and fencing; the driver only performs the platform operation.
pub trait MacOsWakeSleepDriver: fmt::Debug + Send {
    fn arm_wake(&mut self, request: &LifecycleWakeRequest) -> Result<(), LifecycleError>;
    fn disarm_wake(&mut self, receipt: &LifecycleWakeReceipt) -> Result<(), LifecycleError>;
}

#[derive(Debug)]
pub struct MacOsLifecycleAdapter<B> {
    backend: B,
    schedules: BTreeMap<String, LifecycleSchedule>,
    leases: BTreeMap<String, LifecycleLease>,
    armed_wakes: BTreeMap<String, LifecycleWakeReceipt>,
    attempts: BTreeMap<String, AttemptRecord>,
    power_state: PowerState,
    lifecycle_generation: u64,
    slept_at: Option<DateTime<Utc>>,
}

impl<B> MacOsLifecycleAdapter<B>
where
    B: MacOsWakeSleepDriver,
{
    pub fn for_platform(platform: OsPlatform, backend: B) -> Result<Self, LifecycleError> {
        if !platform.supports_wake_sleep() {
            return Err(LifecycleError::UnsupportedPlatform { platform });
        }
        Ok(Self::new(backend))
    }

    pub fn new(backend: B) -> Self {
        Self {
            backend,
            schedules: BTreeMap::new(),
            leases: BTreeMap::new(),
            armed_wakes: BTreeMap::new(),
            attempts: BTreeMap::new(),
            power_state: PowerState::Awake,
            lifecycle_generation: 0,
            slept_at: None,
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub const fn power_state(&self) -> PowerState {
        self.power_state
    }

    pub const fn lifecycle_generation(&self) -> u64 {
        self.lifecycle_generation
    }

    pub fn schedule(&self, schedule_id_digest: &str) -> Option<&LifecycleSchedule> {
        self.schedules.get(schedule_id_digest)
    }

    pub fn register_schedule(&mut self, schedule: LifecycleSchedule) -> Result<(), LifecycleError> {
        schedule.validate()?;
        if self
            .schedules
            .insert(schedule.schedule_id_digest.clone(), schedule)
            .is_some()
        {
            return Err(LifecycleError::DuplicateSchedule);
        }
        Ok(())
    }

    pub fn claim_lease(
        &mut self,
        schedule_id_digest: &str,
        fence: LeaseFence,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<LifecycleLease, LifecycleError> {
        fence.validate()?;
        validate_lease_duration(lease_for)?;
        let contract_valid_until = self
            .schedules
            .get(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?
            .contract_valid_until;
        if now >= contract_valid_until {
            return Err(LifecycleError::ScheduleExpired);
        }
        let previous_fence = if let Some(previous) = self.leases.get(schedule_id_digest) {
            if previous.expires_at > now {
                return Err(LifecycleError::LeaseActive);
            }
            if fence.generation <= previous.fence.generation {
                return Err(LifecycleError::GenerationRegression);
            }
            Some(previous.fence.clone())
        } else {
            None
        };
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(LifecycleError::InvalidLease)?;
        if expires_at >= contract_valid_until {
            return Err(LifecycleError::InvalidLease);
        }
        if let Some(previous_fence) = previous_fence {
            // A takeover must remove any wake armed by the expired owner
            // before the new generation can control this schedule.
            self.disarm_if_armed(schedule_id_digest, &previous_fence)?;
        }
        let lease = LifecycleLease {
            schedule_id_digest: schedule_id_digest.into(),
            fence,
            claimed_at: now,
            heartbeat_at: now,
            expires_at,
        };
        lease.validate()?;
        self.leases.insert(schedule_id_digest.into(), lease.clone());
        Ok(lease)
    }

    pub fn heartbeat_lease(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<LifecycleLease, LifecycleError> {
        fence.validate()?;
        validate_lease_duration(lease_for)?;
        let current = self.current_lease(schedule_id_digest, fence, now)?.clone();
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(LifecycleError::InvalidLease)?;
        let schedule = self
            .schedules
            .get(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        if expires_at >= schedule.contract_valid_until {
            return Err(LifecycleError::InvalidLease);
        }
        let lease = LifecycleLease {
            heartbeat_at: now,
            expires_at,
            ..current
        };
        lease.validate()?;
        self.leases.insert(schedule_id_digest.into(), lease.clone());
        Ok(lease)
    }

    pub fn pause_schedule(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        self.disarm_if_armed(schedule_id_digest, fence)?;
        let schedule = self
            .schedules
            .get_mut(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        match schedule.state {
            LifecycleScheduleState::Pending => {
                schedule.state = LifecycleScheduleState::Paused;
                touch_schedule(schedule, now)?;
                Ok(())
            }
            LifecycleScheduleState::Paused => Ok(()),
            LifecycleScheduleState::Uncertain => Err(LifecycleError::UncertainReplaySuppressed),
            LifecycleScheduleState::Completed | LifecycleScheduleState::Expired => {
                Err(LifecycleError::ScheduleStateConflict)
            }
        }
    }

    pub fn resume_schedule(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        let schedule = self
            .schedules
            .get_mut(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        match schedule.state {
            LifecycleScheduleState::Paused => {
                schedule.state = LifecycleScheduleState::Pending;
                touch_schedule(schedule, now)
            }
            LifecycleScheduleState::Pending => Ok(()),
            LifecycleScheduleState::Uncertain => Err(LifecycleError::UncertainReplaySuppressed),
            LifecycleScheduleState::Completed | LifecycleScheduleState::Expired => {
                Err(LifecycleError::ScheduleStateConflict)
            }
        }
    }

    pub fn plan_wake(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<WakePlan, LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        let schedule = self
            .schedules
            .get(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        if schedule.state != LifecycleScheduleState::Pending {
            return Err(match schedule.state {
                LifecycleScheduleState::Uncertain => LifecycleError::UncertainReplaySuppressed,
                _ => LifecycleError::ScheduleStateConflict,
            });
        }
        let wake_at = schedule.next_due_at.max(now);
        let request = LifecycleWakeRequest {
            schedule_id_digest: schedule_id_digest.into(),
            wake_at,
            contract_valid_until: schedule.contract_valid_until,
            coalesced_ticks: 1,
            lifecycle_generation: self.lifecycle_generation,
            fence: fence.clone(),
        };
        let request_digest = request.request_digest()?;
        if let Some(existing) = self.armed_wakes.get(schedule_id_digest) {
            if existing.request_digest == request_digest {
                return Ok(WakePlan {
                    request,
                    receipt: existing.clone(),
                });
            }
            return Err(LifecycleError::WakeAlreadyArmed);
        }
        self.backend.arm_wake(&request)?;
        let receipt = LifecycleWakeReceipt {
            request_digest,
            schedule_id_digest: schedule_id_digest.into(),
            wake_at,
            lifecycle_generation: self.lifecycle_generation,
            fence: fence.clone(),
        };
        receipt.validate()?;
        self.armed_wakes
            .insert(schedule_id_digest.into(), receipt.clone());
        Ok(WakePlan { request, receipt })
    }

    pub fn coalesce_missed_ticks(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
        max_coalesced_ticks: u64,
    ) -> Result<CoalescedDispatch, LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        if self.attempts.values().any(|attempt| {
            attempt.schedule_id_digest == schedule_id_digest
                && attempt.decision == ReplayDecision::SuppressedUncertain
        }) {
            return Err(LifecycleError::UncertainReplaySuppressed);
        }
        let schedule = self
            .schedules
            .get_mut(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        if schedule.state != LifecycleScheduleState::Pending {
            return Err(match schedule.state {
                LifecycleScheduleState::Uncertain => LifecycleError::UncertainReplaySuppressed,
                _ => LifecycleError::ScheduleStateConflict,
            });
        }
        schedule.coalesce(now, max_coalesced_ticks)
    }

    pub fn record_sleep(
        &mut self,
        slept_at: DateTime<Utc>,
    ) -> Result<SleepObservation, LifecycleError> {
        if self.power_state != PowerState::Awake {
            return Err(LifecycleError::AlreadyAsleep);
        }
        self.lifecycle_generation = self
            .lifecycle_generation
            .checked_add(1)
            .ok_or(LifecycleError::InvalidLifecycleTime)?;
        self.power_state = PowerState::Asleep;
        self.slept_at = Some(slept_at);
        Ok(SleepObservation {
            slept_at,
            lifecycle_generation: self.lifecycle_generation,
            armed_wake_count: self.armed_wakes.len(),
        })
    }

    pub fn record_wake(
        &mut self,
        woke_at: DateTime<Utc>,
    ) -> Result<ResumeObservation, LifecycleError> {
        let slept_at = self.slept_at.ok_or(LifecycleError::NotAsleep)?;
        if woke_at < slept_at {
            return Err(LifecycleError::InvalidLifecycleTime);
        }
        self.power_state = PowerState::Awake;
        self.slept_at = None;
        Ok(ResumeObservation {
            woke_at,
            slept_for: woke_at - slept_at,
            lifecycle_generation: self.lifecycle_generation,
            armed_wake_count: self.armed_wakes.len(),
        })
    }

    pub fn disarm_wake(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        self.disarm_if_armed(schedule_id_digest, fence)
    }

    pub fn record_attempt_uncertain(
        &mut self,
        schedule_id_digest: &str,
        attempt_id_digest: &str,
        surface: AttemptSurface,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        if !is_digest(attempt_id_digest) {
            return Err(LifecycleError::InvalidAttempt);
        }
        self.disarm_if_armed(schedule_id_digest, fence)?;
        let record = AttemptRecord {
            attempt_id_digest: attempt_id_digest.into(),
            schedule_id_digest: schedule_id_digest.into(),
            surface,
            decision: ReplayDecision::SuppressedUncertain,
            fence: fence.clone(),
            observed_at: now,
        };
        record.validate()?;
        if let Some(existing) = self.attempts.get(attempt_id_digest) {
            if existing != &record {
                return Err(LifecycleError::AttemptConflict);
            }
            return Ok(());
        }
        self.attempts.insert(attempt_id_digest.into(), record);
        let schedule = self
            .schedules
            .get_mut(schedule_id_digest)
            .ok_or(LifecycleError::ScheduleNotFound)?;
        schedule.state = LifecycleScheduleState::Uncertain;
        touch_schedule(schedule, now)
    }

    pub fn record_attempt_completed(
        &mut self,
        schedule_id_digest: &str,
        attempt_id_digest: &str,
        surface: AttemptSurface,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<(), LifecycleError> {
        self.current_lease(schedule_id_digest, fence, now)?;
        if !is_digest(attempt_id_digest) {
            return Err(LifecycleError::InvalidAttempt);
        }
        if let Some(existing) = self.attempts.get(attempt_id_digest) {
            return match existing.decision {
                ReplayDecision::SuppressedUncertain => {
                    Err(LifecycleError::UncertainReplaySuppressed)
                }
                ReplayDecision::SuppressedCompleted => Ok(()),
                ReplayDecision::Allowed => Err(LifecycleError::AttemptConflict),
            };
        }
        let record = AttemptRecord {
            attempt_id_digest: attempt_id_digest.into(),
            schedule_id_digest: schedule_id_digest.into(),
            surface,
            decision: ReplayDecision::SuppressedCompleted,
            fence: fence.clone(),
            observed_at: now,
        };
        record.validate()?;
        self.attempts.insert(attempt_id_digest.into(), record);
        Ok(())
    }

    pub fn replay_decision(
        &self,
        attempt_id_digest: &str,
        _surface: AttemptSurface,
    ) -> ReplayDecision {
        self.attempts
            .get(attempt_id_digest)
            .map_or(ReplayDecision::Allowed, |attempt| attempt.decision)
    }

    fn current_lease(
        &self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
        now: DateTime<Utc>,
    ) -> Result<&LifecycleLease, LifecycleError> {
        fence.validate()?;
        let lease = self
            .leases
            .get(schedule_id_digest)
            .ok_or(LifecycleError::LeaseLost {
                schedule_id_digest: schedule_id_digest.into(),
                generation: fence.generation,
            })?;
        if !lease.is_current(fence, now) {
            return Err(LifecycleError::LeaseLost {
                schedule_id_digest: schedule_id_digest.into(),
                generation: fence.generation,
            });
        }
        Ok(lease)
    }

    fn disarm_if_armed(
        &mut self,
        schedule_id_digest: &str,
        fence: &LeaseFence,
    ) -> Result<(), LifecycleError> {
        let Some(receipt) = self.armed_wakes.get(schedule_id_digest).cloned() else {
            return Ok(());
        };
        if receipt.fence != *fence {
            return Err(LifecycleError::WakeReceiptFenceLost);
        }
        self.backend.disarm_wake(&receipt)?;
        self.armed_wakes.remove(schedule_id_digest);
        Ok(())
    }
}

fn touch_schedule(
    schedule: &mut LifecycleSchedule,
    now: DateTime<Utc>,
) -> Result<(), LifecycleError> {
    schedule.revision = schedule
        .revision
        .checked_add(1)
        .ok_or(LifecycleError::InvalidSchedule)?;
    schedule.updated_at = now;
    schedule.validate()
}

fn validate_lease_duration(duration: Duration) -> Result<(), LifecycleError> {
    if !(1..=MAX_LIFECYCLE_LEASE_SECONDS).contains(&duration.num_seconds()) {
        return Err(LifecycleError::InvalidLease);
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LifecycleError {
    #[error("wake/sleep lifecycle is explicitly unsupported on {platform:?}")]
    UnsupportedPlatform { platform: OsPlatform },
    #[error("schedule identifier or interval lifecycle contract is invalid")]
    InvalidSchedule,
    #[error("schedule already exists")]
    DuplicateSchedule,
    #[error("schedule is not registered")]
    ScheduleNotFound,
    #[error("schedule contract has expired")]
    ScheduleExpired,
    #[error("schedule state does not permit this lifecycle transition")]
    ScheduleStateConflict,
    #[error("owner/token/generation lease fence is invalid")]
    InvalidLeaseFence,
    #[error("lease record is invalid")]
    InvalidLease,
    #[error("lease is still active")]
    LeaseActive,
    #[error("lease generation must strictly increase on takeover")]
    GenerationRegression,
    #[error("current owner/token/generation lease is lost")]
    LeaseLost {
        schedule_id_digest: String,
        generation: u64,
    },
    #[error("coalescing limit must be nonzero")]
    InvalidCoalescingLimit,
    #[error("schedule has no due interval ticks")]
    NoDueTicks,
    #[error("attempt is invalid")]
    InvalidAttempt,
    #[error("attempt conflicts with a previously recorded terminal outcome")]
    AttemptConflict,
    #[error("uncertain Runtime/Browser/Effect outcome cannot be replayed")]
    UncertainReplaySuppressed,
    #[error("wake request is invalid")]
    InvalidWakeRequest,
    #[error("wake receipt is invalid")]
    InvalidWakeReceipt,
    #[error("a different wake request is already armed for this schedule")]
    WakeAlreadyArmed,
    #[error("wake receipt owner/token/generation fence is lost")]
    WakeReceiptFenceLost,
    #[error("OS wake/sleep backend failed")]
    Backend,
    #[error("sleep was already recorded")]
    AlreadyAsleep,
    #[error("wake was recorded without a matching sleep")]
    NotAsleep,
    #[error("sleep/wake timestamps are not monotonic")]
    InvalidLifecycleTime,
    #[error("lifecycle contract serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-13T10:00:00Z")
            .expect("valid time")
            .with_timezone(&Utc)
    }

    fn digest(byte: u8) -> String {
        scheduler_digest([byte])
    }

    fn fence(owner: u8, token: u8, generation: u64) -> LeaseFence {
        LeaseFence {
            owner_digest: digest(owner),
            token_digest: digest(token),
            generation,
        }
    }

    fn schedule() -> LifecycleSchedule {
        LifecycleSchedule::new(
            digest(b's'),
            60,
            now() + Duration::minutes(1),
            now() + Duration::hours(2),
            now(),
        )
        .expect("schedule")
    }

    #[derive(Debug, Default)]
    struct RecordingDriver {
        arm_calls: usize,
        disarm_calls: usize,
    }

    impl MacOsWakeSleepDriver for RecordingDriver {
        fn arm_wake(&mut self, _request: &LifecycleWakeRequest) -> Result<(), LifecycleError> {
            self.arm_calls += 1;
            Ok(())
        }

        fn disarm_wake(&mut self, _receipt: &LifecycleWakeReceipt) -> Result<(), LifecycleError> {
            self.disarm_calls += 1;
            Ok(())
        }
    }

    fn adapter() -> MacOsLifecycleAdapter<RecordingDriver> {
        let mut adapter =
            MacOsLifecycleAdapter::for_platform(OsPlatform::MacOs, RecordingDriver::default())
                .expect("macOS adapter");
        adapter.register_schedule(schedule()).expect("schedule");
        adapter
            .claim_lease(
                &digest(b's'),
                fence(b'o', b't', 1),
                now(),
                Duration::minutes(5),
            )
            .expect("lease");
        adapter
    }

    #[test]
    fn missed_ticks_coalesce_to_one_dispatch_and_advance_once() {
        let mut adapter = adapter();
        let result = adapter
            .coalesce_missed_ticks(
                &digest(b's'),
                &fence(b'o', b't', 1),
                now() + Duration::minutes(4),
                2,
            )
            .expect("coalesce");
        assert_eq!(result.due_ticks, 4);
        assert_eq!(result.coalesced_ticks, 2);
        assert_eq!(result.dispatch_count, 1);
        assert_eq!(result.next_due_at, now() + Duration::minutes(5));
        assert_eq!(
            adapter
                .schedule(&digest(b's'))
                .expect("schedule")
                .missed_ticks,
            4
        );
    }

    #[test]
    fn pause_resume_is_fenced_and_does_not_auto_arm_or_dispatch() {
        let mut adapter = adapter();
        let proof = fence(b'o', b't', 1);
        adapter
            .pause_schedule(&digest(b's'), &proof, now() + Duration::seconds(1))
            .expect("pause");
        assert_eq!(
            adapter.schedule(&digest(b's')).expect("schedule").state,
            LifecycleScheduleState::Paused
        );
        adapter
            .resume_schedule(&digest(b's'), &proof, now() + Duration::seconds(2))
            .expect("resume");
        assert_eq!(
            adapter.schedule(&digest(b's')).expect("schedule").state,
            LifecycleScheduleState::Pending
        );
        assert_eq!(adapter.backend().arm_calls, 0);
    }

    #[test]
    fn stale_owner_token_generation_cannot_control_after_takeover() {
        let mut adapter = adapter();
        let old = fence(b'o', b't', 1);
        adapter
            .claim_lease(
                &digest(b's'),
                fence(b'n', b'm', 2),
                now() + Duration::minutes(6),
                Duration::minutes(5),
            )
            .expect("takeover");
        assert!(matches!(
            adapter.resume_schedule(&digest(b's'), &old, now() + Duration::minutes(6)),
            Err(LifecycleError::LeaseLost { .. })
        ));
        assert!(matches!(
            adapter.claim_lease(
                &digest(b's'),
                fence(b'x', b'y', 2),
                now() + Duration::minutes(6),
                Duration::minutes(5),
            ),
            Err(LifecycleError::LeaseActive)
        ));
    }

    #[test]
    fn takeover_disarms_expired_generation_before_new_owner_can_arm() {
        let mut adapter = adapter();
        let old = fence(b'o', b't', 1);
        adapter
            .plan_wake(&digest(b's'), &old, now())
            .expect("old wake");
        adapter
            .claim_lease(
                &digest(b's'),
                fence(b'n', b'm', 2),
                now() + Duration::minutes(6),
                Duration::minutes(5),
            )
            .expect("takeover");
        assert_eq!(adapter.backend().disarm_calls, 1);
        adapter
            .plan_wake(
                &digest(b's'),
                &fence(b'n', b'm', 2),
                now() + Duration::minutes(6),
            )
            .expect("new generation wake");
        assert_eq!(adapter.backend().arm_calls, 2);
    }

    #[test]
    fn uncertain_runtime_browser_and_effect_never_replay() {
        for (index, surface) in [
            AttemptSurface::Runtime,
            AttemptSurface::Browser,
            AttemptSurface::Effect,
        ]
        .into_iter()
        .enumerate()
        {
            let mut adapter = adapter();
            let proof = fence(b'o', b't', 1);
            let attempt_id = digest(u8::try_from(index + 10).expect("test byte"));
            adapter
                .record_attempt_uncertain(
                    &digest(b's'),
                    &attempt_id,
                    surface,
                    &proof,
                    now() + Duration::seconds(1),
                )
                .expect("uncertain attempt");
            assert_eq!(
                adapter.replay_decision(&attempt_id, surface),
                ReplayDecision::SuppressedUncertain
            );
            assert!(matches!(
                adapter.coalesce_missed_ticks(
                    &digest(b's'),
                    &proof,
                    now() + Duration::minutes(4),
                    DEFAULT_MAX_COALESCED_TICKS,
                ),
                Err(LifecycleError::UncertainReplaySuppressed)
            ));
        }
    }

    #[test]
    fn sleep_resume_advances_epoch_and_rejects_invalid_order() {
        let mut adapter = adapter();
        assert!(matches!(
            adapter.record_wake(now()),
            Err(LifecycleError::NotAsleep)
        ));
        let sleep = adapter
            .record_sleep(now() + Duration::minutes(10))
            .expect("sleep");
        assert_eq!(sleep.lifecycle_generation, 1);
        assert!(matches!(
            adapter.record_sleep(now() + Duration::minutes(11)),
            Err(LifecycleError::AlreadyAsleep)
        ));
        assert!(matches!(
            adapter.record_wake(now() + Duration::minutes(9)),
            Err(LifecycleError::InvalidLifecycleTime)
        ));
        let resume = adapter
            .record_wake(now() + Duration::minutes(11))
            .expect("resume");
        assert_eq!(resume.slept_for, Duration::minutes(1));
        assert_eq!(resume.lifecycle_generation, 1);
    }

    #[test]
    fn windows_and_linux_are_explicitly_unsupported() {
        assert!(matches!(
            MacOsLifecycleAdapter::for_platform(OsPlatform::Windows, RecordingDriver::default()),
            Err(LifecycleError::UnsupportedPlatform {
                platform: OsPlatform::Windows
            })
        ));
        assert!(matches!(
            MacOsLifecycleAdapter::for_platform(OsPlatform::Linux, RecordingDriver::default()),
            Err(LifecycleError::UnsupportedPlatform {
                platform: OsPlatform::Linux
            })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_contract_arms_exact_wake_once_and_disarms_with_current_fence() {
        let mut adapter = adapter();
        let proof = fence(b'o', b't', 1);
        let first = adapter
            .plan_wake(&digest(b's'), &proof, now())
            .expect("arm wake");
        let second = adapter
            .plan_wake(&digest(b's'), &proof, now())
            .expect("idempotent arm");
        assert_eq!(first, second);
        assert_eq!(adapter.backend().arm_calls, 1);
        adapter
            .disarm_wake(&digest(b's'), &proof, now())
            .expect("disarm");
        assert_eq!(adapter.backend().disarm_calls, 1);
    }
}
