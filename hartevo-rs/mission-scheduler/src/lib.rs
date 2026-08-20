//! A standalone scheduler core for future Application/Cell integration.
//!
//! The core deliberately has no Application dependency. It owns deterministic
//! selection, missed-tick coalescing, bounded budgets/concurrency, fairness,
//! lease generation fencing and replay suppression. Domain/Application code
//! can later integrate through these contracts without sharing its large
//! service files with the platform scheduler work.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use hartevo_cloud_storage::{
    CellScope, SchedulerAttempt, SchedulerAttemptOutcome, SchedulerAttemptSurface,
    SchedulerLeaseKind, SchedulerLeaseProof, SchedulerLeaseTakeover, SchedulerLeaseTakeoverReason,
    SchedulerReplay, SchedulerSchedule, SchedulerScheduleStatus, SchedulerWorkerLease,
    scheduler_digest,
};
use hartevo_domain_kernel::ProjectId;
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

pub mod local_timer;
pub mod os;
pub mod trigger_receipt;
pub mod plugin_dispatch;
pub mod plugin_invocation;
pub mod recurring_schedule;

pub const DEFAULT_MAX_PENDING: usize = 64;
pub const DEFAULT_MAX_CONCURRENT: usize = 8;
pub const DEFAULT_MAX_PER_TENANT: usize = 2;
pub const DEFAULT_MAX_MISSED_TICKS: u64 = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerConfig {
    pub max_pending: usize,
    pub max_concurrent: usize,
    pub max_concurrent_per_tenant: usize,
    pub max_missed_ticks: u64,
    pub worker_lease_for: Duration,
    pub leader_lease_for: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            max_concurrent_per_tenant: DEFAULT_MAX_PER_TENANT,
            max_missed_ticks: DEFAULT_MAX_MISSED_TICKS,
            worker_lease_for: Duration::minutes(5),
            leader_lease_for: Duration::minutes(5),
        }
    }
}

impl SchedulerConfig {
    fn validate(self) -> Result<(), SchedulerError> {
        if self.max_pending == 0
            || self.max_concurrent == 0
            || self.max_concurrent_per_tenant == 0
            || self.max_missed_ticks == 0
            || !valid_lease_duration(self.worker_lease_for)
            || !valid_lease_duration(self.leader_lease_for)
        {
            return Err(SchedulerError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeClock {
    now: DateTime<Utc>,
}

impl FakeClock {
    pub const fn new(now: DateTime<Utc>) -> Self {
        Self { now }
    }

    pub const fn now(self) -> DateTime<Utc> {
        self.now
    }

    pub fn advance(&mut self, by: Duration) -> DateTime<Utc> {
        self.now = self.now.checked_add_signed(by).unwrap_or(self.now);
        self.now
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseProof {
    pub owner_digest: String,
    pub token_digest: String,
    pub generation: u64,
}

impl LeaseProof {
    pub fn new(
        owner_digest: impl Into<String>,
        token_digest: impl Into<String>,
        generation: u64,
    ) -> Result<Self, SchedulerError> {
        let proof = Self {
            owner_digest: owner_digest.into(),
            token_digest: token_digest.into(),
            generation,
        };
        if !is_digest(&proof.owner_digest)
            || !is_digest(&proof.token_digest)
            || proof.generation == 0
        {
            return Err(SchedulerError::InvalidLeaseProof);
        }
        Ok(proof)
    }
}

impl From<&SchedulerLeaseProof> for LeaseProof {
    fn from(proof: &SchedulerLeaseProof) -> Self {
        Self {
            owner_digest: proof.owner_digest.clone(),
            token_digest: proof.token_digest.clone(),
            generation: proof.generation,
        }
    }
}

impl From<LeaseProof> for SchedulerLeaseProof {
    fn from(proof: LeaseProof) -> Self {
        Self {
            owner_digest: proof.owner_digest,
            token_digest: proof.token_digest,
            generation: proof.generation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchTicket {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub schedule_id: String,
    pub cycle: u64,
    pub missed_ticks: u64,
    pub coalesced_ticks: u64,
    pub worker: SchedulerWorkerLease,
    pub attempt_id_digest: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackpressureReason {
    GlobalConcurrency,
    TenantConcurrency,
    PendingCapacity,
    ScheduleConcurrency,
    BudgetExhausted,
    SchedulePaused,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredDispatch {
    pub schedule_id: String,
    pub reason: BackpressureReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollReport {
    pub tickets: Vec<DispatchTicket>,
    pub deferred: Vec<DeferredDispatch>,
    pub expired_schedule_ids: Vec<String>,
    pub takeovers: Vec<SchedulerLeaseTakeover>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchOutcome {
    Succeeded,
    Failed { retry_at: Option<DateTime<Utc>> },
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionResult {
    pub schedule_id: String,
    pub replay: SchedulerReplay,
    pub outcome: SchedulerAttemptOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptState {
    Running,
    Succeeded,
    Failed,
    Uncertain,
    Completed,
}

#[derive(Debug)]
pub struct SchedulerCore {
    config: SchedulerConfig,
    schedules: BTreeMap<String, SchedulerSchedule>,
    leader: Option<hartevo_cloud_storage::SchedulerLeaderLease>,
    workers: BTreeMap<String, SchedulerWorkerLease>,
    worker_generations: BTreeMap<String, u64>,
    attempts: BTreeMap<String, SchedulerAttempt>,
    attempt_states: BTreeMap<String, AttemptState>,
    tenant_in_flight: BTreeMap<String, usize>,
    tenant_virtual_finish: BTreeMap<String, u64>,
    takeovers: Vec<SchedulerLeaseTakeover>,
}

impl SchedulerCore {
    pub fn new(config: SchedulerConfig) -> Result<Self, SchedulerError> {
        config.validate()?;
        Ok(Self {
            config,
            schedules: BTreeMap::new(),
            leader: None,
            workers: BTreeMap::new(),
            worker_generations: BTreeMap::new(),
            attempts: BTreeMap::new(),
            attempt_states: BTreeMap::new(),
            tenant_in_flight: BTreeMap::new(),
            tenant_virtual_finish: BTreeMap::new(),
            takeovers: Vec::new(),
        })
    }

    pub fn config(&self) -> SchedulerConfig {
        self.config
    }

    pub fn register_schedule(&mut self, schedule: SchedulerSchedule) -> Result<(), SchedulerError> {
        schedule.validate()?;
        let key = schedule_key(&schedule);
        if self.schedules.insert(key, schedule).is_some() {
            return Err(SchedulerError::DuplicateSchedule);
        }
        Ok(())
    }

    pub fn schedule(&self, schedule_id: &str) -> Option<&SchedulerSchedule> {
        self.schedules
            .values()
            .find(|schedule| schedule.schedule_id == schedule_id)
    }

    pub fn schedules(&self) -> impl Iterator<Item = &SchedulerSchedule> {
        self.schedules.values()
    }

    pub fn attempts(&self) -> impl Iterator<Item = &SchedulerAttempt> {
        self.attempts.values()
    }

    pub fn takeovers(&self) -> &[SchedulerLeaseTakeover] {
        &self.takeovers
    }

    pub fn pause_schedule(
        &mut self,
        schedule_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), SchedulerError> {
        let key = self.schedule_key(schedule_id)?;
        let schedule = self
            .schedules
            .get_mut(&key)
            .ok_or(SchedulerError::ScheduleNotFound)?;
        match schedule.status {
            SchedulerScheduleStatus::Pending => {
                schedule.status = SchedulerScheduleStatus::Paused;
                schedule.touch(now)?;
                Ok(())
            }
            SchedulerScheduleStatus::Paused => Ok(()),
            _ => Err(SchedulerError::ScheduleStateConflict),
        }
    }

    pub fn resume_schedule(
        &mut self,
        schedule_id: &str,
        now: DateTime<Utc>,
    ) -> Result<(), SchedulerError> {
        let key = self.schedule_key(schedule_id)?;
        let schedule = self
            .schedules
            .get_mut(&key)
            .ok_or(SchedulerError::ScheduleNotFound)?;
        match schedule.status {
            SchedulerScheduleStatus::Paused => {
                schedule.status = SchedulerScheduleStatus::Pending;
                schedule.touch(now)?;
                Ok(())
            }
            SchedulerScheduleStatus::Pending => Ok(()),
            _ => Err(SchedulerError::ScheduleStateConflict),
        }
    }

    pub fn claim_leader(
        &mut self,
        scope: &CellScope,
        lease_key_digest: &str,
        owner_digest: &str,
        token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<hartevo_cloud_storage::SchedulerLeaderLease, SchedulerError> {
        validate_digest_inputs(&[lease_key_digest, owner_digest, token_digest])?;
        if let Some(current) = &self.leader {
            if current.expires_at > now {
                return Err(SchedulerError::LeaderLeaseActive);
            }
            let previous_generation = current.proof.generation;
            let generation = previous_generation
                .checked_add(1)
                .ok_or(SchedulerError::InvalidLeaseProof)?;
            let takeover = takeover_for_leader(
                current,
                scope,
                lease_key_digest,
                owner_digest,
                generation,
                now,
            )?;
            self.takeovers.push(takeover);
            let lease = make_leader_lease(
                scope,
                lease_key_digest,
                owner_digest,
                token_digest,
                generation,
                now,
                self.config.leader_lease_for,
            )?;
            self.leader = Some(lease.clone());
            return Ok(lease);
        }
        let lease = make_leader_lease(
            scope,
            lease_key_digest,
            owner_digest,
            token_digest,
            1,
            now,
            self.config.leader_lease_for,
        )?;
        self.leader = Some(lease.clone());
        Ok(lease)
    }

    pub fn heartbeat_leader(
        &mut self,
        proof: &LeaseProof,
        now: DateTime<Utc>,
    ) -> Result<(), SchedulerError> {
        let current = self
            .leader
            .as_mut()
            .ok_or(SchedulerError::LeaderLeaseLost)?;
        if current.proof.owner_digest != proof.owner_digest
            || current.proof.token_digest != proof.token_digest
            || current.proof.generation != proof.generation
            || current.expires_at <= now
        {
            return Err(SchedulerError::LeaderLeaseLost);
        }
        current.heartbeat_at = now;
        current.expires_at = now
            .checked_add_signed(self.config.leader_lease_for)
            .ok_or(SchedulerError::InvalidLeaseProof)?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn poll(
        &mut self,
        leader_proof: &LeaseProof,
        worker_owner_digest: &str,
        worker_token_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<PollReport, SchedulerError> {
        validate_digest_inputs(&[worker_owner_digest, worker_token_digest])?;
        self.ensure_leader(leader_proof, now)?;
        let mut report = PollReport {
            tickets: Vec::new(),
            deferred: Vec::new(),
            expired_schedule_ids: Vec::new(),
            takeovers: Vec::new(),
        };
        self.reclaim_expired_workers(now, worker_owner_digest, &mut report)?;
        self.expire_schedules(now, &mut report)?;

        let mut due_keys = self
            .schedules
            .iter()
            .filter_map(|(key, schedule)| {
                schedule_is_temporally_due(schedule, now).then_some(key.clone())
            })
            .collect::<Vec<_>>();
        due_keys.sort_by_key(|key| {
            let schedule = &self.schedules[key];
            (
                self.tenant_virtual_finish
                    .get(schedule.scope.tenant_id.as_str())
                    .copied()
                    .unwrap_or(0),
                schedule.scope.tenant_id.as_str().to_owned(),
                key.clone(),
            )
        });

        let pending_capacity = self.config.max_pending;
        for (index, key) in due_keys.into_iter().enumerate() {
            if index >= pending_capacity {
                report.deferred.push(DeferredDispatch {
                    schedule_id: self.schedules[&key].schedule_id.clone(),
                    reason: BackpressureReason::PendingCapacity,
                });
                continue;
            }
            if self.total_in_flight() >= self.config.max_concurrent {
                report.deferred.push(DeferredDispatch {
                    schedule_id: self.schedules[&key].schedule_id.clone(),
                    reason: BackpressureReason::GlobalConcurrency,
                });
                continue;
            }
            let schedule = &self.schedules[&key];
            let tenant = schedule.scope.tenant_id.as_str().to_owned();
            if self.tenant_in_flight.get(&tenant).copied().unwrap_or(0)
                >= self.config.max_concurrent_per_tenant
            {
                report.deferred.push(DeferredDispatch {
                    schedule_id: schedule.schedule_id.clone(),
                    reason: BackpressureReason::TenantConcurrency,
                });
                continue;
            }
            if !schedule.budget.has_dispatch_capacity() {
                report.deferred.push(DeferredDispatch {
                    schedule_id: schedule.schedule_id.clone(),
                    reason: BackpressureReason::BudgetExhausted,
                });
                continue;
            }
            if !schedule.concurrency.is_open() {
                report.deferred.push(DeferredDispatch {
                    schedule_id: schedule.schedule_id.clone(),
                    reason: BackpressureReason::SchedulePaused,
                });
                continue;
            }
            if schedule.concurrency.in_flight >= schedule.concurrency.max_in_flight {
                report.deferred.push(DeferredDispatch {
                    schedule_id: schedule.schedule_id.clone(),
                    reason: BackpressureReason::ScheduleConcurrency,
                });
                continue;
            }

            let missed_ticks = schedule
                .missed_tick_count(now)?
                .ok_or(SchedulerError::ScheduleNotDue)?;
            let coalesced_ticks = missed_ticks.min(self.config.max_missed_ticks);
            let schedule = self
                .schedules
                .get_mut(&key)
                .ok_or(SchedulerError::ScheduleNotFound)?;
            schedule.consume_coalesced_ticks(now, missed_ticks)?;
            schedule.status = SchedulerScheduleStatus::Leased;
            schedule.budget.used_dispatches = schedule
                .budget
                .used_dispatches
                .checked_add(1)
                .ok_or(SchedulerError::BudgetExhausted)?;
            schedule.concurrency.in_flight = schedule
                .concurrency
                .in_flight
                .checked_add(1)
                .ok_or(SchedulerError::InvalidConfig)?;
            schedule.concurrency.pending = schedule.concurrency.pending.saturating_sub(1);
            schedule.touch(now)?;

            let worker_id_digest = scheduler_digest(format!("worker:{key}").as_bytes());
            let generation = self
                .worker_generations
                .get(&key)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(SchedulerError::InvalidLeaseProof)?;
            self.worker_generations.insert(key.clone(), generation);
            let worker = SchedulerWorkerLease {
                scope: schedule.scope.clone(),
                project_id: schedule.project_id.clone(),
                schedule_id: schedule.schedule_id.clone(),
                worker_id_digest: worker_id_digest.clone(),
                proof: SchedulerLeaseProof {
                    owner_digest: worker_owner_digest.into(),
                    token_digest: worker_token_digest.into(),
                    generation,
                },
                claimed_at: now,
                heartbeat_at: now,
                expires_at: now
                    .checked_add_signed(self.config.worker_lease_for)
                    .ok_or(SchedulerError::InvalidLeaseProof)?,
            };
            worker.validate()?;
            self.workers.insert(key.clone(), worker.clone());
            *self.tenant_in_flight.entry(tenant.clone()).or_default() += 1;
            let quantum = 1_000_u64.div_ceil(u64::from(schedule.fairness.weight));
            schedule.fairness.virtual_finish = schedule
                .fairness
                .virtual_finish
                .checked_add(quantum)
                .ok_or(SchedulerError::InvalidConfig)?;
            schedule.touch(now)?;
            let tenant_finish = self.tenant_virtual_finish.entry(tenant).or_default();
            *tenant_finish = tenant_finish
                .checked_add(quantum)
                .ok_or(SchedulerError::InvalidConfig)?;

            let attempt_id_digest =
                scheduler_digest(format!("attempt:{key}:{generation}").as_bytes());
            self.attempt_states
                .insert(attempt_id_digest.clone(), AttemptState::Running);
            let attempt = SchedulerAttempt {
                scope: schedule.scope.clone(),
                project_id: schedule.project_id.clone(),
                schedule_id: schedule.schedule_id.clone(),
                attempt_id_digest: attempt_id_digest.clone(),
                worker_generation: generation,
                surface: SchedulerAttemptSurface::Runtime,
                outcome: SchedulerAttemptOutcome::Running,
                replay: SchedulerReplay::Allowed,
                idempotency_key_digest: scheduler_digest(format!("dispatch:{key}").as_bytes()),
                started_at: now,
                updated_at: now,
            };
            attempt.validate()?;
            self.attempts.insert(attempt_id_digest.clone(), attempt);
            report.tickets.push(DispatchTicket {
                scope: schedule.scope.clone(),
                project_id: schedule.project_id.clone(),
                schedule_id: schedule.schedule_id.clone(),
                cycle: schedule.cycle,
                missed_ticks,
                coalesced_ticks,
                worker,
                attempt_id_digest,
                issued_at: now,
            });
        }
        Ok(report)
    }

    fn schedule_key(&self, schedule_id: &str) -> Result<String, SchedulerError> {
        self.schedules
            .iter()
            .find_map(|(key, schedule)| {
                (schedule.schedule_id == schedule_id).then_some(key.clone())
            })
            .ok_or(SchedulerError::ScheduleNotFound)
    }

    pub fn complete(
        &mut self,
        schedule_id: &str,
        proof: &LeaseProof,
        surface: SchedulerAttemptSurface,
        outcome: DispatchOutcome,
        now: DateTime<Utc>,
    ) -> Result<CompletionResult, SchedulerError> {
        let key = self
            .workers
            .iter()
            .find_map(|(key, worker)| (worker.schedule_id == schedule_id).then_some(key.clone()))
            .ok_or(SchedulerError::WorkerLeaseLost)?;
        let worker = self
            .workers
            .get(&key)
            .ok_or(SchedulerError::WorkerLeaseLost)?;
        if worker.proof.owner_digest != proof.owner_digest
            || worker.proof.token_digest != proof.token_digest
            || worker.proof.generation != proof.generation
            || worker.expires_at <= now
        {
            return Err(SchedulerError::WorkerLeaseLost);
        }
        let schedule = self
            .schedules
            .get_mut(&key)
            .ok_or(SchedulerError::ScheduleNotFound)?;
        if schedule.status != SchedulerScheduleStatus::Leased {
            return Err(SchedulerError::WorkerLeaseLost);
        }
        let (attempt_outcome, replay) = match outcome {
            DispatchOutcome::Succeeded => {
                schedule.status = SchedulerScheduleStatus::Triggered;
                (
                    SchedulerAttemptOutcome::Completed,
                    SchedulerReplay::SuppressedCompleted,
                )
            }
            DispatchOutcome::Failed { retry_at } => {
                if let Some(retry_at) = retry_at {
                    if retry_at <= now || retry_at >= schedule.contract_valid_until {
                        return Err(SchedulerError::InvalidRetryWindow);
                    }
                    schedule.next_due_at = Some(retry_at);
                    schedule.status = SchedulerScheduleStatus::Pending;
                } else {
                    schedule.status = SchedulerScheduleStatus::DeadLetter;
                }
                (SchedulerAttemptOutcome::Failed, SchedulerReplay::Allowed)
            }
            DispatchOutcome::Uncertain => {
                schedule.status = SchedulerScheduleStatus::Uncertain;
                (
                    SchedulerAttemptOutcome::Uncertain,
                    SchedulerReplay::SuppressedUncertain,
                )
            }
        };
        schedule.concurrency.in_flight = schedule.concurrency.in_flight.saturating_sub(1);
        schedule.touch(now)?;
        let worker = self
            .workers
            .remove(&key)
            .ok_or(SchedulerError::WorkerLeaseLost)?;
        if let Some(in_flight) = self
            .tenant_in_flight
            .get_mut(worker.scope.tenant_id.as_str())
        {
            *in_flight = in_flight.saturating_sub(1);
        }
        let attempt_id = self
            .attempts
            .iter()
            .find_map(|(id, attempt)| {
                (attempt.schedule_id == schedule_id
                    && attempt.worker_generation == proof.generation
                    && attempt.outcome == SchedulerAttemptOutcome::Running)
                    .then_some(id.clone())
            })
            .ok_or(SchedulerError::AttemptNotFound)?;
        let attempt = self
            .attempts
            .get_mut(&attempt_id)
            .ok_or(SchedulerError::AttemptNotFound)?;
        attempt.surface = surface;
        attempt.outcome = attempt_outcome;
        attempt.replay = replay;
        attempt.updated_at = now;
        attempt.validate()?;
        self.attempt_states.insert(
            attempt_id,
            match attempt_outcome {
                SchedulerAttemptOutcome::Completed => AttemptState::Completed,
                SchedulerAttemptOutcome::Failed => AttemptState::Failed,
                SchedulerAttemptOutcome::Uncertain => AttemptState::Uncertain,
                SchedulerAttemptOutcome::Running => AttemptState::Running,
                SchedulerAttemptOutcome::Succeeded => AttemptState::Succeeded,
            },
        );
        Ok(CompletionResult {
            schedule_id: schedule_id.into(),
            replay,
            outcome: attempt_outcome,
        })
    }

    pub fn replay_decision(
        &self,
        attempt_id_digest: &str,
        surface: SchedulerAttemptSurface,
    ) -> Result<SchedulerReplay, SchedulerError> {
        let state = self
            .attempt_states
            .get(attempt_id_digest)
            .ok_or(SchedulerError::AttemptNotFound)?;
        Ok(match state {
            AttemptState::Uncertain => {
                let _ = surface;
                SchedulerReplay::SuppressedUncertain
            }
            AttemptState::Completed | AttemptState::Succeeded => {
                SchedulerReplay::SuppressedCompleted
            }
            AttemptState::Running => SchedulerReplay::SuppressedUncertain,
            AttemptState::Failed => SchedulerReplay::Allowed,
        })
    }

    fn ensure_leader(&self, proof: &LeaseProof, now: DateTime<Utc>) -> Result<(), SchedulerError> {
        let current = self
            .leader
            .as_ref()
            .ok_or(SchedulerError::LeaderLeaseLost)?;
        if current.proof.owner_digest != proof.owner_digest
            || current.proof.token_digest != proof.token_digest
            || current.proof.generation != proof.generation
            || current.expires_at <= now
        {
            return Err(SchedulerError::LeaderLeaseLost);
        }
        Ok(())
    }

    fn reclaim_expired_workers(
        &mut self,
        now: DateTime<Utc>,
        owner_digest: &str,
        report: &mut PollReport,
    ) -> Result<(), SchedulerError> {
        let expired = self
            .workers
            .iter()
            .filter_map(|(key, lease)| (lease.expires_at <= now).then_some(key.clone()))
            .collect::<Vec<_>>();
        for key in expired {
            let old = self
                .workers
                .remove(&key)
                .ok_or(SchedulerError::WorkerLeaseLost)?;
            self.mark_attempt_uncertain(&old.schedule_id, old.proof.generation, now)?;
            let schedule = self
                .schedules
                .get_mut(&key)
                .ok_or(SchedulerError::ScheduleNotFound)?;
            schedule.status = SchedulerScheduleStatus::Uncertain;
            schedule.concurrency.in_flight = schedule.concurrency.in_flight.saturating_sub(1);
            schedule.touch(now)?;
            if let Some(in_flight) = self
                .tenant_in_flight
                .get_mut(schedule.scope.tenant_id.as_str())
            {
                *in_flight = in_flight.saturating_sub(1);
            }
            let generation = old
                .proof
                .generation
                .checked_add(1)
                .ok_or(SchedulerError::InvalidLeaseProof)?;
            self.worker_generations.insert(key.clone(), generation - 1);
            let takeover = SchedulerLeaseTakeover {
                scope: old.scope.clone(),
                project_id: Some(old.project_id.clone()),
                lease_kind: SchedulerLeaseKind::Worker,
                lease_id_digest: old.worker_id_digest.clone(),
                previous_generation: old.proof.generation,
                generation,
                previous_owner_digest: old.proof.owner_digest,
                owner_digest: owner_digest.into(),
                reason: SchedulerLeaseTakeoverReason::Expired,
                evidence_digest: scheduler_digest(
                    format!("{}:{}", key, old.proof.generation).as_bytes(),
                ),
                observed_at: now,
            };
            takeover.validate()?;
            self.takeovers.push(takeover.clone());
            report.takeovers.push(takeover);
        }
        Ok(())
    }

    fn mark_attempt_uncertain(
        &mut self,
        schedule_id: &str,
        worker_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<(), SchedulerError> {
        let attempt_id = self.attempts.iter().find_map(|(id, attempt)| {
            (attempt.schedule_id == schedule_id
                && attempt.worker_generation == worker_generation
                && attempt.outcome == SchedulerAttemptOutcome::Running)
                .then_some(id.clone())
        });
        let Some(attempt_id) = attempt_id else {
            return Ok(());
        };
        let attempt = self
            .attempts
            .get_mut(&attempt_id)
            .ok_or(SchedulerError::AttemptNotFound)?;
        attempt.outcome = SchedulerAttemptOutcome::Uncertain;
        attempt.replay = SchedulerReplay::SuppressedUncertain;
        attempt.updated_at = now;
        attempt.validate()?;
        self.attempt_states
            .insert(attempt_id, AttemptState::Uncertain);
        Ok(())
    }

    fn expire_schedules(
        &mut self,
        now: DateTime<Utc>,
        report: &mut PollReport,
    ) -> Result<(), SchedulerError> {
        let expired = self
            .schedules
            .iter()
            .filter_map(|(key, schedule)| {
                (matches!(
                    schedule.status,
                    SchedulerScheduleStatus::Pending | SchedulerScheduleStatus::Leased
                ) && now >= schedule.contract_valid_until)
                    .then_some(key.clone())
            })
            .collect::<Vec<_>>();
        for key in expired {
            let expired_worker = self.workers.remove(&key);
            if let Some(worker) = &expired_worker {
                self.mark_attempt_uncertain(&worker.schedule_id, worker.proof.generation, now)?;
            }
            let schedule = self
                .schedules
                .get_mut(&key)
                .ok_or(SchedulerError::ScheduleNotFound)?;
            schedule.status = SchedulerScheduleStatus::Expired;
            schedule.concurrency.in_flight = 0;
            schedule.touch(now)?;
            report
                .expired_schedule_ids
                .push(schedule.schedule_id.clone());
            if expired_worker.is_some()
                && let Some(in_flight) = self
                    .tenant_in_flight
                    .get_mut(schedule.scope.tenant_id.as_str())
            {
                *in_flight = in_flight.saturating_sub(1);
            }
        }
        Ok(())
    }

    fn total_in_flight(&self) -> usize {
        self.tenant_in_flight.values().sum()
    }
}

fn make_leader_lease(
    scope: &CellScope,
    lease_key_digest: &str,
    owner_digest: &str,
    token_digest: &str,
    generation: u64,
    now: DateTime<Utc>,
    lease_for: Duration,
) -> Result<hartevo_cloud_storage::SchedulerLeaderLease, SchedulerError> {
    let expires_at = now
        .checked_add_signed(lease_for)
        .ok_or(SchedulerError::InvalidLeaseProof)?;
    let lease = hartevo_cloud_storage::SchedulerLeaderLease {
        scope: scope.clone(),
        lease_key_digest: lease_key_digest.into(),
        proof: SchedulerLeaseProof {
            owner_digest: owner_digest.into(),
            token_digest: token_digest.into(),
            generation,
        },
        claimed_at: now,
        heartbeat_at: now,
        expires_at,
    };
    lease.validate()?;
    Ok(lease)
}

fn takeover_for_leader(
    current: &hartevo_cloud_storage::SchedulerLeaderLease,
    scope: &CellScope,
    lease_key_digest: &str,
    owner_digest: &str,
    generation: u64,
    now: DateTime<Utc>,
) -> Result<SchedulerLeaseTakeover, SchedulerError> {
    let takeover = SchedulerLeaseTakeover {
        scope: scope.clone(),
        project_id: None,
        lease_kind: SchedulerLeaseKind::Leader,
        lease_id_digest: lease_key_digest.into(),
        previous_generation: current.proof.generation,
        generation,
        previous_owner_digest: current.proof.owner_digest.clone(),
        owner_digest: owner_digest.into(),
        reason: SchedulerLeaseTakeoverReason::Expired,
        evidence_digest: scheduler_digest(
            format!("{}:{}", lease_key_digest, current.proof.generation).as_bytes(),
        ),
        observed_at: now,
    };
    takeover.validate()?;
    Ok(takeover)
}

fn schedule_key(schedule: &SchedulerSchedule) -> String {
    format!(
        "{}:{}:{}",
        schedule.scope.tenant_id.as_str(),
        schedule.project_id.as_str(),
        schedule.schedule_id
    )
}

fn schedule_is_temporally_due(schedule: &SchedulerSchedule, now: DateTime<Utc>) -> bool {
    matches!(schedule.status, SchedulerScheduleStatus::Pending)
        && now < schedule.contract_valid_until
        && (schedule.next_due_at.is_some_and(|due_at| due_at <= now)
            || schedule.signal_digest.is_some())
}

fn valid_lease_duration(duration: Duration) -> bool {
    (1..=hartevo_cloud_storage::MAX_SCHEDULER_LEASE_SECONDS).contains(&duration.num_seconds())
}

fn validate_digest_inputs(values: &[&str]) -> Result<(), SchedulerError> {
    if values.iter().all(|value| is_digest(value)) {
        Ok(())
    } else {
        Err(SchedulerError::InvalidLeaseProof)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("scheduler configuration is empty, unbounded, or outside the lease contract")]
    InvalidConfig,
    #[error("scheduler schedule is invalid")]
    InvalidSchedule(#[from] hartevo_cloud_storage::CloudStorageError),
    #[error("scheduler schedule is already registered")]
    DuplicateSchedule,
    #[error("scheduler schedule is not registered")]
    ScheduleNotFound,
    #[error("scheduler schedule is not due")]
    ScheduleNotDue,
    #[error("scheduler schedule is in a state that cannot be paused or resumed")]
    ScheduleStateConflict,
    #[error("scheduler leader lease is still active")]
    LeaderLeaseActive,
    #[error("scheduler leader lease is stale or expired")]
    LeaderLeaseLost,
    #[error("scheduler worker lease is stale or expired")]
    WorkerLeaseLost,
    #[error("scheduler lease proof is malformed")]
    InvalidLeaseProof,
    #[error("scheduler budget has no remaining dispatch capacity")]
    BudgetExhausted,
    #[error("scheduler retry time is outside the exact contract window")]
    InvalidRetryWindow,
    #[error("scheduler attempt is not registered")]
    AttemptNotFound,
    #[error("scheduler persistence failed: {0}")]
    Persistence(#[from] SchedulerPersistenceError),
}

#[derive(Debug, Error)]
pub enum SchedulerPersistenceError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Contract(#[from] hartevo_cloud_storage::CloudStorageError),
    #[error("SQLite scheduler record conflicts with an existing immutable request")]
    Conflict,
    #[error("SQLite scheduler record was not found")]
    NotFound,
}

#[derive(Debug)]
pub struct SqliteSchedulerStore {
    connection: Connection,
}

impl SqliteSchedulerStore {
    pub fn open_in_memory() -> Result<Self, SchedulerPersistenceError> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection };
        store.initialize()?;
        Ok(store)
    }

    pub fn initialize(&self) -> Result<(), SchedulerPersistenceError> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS scheduler_schedules (
                 cell TEXT NOT NULL,
                 tenant_id TEXT NOT NULL,
                 project_id TEXT NOT NULL,
                 schedule_id TEXT NOT NULL,
                 revision INTEGER NOT NULL,
                 status TEXT NOT NULL,
                 record_json TEXT NOT NULL,
                 PRIMARY KEY (cell, tenant_id, project_id, schedule_id)
             );
             CREATE TABLE IF NOT EXISTS scheduler_attempts (
                 cell TEXT NOT NULL,
                 tenant_id TEXT NOT NULL,
                 project_id TEXT NOT NULL,
                 attempt_id_digest TEXT NOT NULL,
                 record_json TEXT NOT NULL,
                 PRIMARY KEY (cell, tenant_id, project_id, attempt_id_digest)
             );",
        )?;
        Ok(())
    }

    pub fn save_schedule(
        &self,
        schedule: &SchedulerSchedule,
    ) -> Result<(), SchedulerPersistenceError> {
        schedule.validate()?;
        let record = serde_json::to_string(schedule)?;
        let existing = self
            .connection
            .query_row(
                "SELECT record_json FROM scheduler_schedules
                 WHERE cell = ?1 AND tenant_id = ?2 AND project_id = ?3 AND schedule_id = ?4",
                params![
                    schedule.scope.cell.as_str(),
                    schedule.scope.tenant_id.as_str(),
                    schedule.project_id.as_str(),
                    schedule.schedule_id,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != record {
                return Err(SchedulerPersistenceError::Conflict);
            }
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO scheduler_schedules
               (cell, tenant_id, project_id, schedule_id, revision, status, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                schedule.scope.cell.as_str(),
                schedule.scope.tenant_id.as_str(),
                schedule.project_id.as_str(),
                schedule.schedule_id,
                i64::try_from(schedule.revision).map_err(|_| {
                    SchedulerPersistenceError::Contract(
                        hartevo_cloud_storage::CloudStorageError::RevisionOverflow,
                    )
                })?,
                serde_json::to_value(schedule.status)?.as_str(),
                record,
            ],
        )?;
        Ok(())
    }

    pub fn load_schedule(
        &self,
        scope: &CellScope,
        project_id: &ProjectId,
        schedule_id: &str,
    ) -> Result<SchedulerSchedule, SchedulerPersistenceError> {
        let record = self
            .connection
            .query_row(
                "SELECT record_json FROM scheduler_schedules
                 WHERE cell = ?1 AND tenant_id = ?2 AND project_id = ?3 AND schedule_id = ?4",
                params![
                    scope.cell.as_str(),
                    scope.tenant_id.as_str(),
                    project_id.as_str(),
                    schedule_id
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(SchedulerPersistenceError::NotFound)?;
        let schedule: SchedulerSchedule = serde_json::from_str(&record)?;
        schedule.validate()?;
        if schedule.scope != *scope
            || schedule.project_id != *project_id
            || schedule.schedule_id != schedule_id
        {
            return Err(SchedulerPersistenceError::Conflict);
        }
        Ok(schedule)
    }

    pub fn save_attempt(
        &self,
        attempt: &SchedulerAttempt,
    ) -> Result<(), SchedulerPersistenceError> {
        attempt.validate()?;
        let record = serde_json::to_string(attempt)?;
        let existing = self
            .connection
            .query_row(
                "SELECT record_json FROM scheduler_attempts
                 WHERE cell = ?1 AND tenant_id = ?2 AND project_id = ?3 AND attempt_id_digest = ?4",
                params![
                    attempt.scope.cell.as_str(),
                    attempt.scope.tenant_id.as_str(),
                    attempt.project_id.as_str(),
                    attempt.attempt_id_digest,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != record {
                return Err(SchedulerPersistenceError::Conflict);
            }
            return Ok(());
        }
        self.connection.execute(
            "INSERT INTO scheduler_attempts
               (cell, tenant_id, project_id, attempt_id_digest, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                attempt.scope.cell.as_str(),
                attempt.scope.tenant_id.as_str(),
                attempt.project_id.as_str(),
                attempt.attempt_id_digest,
                record,
            ],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_cloud_storage::{
        DataCell, SchedulerBackpressure, SchedulerBackpressureState, SchedulerBudget,
        SchedulerFairness, SchedulerTrigger,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn digest(byte: char) -> String {
        scheduler_digest(byte.to_string().as_bytes())
    }

    fn scope(tenant: &str) -> CellScope {
        CellScope {
            cell: DataCell::Us,
            tenant_id: tenant.into(),
        }
    }

    fn schedule(tenant: &str, id: &str, due_at: DateTime<Utc>) -> SchedulerSchedule {
        SchedulerSchedule {
            scope: scope(tenant),
            project_id: ProjectId::from_stable(format!("project-{tenant}")),
            schedule_id: id.into(),
            mission_id_digest: digest('a'),
            cycle: 1,
            trigger: SchedulerTrigger::Interval,
            interval_seconds: 60,
            anchor_at: now(),
            next_due_at: Some(due_at),
            signal_digest: None,
            contract_valid_until: now() + Duration::days(1),
            budget: SchedulerBudget {
                max_dispatches: 10,
                used_dispatches: 0,
                max_cost_micros: 100,
                used_cost_micros: 0,
                max_runtime_seconds: 600,
                used_runtime_seconds: 0,
            },
            concurrency: SchedulerBackpressure {
                state: SchedulerBackpressureState::Open,
                pending: 0,
                in_flight: 0,
                max_pending: 10,
                max_in_flight: 1,
            },
            fairness: SchedulerFairness {
                weight: 1,
                virtual_finish: 0,
            },
            status: SchedulerScheduleStatus::Pending,
            missed_ticks: 0,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    fn leader_proof(core: &mut SchedulerCore) -> LeaseProof {
        let lease = core
            .claim_leader(
                &scope("leader-tenant"),
                &digest('l'),
                &digest('o'),
                &digest('t'),
                now(),
            )
            .expect("leader");
        LeaseProof::from(&lease.proof)
    }

    #[test]
    fn fake_clock_and_sqlite_restart_preserve_typed_schedule() {
        let mut clock = FakeClock::new(now());
        let due = clock.advance(Duration::minutes(1));
        let schedule = schedule("tenant-a", "schedule-a", due);
        let store = SqliteSchedulerStore::open_in_memory().expect("sqlite");
        store.save_schedule(&schedule).expect("save schedule");
        let restored = store
            .load_schedule(
                &scope("tenant-a"),
                &schedule.project_id,
                &schedule.schedule_id,
            )
            .expect("restore schedule");
        assert_eq!(restored, schedule);
        assert_eq!(clock.now(), due);
    }

    #[test]
    fn missed_ticks_are_coalesced_into_one_bounded_dispatch() {
        let mut core = SchedulerCore::new(SchedulerConfig {
            max_missed_ticks: 2,
            ..SchedulerConfig::default()
        })
        .expect("core");
        core.register_schedule(schedule(
            "tenant-a",
            "schedule-a",
            now() + Duration::minutes(1),
        ))
        .expect("schedule");
        let leader = leader_proof(&mut core);
        let report = core
            .poll(
                &leader,
                &digest('w'),
                &digest('k'),
                now() + Duration::minutes(4),
            )
            .expect("poll");
        assert_eq!(report.tickets.len(), 1);
        assert_eq!(report.tickets[0].missed_ticks, 4);
        assert_eq!(report.tickets[0].coalesced_ticks, 2);
        assert!(report.deferred.is_empty());
    }

    #[test]
    fn pause_and_resume_are_explicit_and_revisioned() {
        let mut core = SchedulerCore::new(SchedulerConfig::default()).expect("core");
        core.register_schedule(schedule("tenant-a", "schedule-a", now()))
            .expect("schedule");
        core.pause_schedule("schedule-a", now() + Duration::seconds(1))
            .expect("pause");
        assert_eq!(
            core.schedule("schedule-a").expect("schedule").status,
            SchedulerScheduleStatus::Paused
        );
        let leader = leader_proof(&mut core);
        let paused = core
            .poll(
                &leader,
                &digest('w'),
                &digest('k'),
                now() + Duration::seconds(2),
            )
            .expect("paused poll");
        assert!(paused.tickets.is_empty());
        core.resume_schedule("schedule-a", now() + Duration::seconds(3))
            .expect("resume");
        assert_eq!(
            core.schedule("schedule-a").expect("schedule").status,
            SchedulerScheduleStatus::Pending
        );
        let resumed = core
            .poll(
                &leader,
                &digest('w'),
                &digest('k'),
                now() + Duration::seconds(4),
            )
            .expect("resumed poll");
        assert_eq!(resumed.tickets.len(), 1);
    }

    #[test]
    fn fairness_and_global_backpressure_bound_one_tenant_without_starvation() {
        let mut core = SchedulerCore::new(SchedulerConfig {
            max_concurrent: 1,
            max_concurrent_per_tenant: 1,
            ..SchedulerConfig::default()
        })
        .expect("core");
        for (tenant, id) in [
            ("tenant-a", "a-1"),
            ("tenant-a", "a-2"),
            ("tenant-b", "b-1"),
        ] {
            core.register_schedule(schedule(tenant, id, now()))
                .expect("schedule");
        }
        let leader = leader_proof(&mut core);
        let first = core
            .poll(&leader, &digest('w'), &digest('k'), now())
            .expect("first poll");
        assert_eq!(first.tickets.len(), 1);
        let first_ticket = &first.tickets[0];
        assert_eq!(first_ticket.scope.tenant_id.as_str(), "tenant-a");
        let first_proof = LeaseProof::from(&first_ticket.worker.proof);
        core.complete(
            &first_ticket.schedule_id,
            &first_proof,
            SchedulerAttemptSurface::Runtime,
            DispatchOutcome::Succeeded,
            now() + Duration::seconds(1),
        )
        .expect("complete first");
        let second = core
            .poll(
                &leader,
                &digest('w'),
                &digest('k'),
                now() + Duration::seconds(2),
            )
            .expect("second poll");
        assert_eq!(second.tickets.len(), 1);
        assert_eq!(second.tickets[0].scope.tenant_id.as_str(), "tenant-b");
        assert!(second.deferred.iter().any(|deferred| {
            deferred.reason == BackpressureReason::PendingCapacity
                || deferred.reason == BackpressureReason::GlobalConcurrency
        }));
    }

    #[test]
    fn budget_and_per_schedule_concurrency_are_typed_deferrals() {
        let mut limited = schedule("tenant-a", "limited", now());
        limited.budget.max_dispatches = 0;
        limited.concurrency.state = SchedulerBackpressureState::Soft;
        assert!(limited.validate().is_ok());
        let mut core = SchedulerCore::new(SchedulerConfig::default()).expect("core");
        core.register_schedule(limited).expect("schedule");
        let leader = leader_proof(&mut core);
        let report = core
            .poll(&leader, &digest('w'), &digest('k'), now())
            .expect("poll");
        assert!(report.tickets.is_empty());
        assert_eq!(report.deferred.len(), 1);
        assert_eq!(
            report.deferred[0].reason,
            BackpressureReason::BudgetExhausted
        );
    }

    #[test]
    fn expired_worker_fences_ack_and_suppresses_uncertain_replay() {
        let mut core = SchedulerCore::new(SchedulerConfig {
            worker_lease_for: Duration::seconds(1),
            ..SchedulerConfig::default()
        })
        .expect("core");
        core.register_schedule(schedule("tenant-a", "schedule-a", now()))
            .expect("schedule");
        let leader = leader_proof(&mut core);
        let first = core
            .poll(&leader, &digest('w'), &digest('k'), now())
            .expect("first poll")
            .tickets
            .pop()
            .expect("first ticket");
        let old_proof = LeaseProof::from(&first.worker.proof);
        let takeover_report = core
            .poll(
                &leader,
                &digest('n'),
                &digest('m'),
                now() + Duration::seconds(61),
            )
            .expect("takeover poll");
        assert!(takeover_report.tickets.is_empty());
        assert_eq!(takeover_report.takeovers.len(), 1);
        assert!(takeover_report.takeovers[0].generation > old_proof.generation);
        assert_eq!(
            core.schedule("schedule-a").expect("schedule").status,
            SchedulerScheduleStatus::Uncertain
        );
        assert_eq!(
            core.replay_decision(&first.attempt_id_digest, SchedulerAttemptSurface::Effect)
                .expect("replay decision"),
            SchedulerReplay::SuppressedUncertain
        );
        assert!(matches!(
            core.complete(
                &first.schedule_id,
                &old_proof,
                SchedulerAttemptSurface::Runtime,
                DispatchOutcome::Succeeded,
                now() + Duration::seconds(61),
            ),
            Err(SchedulerError::WorkerLeaseLost)
        ));
    }

    #[test]
    fn runtime_browser_and_effect_uncertain_outcomes_suppress_replay() {
        for surface in [
            SchedulerAttemptSurface::Runtime,
            SchedulerAttemptSurface::Browser,
            SchedulerAttemptSurface::Effect,
        ] {
            let mut core = SchedulerCore::new(SchedulerConfig::default()).expect("core");
            core.register_schedule(schedule("tenant-a", "schedule-a", now()))
                .expect("schedule");
            let leader = leader_proof(&mut core);
            let ticket = core
                .poll(&leader, &digest('w'), &digest('k'), now())
                .expect("poll")
                .tickets
                .pop()
                .expect("ticket");
            let proof = LeaseProof::from(&ticket.worker.proof);
            let result = core
                .complete(
                    &ticket.schedule_id,
                    &proof,
                    surface,
                    DispatchOutcome::Uncertain,
                    now() + Duration::seconds(1),
                )
                .expect("uncertain completion");
            assert_eq!(result.replay, SchedulerReplay::SuppressedUncertain);
            assert_eq!(
                core.replay_decision(&ticket.attempt_id_digest, surface)
                    .expect("replay decision"),
                SchedulerReplay::SuppressedUncertain
            );
        }
    }

    #[test]
    fn leader_generation_fences_old_coordinator() {
        let mut core = SchedulerCore::new(SchedulerConfig {
            leader_lease_for: Duration::seconds(1),
            ..SchedulerConfig::default()
        })
        .expect("core");
        let old = leader_proof(&mut core);
        let new_lease = core
            .claim_leader(
                &scope("leader-tenant"),
                &digest('l'),
                &digest('n'),
                &digest('m'),
                now() + Duration::seconds(2),
            )
            .expect("leader takeover");
        let new = LeaseProof::from(&new_lease.proof);
        assert!(new.generation > old.generation);
        assert_eq!(core.takeovers().len(), 1);
        assert!(matches!(
            core.heartbeat_leader(&old, now() + Duration::seconds(2)),
            Err(SchedulerError::LeaderLeaseLost)
        ));
    }

    #[test]
    fn sqlite_attempt_persistence_is_exact_and_idempotent() {
        let store = SqliteSchedulerStore::open_in_memory().expect("sqlite");
        let attempt = SchedulerAttempt {
            scope: scope("tenant-a"),
            project_id: ProjectId::from("project-tenant-a"),
            schedule_id: "schedule-a".into(),
            attempt_id_digest: digest('a'),
            worker_generation: 1,
            surface: SchedulerAttemptSurface::Browser,
            outcome: SchedulerAttemptOutcome::Uncertain,
            replay: SchedulerReplay::SuppressedUncertain,
            idempotency_key_digest: digest('i'),
            started_at: now(),
            updated_at: now(),
        };
        store.save_attempt(&attempt).expect("save attempt");
        store.save_attempt(&attempt).expect("exact replay");
        let mut changed = attempt;
        changed.idempotency_key_digest = digest('j');
        assert!(matches!(
            store.save_attempt(&changed),
            Err(SchedulerPersistenceError::Conflict)
        ));
    }
}
