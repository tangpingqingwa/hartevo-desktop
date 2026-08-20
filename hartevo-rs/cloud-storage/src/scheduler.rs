//! Typed Cell-side contracts for the platform scheduler.
//!
//! The local SQLCipher `mission_schedules` table remains the source of truth
//! for a Desktop Mission. These records are the deliberately smaller remote
//! coordination contract: they contain scope, digests, revisions and bounded
//! counters, never raw lease tokens, runtime identifiers or project content.

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::ProjectId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};

use super::{
    CellScope, CloudStorageError, DataCell, PostgresCellStore, ensure_database_cell,
    ensure_project_exists, from_sql_u64, set_scope, to_sql_u64,
};

pub const MAX_SCHEDULER_LEASE_SECONDS: i64 = 15 * 60;
pub const MAX_SCHEDULER_WEIGHT: u32 = 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerTrigger {
    Interval,
    Event,
    IntervalOrEvent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerScheduleStatus {
    Pending,
    Leased,
    Triggered,
    Paused,
    Expired,
    DeadLetter,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerLeaseKind {
    Leader,
    Worker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerLeaseTakeoverReason {
    Expired,
    CoordinatorRestart,
    Explicit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerAttemptSurface {
    Runtime,
    Browser,
    Effect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerAttemptOutcome {
    Running,
    Succeeded,
    Failed,
    Uncertain,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerReplay {
    Allowed,
    SuppressedUncertain,
    SuppressedCompleted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerBackpressureState {
    Open,
    Soft,
    Hard,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerBudget {
    pub max_dispatches: u64,
    pub used_dispatches: u64,
    pub max_cost_micros: u64,
    pub used_cost_micros: u64,
    pub max_runtime_seconds: u64,
    pub used_runtime_seconds: u64,
}

impl SchedulerBudget {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.used_dispatches > self.max_dispatches
            || self.used_cost_micros > self.max_cost_micros
            || self.used_runtime_seconds > self.max_runtime_seconds
        {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        Ok(())
    }

    pub const fn has_dispatch_capacity(&self) -> bool {
        self.used_dispatches < self.max_dispatches
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerFairness {
    pub weight: u32,
    pub virtual_finish: u64,
}

impl SchedulerFairness {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.weight == 0 || self.weight > MAX_SCHEDULER_WEIGHT {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerBackpressure {
    pub state: SchedulerBackpressureState,
    pub pending: u64,
    pub in_flight: u64,
    pub max_pending: u64,
    pub max_in_flight: u64,
}

impl SchedulerBackpressure {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.max_pending == 0
            || self.max_in_flight == 0
            || self.pending > self.max_pending
            || self.in_flight > self.max_in_flight
        {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        Ok(())
    }

    pub const fn is_open(&self) -> bool {
        matches!(self.state, SchedulerBackpressureState::Open)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerSchedule {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub schedule_id: String,
    pub mission_id_digest: String,
    pub cycle: u64,
    pub trigger: SchedulerTrigger,
    pub interval_seconds: u64,
    pub anchor_at: DateTime<Utc>,
    pub next_due_at: Option<DateTime<Utc>>,
    pub signal_digest: Option<String>,
    pub contract_valid_until: DateTime<Utc>,
    pub budget: SchedulerBudget,
    pub concurrency: SchedulerBackpressure,
    pub fairness: SchedulerFairness,
    pub status: SchedulerScheduleStatus,
    pub missed_ticks: u64,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SchedulerSchedule {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.scope.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.schedule_id.trim().is_empty()
            || !is_sha256(&self.mission_id_digest)
            || self.cycle == 0
            || self.contract_valid_until <= self.created_at
            || self.updated_at < self.created_at
            || self.revision == 0
        {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        let shape_is_valid = match self.trigger {
            SchedulerTrigger::Interval => {
                self.interval_seconds > 0
                    && self.next_due_at.is_some()
                    && self.signal_digest.is_none()
            }
            SchedulerTrigger::Event => self.interval_seconds == 0 && self.next_due_at.is_none(),
            SchedulerTrigger::IntervalOrEvent => {
                self.interval_seconds > 0 && self.next_due_at.is_some()
            }
        };
        if !shape_is_valid
            || self
                .next_due_at
                .is_some_and(|due_at| due_at >= self.contract_valid_until)
            || self
                .signal_digest
                .as_ref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        self.budget.validate()?;
        self.concurrency.validate()?;
        self.fairness.validate()?;
        Ok(())
    }

    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        matches!(self.status, SchedulerScheduleStatus::Pending)
            && now < self.contract_valid_until
            && (self.next_due_at.is_some_and(|due_at| due_at <= now)
                || self.signal_digest.is_some())
            && self.budget.has_dispatch_capacity()
            && self.concurrency.in_flight < self.concurrency.max_in_flight
            && self.concurrency.is_open()
    }

    /// Returns the number of logical ticks represented by one coalesced run.
    /// The caller still emits exactly one dispatch and can retain this count
    /// for audit/metrics without replaying each missed interval.
    pub fn missed_tick_count(&self, now: DateTime<Utc>) -> Result<Option<u64>, CloudStorageError> {
        self.validate()?;
        if !self.is_due(now) {
            return Ok(None);
        }
        if self.signal_digest.is_some() && self.next_due_at.is_none_or(|due_at| due_at > now) {
            return Ok(Some(1));
        }
        let due_at = self
            .next_due_at
            .ok_or(CloudStorageError::InvalidSchedulerSchedule)?;
        let elapsed = (now - due_at).num_seconds().max(0);
        let interval = i64::try_from(self.interval_seconds)
            .map_err(|_| CloudStorageError::InvalidSchedulerSchedule)?;
        let intervals = u64::try_from(elapsed / interval)
            .map_err(|_| CloudStorageError::InvalidSchedulerSchedule)?;
        intervals
            .checked_add(1)
            .ok_or(CloudStorageError::InvalidSchedulerSchedule)
            .map(Some)
    }

    /// Advances the schedule after one dispatch. `ticks` is deliberately
    /// separate from the number of executions: missed ticks are consumed once
    /// and never expanded into multiple Runtime/Browser/Effect calls.
    pub fn consume_coalesced_ticks(
        &mut self,
        now: DateTime<Utc>,
        ticks: u64,
    ) -> Result<(), CloudStorageError> {
        self.validate()?;
        if ticks == 0 || !matches!(self.status, SchedulerScheduleStatus::Pending) {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        let interval_due = self.next_due_at.is_some_and(|due_at| due_at <= now);
        if interval_due {
            let due_at = self
                .next_due_at
                .ok_or(CloudStorageError::InvalidSchedulerSchedule)?;
            let seconds = self
                .interval_seconds
                .checked_mul(ticks)
                .ok_or(CloudStorageError::InvalidSchedulerSchedule)?;
            let seconds =
                i64::try_from(seconds).map_err(|_| CloudStorageError::InvalidSchedulerSchedule)?;
            self.next_due_at = due_at.checked_add_signed(Duration::seconds(seconds));
        }
        self.signal_digest = None;
        self.missed_ticks = self
            .missed_ticks
            .checked_add(ticks)
            .ok_or(CloudStorageError::InvalidSchedulerSchedule)?;
        self.touch(now)
    }

    pub fn touch(&mut self, now: DateTime<Utc>) -> Result<(), CloudStorageError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(CloudStorageError::InvalidSchedulerSchedule)?;
        self.updated_at = now;
        self.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerLeaseProof {
    pub owner_digest: String,
    pub token_digest: String,
    pub generation: u64,
}

impl SchedulerLeaseProof {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if !is_sha256(&self.owner_digest) || !is_sha256(&self.token_digest) || self.generation == 0
        {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerLeaderLease {
    pub scope: CellScope,
    pub lease_key_digest: String,
    pub proof: SchedulerLeaseProof,
    pub claimed_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SchedulerLeaderLease {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.scope.tenant_id.as_str().trim().is_empty()
            || !is_sha256(&self.lease_key_digest)
            || self.heartbeat_at < self.claimed_at
            || self.expires_at <= self.heartbeat_at
        {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        self.proof.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerWorkerLease {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub schedule_id: String,
    pub worker_id_digest: String,
    pub proof: SchedulerLeaseProof,
    pub claimed_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SchedulerWorkerLease {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.scope.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.schedule_id.trim().is_empty()
            || !is_sha256(&self.worker_id_digest)
            || self.heartbeat_at < self.claimed_at
            || self.expires_at <= self.heartbeat_at
        {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        self.proof.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerLeaseTakeover {
    pub scope: CellScope,
    pub project_id: Option<ProjectId>,
    pub lease_kind: SchedulerLeaseKind,
    pub lease_id_digest: String,
    pub previous_generation: u64,
    pub generation: u64,
    pub previous_owner_digest: String,
    pub owner_digest: String,
    pub reason: SchedulerLeaseTakeoverReason,
    pub evidence_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl SchedulerLeaseTakeover {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if !is_sha256(&self.lease_id_digest)
            || !is_sha256(&self.previous_owner_digest)
            || !is_sha256(&self.owner_digest)
            || !is_sha256(&self.evidence_digest)
            || self.previous_generation == 0
            || self.generation != self.previous_generation + 1
        {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerAttempt {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub schedule_id: String,
    pub attempt_id_digest: String,
    pub worker_generation: u64,
    pub surface: SchedulerAttemptSurface,
    pub outcome: SchedulerAttemptOutcome,
    pub replay: SchedulerReplay,
    pub idempotency_key_digest: String,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SchedulerAttempt {
    pub fn validate(&self) -> Result<(), CloudStorageError> {
        if self.scope.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.schedule_id.trim().is_empty()
            || !is_sha256(&self.attempt_id_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || self.worker_generation == 0
            || self.updated_at < self.started_at
        {
            return Err(CloudStorageError::InvalidSchedulerAttempt);
        }
        if matches!(self.outcome, SchedulerAttemptOutcome::Uncertain)
            && !matches!(self.replay, SchedulerReplay::SuppressedUncertain)
        {
            return Err(CloudStorageError::InvalidSchedulerAttempt);
        }
        if matches!(self.outcome, SchedulerAttemptOutcome::Completed)
            && !matches!(self.replay, SchedulerReplay::SuppressedCompleted)
        {
            return Err(CloudStorageError::InvalidSchedulerAttempt);
        }
        Ok(())
    }
}

impl PostgresCellStore {
    pub async fn create_scheduler_schedule(
        &self,
        client: &mut Client,
        schedule: &SchedulerSchedule,
    ) -> Result<(), CloudStorageError> {
        if schedule.scope.cell != self.cell() {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        schedule.validate()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &schedule.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, &schedule.scope, &schedule.project_id).await?;
        let record = serde_json::to_value(schedule)?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT record_json FROM hartevo_cell.scheduler_schedules
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND schedule_id = $4
                 FOR UPDATE",
                &[
                    &schedule.scope.cell.as_str(),
                    &schedule.scope.tenant_id.as_str(),
                    &schedule.project_id.as_str(),
                    &schedule.schedule_id,
                ],
            )
            .await?
        {
            let existing: serde_json::Value = existing.get(0);
            if existing != record {
                return Err(CloudStorageError::SchedulerScheduleConflict);
            }
            transaction.commit().await?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO hartevo_cell.scheduler_schedules
                   (cell, tenant_id, project_id, schedule_id, mission_id_digest, cycle,
                    trigger, status, next_due_at, contract_valid_until, revision, record_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
                &[
                    &schedule.scope.cell.as_str(),
                    &schedule.scope.tenant_id.as_str(),
                    &schedule.project_id.as_str(),
                    &schedule.schedule_id,
                    &schedule.mission_id_digest,
                    &to_sql_u64(schedule.cycle)?,
                    &enum_name(&schedule.trigger)?,
                    &enum_name(&schedule.status)?,
                    &schedule.next_due_at,
                    &schedule.contract_valid_until,
                    &to_sql_u64(schedule.revision)?,
                    &record,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn load_scheduler_schedule(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        schedule_id: &str,
    ) -> Result<SchedulerSchedule, CloudStorageError> {
        if scope.cell != self.cell() {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        if schedule_id.trim().is_empty() {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        let record = transaction
            .query_opt(
                "SELECT record_json FROM hartevo_cell.scheduler_schedules
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND schedule_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &schedule_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::SchedulerScheduleNotFound)?
            .get::<_, serde_json::Value>(0);
        let schedule: SchedulerSchedule = serde_json::from_value(record)?;
        if schedule.scope != *scope
            || schedule.project_id != *project_id
            || schedule.schedule_id != schedule_id
        {
            return Err(CloudStorageError::InvalidSchedulerSchedule);
        }
        schedule.validate()?;
        transaction.commit().await?;
        Ok(schedule)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn claim_scheduler_leader(
        &self,
        client: &mut Client,
        scope: &CellScope,
        lease_key_digest: &str,
        owner_digest: &str,
        token_digest: &str,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<SchedulerLeaderLease, CloudStorageError> {
        validate_lease_request(
            self.cell(),
            scope,
            lease_key_digest,
            owner_digest,
            token_digest,
            lease_for,
        )?;
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(CloudStorageError::InvalidSchedulerLease)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        let previous = transaction
            .query_opt(
                "SELECT owner_digest, generation, claimed_at, heartbeat_at, expires_at
                 FROM hartevo_cell.scheduler_leader_leases
                 WHERE cell = $1 AND tenant_id = $2 AND lease_key_digest = $3
                 FOR UPDATE",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &lease_key_digest,
                ],
            )
            .await?;
        let (generation, claimed_at, previous_owner) = if let Some(row) = previous {
            let previous_expires_at: DateTime<Utc> = row.get(4);
            if previous_expires_at > now {
                return Err(CloudStorageError::SchedulerLeaseActive);
            }
            let previous_generation = from_sql_u64(row.get(1), "scheduler leader generation")?;
            (
                previous_generation
                    .checked_add(1)
                    .ok_or(CloudStorageError::InvalidSchedulerLease)?,
                now,
                Some((row.get::<_, String>(0), previous_generation)),
            )
        } else {
            (1, now, None)
        };
        transaction
            .execute(
                "INSERT INTO hartevo_cell.scheduler_leader_leases
                   (cell, tenant_id, lease_key_digest, owner_digest, token_digest, generation,
                    claimed_at, heartbeat_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)
                 ON CONFLICT (cell, tenant_id, lease_key_digest) DO UPDATE SET
                   owner_digest = EXCLUDED.owner_digest,
                   token_digest = EXCLUDED.token_digest,
                   generation = EXCLUDED.generation,
                   claimed_at = EXCLUDED.claimed_at,
                   heartbeat_at = EXCLUDED.heartbeat_at,
                   expires_at = EXCLUDED.expires_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &lease_key_digest,
                    &owner_digest,
                    &token_digest,
                    &to_sql_u64(generation)?,
                    &claimed_at,
                    &expires_at,
                ],
            )
            .await?;
        if let Some((previous_owner, previous_generation)) = previous_owner {
            insert_takeover(
                &transaction,
                scope,
                None,
                lease_key_digest,
                SchedulerLeaseKind::Leader,
                previous_generation,
                generation,
                &previous_owner,
                owner_digest,
                SchedulerLeaseTakeoverReason::Expired,
                now,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(SchedulerLeaderLease {
            scope: scope.clone(),
            lease_key_digest: lease_key_digest.into(),
            proof: SchedulerLeaseProof {
                owner_digest: owner_digest.into(),
                token_digest: token_digest.into(),
                generation,
            },
            claimed_at,
            heartbeat_at: now,
            expires_at,
        })
    }

    pub async fn heartbeat_scheduler_leader(
        &self,
        client: &mut Client,
        scope: &CellScope,
        lease_key_digest: &str,
        proof: &SchedulerLeaseProof,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<SchedulerLeaderLease, CloudStorageError> {
        validate_lease_request(
            self.cell(),
            scope,
            lease_key_digest,
            &proof.owner_digest,
            &proof.token_digest,
            lease_for,
        )?;
        proof.validate()?;
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(CloudStorageError::InvalidSchedulerLease)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        let row = transaction
            .query_opt(
                "UPDATE hartevo_cell.scheduler_leader_leases
                 SET heartbeat_at = $7, expires_at = $8
                 WHERE cell = $1 AND tenant_id = $2 AND lease_key_digest = $3
                   AND owner_digest = $4 AND token_digest = $5 AND generation = $6
                   AND expires_at > $7
                 RETURNING claimed_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &lease_key_digest,
                    &proof.owner_digest,
                    &proof.token_digest,
                    &to_sql_u64(proof.generation)?,
                    &now,
                    &expires_at,
                ],
            )
            .await?
            .ok_or_else(|| CloudStorageError::SchedulerLeaseLost {
                kind: SchedulerLeaseKind::Leader,
                id: lease_key_digest.into(),
                generation: proof.generation,
            })?;
        let claimed_at: DateTime<Utc> = row.get(0);
        transaction.commit().await?;
        Ok(SchedulerLeaderLease {
            scope: scope.clone(),
            lease_key_digest: lease_key_digest.into(),
            proof: proof.clone(),
            claimed_at,
            heartbeat_at: now,
            expires_at,
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn claim_scheduler_worker(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        schedule_id: &str,
        worker_id_digest: &str,
        owner_digest: &str,
        token_digest: &str,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<SchedulerWorkerLease, CloudStorageError> {
        if schedule_id.trim().is_empty() || !is_sha256(worker_id_digest) {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        validate_lease_request(
            self.cell(),
            scope,
            worker_id_digest,
            owner_digest,
            token_digest,
            lease_for,
        )?;
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(CloudStorageError::InvalidSchedulerLease)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, scope, project_id).await?;
        if transaction
            .query_opt(
                "SELECT 1 FROM hartevo_cell.scheduler_schedules
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND schedule_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &schedule_id,
                ],
            )
            .await?
            .is_none()
        {
            return Err(CloudStorageError::SchedulerScheduleNotFound);
        }
        let previous = transaction
            .query_opt(
                "SELECT owner_digest, generation, claimed_at, heartbeat_at, expires_at
                 FROM hartevo_cell.scheduler_worker_leases
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND schedule_id = $4 AND worker_id_digest = $5
                 FOR UPDATE",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &schedule_id,
                    &worker_id_digest,
                ],
            )
            .await?;
        let (generation, claimed_at, previous_owner) = if let Some(row) = previous {
            let previous_expires_at: DateTime<Utc> = row.get(4);
            if previous_expires_at > now {
                return Err(CloudStorageError::SchedulerLeaseActive);
            }
            let previous_generation = from_sql_u64(row.get(1), "scheduler worker generation")?;
            (
                previous_generation
                    .checked_add(1)
                    .ok_or(CloudStorageError::InvalidSchedulerLease)?,
                now,
                Some((row.get::<_, String>(0), previous_generation)),
            )
        } else {
            (1, now, None)
        };
        transaction
            .execute(
                "INSERT INTO hartevo_cell.scheduler_worker_leases
                   (cell, tenant_id, project_id, schedule_id, worker_id_digest,
                    owner_digest, token_digest, generation, claimed_at, heartbeat_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)
                 ON CONFLICT (cell, tenant_id, project_id, schedule_id, worker_id_digest)
                 DO UPDATE SET owner_digest = EXCLUDED.owner_digest,
                    token_digest = EXCLUDED.token_digest,
                    generation = EXCLUDED.generation,
                    claimed_at = EXCLUDED.claimed_at,
                    heartbeat_at = EXCLUDED.heartbeat_at,
                    expires_at = EXCLUDED.expires_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &schedule_id,
                    &worker_id_digest,
                    &owner_digest,
                    &token_digest,
                    &to_sql_u64(generation)?,
                    &claimed_at,
                    &expires_at,
                ],
            )
            .await?;
        if let Some((previous_owner, previous_generation)) = previous_owner {
            insert_takeover(
                &transaction,
                scope,
                Some(project_id),
                worker_id_digest,
                SchedulerLeaseKind::Worker,
                previous_generation,
                generation,
                &previous_owner,
                owner_digest,
                SchedulerLeaseTakeoverReason::Expired,
                now,
            )
            .await?;
        }
        transaction.commit().await?;
        Ok(SchedulerWorkerLease {
            scope: scope.clone(),
            project_id: project_id.clone(),
            schedule_id: schedule_id.into(),
            worker_id_digest: worker_id_digest.into(),
            proof: SchedulerLeaseProof {
                owner_digest: owner_digest.into(),
                token_digest: token_digest.into(),
                generation,
            },
            claimed_at,
            heartbeat_at: now,
            expires_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn heartbeat_scheduler_worker(
        &self,
        client: &mut Client,
        scope: &CellScope,
        project_id: &ProjectId,
        schedule_id: &str,
        worker_id_digest: &str,
        proof: &SchedulerLeaseProof,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<SchedulerWorkerLease, CloudStorageError> {
        if schedule_id.trim().is_empty() || !is_sha256(worker_id_digest) {
            return Err(CloudStorageError::InvalidSchedulerLease);
        }
        validate_lease_request(
            self.cell(),
            scope,
            worker_id_digest,
            &proof.owner_digest,
            &proof.token_digest,
            lease_for,
        )?;
        proof.validate()?;
        let expires_at = now
            .checked_add_signed(lease_for)
            .ok_or(CloudStorageError::InvalidSchedulerLease)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        let row = transaction
            .query_opt(
                "UPDATE hartevo_cell.scheduler_worker_leases
                 SET heartbeat_at = $8, expires_at = $9
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND schedule_id = $4 AND worker_id_digest = $5
                   AND owner_digest = $6 AND token_digest = $7 AND generation = $10
                   AND expires_at > $8
                 RETURNING claimed_at",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &schedule_id,
                    &worker_id_digest,
                    &proof.owner_digest,
                    &proof.token_digest,
                    &now,
                    &expires_at,
                    &to_sql_u64(proof.generation)?,
                ],
            )
            .await?
            .ok_or_else(|| CloudStorageError::SchedulerLeaseLost {
                kind: SchedulerLeaseKind::Worker,
                id: worker_id_digest.into(),
                generation: proof.generation,
            })?;
        let claimed_at: DateTime<Utc> = row.get(0);
        transaction.commit().await?;
        Ok(SchedulerWorkerLease {
            scope: scope.clone(),
            project_id: project_id.clone(),
            schedule_id: schedule_id.into(),
            worker_id_digest: worker_id_digest.into(),
            proof: proof.clone(),
            claimed_at,
            heartbeat_at: now,
            expires_at,
        })
    }

    pub async fn record_scheduler_attempt(
        &self,
        client: &mut Client,
        attempt: &SchedulerAttempt,
    ) -> Result<(), CloudStorageError> {
        if attempt.scope.cell != self.cell() {
            return Err(CloudStorageError::CellOrTenantScopeMismatch);
        }
        attempt.validate()?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &attempt.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        ensure_project_exists(&transaction, &attempt.scope, &attempt.project_id).await?;
        let record = serde_json::to_value(attempt)?;
        if let Some(existing) = transaction
            .query_opt(
                "SELECT record_json FROM hartevo_cell.scheduler_attempts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND attempt_id_digest = $4 FOR UPDATE",
                &[
                    &attempt.scope.cell.as_str(),
                    &attempt.scope.tenant_id.as_str(),
                    &attempt.project_id.as_str(),
                    &attempt.attempt_id_digest,
                ],
            )
            .await?
        {
            let existing: serde_json::Value = existing.get(0);
            if existing != record {
                return Err(CloudStorageError::SchedulerAttemptConflict);
            }
            transaction.commit().await?;
            return Ok(());
        }
        transaction
            .execute(
                "INSERT INTO hartevo_cell.scheduler_attempts
                   (cell, tenant_id, project_id, schedule_id, attempt_id_digest,
                    worker_generation, surface, outcome, replay, idempotency_key_digest,
                    started_at, updated_at, record_json)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
                &[
                    &attempt.scope.cell.as_str(),
                    &attempt.scope.tenant_id.as_str(),
                    &attempt.project_id.as_str(),
                    &attempt.schedule_id,
                    &attempt.attempt_id_digest,
                    &to_sql_u64(attempt.worker_generation)?,
                    &enum_name(&attempt.surface)?,
                    &enum_name(&attempt.outcome)?,
                    &enum_name(&attempt.replay)?,
                    &attempt.idempotency_key_digest,
                    &attempt.started_at,
                    &attempt.updated_at,
                    &record,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_takeover(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: Option<&ProjectId>,
    lease_id_digest: &str,
    lease_kind: SchedulerLeaseKind,
    previous_generation: u64,
    generation: u64,
    previous_owner_digest: &str,
    owner_digest: &str,
    reason: SchedulerLeaseTakeoverReason,
    observed_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let evidence_digest = scheduler_digest(
        format!("{lease_id_digest}:{previous_generation}:{generation}:{previous_owner_digest}")
            .as_bytes(),
    );
    transaction
        .execute(
            "INSERT INTO hartevo_cell.scheduler_lease_takeovers
               (cell, tenant_id, project_id, lease_kind, lease_id_digest,
                previous_generation, generation, previous_owner_digest, owner_digest,
                reason, evidence_digest, observed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.map(ProjectId::as_str),
                &enum_name(&lease_kind)?,
                &lease_id_digest,
                &to_sql_u64(previous_generation)?,
                &to_sql_u64(generation)?,
                &previous_owner_digest,
                &owner_digest,
                &enum_name(&reason)?,
                &evidence_digest,
                &observed_at,
            ],
        )
        .await?;
    Ok(())
}

fn validate_lease_request(
    expected_cell: DataCell,
    scope: &CellScope,
    lease_id_digest: &str,
    owner_digest: &str,
    token_digest: &str,
    lease_for: Duration,
) -> Result<(), CloudStorageError> {
    if scope.cell != expected_cell
        || scope.tenant_id.as_str().trim().is_empty()
        || !is_sha256(lease_id_digest)
        || !is_sha256(owner_digest)
        || !is_sha256(token_digest)
        || !(1..=MAX_SCHEDULER_LEASE_SECONDS).contains(&lease_for.num_seconds())
    {
        return Err(CloudStorageError::InvalidSchedulerLease);
    }
    Ok(())
}

fn enum_name(value: &impl Serialize) -> Result<String, CloudStorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or(CloudStorageError::InvalidSchedulerSchedule)
}

pub fn scheduler_digest(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn schedule() -> SchedulerSchedule {
        let scope = CellScope {
            cell: DataCell::Us,
            tenant_id: hartevo_domain_kernel::TenantId::from("tenant-scheduler"),
        };
        SchedulerSchedule {
            scope,
            project_id: ProjectId::from("project-scheduler"),
            schedule_id: "schedule-1".into(),
            mission_id_digest: "a".repeat(64),
            cycle: 1,
            trigger: SchedulerTrigger::Interval,
            interval_seconds: 60,
            anchor_at: now(),
            next_due_at: Some(now() + Duration::minutes(1)),
            signal_digest: None,
            contract_valid_until: now() + Duration::days(1),
            budget: SchedulerBudget {
                max_dispatches: 10,
                used_dispatches: 0,
                max_cost_micros: 100,
                used_cost_micros: 0,
                max_runtime_seconds: 100,
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

    #[test]
    fn schedule_contract_coalesces_without_replaying_each_missed_interval() {
        let mut schedule = schedule();
        let due = schedule
            .missed_tick_count(now() + Duration::minutes(4))
            .expect("count ticks")
            .expect("due");
        assert_eq!(due, 4);
        schedule
            .consume_coalesced_ticks(now() + Duration::minutes(4), due)
            .expect("consume one coalesced dispatch");
        assert_eq!(schedule.missed_ticks, 4);
        assert_eq!(schedule.next_due_at, Some(now() + Duration::minutes(5)));
    }

    #[test]
    fn uncertain_attempts_are_never_replayable() {
        let attempt = SchedulerAttempt {
            scope: schedule().scope,
            project_id: ProjectId::from("project-scheduler"),
            schedule_id: "schedule-1".into(),
            attempt_id_digest: "b".repeat(64),
            worker_generation: 1,
            surface: SchedulerAttemptSurface::Effect,
            outcome: SchedulerAttemptOutcome::Uncertain,
            replay: SchedulerReplay::SuppressedUncertain,
            idempotency_key_digest: "c".repeat(64),
            started_at: now(),
            updated_at: now(),
        };
        assert!(attempt.validate().is_ok());
        let mut invalid = attempt;
        invalid.replay = SchedulerReplay::Allowed;
        assert!(matches!(
            invalid.validate(),
            Err(CloudStorageError::InvalidSchedulerAttempt)
        ));
    }

    #[tokio::test]
    async fn postgres_scheduler_gate_reports_blocked_or_checks_schema_rls() {
        let Some(database_url) = std::env::var_os(super::super::POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {} is absent; scheduler PostgreSQL schema/RLS contract did not execute",
                super::super::POSTGRES_L2_URL_ENV
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let (mut client, connection) =
            tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                .await
                .expect("connect disposable PostgreSQL scheduler database");
        let _connection_task = tokio::spawn(connection);
        let role = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect PostgreSQL scheduler test role");
        assert!(!role.get::<_, bool>(0) && !role.get::<_, bool>(1));

        let store = PostgresCellStore::new(DataCell::Us);
        store
            .migrate(&mut client, now())
            .await
            .expect("migrate scheduler Cell schema");
        for table in [
            "scheduler_schedules",
            "scheduler_leader_leases",
            "scheduler_worker_leases",
            "scheduler_tenant_state",
            "scheduler_lease_takeovers",
            "scheduler_attempts",
        ] {
            let forced = client
                .query_one(
                    "SELECT relforcerowsecurity FROM pg_class
                     WHERE relnamespace = 'hartevo_cell'::regnamespace AND relname = $1",
                    &[&table],
                )
                .await
                .expect("find scheduler table");
            assert!(
                forced.get::<_, bool>(0),
                "scheduler table is not FORCE RLS: {table}"
            );
        }
    }
}
