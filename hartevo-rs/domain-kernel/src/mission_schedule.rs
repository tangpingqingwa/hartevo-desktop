use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::mission::next_interval_due_at;
use crate::{
    CadenceTriggerKind, Mission, MissionId, MissionScheduleId, MissionStage, ProjectId, TenantId,
};

const MAX_FAILURES: usize = 5;
const MAX_LEASE_SECONDS: i64 = 15 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionScheduleStatus {
    Pending,
    Leased,
    Triggered,
    Cancelled,
    Expired,
    DeadLetter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionScheduleFailureClass {
    LeaseExpired,
    CoordinatorRestart,
    RuntimeUnavailable,
    MissionConflict,
    InvalidTrigger,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleSignal {
    pub topic: String,
    pub event_id_digest: String,
    pub payload_digest: String,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleLease {
    pub owner_digest: String,
    pub token_digest: String,
    pub generation: u64,
    pub claimed_at: DateTime<Utc>,
    pub heartbeat_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionScheduleFailure {
    pub sequence: u32,
    pub class: MissionScheduleFailureClass,
    pub evidence_digest: String,
    pub retryable: bool,
    pub observed_at: DateTime<Utc>,
}

/// Durable authority for exactly one future Mission cycle.
///
/// The record carries only worker/token digests. A caller must present the raw
/// owner and token again at the Application boundary; neither value belongs in
/// Domain events, Desktop projections, or logs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSchedule {
    pub id: MissionScheduleId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub cycle: u64,
    pub scheduled_from_mission_revision: u64,
    pub contract_version: u64,
    pub definition_cycle: Option<u64>,
    pub trigger: CadenceTriggerKind,
    pub interval_seconds: u64,
    pub anchor_at: DateTime<Utc>,
    pub event_topics: BTreeSet<String>,
    pub due_at: Option<DateTime<Utc>>,
    pub retry_not_before: Option<DateTime<Utc>>,
    pub contract_valid_until: DateTime<Utc>,
    pub signal: Option<MissionScheduleSignal>,
    pub status: MissionScheduleStatus,
    pub lease_generation: u64,
    pub lease: Option<MissionScheduleLease>,
    pub failures: Vec<MissionScheduleFailure>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MissionSchedule {
    pub fn prepare(mission: &Mission, now: DateTime<Utc>) -> Result<Self, MissionScheduleError> {
        if mission.stage != MissionStage::Scheduled {
            return Err(MissionScheduleError::MissionNotScheduled);
        }
        mission.contract.validate(now)?;
        let cadence = mission
            .contract
            .cadence
            .as_ref()
            .ok_or(MissionScheduleError::CadenceMissing)?;
        let outcome = mission
            .outcome_history
            .last()
            .ok_or(MissionScheduleError::OutcomeMissing)?;
        if outcome.observed_at > now || mission.contract.valid_until <= now {
            return Err(MissionScheduleError::OutsideContractWindow);
        }
        let cycle = u64::try_from(mission.outcome_history.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(MissionScheduleError::CycleOverflow)?;
        if cycle < 2
            || mission
                .definition
                .as_ref()
                .is_some_and(|definition| definition.cycle.checked_add(1) != Some(cycle))
        {
            return Err(MissionScheduleError::CycleMismatch);
        }
        let due_at = if cadence.trigger == CadenceTriggerKind::EventDriven {
            None
        } else {
            Some(next_interval_due_at(cadence, now).ok_or(MissionScheduleError::CycleOverflow)?)
        };
        if cadence.trigger == CadenceTriggerKind::Interval
            && due_at.is_some_and(|due| due >= mission.contract.valid_until)
        {
            return Err(MissionScheduleError::OutsideContractWindow);
        }
        let schedule = Self {
            id: MissionScheduleId::from_stable(format!(
                "mission-schedule:{}:cycle:{cycle}",
                mission.id
            )),
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            cycle,
            scheduled_from_mission_revision: mission.revision,
            contract_version: mission.contract.version,
            definition_cycle: mission
                .definition
                .as_ref()
                .map(|definition| definition.cycle),
            trigger: cadence.trigger,
            interval_seconds: cadence.interval_seconds,
            anchor_at: cadence.anchor_at,
            event_topics: cadence.event_topics.clone(),
            due_at,
            retry_not_before: None,
            contract_valid_until: mission.contract.valid_until,
            signal: None,
            status: MissionScheduleStatus::Pending,
            lease_generation: 0,
            lease: None,
            failures: Vec::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    pub fn validate(&self) -> Result<(), MissionScheduleError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.cycle < 2
            || self.scheduled_from_mission_revision == 0
            || self.contract_version == 0
            || self
                .definition_cycle
                .is_some_and(|cycle| cycle.checked_add(1) != Some(self.cycle))
            || self.contract_valid_until <= self.created_at
            || self.updated_at < self.created_at
            || self.revision == 0
            || self
                .event_topics
                .iter()
                .any(|topic| topic.trim().is_empty())
            || !trigger_shape_is_valid(self)
            || self
                .retry_not_before
                .is_some_and(|value| value >= self.contract_valid_until)
            || self.signal.as_ref().is_some_and(|signal| {
                !self.event_topics.contains(&signal.topic)
                    || !is_sha256(&signal.event_id_digest)
                    || !is_sha256(&signal.payload_digest)
                    || signal.observed_at < self.created_at
                    || signal.observed_at >= self.contract_valid_until
            })
            || self.failures.len() > MAX_FAILURES
            || self.failures.iter().enumerate().any(|(index, failure)| {
                usize::try_from(failure.sequence).ok() != Some(index + 1)
                    || !is_sha256(&failure.evidence_digest)
                    || failure.observed_at < self.created_at
            })
        {
            return Err(MissionScheduleError::InvalidRecord);
        }
        match self.status {
            MissionScheduleStatus::Pending
            | MissionScheduleStatus::Cancelled
            | MissionScheduleStatus::Expired
            | MissionScheduleStatus::DeadLetter => {
                if self.lease.is_some() {
                    return Err(MissionScheduleError::InvalidRecord);
                }
            }
            MissionScheduleStatus::Leased | MissionScheduleStatus::Triggered => {
                let lease = self
                    .lease
                    .as_ref()
                    .ok_or(MissionScheduleError::InvalidRecord)?;
                if lease.generation != self.lease_generation
                    || lease.generation == 0
                    || !is_sha256(&lease.owner_digest)
                    || !is_sha256(&lease.token_digest)
                    || lease.claimed_at < self.created_at
                    || lease.heartbeat_at < lease.claimed_at
                    || lease.expires_at <= lease.heartbeat_at
                {
                    return Err(MissionScheduleError::InvalidRecord);
                }
            }
        }
        Ok(())
    }

    pub fn is_due(&self, now: DateTime<Utc>) -> bool {
        self.status == MissionScheduleStatus::Pending
            && now < self.contract_valid_until
            && self.retry_not_before.is_none_or(|retry_at| retry_at <= now)
            && (self.signal.is_some() || self.due_at.is_some_and(|due_at| due_at <= now))
    }

    pub fn signal_event(
        &mut self,
        topic: impl Into<String>,
        event_id_digest: impl Into<String>,
        payload_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<bool, MissionScheduleError> {
        self.validate()?;
        if self.status != MissionScheduleStatus::Pending {
            return Err(MissionScheduleError::NotSignalable);
        }
        let candidate = MissionScheduleSignal {
            topic: topic.into(),
            event_id_digest: event_id_digest.into(),
            payload_digest: payload_digest.into(),
            observed_at,
        };
        if !self.event_topics.contains(&candidate.topic)
            || !is_sha256(&candidate.event_id_digest)
            || !is_sha256(&candidate.payload_digest)
            || observed_at < self.created_at
            || observed_at >= self.contract_valid_until
        {
            return Err(MissionScheduleError::InvalidSignal);
        }
        if self.signal.as_ref() == Some(&candidate) {
            return Ok(false);
        }
        if self.signal.is_some() {
            return Err(MissionScheduleError::SignalAlreadyBound);
        }
        self.ensure_touchable()?;
        self.signal = Some(candidate);
        self.touch(observed_at);
        self.validate()?;
        Ok(true)
    }

    pub fn claim(
        &mut self,
        owner_digest: impl Into<String>,
        token_digest: impl Into<String>,
        lease_duration: Duration,
        now: DateTime<Utc>,
    ) -> Result<MissionScheduleLease, MissionScheduleError> {
        self.validate()?;
        let owner_digest = owner_digest.into();
        let token_digest = token_digest.into();
        let lease_seconds = lease_duration.num_seconds();
        if !is_sha256(&owner_digest)
            || !is_sha256(&token_digest)
            || !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds)
            || now >= self.contract_valid_until
        {
            return Err(MissionScheduleError::InvalidLease);
        }
        if self.status == MissionScheduleStatus::Leased {
            let previous = self
                .lease
                .as_ref()
                .ok_or(MissionScheduleError::InvalidRecord)?;
            if previous.expires_at > now {
                return Err(MissionScheduleError::LeaseActive);
            }
            let failure = MissionScheduleFailure {
                sequence: u32::try_from(self.failures.len() + 1)
                    .map_err(|_| MissionScheduleError::FailureLimitReached)?,
                class: MissionScheduleFailureClass::LeaseExpired,
                evidence_digest: sha256(
                    format!(
                        "{}:{}:{}",
                        previous.owner_digest, previous.token_digest, previous.generation
                    )
                    .as_bytes(),
                ),
                retryable: true,
                observed_at: now,
            };
            self.failures.push(failure);
            if self.failures.len() >= MAX_FAILURES {
                self.ensure_touchable()?;
                self.status = MissionScheduleStatus::DeadLetter;
                self.lease = None;
                self.touch(now);
                return Err(MissionScheduleError::FailureLimitReached);
            }
        } else if !self.is_due(now) {
            return Err(MissionScheduleError::NotDue);
        }
        let generation = self
            .lease_generation
            .checked_add(1)
            .ok_or(MissionScheduleError::RevisionOverflow)?;
        let expires_at = now
            .checked_add_signed(lease_duration)
            .ok_or(MissionScheduleError::InvalidLease)?;
        if expires_at >= self.contract_valid_until {
            return Err(MissionScheduleError::InvalidLease);
        }
        self.ensure_touchable()?;
        let lease = MissionScheduleLease {
            owner_digest,
            token_digest,
            generation,
            claimed_at: now,
            heartbeat_at: now,
            expires_at,
        };
        self.status = MissionScheduleStatus::Leased;
        self.lease_generation = generation;
        self.lease = Some(lease.clone());
        self.retry_not_before = None;
        self.touch(now);
        self.validate()?;
        Ok(lease)
    }

    pub fn heartbeat(
        &mut self,
        owner_digest: &str,
        token_digest: &str,
        generation: u64,
        lease_duration: Duration,
        now: DateTime<Utc>,
    ) -> Result<(), MissionScheduleError> {
        self.validate()?;
        self.verify_lease(owner_digest, token_digest, generation, now)?;
        let lease_seconds = lease_duration.num_seconds();
        if !(1..=MAX_LEASE_SECONDS).contains(&lease_seconds) {
            return Err(MissionScheduleError::InvalidLease);
        }
        let expires_at = now
            .checked_add_signed(lease_duration)
            .ok_or(MissionScheduleError::InvalidLease)?;
        if expires_at >= self.contract_valid_until {
            return Err(MissionScheduleError::InvalidLease);
        }
        self.ensure_touchable()?;
        let lease = self
            .lease
            .as_mut()
            .ok_or(MissionScheduleError::InvalidRecord)?;
        lease.heartbeat_at = now;
        lease.expires_at = expires_at;
        self.touch(now);
        self.validate()
    }

    pub fn mark_triggered(
        &mut self,
        owner_digest: &str,
        token_digest: &str,
        generation: u64,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<(), MissionScheduleError> {
        self.validate()?;
        self.verify_lease(owner_digest, token_digest, generation, now)?;
        if mission.tenant_id != self.tenant_id
            || mission.project_id != self.project_id
            || mission.id != self.mission_id
            || mission.stage != MissionStage::Running
            || u64::try_from(mission.outcome_history.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                != Some(self.cycle)
            || mission
                .definition
                .as_ref()
                .is_some_and(|definition| definition.cycle != self.cycle)
        {
            return Err(MissionScheduleError::CycleMismatch);
        }
        self.ensure_touchable()?;
        self.status = MissionScheduleStatus::Triggered;
        self.touch(now);
        self.validate()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "a failed schedule lease is fenced by its complete exact proof and retry evidence"
    )]
    pub fn record_failure(
        &mut self,
        owner_digest: &str,
        token_digest: &str,
        generation: u64,
        class: MissionScheduleFailureClass,
        evidence_digest: impl Into<String>,
        retryable: bool,
        retry_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Result<(), MissionScheduleError> {
        self.validate()?;
        self.verify_lease(owner_digest, token_digest, generation, now)?;
        let evidence_digest = evidence_digest.into();
        if !is_sha256(&evidence_digest)
            || retryable
                != retry_at
                    .is_some_and(|retry_at| retry_at > now && retry_at < self.contract_valid_until)
        {
            return Err(MissionScheduleError::InvalidFailure);
        }
        if self.failures.len() >= MAX_FAILURES {
            return Err(MissionScheduleError::FailureLimitReached);
        }
        self.ensure_touchable()?;
        self.failures.push(MissionScheduleFailure {
            sequence: u32::try_from(self.failures.len() + 1)
                .map_err(|_| MissionScheduleError::FailureLimitReached)?,
            class,
            evidence_digest,
            retryable,
            observed_at: now,
        });
        if retryable && self.failures.len() < MAX_FAILURES {
            self.status = MissionScheduleStatus::Pending;
            self.retry_not_before = retry_at;
        } else {
            self.status = MissionScheduleStatus::DeadLetter;
            self.retry_not_before = None;
        }
        self.lease = None;
        self.touch(now);
        self.validate()
    }

    pub fn cancel(
        &mut self,
        evidence_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(), MissionScheduleError> {
        self.validate()?;
        if !matches!(
            self.status,
            MissionScheduleStatus::Pending | MissionScheduleStatus::Leased
        ) || !is_sha256(evidence_digest)
        {
            return Err(MissionScheduleError::NotCancellable);
        }
        self.ensure_touchable()?;
        self.status = MissionScheduleStatus::Cancelled;
        self.lease = None;
        self.retry_not_before = None;
        self.touch(now);
        self.validate()
    }

    /// Closes a future cycle when its exact Operating Contract window ends.
    ///
    /// Expiry is not a user cancellation and never consumes or replays a
    /// lease. The corresponding Mission terminal transition is committed by
    /// Storage in the same transaction as this Schedule transition.
    pub fn expire(&mut self, now: DateTime<Utc>) -> Result<(), MissionScheduleError> {
        self.validate()?;
        if !matches!(
            self.status,
            MissionScheduleStatus::Pending | MissionScheduleStatus::Leased
        ) || now < self.contract_valid_until
        {
            return Err(MissionScheduleError::NotExpirable);
        }
        self.ensure_touchable()?;
        self.status = MissionScheduleStatus::Expired;
        self.lease = None;
        self.retry_not_before = None;
        self.touch(now);
        self.validate()
    }

    fn verify_lease(
        &self,
        owner_digest: &str,
        token_digest: &str,
        generation: u64,
        now: DateTime<Utc>,
    ) -> Result<(), MissionScheduleError> {
        let lease = self.lease.as_ref().ok_or(MissionScheduleError::LeaseLost)?;
        if self.status != MissionScheduleStatus::Leased
            || lease.owner_digest != owner_digest
            || lease.token_digest != token_digest
            || lease.generation != generation
            || lease.expires_at <= now
        {
            return Err(MissionScheduleError::LeaseLost);
        }
        Ok(())
    }

    fn ensure_touchable(&self) -> Result<(), MissionScheduleError> {
        self.revision
            .checked_add(1)
            .map(|_| ())
            .ok_or(MissionScheduleError::RevisionOverflow)
    }

    fn touch(&mut self, now: DateTime<Utc>) {
        self.revision += 1;
        self.updated_at = now;
    }
}

fn trigger_shape_is_valid(schedule: &MissionSchedule) -> bool {
    match schedule.trigger {
        CadenceTriggerKind::Interval => {
            schedule.interval_seconds > 0
                && schedule.event_topics.is_empty()
                && schedule.due_at.is_some()
                && schedule.signal.is_none()
        }
        CadenceTriggerKind::EventDriven => {
            schedule.interval_seconds == 0
                && !schedule.event_topics.is_empty()
                && schedule.due_at.is_none()
        }
        CadenceTriggerKind::IntervalOrEvent => {
            schedule.interval_seconds > 0
                && !schedule.event_topics.is_empty()
                && schedule.due_at.is_some()
        }
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionScheduleError {
    #[error(transparent)]
    OperatingContract(#[from] crate::OperatingContractError),
    #[error("Mission must be in Scheduled before a future cycle can be prepared")]
    MissionNotScheduled,
    #[error("scheduled Mission has no cadence")]
    CadenceMissing,
    #[error("cadence cannot produce an anchored future trigger")]
    CadenceInvalid,
    #[error("scheduled Mission has no reviewed Outcome")]
    OutcomeMissing,
    #[error("Mission schedule is outside the Operating Contract validity window")]
    OutsideContractWindow,
    #[error("Mission schedule cycle overflowed")]
    CycleOverflow,
    #[error("Mission schedule does not match the exact Mission cycle")]
    CycleMismatch,
    #[error("Mission schedule record is malformed or projection-inconsistent")]
    InvalidRecord,
    #[error("Mission schedule does not accept an event signal in its current state")]
    NotSignalable,
    #[error("Mission schedule event topic, digest, or time is invalid")]
    InvalidSignal,
    #[error("Mission schedule already bound a different first event signal")]
    SignalAlreadyBound,
    #[error("Mission schedule is not due")]
    NotDue,
    #[error("Mission schedule lease owner, token, duration, or validity is invalid")]
    InvalidLease,
    #[error("Mission schedule already has an unexpired lease")]
    LeaseActive,
    #[error("Mission schedule lease proof is stale, expired, or owned elsewhere")]
    LeaseLost,
    #[error("Mission schedule failure evidence or retry window is invalid")]
    InvalidFailure,
    #[error("Mission schedule exhausted its bounded failure budget")]
    FailureLimitReached,
    #[error("Mission schedule cannot be cancelled in its current state")]
    NotCancellable,
    #[error("Mission schedule cannot expire before its Operating Contract boundary")]
    NotExpirable,
    #[error("Mission schedule revision overflowed")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        Cadence, MissionContract, OperatingMode, Outcome, OutcomeDecision, Task, TaskId, TaskStatus,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 9, 0, 0)
            .single()
            .expect("valid time")
    }

    fn scheduled_mission(trigger: CadenceTriggerKind) -> Mission {
        let mut contract = MissionContract::bootstrap(
            "Operate a verified recurring Mission",
            ["outcome.review".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousRelationship;
        contract.valid_until = now() + Duration::days(90);
        contract.cadence = Some(Cadence {
            interval_seconds: if trigger == CadenceTriggerKind::EventDriven {
                0
            } else {
                7 * 24 * 60 * 60
            },
            anchor_at: now(),
            trigger,
            event_topics: if trigger == CadenceTriggerKind::Interval {
                BTreeSet::new()
            } else {
                BTreeSet::from(["conversation.inbound".into()])
            },
        });
        let mut mission = Mission::compile(
            TenantId::from("tenant-1"),
            MissionId::from("mission-1"),
            ProjectId::from("project-1"),
            "Relationship operator",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-1"),
                    title: "First cycle".into(),
                    status: TaskStatus::Running,
                    capability: "outcome.review".into(),
                }],
                now(),
            )
            .expect("first cycle");
        mission
            .record_outcome(Outcome {
                summary: "Cycle one reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(1),
            })
            .expect("schedule next cycle");
        mission
    }

    #[test]
    fn interval_schedule_is_anchor_aligned_and_cannot_be_claimed_early() {
        let mission = scheduled_mission(CadenceTriggerKind::Interval);
        let mut schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        assert_eq!(schedule.cycle, 2);
        assert_eq!(schedule.due_at, Some(now() + Duration::days(7)));
        assert_eq!(
            schedule.claim(
                "a".repeat(64),
                "b".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(2),
            ),
            Err(MissionScheduleError::NotDue)
        );
        schedule
            .claim(
                "a".repeat(64),
                "b".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(7),
            )
            .expect("due claim");
        assert_eq!(schedule.status, MissionScheduleStatus::Leased);
    }

    #[test]
    fn event_schedule_binds_first_signal_and_exact_lease_generation() {
        let mission = scheduled_mission(CadenceTriggerKind::EventDriven);
        let mut schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        assert_eq!(schedule.due_at, None);
        assert!(!schedule.is_due(now() + Duration::days(2)));
        schedule
            .signal_event(
                "conversation.inbound",
                "c".repeat(64),
                "d".repeat(64),
                now() + Duration::days(2),
            )
            .expect("signal");
        assert!(schedule.is_due(now() + Duration::days(2)));
        let lease = schedule
            .claim(
                "a".repeat(64),
                "b".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(2),
            )
            .expect("claim");
        assert_eq!(lease.generation, 1);
        assert_eq!(
            schedule.heartbeat(
                &"a".repeat(64),
                &"0".repeat(64),
                1,
                Duration::minutes(5),
                now() + Duration::days(2) + Duration::minutes(1),
            ),
            Err(MissionScheduleError::LeaseLost)
        );
    }

    #[test]
    fn expired_leases_are_generation_fenced_and_failures_are_bounded() {
        let mission = scheduled_mission(CadenceTriggerKind::Interval);
        let mut schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        let due = now() + Duration::days(7);
        schedule
            .claim("a".repeat(64), "b".repeat(64), Duration::minutes(1), due)
            .expect("first claim");
        let second = schedule
            .claim(
                "c".repeat(64),
                "d".repeat(64),
                Duration::minutes(1),
                due + Duration::minutes(2),
            )
            .expect("reclaimed");
        assert_eq!(second.generation, 2);
        assert_eq!(schedule.failures.len(), 1);
        assert_eq!(
            schedule.record_failure(
                &"a".repeat(64),
                &"b".repeat(64),
                1,
                MissionScheduleFailureClass::RuntimeUnavailable,
                "e".repeat(64),
                true,
                Some(due + Duration::minutes(4)),
                due + Duration::minutes(3),
            ),
            Err(MissionScheduleError::LeaseLost)
        );
    }

    #[test]
    fn contract_expiry_closes_a_pending_or_leased_cycle_without_replay() {
        let mission = scheduled_mission(CadenceTriggerKind::Interval);
        let mut schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        assert_eq!(
            schedule.expire(now() + Duration::days(89)),
            Err(MissionScheduleError::NotExpirable)
        );
        schedule
            .claim(
                "a".repeat(64),
                "b".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(7),
            )
            .expect("lease");
        schedule
            .expire(now() + Duration::days(90))
            .expect("contract expiry");
        assert_eq!(schedule.status, MissionScheduleStatus::Expired);
        assert!(schedule.lease.is_none());
        assert!(!schedule.is_due(now() + Duration::days(91)));
        assert_eq!(
            schedule.claim(
                "c".repeat(64),
                "d".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(91),
            ),
            Err(MissionScheduleError::InvalidLease)
        );
    }

    #[test]
    fn hybrid_schedule_preserves_the_last_event_window_past_its_interval_due_date() {
        let mut contract = MissionContract::bootstrap(
            "Operate an event-or-weekly relationship",
            ["outcome.review".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousRelationship;
        contract.valid_until = now() + Duration::days(5);
        contract.cadence = Some(Cadence {
            interval_seconds: 7 * 24 * 60 * 60,
            anchor_at: now(),
            trigger: CadenceTriggerKind::IntervalOrEvent,
            event_topics: BTreeSet::from(["conversation.inbound".into()]),
        });
        let mut mission = Mission::compile(
            TenantId::from("tenant-hybrid"),
            MissionId::from("mission-hybrid"),
            ProjectId::from("project-hybrid"),
            "Hybrid relationship",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("first cycle");
        mission
            .record_outcome(Outcome {
                summary: "First cycle reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(1),
            })
            .expect("outcome");
        assert_eq!(mission.stage, MissionStage::Scheduled);
        let mut schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        assert_eq!(schedule.due_at, Some(now() + Duration::days(7)));
        schedule
            .signal_event(
                "conversation.inbound",
                "c".repeat(64),
                "d".repeat(64),
                now() + Duration::days(4),
            )
            .expect("event inside final contract window");
        assert!(schedule.is_due(now() + Duration::days(4)));
    }
}
