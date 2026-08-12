use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    Conversation, Mission, MissionId, MissionSchedule, MissionScheduleError, MissionScheduleId,
    MissionScheduleStatus, MissionStage, MissionTerminalDisposition, ProjectId,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::normalized::{load_mission_normalized, update_mission_normalized_cas};
use crate::relationship_store::{
    ensure_conversation_scope, persist_conversation_messages, require_next, require_updated,
    update_conversation_row, validate_conversation, validate_conversation_transition,
};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Persists a verified inbound Conversation event and the first matching
    /// event-driven schedule signal atomically. A coordinator crash cannot
    /// retain the message while losing the wake-up, or wake without the message.
    pub fn update_conversation_and_signal_schedule_atomic(
        &mut self,
        conversation: &Conversation,
        expected_conversation_revision: u64,
        schedule: &MissionSchedule,
        expected_schedule_revision: u64,
        conversation_events: &[PendingEvent],
        schedule_events: &[PendingEvent],
    ) -> Result<(), StorageError> {
        validate_conversation(conversation)?;
        require_next(expected_conversation_revision, conversation.revision)?;
        validate_conversation_transition(self, conversation, expected_conversation_revision)?;
        validate_schedule(schedule)?;
        if conversation_events.is_empty() || schedule_events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if conversation.tenant_id != schedule.tenant_id
            || conversation.project_id != schedule.project_id
            || conversation.mission_id.as_ref() != Some(&schedule.mission_id)
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        let transaction = self.connection.transaction()?;
        ensure_conversation_scope(&transaction, conversation)?;
        let previous = load_schedule(&transaction, &schedule.project_id, &schedule.id)?;
        validate_schedule_transition(&previous, schedule, expected_schedule_revision)?;
        let updated =
            update_conversation_row(&transaction, conversation, expected_conversation_revision)?;
        require_updated(
            updated,
            "conversation",
            conversation.id.as_str(),
            expected_conversation_revision,
        )?;
        persist_conversation_messages(&transaction, conversation)?;
        update_schedule_row(&transaction, schedule, expected_schedule_revision)?;
        append_events(
            &transaction,
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            conversation.mission_id.as_ref().map(MissionId::as_str),
            "conversation",
            conversation.id.as_str(),
            conversation_events,
        )?;
        append_events(
            &transaction,
            schedule.tenant_id.as_str(),
            schedule.project_id.as_str(),
            Some(schedule.mission_id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            schedule_events,
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Commits the reviewed Mission Outcome and its exact next-cycle schedule
    /// as one SQLCipher transaction. A crash can expose neither half alone.
    pub fn update_mission_and_create_schedule_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        schedule: &MissionSchedule,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        validate_schedule(schedule)?;
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if mission.revision <= expected_mission_revision
            || mission.stage != MissionStage::Scheduled
            || schedule.revision != 1
            || schedule.tenant_id != mission.tenant_id
            || schedule.project_id != mission.project_id
            || schedule.mission_id != mission.id
            || schedule.scheduled_from_mission_revision != mission.revision
            || u64::try_from(mission.outcome_history.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                != Some(schedule.cycle)
            || schedule.definition_cycle
                != mission
                    .definition
                    .as_ref()
                    .map(|definition| definition.cycle)
        {
            return Err(StorageError::DomainDecode(
                "Mission and next-cycle schedule are not one exact reviewed state".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        insert_schedule(&transaction, schedule)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    pub fn load_mission_schedule(
        &self,
        project_id: &ProjectId,
        schedule_id: &MissionScheduleId,
    ) -> Result<MissionSchedule, StorageError> {
        load_schedule(&self.connection, project_id, schedule_id)
    }

    pub fn list_mission_schedules(
        &self,
        project_id: &ProjectId,
        mission_id: Option<&MissionId>,
    ) -> Result<Vec<MissionSchedule>, StorageError> {
        self.load_project(project_id)?;
        let ids = if let Some(mission_id) = mission_id {
            self.load_mission(project_id, mission_id)?;
            let mut statement = self.connection.prepare(
                "SELECT id FROM mission_schedules
                 WHERE project_id = ?1 AND mission_id = ?2 ORDER BY cycle ASC, id ASC",
            )?;
            statement
                .query_map(params![project_id.as_str(), mission_id.as_str()], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            let mut statement = self.connection.prepare(
                "SELECT id FROM mission_schedules
                 WHERE project_id = ?1 ORDER BY mission_id ASC, cycle ASC, id ASC",
            )?;
            statement
                .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| self.load_mission_schedule(project_id, &MissionScheduleId::from_stable(id)))
            .collect()
    }

    pub fn latest_mission_schedule(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Option<MissionSchedule>, StorageError> {
        self.load_mission(project_id, mission_id)?;
        let id = self
            .connection
            .query_row(
                "SELECT id FROM mission_schedules
                 WHERE project_id = ?1 AND mission_id = ?2
                 ORDER BY cycle DESC, id DESC LIMIT 1",
                params![project_id.as_str(), mission_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        id.map(|id| self.load_mission_schedule(project_id, &MissionScheduleId::from_stable(id)))
            .transpose()
    }

    /// Returns only non-terminal schedules whose exact Operating Contract
    /// window has ended. Callers must close each Schedule and its Mission in
    /// one atomic transition before normal scheduling resumes.
    pub fn list_expired_mission_schedules(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<MissionSchedule>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT project_id, id FROM mission_schedules
             WHERE status IN ('pending', 'leased') AND contract_valid_until <= ?1
             ORDER BY contract_valid_until, created_at, project_id, mission_id, cycle",
        )?;
        let ids = statement
            .query_map([now.to_rfc3339()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|(project_id, schedule_id)| {
                self.load_mission_schedule(
                    &ProjectId::from_stable(project_id),
                    &MissionScheduleId::from_stable(schedule_id),
                )
            })
            .collect()
    }

    pub fn update_mission_schedule_atomic(
        &mut self,
        schedule: &MissionSchedule,
        expected_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        validate_schedule(schedule)?;
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let transaction = self.connection.transaction()?;
        let previous = load_schedule(&transaction, &schedule.project_id, &schedule.id)?;
        validate_schedule_transition(&previous, schedule, expected_revision)?;
        update_schedule_row(&transaction, schedule, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            schedule.tenant_id.as_str(),
            schedule.project_id.as_str(),
            Some(schedule.mission_id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: schedule.revision,
        })
    }

    /// Claims one due schedule under `BEGIN IMMEDIATE`, making concurrent
    /// Desktop coordinators and restart recovery generation-safe.
    pub fn claim_due_mission_schedule(
        &mut self,
        owner_digest: &str,
        token_digest: &str,
        lease_duration: Duration,
        now: DateTime<Utc>,
    ) -> Result<Option<MissionSchedule>, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT project_id, id FROM mission_schedules
                 WHERE contract_valid_until > ?1 AND (
                   (status = 'pending'
                     AND (retry_not_before IS NULL OR retry_not_before <= ?1)
                     AND (signal_event_id_digest IS NOT NULL OR due_at <= ?1))
                   OR (status = 'leased' AND lease_expires_at <= ?1)
                 )
                 ORDER BY
                   CASE WHEN signal_event_id_digest IS NOT NULL THEN 0 ELSE 1 END,
                   COALESCE(retry_not_before, due_at, lease_expires_at),
                   created_at, project_id, mission_id, cycle
                 LIMIT 1",
                [now.to_rfc3339()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((project_id, schedule_id)) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        let project_id = ProjectId::from_stable(project_id);
        let schedule_id = MissionScheduleId::from_stable(schedule_id);
        let mut schedule = load_schedule(&transaction, &project_id, &schedule_id)?;
        let expected_revision = schedule.revision;
        let claim = schedule.claim(owner_digest, token_digest, lease_duration, now);
        if claim == Err(MissionScheduleError::FailureLimitReached)
            && schedule.status == MissionScheduleStatus::DeadLetter
        {
            commit_exhausted_schedule_claim(transaction, &schedule, expected_revision, now)?;
            return Ok(None);
        }
        let lease = claim?;
        update_schedule_row(&transaction, &schedule, expected_revision)?;
        append_events(
            &transaction,
            schedule.tenant_id.as_str(),
            schedule.project_id.as_str(),
            Some(schedule.mission_id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            &[PendingEvent::new(
                "mission.schedule_claimed",
                serde_json::json!({
                    "scheduleId": schedule.id,
                    "missionId": schedule.mission_id,
                    "cycle": schedule.cycle,
                    "trigger": schedule.trigger,
                    "signalReceived": schedule.signal.is_some(),
                    "dueAt": schedule.due_at,
                    "leaseGeneration": lease.generation,
                    "leaseExpiresAt": lease.expires_at,
                }),
                now,
            )],
        )?;
        transaction.commit()?;
        Ok(Some(schedule))
    }

    /// Commits a claimed Schedule terminal transition and the corresponding
    /// Mission cycle start together. The scheduler lease can never be consumed
    /// while the Mission remains `Scheduled`, or vice versa.
    pub fn trigger_mission_schedule_and_start_cycle_atomic(
        &mut self,
        schedule: &MissionSchedule,
        expected_schedule_revision: u64,
        mission: &Mission,
        expected_mission_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        validate_schedule(schedule)?;
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if schedule.status != MissionScheduleStatus::Triggered
            || mission.stage != MissionStage::Running
            || schedule.tenant_id != mission.tenant_id
            || schedule.project_id != mission.project_id
            || schedule.mission_id != mission.id
            || schedule.scheduled_from_mission_revision != expected_mission_revision
            || mission.revision <= expected_mission_revision
            || mission
                .definition
                .as_ref()
                .is_some_and(|definition| definition.cycle != schedule.cycle)
        {
            return Err(StorageError::DomainDecode(
                "triggered schedule and running Mission cycle do not match".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let previous = load_schedule(&transaction, &schedule.project_id, &schedule.id)?;
        validate_schedule_transition(&previous, schedule, expected_schedule_revision)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_schedule_row(&transaction, schedule, expected_schedule_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    /// Commits natural contract expiry as one Schedule+Mission transition.
    /// A restart can observe neither an expired Schedule with a still-running
    /// Mission nor a completed Mission with a replayable Schedule lease.
    pub fn expire_mission_schedule_and_complete_mission_atomic(
        &mut self,
        schedule: &MissionSchedule,
        expected_schedule_revision: u64,
        mission: &Mission,
        expected_mission_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        validate_schedule(schedule)?;
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if schedule.status != MissionScheduleStatus::Expired
            || mission.stage != MissionStage::Completed
            || schedule.tenant_id != mission.tenant_id
            || schedule.project_id != mission.project_id
            || schedule.mission_id != mission.id
            || schedule.scheduled_from_mission_revision != expected_mission_revision
            || schedule.contract_version != mission.contract.version
            || schedule.contract_valid_until != mission.contract.valid_until
            || schedule.updated_at < schedule.contract_valid_until
            || mission.revision
                != expected_mission_revision
                    .checked_add(1)
                    .ok_or(StorageError::RevisionOverflow(expected_mission_revision))?
            || u64::try_from(mission.outcome_history.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                != Some(schedule.cycle)
        {
            return Err(StorageError::DomainDecode(
                "expired schedule and completed Mission do not match one contract boundary".into(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let previous = load_schedule(&transaction, &schedule.project_id, &schedule.id)?;
        validate_schedule_transition(&previous, schedule, expected_schedule_revision)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_schedule_row(&transaction, schedule, expected_schedule_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    /// Commits a non-retryable or exhausted Schedule together with an honest
    /// partial Mission terminal. No caller can leave a dead-lettered future
    /// cycle presented as still scheduled.
    pub fn dead_letter_mission_schedule_and_partial_mission_atomic(
        &mut self,
        schedule: &MissionSchedule,
        expected_schedule_revision: u64,
        mission: &Mission,
        expected_mission_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        validate_schedule(schedule)?;
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if schedule.status != MissionScheduleStatus::DeadLetter
            || mission.stage != MissionStage::Partial
            || mission.revision
                != expected_mission_revision
                    .checked_add(1)
                    .ok_or(StorageError::RevisionOverflow(expected_mission_revision))?
        {
            return Err(StorageError::DomainDecode(
                "dead-lettered schedule and partial Mission do not match".into(),
            ));
        }
        validate_schedule_mission_waiting_pair(schedule, mission)?;
        let transaction = self.connection.transaction()?;
        let previous = load_schedule(&transaction, &schedule.project_id, &schedule.id)?;
        validate_schedule_transition(&previous, schedule, expected_schedule_revision)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_schedule_row(&transaction, schedule, expected_schedule_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_schedule",
            schedule.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }
}

fn commit_exhausted_schedule_claim(
    transaction: Transaction<'_>,
    schedule: &MissionSchedule,
    expected_schedule_revision: u64,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let mut mission =
        load_mission_normalized(&transaction, &schedule.project_id, &schedule.mission_id)?
            .ok_or_else(|| StorageError::MissionNotFound {
                project_id: schedule.project_id.clone(),
                mission_id: schedule.mission_id.clone(),
            })?;
    let expected_mission_revision = mission.revision;
    validate_schedule_mission_waiting_pair(schedule, &mission)?;
    mission.terminate(MissionTerminalDisposition::Partial, now)?;
    update_mission_normalized_cas(&transaction, &mission, expected_mission_revision)?;
    update_schedule_row(&transaction, schedule, expected_schedule_revision)?;
    append_events(
        &transaction,
        schedule.tenant_id.as_str(),
        schedule.project_id.as_str(),
        Some(schedule.mission_id.as_str()),
        "mission_schedule",
        schedule.id.as_str(),
        &[
            PendingEvent::new(
                "mission.schedule_dead_lettered",
                serde_json::json!({
                    "scheduleId": schedule.id,
                    "missionId": schedule.mission_id,
                    "cycle": schedule.cycle,
                    "failureCount": schedule.failures.len(),
                    "reason": "lease_failure_budget_exhausted",
                    "externalEffectReplayed": false,
                }),
                now,
            ),
            PendingEvent::new(
                "mission.partial",
                serde_json::json!({
                    "missionId": mission.id,
                    "reason": "mission_schedule_dead_lettered",
                    "revision": mission.revision,
                    "stage": mission.stage,
                    "terminal": true,
                }),
                now,
            ),
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

fn validate_schedule_mission_waiting_pair(
    schedule: &MissionSchedule,
    mission: &Mission,
) -> Result<(), StorageError> {
    let revision_matches_waiting_or_terminal = mission.revision
        == schedule.scheduled_from_mission_revision
        || mission.revision.checked_sub(1) == Some(schedule.scheduled_from_mission_revision);
    if schedule.tenant_id != mission.tenant_id
        || schedule.project_id != mission.project_id
        || schedule.mission_id != mission.id
        || !matches!(
            mission.stage,
            MissionStage::Scheduled | MissionStage::Partial
        )
        || !revision_matches_waiting_or_terminal
        || schedule.contract_version != mission.contract.version
        || schedule.contract_valid_until != mission.contract.valid_until
        || u64::try_from(mission.outcome_history.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            != Some(schedule.cycle)
    {
        return Err(StorageError::DomainDecode(
            "Mission schedule no longer matches its exact waiting Mission cycle".into(),
        ));
    }
    Ok(())
}

fn insert_schedule(
    transaction: &Transaction<'_>,
    schedule: &MissionSchedule,
) -> Result<(), StorageError> {
    validate_schedule(schedule)?;
    transaction.execute(
        "INSERT INTO mission_schedules (
           tenant_id, project_id, id, mission_id, cycle,
           scheduled_from_mission_revision, contract_version, definition_cycle,
           trigger, interval_seconds, anchor_at, event_topics_digest, due_at,
           retry_not_before, contract_valid_until, signal_event_id_digest,
           status, lease_generation, lease_owner_digest, lease_token_digest,
           lease_expires_at, failure_count, revision, created_at, updated_at, record_json
         ) VALUES (
           ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
           ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26
         )",
        schedule_params(schedule)?,
    )?;
    Ok(())
}

pub(crate) fn update_schedule_row(
    transaction: &Transaction<'_>,
    schedule: &MissionSchedule,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let values = schedule_values(schedule)?;
    let updated = transaction.execute(
        "UPDATE mission_schedules SET
           tenant_id = ?1, mission_id = ?4, cycle = ?5,
           scheduled_from_mission_revision = ?6, contract_version = ?7,
           definition_cycle = ?8, trigger = ?9, interval_seconds = ?10,
           anchor_at = ?11, event_topics_digest = ?12, due_at = ?13,
           retry_not_before = ?14, contract_valid_until = ?15,
           signal_event_id_digest = ?16, status = ?17, lease_generation = ?18,
           lease_owner_digest = ?19, lease_token_digest = ?20,
           lease_expires_at = ?21, failure_count = ?22, revision = ?23,
           created_at = ?24, updated_at = ?25, record_json = ?26
         WHERE project_id = ?2 AND id = ?3 AND revision = ?27",
        rusqlite::params_from_iter(values.into_iter().chain([rusqlite::types::Value::Integer(
            to_sql_u64(expected_revision)?,
        )])),
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("mission_schedule:{}", schedule.id),
            expected_revision,
        });
    }
    Ok(())
}

fn schedule_params(
    schedule: &MissionSchedule,
) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(schedule_values(schedule)?))
}

fn schedule_values(
    schedule: &MissionSchedule,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    let lease = schedule.lease.as_ref();
    Ok(vec![
        schedule.tenant_id.to_string().into(),
        schedule.project_id.to_string().into(),
        schedule.id.to_string().into(),
        schedule.mission_id.to_string().into(),
        to_sql_u64(schedule.cycle)?.into(),
        to_sql_u64(schedule.scheduled_from_mission_revision)?.into(),
        to_sql_u64(schedule.contract_version)?.into(),
        schedule
            .definition_cycle
            .map(to_sql_u64)
            .transpose()?
            .into(),
        enum_name(&schedule.trigger)?.into(),
        to_sql_u64(schedule.interval_seconds)?.into(),
        schedule.anchor_at.to_rfc3339().into(),
        digest_json(&schedule.event_topics)?.into(),
        schedule.due_at.map(|value| value.to_rfc3339()).into(),
        schedule
            .retry_not_before
            .map(|value| value.to_rfc3339())
            .into(),
        schedule.contract_valid_until.to_rfc3339().into(),
        schedule
            .signal
            .as_ref()
            .map(|signal| signal.event_id_digest.clone())
            .into(),
        enum_name(&schedule.status)?.into(),
        to_sql_u64(schedule.lease_generation)?.into(),
        lease.map(|lease| lease.owner_digest.clone()).into(),
        lease.map(|lease| lease.token_digest.clone()).into(),
        lease.map(|lease| lease.expires_at.to_rfc3339()).into(),
        i64::try_from(schedule.failures.len())
            .map_err(|_| StorageError::DomainDecode("schedule failure count overflow".into()))?
            .into(),
        to_sql_u64(schedule.revision)?.into(),
        schedule.created_at.to_rfc3339().into(),
        schedule.updated_at.to_rfc3339().into(),
        serde_json::to_string(schedule)?.into(),
    ])
}

fn load_schedule(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    schedule_id: &MissionScheduleId,
) -> Result<MissionSchedule, StorageError> {
    let projection = connection
        .query_row(
            "SELECT tenant_id, project_id, id, mission_id, cycle,
                    scheduled_from_mission_revision, contract_version, definition_cycle,
                    trigger, interval_seconds, anchor_at, event_topics_digest, due_at,
                    retry_not_before, contract_valid_until, signal_event_id_digest,
                    status, lease_generation, lease_owner_digest, lease_token_digest,
                    lease_expires_at, failure_count, revision, created_at, updated_at, record_json
             FROM mission_schedules WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), schedule_id.as_str()],
            |row| {
                Ok(ScheduleProjection {
                    tenant_id: row.get(0)?,
                    project_id: row.get(1)?,
                    id: row.get(2)?,
                    mission_id: row.get(3)?,
                    cycle: row.get(4)?,
                    scheduled_from_mission_revision: row.get(5)?,
                    contract_version: row.get(6)?,
                    definition_cycle: row.get(7)?,
                    trigger: row.get(8)?,
                    interval_seconds: row.get(9)?,
                    anchor_at: row.get(10)?,
                    event_topics_digest: row.get(11)?,
                    due_at: row.get(12)?,
                    retry_not_before: row.get(13)?,
                    contract_valid_until: row.get(14)?,
                    signal_event_id_digest: row.get(15)?,
                    status: row.get(16)?,
                    lease_generation: row.get(17)?,
                    lease_owner_digest: row.get(18)?,
                    lease_token_digest: row.get(19)?,
                    lease_expires_at: row.get(20)?,
                    failure_count: row.get(21)?,
                    revision: row.get(22)?,
                    created_at: row.get(23)?,
                    updated_at: row.get(24)?,
                    record_json: row.get(25)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "mission schedule",
            project_id: project_id.clone(),
            id: schedule_id.to_string(),
        })?;
    let schedule: MissionSchedule = serde_json::from_str(&projection.record_json)?;
    validate_schedule(&schedule)?;
    if !projection.matches(&schedule)? {
        return Err(StorageError::DomainDecode(
            "Mission schedule projection differs from its full record".into(),
        ));
    }
    Ok(schedule)
}

pub(crate) fn validate_schedule_transition(
    previous: &MissionSchedule,
    next: &MissionSchedule,
    expected_revision: u64,
) -> Result<(), StorageError> {
    validate_schedule(previous)?;
    validate_schedule(next)?;
    if previous.revision != expected_revision
        || previous.revision.checked_add(1) != Some(next.revision)
        || previous.id != next.id
        || previous.tenant_id != next.tenant_id
        || previous.project_id != next.project_id
        || previous.mission_id != next.mission_id
        || previous.cycle != next.cycle
        || previous.scheduled_from_mission_revision != next.scheduled_from_mission_revision
        || previous.contract_version != next.contract_version
        || previous.definition_cycle != next.definition_cycle
        || previous.trigger != next.trigger
        || previous.interval_seconds != next.interval_seconds
        || previous.anchor_at != next.anchor_at
        || previous.event_topics != next.event_topics
        || previous.due_at != next.due_at
        || previous.contract_valid_until != next.contract_valid_until
        || previous.created_at != next.created_at
        || next.updated_at < previous.updated_at
        || !next.failures.starts_with(&previous.failures)
        || previous
            .signal
            .as_ref()
            .is_some_and(|signal| next.signal.as_ref() != Some(signal))
        || next.lease_generation < previous.lease_generation
        || next.lease_generation > previous.lease_generation.saturating_add(1)
        || matches!(
            previous.status,
            MissionScheduleStatus::Triggered
                | MissionScheduleStatus::Cancelled
                | MissionScheduleStatus::Expired
                | MissionScheduleStatus::DeadLetter
        )
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "mission schedule transition",
            id: next.id.to_string(),
        });
    }
    Ok(())
}

fn validate_schedule(schedule: &MissionSchedule) -> Result<(), StorageError> {
    schedule.validate()?;
    Ok(())
}

#[derive(Debug)]
struct ScheduleProjection {
    tenant_id: String,
    project_id: String,
    id: String,
    mission_id: String,
    cycle: i64,
    scheduled_from_mission_revision: i64,
    contract_version: i64,
    definition_cycle: Option<i64>,
    trigger: String,
    interval_seconds: i64,
    anchor_at: String,
    event_topics_digest: String,
    due_at: Option<String>,
    retry_not_before: Option<String>,
    contract_valid_until: String,
    signal_event_id_digest: Option<String>,
    status: String,
    lease_generation: i64,
    lease_owner_digest: Option<String>,
    lease_token_digest: Option<String>,
    lease_expires_at: Option<String>,
    failure_count: i64,
    revision: i64,
    created_at: String,
    updated_at: String,
    record_json: String,
}

impl ScheduleProjection {
    fn matches(&self, schedule: &MissionSchedule) -> Result<bool, StorageError> {
        let lease = schedule.lease.as_ref();
        Ok(self.tenant_id == schedule.tenant_id.as_str()
            && self.project_id == schedule.project_id.as_str()
            && self.id == schedule.id.as_str()
            && self.mission_id == schedule.mission_id.as_str()
            && self.cycle == to_sql_u64(schedule.cycle)?
            && self.scheduled_from_mission_revision
                == to_sql_u64(schedule.scheduled_from_mission_revision)?
            && self.contract_version == to_sql_u64(schedule.contract_version)?
            && self.definition_cycle == schedule.definition_cycle.map(to_sql_u64).transpose()?
            && self.trigger == enum_name(&schedule.trigger)?
            && self.interval_seconds == to_sql_u64(schedule.interval_seconds)?
            && self.anchor_at == schedule.anchor_at.to_rfc3339()
            && self.event_topics_digest == digest_json(&schedule.event_topics)?
            && self.due_at == schedule.due_at.map(|value| value.to_rfc3339())
            && self.retry_not_before == schedule.retry_not_before.map(|value| value.to_rfc3339())
            && self.contract_valid_until == schedule.contract_valid_until.to_rfc3339()
            && self.signal_event_id_digest
                == schedule
                    .signal
                    .as_ref()
                    .map(|signal| signal.event_id_digest.clone())
            && self.status == enum_name(&schedule.status)?
            && self.lease_generation == to_sql_u64(schedule.lease_generation)?
            && self.lease_owner_digest == lease.map(|lease| lease.owner_digest.clone())
            && self.lease_token_digest == lease.map(|lease| lease.token_digest.clone())
            && self.lease_expires_at == lease.map(|lease| lease.expires_at.to_rfc3339())
            && usize::try_from(self.failure_count).ok() == Some(schedule.failures.len())
            && self.revision == to_sql_u64(schedule.revision)?
            && self.created_at == schedule.created_at.to_rfc3339()
            && self.updated_at == schedule.updated_at.to_rfc3339())
    }
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn digest_json(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{TimeZone, Utc};
    use hartevo_domain_kernel::{
        AccountId, Cadence, CadenceTriggerKind, Connection, ConnectionId, ContactChannel,
        Conversation, ConversationContentRisk, ConversationId, InboundMessageInput, MessageId,
        MessagingGateway, MissionContract, MissionScheduleFailureClass, MissionTerminalDisposition,
        Money, OperatingMode, Outcome, OutcomeDecision, Person, PersonId, Project, StorageMode,
        Task, TaskId, TaskStatus, TenantId, WebhookAttestation,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn fixture() -> (ProjectStore, Mission, MissionSchedule) {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-schedule"),
            ProjectId::from("project-schedule"),
            "Schedule project",
            "",
            "/tmp/project-schedule",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store.save_project(&project).expect("persist project");
        let mut contract = MissionContract::bootstrap(
            "Operate signed inbound events",
            ["webhook.ingest".into()],
            now(),
        );
        contract.mode = OperatingMode::ContinuousRelationship;
        contract.cadence = Some(Cadence {
            interval_seconds: 0,
            anchor_at: now(),
            trigger: CadenceTriggerKind::EventDriven,
            event_topics: BTreeSet::from(["conversation.inbound".into()]),
        });
        contract.valid_until = now() + Duration::days(90);
        contract.budget = Money::zero(contract.budget.currency.clone());
        let mut mission = Mission::compile(
            project.tenant_id,
            MissionId::from("mission-schedule"),
            project.id,
            "Inbox operator",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-cycle-1"),
                    title: "Cycle one".into(),
                    status: TaskStatus::Running,
                    capability: "webhook.ingest".into(),
                }],
                now(),
            )
            .expect("first cycle");
        store.save_mission(&mission).expect("persist mission");
        let expected_revision = mission.revision;
        mission
            .record_outcome(Outcome {
                summary: "First event cycle reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(1),
            })
            .expect("outcome");
        let schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        store
            .update_mission_and_create_schedule_atomic(
                &mission,
                expected_revision,
                &schedule,
                &[PendingEvent::new(
                    "mission.schedule_created",
                    serde_json::json!({"scheduleId": schedule.id, "cycle": schedule.cycle}),
                    now() + Duration::days(1),
                )],
            )
            .expect("persist outcome and schedule");
        (store, mission, schedule)
    }

    fn persisted_inbound_conversation(
        store: &mut ProjectStore,
        mission: &Mission,
    ) -> (Conversation, InboundMessageInput, WebhookAttestation) {
        let created_at = now() + Duration::days(1);
        let connection = Connection::register(
            ConnectionId::from("connection-schedule-gmail"),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            "gmail",
            AccountId::from("account-schedule"),
            "owner@example.invalid",
            ["conversation.reply".into()],
            created_at,
        )
        .expect("connection");
        store
            .create_connection(
                &connection,
                "connection.registered",
                &serde_json::json!({"connectionId": connection.id()}),
                created_at,
            )
            .expect("persist connection");
        let person = Person::create(
            PersonId::from("person-schedule"),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            "Verified sender",
            None,
            vec![],
        )
        .expect("person");
        store
            .create_person(
                &person,
                "person.created",
                &serde_json::json!({"personId": person.id}),
                created_at,
            )
            .expect("persist person");
        let conversation = Conversation::open(
            ConversationId::from("conversation-schedule"),
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            Some(mission.id.clone()),
            person.id,
            None,
            MessagingGateway::Gmail,
            "gmail",
            connection.id().clone(),
            connection.account_id().clone(),
            "f".repeat(64),
            ContactChannel::Email,
            "US",
            created_at,
        )
        .expect("conversation");
        store
            .create_conversation(
                &conversation,
                "conversation.opened",
                &serde_json::json!({"conversationId": conversation.id}),
                created_at,
            )
            .expect("persist conversation");
        let received_at = now() + Duration::days(2);
        let input = InboundMessageInput {
            id: MessageId::from("inbound-schedule"),
            provider_event_digest: "a".repeat(64),
            content_digest: "b".repeat(64),
            attachment_digests: BTreeSet::new(),
            risk: ConversationContentRisk::Safe,
            classification_confidence: "0.99".parse().expect("confidence"),
            occurred_at: received_at,
        };
        let attestation = WebhookAttestation {
            signature_verified: true,
            route_digest: "f".repeat(64),
            provider: "gmail".into(),
            connection_id: connection.id().clone(),
            account_id: connection.account_id().clone(),
            received_at,
        };
        (conversation, input, attestation)
    }

    #[test]
    fn event_signal_claim_and_cycle_start_are_exact_atomic_and_redacted() {
        let (mut store, mut mission, mut schedule) = fixture();
        let expected_signal_revision = schedule.revision;
        schedule
            .signal_event(
                "conversation.inbound",
                "a".repeat(64),
                "b".repeat(64),
                now() + Duration::days(2),
            )
            .expect("signal");
        store
            .update_mission_schedule_atomic(
                &schedule,
                expected_signal_revision,
                &[PendingEvent::new(
                    "mission.schedule_signalled",
                    serde_json::json!({
                        "scheduleId": schedule.id,
                        "topic": "conversation.inbound",
                        "eventIdDigest": "a".repeat(64),
                    }),
                    now() + Duration::days(2),
                )],
            )
            .expect("persist signal");

        let claimed = store
            .claim_due_mission_schedule(
                &"c".repeat(64),
                &"d".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(2),
            )
            .expect("claim")
            .expect("due schedule");
        let expected_schedule_revision = claimed.revision;
        let mut triggered = claimed;
        let expected_mission_revision = mission.revision;
        mission
            .start_scheduled_cycle(
                2,
                [Task {
                    id: TaskId::from("task-cycle-2"),
                    title: "Cycle two".into(),
                    status: TaskStatus::Running,
                    capability: "webhook.ingest".into(),
                }],
                now() + Duration::days(2) + Duration::seconds(1),
            )
            .expect("start cycle");
        triggered
            .mark_triggered(
                &"c".repeat(64),
                &"d".repeat(64),
                1,
                &mission,
                now() + Duration::days(2) + Duration::seconds(1),
            )
            .expect("trigger");
        store
            .trigger_mission_schedule_and_start_cycle_atomic(
                &triggered,
                expected_schedule_revision,
                &mission,
                expected_mission_revision,
                &[PendingEvent::new(
                    "mission.cycle_started",
                    serde_json::json!({
                        "scheduleId": triggered.id,
                        "cycle": triggered.cycle,
                        "leaseGeneration": 1,
                    }),
                    now() + Duration::days(2) + Duration::seconds(1),
                )],
            )
            .expect("atomic trigger");

        let restored_mission = store
            .load_mission(&mission.project_id, &mission.id)
            .expect("mission");
        let restored_schedule = store
            .load_mission_schedule(&mission.project_id, &triggered.id)
            .expect("schedule");
        assert_eq!(restored_mission.stage, MissionStage::Running);
        assert_eq!(restored_schedule.status, MissionScheduleStatus::Triggered);
        let events = store
            .events_for_mission(&mission.project_id, &mission.id)
            .expect("events");
        let json = serde_json::to_string(&events).expect("json");
        assert!(!json.contains(&"c".repeat(64)));
        assert!(!json.contains(&"d".repeat(64)));
    }

    #[test]
    fn schedule_insert_failure_rolls_back_reviewed_mission_outcome() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = Project::create_local(
            TenantId::from("tenant-rollback"),
            ProjectId::from("project-rollback"),
            "Rollback project",
            "",
            "/tmp/project-rollback",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store.save_project(&project).expect("project");
        let mut contract = MissionContract::bootstrap("Operate weekly", [], now());
        contract.mode = OperatingMode::ContinuousOperator;
        contract.cadence = Some(Cadence {
            interval_seconds: 7 * 24 * 60 * 60,
            anchor_at: now(),
            trigger: CadenceTriggerKind::Interval,
            event_topics: BTreeSet::new(),
        });
        contract.valid_until = now() + Duration::days(90);
        let mut mission = Mission::compile(
            project.tenant_id,
            MissionId::from("mission-rollback"),
            project.id,
            "Weekly operator",
            contract,
            now(),
        )
        .expect("mission");
        mission.start_research([], now()).expect("start");
        store.save_mission(&mission).expect("mission");
        let expected_revision = mission.revision;
        mission
            .record_outcome(Outcome {
                summary: "Reviewed".into(),
                decision: OutcomeDecision::Continue,
                metrics: BTreeMap::new(),
                observed_at: now() + Duration::days(1),
            })
            .expect("outcome");
        let schedule =
            MissionSchedule::prepare(&mission, now() + Duration::days(1)).expect("schedule");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_schedule_insert BEFORE INSERT ON mission_schedules
                 BEGIN SELECT RAISE(ABORT, 'schedule insert failure'); END;",
            )
            .expect("trigger");
        assert!(
            store
                .update_mission_and_create_schedule_atomic(
                    &mission,
                    expected_revision,
                    &schedule,
                    &[PendingEvent::new(
                        "mission.schedule_created",
                        serde_json::json!({"cycle": 2}),
                        now() + Duration::days(1),
                    )],
                )
                .is_err()
        );
        let restored = store
            .load_mission(&mission.project_id, &mission.id)
            .expect("unchanged mission");
        assert_eq!(restored.revision, expected_revision);
        assert_eq!(restored.stage, MissionStage::Running);
        assert!(
            store
                .list_mission_schedules(&mission.project_id, Some(&mission.id))
                .expect("schedules")
                .is_empty()
        );
    }

    #[test]
    fn schedule_projection_tamper_fails_closed() {
        let (store, mission, schedule) = fixture();
        store
            .connection
            .execute(
                "UPDATE mission_schedules SET event_topics_digest = ?3
                 WHERE project_id = ?1 AND id = ?2",
                params![
                    mission.project_id.as_str(),
                    schedule.id.as_str(),
                    "f".repeat(64)
                ],
            )
            .expect("tamper");
        assert!(matches!(
            store.load_mission_schedule(&mission.project_id, &schedule.id),
            Err(StorageError::DomainDecode(_))
        ));
    }

    #[test]
    fn stale_schedule_lease_cannot_append_failure_or_change_persisted_revision() {
        let (mut store, mission, mut schedule) = fixture();
        let expected_signal_revision = schedule.revision;
        schedule
            .signal_event(
                "conversation.inbound",
                "a".repeat(64),
                "b".repeat(64),
                now() + Duration::days(2),
            )
            .expect("signal");
        store
            .update_mission_schedule_atomic(
                &schedule,
                expected_signal_revision,
                &[PendingEvent::new(
                    "mission.schedule_signalled",
                    serde_json::json!({"cycle": schedule.cycle}),
                    now() + Duration::days(2),
                )],
            )
            .expect("persist signal");
        let claimed = store
            .claim_due_mission_schedule(
                &"c".repeat(64),
                &"d".repeat(64),
                Duration::minutes(5),
                now() + Duration::days(2),
            )
            .expect("claim")
            .expect("due schedule");
        let persisted_revision = claimed.revision;
        let mut stale = claimed.clone();
        assert_eq!(
            stale.record_failure(
                &"c".repeat(64),
                &"0".repeat(64),
                claimed.lease_generation,
                MissionScheduleFailureClass::CoordinatorRestart,
                "e".repeat(64),
                false,
                None,
                now() + Duration::days(2) + Duration::minutes(1),
            ),
            Err(MissionScheduleError::LeaseLost)
        );
        let restored = store
            .load_mission_schedule(&mission.project_id, &schedule.id)
            .expect("schedule");
        assert_eq!(restored.revision, persisted_revision);
        assert!(restored.failures.is_empty());
    }

    #[test]
    fn inbound_message_and_schedule_signal_roll_back_together_on_storage_failure() {
        let (mut store, mission, mut schedule) = fixture();
        let (mut conversation, input, attestation) =
            persisted_inbound_conversation(&mut store, &mission);
        let expected_conversation_revision = conversation.revision;
        let received_at = attestation.received_at;
        let ingest = conversation
            .ingest_inbound(input, &attestation)
            .expect("inbound");
        assert_eq!(ingest, hartevo_domain_kernel::InboundIngest::Inserted);
        let expected_schedule_revision = schedule.revision;
        schedule
            .signal_event(
                "conversation.inbound",
                "c".repeat(64),
                "a".repeat(64),
                received_at,
            )
            .expect("signal");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_schedule_signal BEFORE UPDATE ON mission_schedules
                 BEGIN SELECT RAISE(ABORT, 'schedule signal failure'); END;",
            )
            .expect("failure injection");
        assert!(
            store
                .update_conversation_and_signal_schedule_atomic(
                    &conversation,
                    expected_conversation_revision,
                    &schedule,
                    expected_schedule_revision,
                    &[PendingEvent::new(
                        "conversation.inbound_ingested",
                        serde_json::json!({"conversationId": conversation.id}),
                        received_at,
                    )],
                    &[PendingEvent::new(
                        "mission.schedule_signalled",
                        serde_json::json!({"scheduleId": schedule.id}),
                        received_at,
                    )],
                )
                .is_err()
        );
        let restored_conversation = store
            .load_conversation(&mission.project_id, &conversation.id)
            .expect("conversation rollback");
        let restored_schedule = store
            .load_mission_schedule(&mission.project_id, &schedule.id)
            .expect("schedule rollback");
        assert_eq!(
            restored_conversation.revision,
            expected_conversation_revision
        );
        assert!(restored_conversation.messages.is_empty());
        assert_eq!(restored_schedule.revision, expected_schedule_revision);
        assert!(restored_schedule.signal.is_none());
        let events = store
            .events_for_mission(&mission.project_id, &mission.id)
            .expect("events");
        assert!(events.iter().all(|event| {
            event.event_type != "conversation.inbound_ingested"
                && event.event_type != "mission.schedule_signalled"
        }));
    }

    #[test]
    fn contract_expiry_commits_schedule_and_mission_terminal_state_together() {
        let (mut store, mut mission, mut schedule) = fixture();
        let expired_at = now() + Duration::days(90);
        assert!(
            store
                .list_expired_mission_schedules(expired_at - Duration::seconds(1))
                .expect("not expired")
                .is_empty()
        );
        assert_eq!(
            store
                .list_expired_mission_schedules(expired_at)
                .expect("expired")
                .len(),
            1
        );
        let expected_schedule_revision = schedule.revision;
        let expected_mission_revision = mission.revision;
        schedule.expire(expired_at).expect("expire schedule");
        mission
            .terminate(MissionTerminalDisposition::Completed, expired_at)
            .expect("complete mission");
        store
            .expire_mission_schedule_and_complete_mission_atomic(
                &schedule,
                expected_schedule_revision,
                &mission,
                expected_mission_revision,
                &[
                    PendingEvent::new(
                        "mission.schedule_expired",
                        serde_json::json!({"scheduleId": schedule.id}),
                        expired_at,
                    ),
                    PendingEvent::new(
                        "mission.completed",
                        serde_json::json!({"missionId": mission.id}),
                        expired_at,
                    ),
                ],
            )
            .expect("atomic expiry");
        assert_eq!(
            store
                .load_mission_schedule(&mission.project_id, &schedule.id)
                .expect("schedule")
                .status,
            MissionScheduleStatus::Expired
        );
        assert_eq!(
            store
                .load_mission(&mission.project_id, &mission.id)
                .expect("mission")
                .stage,
            MissionStage::Completed
        );
        assert!(
            store
                .list_expired_mission_schedules(expired_at + Duration::seconds(1))
                .expect("reconciled")
                .is_empty()
        );
    }

    #[test]
    fn fifth_expired_lease_dead_letters_schedule_and_partials_mission_atomically() {
        let (mut store, mission, mut schedule) = fixture();
        let expected_signal_revision = schedule.revision;
        let mut claimed_at = now() + Duration::days(2);
        schedule
            .signal_event(
                "conversation.inbound",
                "a".repeat(64),
                "b".repeat(64),
                claimed_at,
            )
            .expect("signal");
        store
            .update_mission_schedule_atomic(
                &schedule,
                expected_signal_revision,
                &[PendingEvent::new(
                    "mission.schedule_signalled",
                    serde_json::json!({"scheduleId": schedule.id}),
                    claimed_at,
                )],
            )
            .expect("persist signal");
        let first = store
            .claim_due_mission_schedule(
                &"c".repeat(64),
                &"d".repeat(64),
                Duration::minutes(1),
                claimed_at,
            )
            .expect("first claim")
            .expect("schedule");
        assert_eq!(first.lease_generation, 1);
        for expected_failure_count in 1..5 {
            claimed_at += Duration::minutes(2);
            let reclaimed = store
                .claim_due_mission_schedule(
                    &format!("{expected_failure_count:x}").repeat(64),
                    &format!("{:x}", expected_failure_count + 8).repeat(64),
                    Duration::minutes(1),
                    claimed_at,
                )
                .expect("reclaim")
                .expect("retryable schedule");
            assert_eq!(reclaimed.failures.len(), expected_failure_count);
        }
        claimed_at += Duration::minutes(2);
        assert!(
            store
                .claim_due_mission_schedule(
                    &"e".repeat(64),
                    &"f".repeat(64),
                    Duration::minutes(1),
                    claimed_at,
                )
                .expect("fifth expiry")
                .is_none()
        );
        let dead_letter = store
            .load_mission_schedule(&mission.project_id, &schedule.id)
            .expect("dead letter");
        let partial = store
            .load_mission(&mission.project_id, &mission.id)
            .expect("partial mission");
        assert_eq!(dead_letter.status, MissionScheduleStatus::DeadLetter);
        assert_eq!(dead_letter.failures.len(), 5);
        assert!(dead_letter.lease.is_none());
        assert_eq!(partial.stage, MissionStage::Partial);
        let event_json = serde_json::to_string(
            &store
                .events_for_mission(&mission.project_id, &mission.id)
                .expect("events"),
        )
        .expect("event json");
        assert!(event_json.contains("mission.schedule_dead_lettered"));
        assert!(event_json.contains("mission.partial"));
        assert!(event_json.contains("\"externalEffectReplayed\":false"));
    }

    #[test]
    fn migrations_v40_v41_install_mission_schedule_ledger_idempotently() {
        let (mut store, _, _) = fixture();
        store
            .connection
            .execute_batch(
                "DROP TABLE mission_schedules;
                 DELETE FROM schema_migrations WHERE version >= 40;",
            )
            .expect("construct v39 schema");
        store.migrate().expect("migrate v39 through v41");
        assert_eq!(
            store.schema_version().expect("schema"),
            crate::STORAGE_SCHEMA_VERSION
        );
        let table_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'mission_schedules'",
                [],
                |row| row.get(0),
            )
            .expect("mission schedule table");
        assert_eq!(table_count, 1);
        store.migrate().expect("idempotent v41 migration");
        assert_eq!(
            store.schema_version().expect("schema replay"),
            crate::STORAGE_SCHEMA_VERSION
        );
    }

    #[test]
    fn migration_v41_preserves_existing_v40_schedule_rows() {
        let (mut store, mission, schedule) = fixture();
        store
            .connection
            .execute("DELETE FROM schema_migrations WHERE version = 41", [])
            .expect("construct v40 marker");
        store.migrate().expect("migrate v40 to v41");
        assert_eq!(
            store
                .load_mission_schedule(&mission.project_id, &schedule.id)
                .expect("preserved schedule"),
            schedule
        );
        store.migrate().expect("idempotent v41 replay");
    }
}
