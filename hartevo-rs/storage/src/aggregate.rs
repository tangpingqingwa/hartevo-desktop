use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{Mission, Project};
use rusqlite::{OptionalExtension, Transaction, params};
use serde_json::Value;

use crate::normalized::{
    insert_mission_normalized, insert_project_normalized, update_mission_normalized_cas,
    update_project_normalized_cas,
};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug, PartialEq)]
pub struct PendingEvent {
    pub event_type: String,
    pub payload: Value,
    pub recorded_at: DateTime<Utc>,
}

impl PendingEvent {
    pub fn new(event_type: impl Into<String>, payload: Value, recorded_at: DateTime<Utc>) -> Self {
        Self {
            event_type: event_type.into(),
            payload,
            recorded_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicMutation {
    pub event_sequences: Vec<i64>,
    pub outbox_sequences: Vec<i64>,
    pub state_revision: u64,
}

impl ProjectStore {
    pub fn create_project_atomic(
        &mut self,
        project: &Project,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if project.revision != 1 {
            return Err(StorageError::InvalidInitialRevision(project.revision));
        }
        if project.data_cell.is_some() {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "project data Cell selection",
                id: project.id.to_string(),
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let transaction = self.connection.transaction()?;
        insert_project_normalized(&transaction, project)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            project.tenant_id.as_str(),
            project.id.as_str(),
            None,
            "project",
            project.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: project.revision,
        })
    }

    pub fn create_mission_atomic(
        &mut self,
        mission: &Mission,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        insert_mission_normalized(&transaction, mission)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    pub fn update_project_atomic(
        &mut self,
        project: &Project,
        expected_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if project.revision <= expected_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision,
                actual: project.revision,
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let transaction = self.connection.transaction()?;
        let stored = crate::normalized::load_project_normalized(&transaction, &project.id)?
            .ok_or_else(|| StorageError::ProjectNotFound(project.id.clone()))?;
        if stored.tenant_id != project.tenant_id
            || stored.storage_mode != project.storage_mode
            || stored.data_cell != project.data_cell
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "project scope or data Cell",
                id: project.id.to_string(),
            });
        }
        update_project_normalized_cas(&transaction, project, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            project.tenant_id.as_str(),
            project.id.as_str(),
            None,
            "project",
            project.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: project.revision,
        })
    }

    pub fn update_mission_atomic(
        &mut self,
        mission: &Mission,
        expected_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if mission.revision <= expected_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision,
                actual: mission.revision,
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        update_mission_normalized_cas(&transaction, mission, expected_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    /// Updates a Mission only while the project Outcome Ledger remains at the
    /// exact revision inspected by an Application Checkpoint handler. The
    /// source fence and Mission CAS are evaluated in the same SQL transaction,
    /// so a concurrent webhook cannot make stale Oracle evidence visible.
    pub fn update_mission_atomic_with_outcome_ledger_fence(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        expected_outcome_ledger_revision: Option<u64>,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let expected_source_revision = expected_outcome_ledger_revision
            .map(|revision| {
                i64::try_from(revision).map_err(|_| StorageError::RevisionOverflow(revision))
            })
            .transpose()?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        let source = transaction
            .query_row(
                "SELECT tenant_id, revision FROM outcome_ledgers WHERE project_id = ?1",
                [mission.project_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        if source
            .as_ref()
            .is_some_and(|(tenant_id, _)| tenant_id != mission.tenant_id.as_str())
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        if source.as_ref().map(|(_, revision)| *revision) != expected_source_revision {
            return Err(StorageError::OptimisticConflict {
                aggregate: "outcome_ledger_source_fence".into(),
                expected_revision: expected_outcome_ledger_revision.unwrap_or(0),
            });
        }
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
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

fn ensure_project_scope(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
) -> Result<(), StorageError> {
    let stored_tenant = transaction
        .query_row(
            "SELECT tenant_id FROM projects WHERE id = ?1",
            [project_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::ProjectNotFound(hartevo_domain_kernel::ProjectId::from_stable(project_id))
        })?;
    if stored_tenant != tenant_id {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_events(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
    mission_id: Option<&str>,
    aggregate_type: &str,
    aggregate_id: &str,
    events: &[PendingEvent],
) -> Result<(Vec<i64>, Vec<i64>), StorageError> {
    let mut event_sequences = Vec::with_capacity(events.len());
    let mut outbox_sequences = Vec::with_capacity(events.len());
    for event in events {
        if event.event_type.trim().is_empty() {
            return Err(StorageError::EmptyEventType);
        }
        let payload_json = serde_json::to_string(&event.payload)?;
        transaction.execute(
            "INSERT INTO domain_events
               (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                tenant_id,
                project_id,
                mission_id,
                event.event_type,
                payload_json,
                event.recorded_at.to_rfc3339(),
            ],
        )?;
        event_sequences.push(transaction.last_insert_rowid());
        transaction.execute(
            "INSERT INTO outbox_messages
               (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type,
                payload_json, available_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![
                tenant_id,
                project_id,
                mission_id,
                aggregate_type,
                aggregate_id,
                event.event_type,
                payload_json,
                event.recorded_at.to_rfc3339(),
            ],
        )?;
        outbox_sequences.push(transaction.last_insert_rowid());
    }
    Ok((event_sequences, outbox_sequences))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        MissionContract, MissionId, ProjectId, StorageMode, Task, TaskId, TaskStatus, TenantId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 10, 13, 0, 0)
            .single()
            .expect("valid time")
    }

    fn project() -> Project {
        Project::create_local(
            TenantId::from("tenant-atomic"),
            ProjectId::from("project-atomic"),
            "Atomic project",
            "",
            "/tmp/hartevo-atomic",
            StorageMode::LocalExisting,
        )
        .expect("project")
    }

    #[test]
    fn event_failure_rolls_back_the_aggregate_write() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project();
        let result = store.create_project_atomic(
            &project,
            &[PendingEvent::new("", serde_json::json!({}), now())],
        );

        assert!(matches!(result, Err(StorageError::EmptyEventType)));
        assert!(matches!(
            store.load_project(&project.id),
            Err(StorageError::ProjectNotFound(_))
        ));
    }

    #[test]
    fn stale_mission_update_cannot_overwrite_newer_state_or_events() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project = project();
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new(
                    "project.created",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("project");
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-atomic"),
            project.id.clone(),
            "Atomic mission",
            MissionContract::bootstrap("Prove CAS", ["research.read".into()], now()),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-1"),
                    title: "Research".into(),
                    status: TaskStatus::Running,
                    capability: "research.read".into(),
                }],
                now(),
            )
            .expect("start");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new(
                    "mission.started",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("mission");
        let stale = mission.clone();
        mission.updated_at = now() + chrono::Duration::minutes(1);
        mission.revision += 1;
        store
            .update_mission_atomic(
                &mission,
                2,
                &[PendingEvent::new(
                    "mission.updated",
                    serde_json::json!({}),
                    mission.updated_at,
                )],
            )
            .expect("fresh update");
        let mut stale_retry = stale;
        stale_retry.updated_at = now() + chrono::Duration::minutes(2);
        stale_retry.revision += 1;

        assert!(matches!(
            store.update_mission_atomic(
                &stale_retry,
                2,
                &[PendingEvent::new(
                    "mission.stale",
                    serde_json::json!({}),
                    stale_retry.updated_at,
                )],
            ),
            Err(StorageError::OptimisticConflict { .. })
        ));
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("stored mission")
                .revision,
            mission.revision
        );
        let event_types = store
            .events_for_mission(&project.id, &mission.id)
            .expect("events")
            .into_iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>();
        assert_eq!(event_types, vec!["mission.started", "mission.updated"]);
    }
}
