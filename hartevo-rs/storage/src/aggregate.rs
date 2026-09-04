use std::collections::BTreeSet;

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

/// A typed, project-scoped read fence for an Application Checkpoint source.
/// `None` fences a required absence, allowing a missing-record block to race
/// safely with sync or recovery inserting that record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApplicationSourceKind {
    Project,
    Mission,
    Connection,
    IdentityLink,
    Person,
    Company,
    Partner,
    Opportunity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutcomeLedgerSourceFence {
    NotRequired,
    Expected(Option<u64>),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ApplicationSourceRevisionFence {
    pub(crate) kind: ApplicationSourceKind,
    pub(crate) id: String,
    pub(crate) expected_revision: Option<u64>,
}

impl ApplicationSourceRevisionFence {
    pub fn present(
        kind: ApplicationSourceKind,
        id: impl Into<String>,
        expected_revision: u64,
    ) -> Self {
        Self {
            kind,
            id: id.into(),
            expected_revision: Some(expected_revision),
        }
    }

    pub fn absent(kind: ApplicationSourceKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            expected_revision: None,
        }
    }

    pub const fn kind(&self) -> ApplicationSourceKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }
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
        self.update_mission_atomic_with_application_source_fences(
            mission,
            expected_mission_revision,
            expected_outcome_ledger_revision,
            &[],
            events,
        )
    }

    /// Extends the Outcome Ledger fence with the exact Connection/Identity/
    /// Relationship revisions inspected by a deterministic Application
    /// handler. Every fence and the Mission CAS is evaluated in the same SQL
    /// transaction as its Event/Outbox append.
    pub fn update_mission_atomic_with_application_source_fences(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        expected_outcome_ledger_revision: Option<u64>,
        source_fences: &[ApplicationSourceRevisionFence],
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.update_mission_atomic_with_optional_outcome_ledger_fence(
            mission,
            expected_mission_revision,
            OutcomeLedgerSourceFence::Expected(expected_outcome_ledger_revision),
            source_fences,
            events,
        )
    }

    /// Updates a Mission while fencing only the exact Application sources it
    /// inspected. This is for handlers whose Oracle inputs do not include the
    /// project Outcome Ledger.
    pub fn update_mission_atomic_with_application_source_fences_only(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        source_fences: &[ApplicationSourceRevisionFence],
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        self.update_mission_atomic_with_optional_outcome_ledger_fence(
            mission,
            expected_mission_revision,
            OutcomeLedgerSourceFence::NotRequired,
            source_fences,
            events,
        )
    }

    fn update_mission_atomic_with_optional_outcome_ledger_fence(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        outcome_ledger_fence: OutcomeLedgerSourceFence,
        source_fences: &[ApplicationSourceRevisionFence],
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
        let mut unique_fences = BTreeSet::new();
        for fence in source_fences {
            if fence.id.trim().is_empty()
                || fence
                    .expected_revision
                    .is_some_and(|revision| revision == 0)
                || !unique_fences.insert((fence.kind, fence.id.as_str()))
            {
                return Err(StorageError::DomainDecode(
                    "application source fences must be non-empty, non-zero and unique".into(),
                ));
            }
        }
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        if let OutcomeLedgerSourceFence::Expected(expected_outcome_ledger_revision) =
            outcome_ledger_fence
        {
            let expected_source_revision = expected_outcome_ledger_revision
                .map(|revision| {
                    i64::try_from(revision).map_err(|_| StorageError::RevisionOverflow(revision))
                })
                .transpose()?;
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
        }
        for fence in source_fences {
            require_application_source_fence(
                &transaction,
                mission.tenant_id.as_str(),
                mission.project_id.as_str(),
                fence,
            )?;
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

pub(crate) fn require_application_source_fence(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    project_id: &str,
    fence: &ApplicationSourceRevisionFence,
) -> Result<(), StorageError> {
    let query = match fence.kind {
        ApplicationSourceKind::Project => {
            "SELECT tenant_id, revision FROM projects WHERE id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Mission => {
            "SELECT tenant_id, revision FROM missions WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Connection => {
            "SELECT tenant_id, revision FROM connections WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::IdentityLink => {
            "SELECT tenant_id, revision FROM identity_links WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Person => {
            "SELECT tenant_id, revision FROM people WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Company => {
            "SELECT tenant_id, revision FROM companies WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Partner => {
            "SELECT tenant_id, revision FROM partners WHERE project_id = ?1 AND id = ?2"
        }
        ApplicationSourceKind::Opportunity => {
            "SELECT tenant_id, revision FROM opportunities WHERE project_id = ?1 AND id = ?2"
        }
    };
    let stored = transaction
        .query_row(query, params![project_id, fence.id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if stored
        .as_ref()
        .is_some_and(|(stored_tenant, _)| stored_tenant != tenant_id)
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    let stored_revision = stored
        .map(|(_, revision)| {
            u64::try_from(revision).map_err(|_| {
                StorageError::DomainDecode(format!(
                    "invalid {} source revision {revision}",
                    application_source_name(fence.kind)
                ))
            })
        })
        .transpose()?;
    if stored_revision != fence.expected_revision {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("{}_source_fence", application_source_name(fence.kind)),
            expected_revision: fence.expected_revision.unwrap_or(0),
        });
    }
    Ok(())
}

pub(crate) const fn application_source_name(kind: ApplicationSourceKind) -> &'static str {
    match kind {
        ApplicationSourceKind::Project => "project",
        ApplicationSourceKind::Mission => "mission",
        ApplicationSourceKind::Connection => "connection",
        ApplicationSourceKind::IdentityLink => "identity_link",
        ApplicationSourceKind::Person => "person",
        ApplicationSourceKind::Company => "company",
        ApplicationSourceKind::Partner => "partner",
        ApplicationSourceKind::Opportunity => "opportunity",
    }
}

pub(crate) fn ensure_project_scope(
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
        Company, CompanyId, MissionBlock, MissionContract, MissionId, MissionStage, ProjectId,
        StorageMode, Task, TaskId, TaskStatus, TenantId,
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

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered SQL transaction regression proves both absence and present-revision races roll back before the current source succeeds"
    )]
    fn application_source_revisions_and_absence_are_fenced_in_the_mission_transaction() {
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
            MissionId::from("mission-source-fence"),
            project.id.clone(),
            "Source-fenced mission",
            MissionContract::bootstrap("Fence sources", ["research.read".into()], now()),
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("source-fence-task"),
                    title: "Fence".into(),
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
        let mut company = Company::create(
            CompanyId::from("source-fence-company"),
            project.tenant_id.clone(),
            project.id.clone(),
            "Fence Company",
            "US",
        )
        .expect("company");
        store
            .create_company(&company, "company.created", &serde_json::json!({}), now())
            .expect("persist company");

        let mut candidate = mission.clone();
        candidate.revision += 1;
        let event_count = store
            .events_for_mission(&project.id, &mission.id)
            .expect("events")
            .len();
        let mut revised_project = project.clone();
        revised_project
            .update_metadata("Source fence revised", "")
            .expect("revise project");
        store
            .update_project_atomic(
                &revised_project,
                project.revision,
                &[PendingEvent::new(
                    "project.metadata_updated",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("persist revised project");
        assert!(matches!(
            store.update_mission_atomic_with_application_source_fences(
                &candidate,
                mission.revision,
                None,
                &[ApplicationSourceRevisionFence::present(
                    ApplicationSourceKind::Project,
                    project.id.to_string(),
                    project.revision,
                )],
                &[PendingEvent::new(
                    "test.stale_project_must_rollback",
                    serde_json::json!({}),
                    now(),
                )],
            ),
            Err(StorageError::OptimisticConflict {
                aggregate,
                expected_revision,
            }) if aggregate == "project_source_fence" && expected_revision == project.revision
        ));
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after stale project conflict")
                .len(),
            event_count
        );
        assert!(matches!(
            store.update_mission_atomic_with_application_source_fences(
                &candidate,
                mission.revision,
                None,
                &[ApplicationSourceRevisionFence::absent(
                    ApplicationSourceKind::Company,
                    company.id.to_string(),
                )],
                &[PendingEvent::new(
                    "test.absence_race_must_rollback",
                    serde_json::json!({}),
                    now(),
                )],
            ),
            Err(StorageError::OptimisticConflict {
                aggregate,
                expected_revision: 0,
            }) if aggregate == "company_source_fence"
        ));
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after absence conflict")
                .len(),
            event_count
        );

        company.legal_name = "Fence Company Revised".into();
        company.revision = 2;
        store
            .update_company(
                &company,
                1,
                "company.updated",
                &serde_json::json!({}),
                now(),
            )
            .expect("update company");
        assert!(matches!(
            store.update_mission_atomic_with_application_source_fences(
                &candidate,
                mission.revision,
                None,
                &[ApplicationSourceRevisionFence::present(
                    ApplicationSourceKind::Company,
                    company.id.to_string(),
                    1,
                )],
                &[PendingEvent::new(
                    "test.stale_source_must_rollback",
                    serde_json::json!({}),
                    now(),
                )],
            ),
            Err(StorageError::OptimisticConflict {
                aggregate,
                expected_revision: 1,
            }) if aggregate == "company_source_fence"
        ));
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("unchanged mission"),
            mission
        );
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after stale conflict")
                .len(),
            event_count
        );

        let mut parent = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-source-fence-parent"),
            project.id.clone(),
            "Parent mission",
            MissionContract::bootstrap("Parent KPI source", ["research.read".into()], now()),
            now(),
        )
        .expect("parent mission");
        parent
            .start_research([], now())
            .expect("start parent mission");
        store
            .create_mission_atomic(
                &parent,
                &[PendingEvent::new(
                    "mission.parent_started",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("persist parent mission");
        let parent_previous_revision = parent.revision;
        parent
            .block(
                MissionBlock {
                    code: "fixture_parent_changed".into(),
                    detail: "Change the parent revision before the child transaction".into(),
                    recoverable: true,
                    observed_at: now(),
                },
                MissionStage::Blocked,
            )
            .expect("change parent mission");
        store
            .update_mission_atomic(
                &parent,
                parent_previous_revision,
                &[PendingEvent::new(
                    "mission.parent_changed",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("persist changed parent");
        assert!(matches!(
            store.update_mission_atomic_with_application_source_fences(
                &candidate,
                mission.revision,
                None,
                &[ApplicationSourceRevisionFence::present(
                    ApplicationSourceKind::Mission,
                    parent.id.to_string(),
                    parent_previous_revision,
                )],
                &[PendingEvent::new(
                    "test.stale_parent_must_rollback",
                    serde_json::json!({}),
                    now(),
                )],
            ),
            Err(StorageError::OptimisticConflict {
                aggregate,
                expected_revision,
            }) if aggregate == "mission_source_fence" && expected_revision == parent_previous_revision
        ));
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after stale parent conflict")
                .len(),
            event_count
        );
        store
            .update_mission_atomic_with_application_source_fences(
                &candidate,
                mission.revision,
                None,
                &[
                    ApplicationSourceRevisionFence::present(
                        ApplicationSourceKind::Project,
                        revised_project.id.to_string(),
                        revised_project.revision,
                    ),
                    ApplicationSourceRevisionFence::present(
                        ApplicationSourceKind::Company,
                        company.id.to_string(),
                        2,
                    ),
                    ApplicationSourceRevisionFence::present(
                        ApplicationSourceKind::Mission,
                        parent.id.to_string(),
                        parent.revision,
                    ),
                ],
                &[PendingEvent::new(
                    "mission.source_fence_verified",
                    serde_json::json!({}),
                    now(),
                )],
            )
            .expect("current source revision and Mission commit atomically");
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("updated mission"),
            candidate
        );
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("events after successful fence")
                .len(),
            event_count + 1
        );
    }
}
