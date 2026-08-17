use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ActorId, CreatorAcceptance, CreatorDeliverable, CreatorHiringAward, CreatorId,
    CreatorMilestone, CreatorMilestoneId, CreatorPayoutRecord, CreatorTask, CreatorTaskId,
    CurrencyCode, DeliverableAssessment, DeliverableId, DeliverableReview, Mission, MissionId,
    Money, PayoutAuthorization, ProjectId, ReviewId, RightsAttestation, TenantId, UsageRights,
};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::aggregate::{PendingEvent, append_events};
use crate::normalized::update_mission_normalized_cas;
use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedMutation {
    pub event_sequence: i64,
    pub outbox_sequence: i64,
    pub state_revision: u64,
}

impl ProjectStore {
    pub fn creator_tasks_for_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<CreatorTask>, StorageError> {
        self.load_project(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT id FROM creator_tasks
             WHERE project_id = ?1 ORDER BY created_at, id",
        )?;
        let ids = statement
            .query_map(params![project_id.as_str()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| self.load_creator_task(project_id, &CreatorTaskId::from_stable(id)))
            .collect()
    }

    pub fn create_creator_task(
        &mut self,
        task: &CreatorTask,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        if task.state_revision != 1 {
            return Err(StorageError::InvalidInitialRevision(task.state_revision));
        }
        self.persist_creator_task(task, None, event_type, payload, recorded_at)
    }

    pub fn update_creator_task(
        &mut self,
        task: &CreatorTask,
        expected_revision: u64,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        if task.state_revision != expected_revision.saturating_add(1) {
            return Err(StorageError::UnexpectedNextRevision {
                expected: expected_revision.saturating_add(1),
                actual: task.state_revision,
            });
        }
        self.persist_creator_task(
            task,
            Some(expected_revision),
            event_type,
            payload,
            recorded_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_creator_task_and_mission_atomic(
        &mut self,
        task: &CreatorTask,
        expected_task_revision: u64,
        task_event: &PendingEvent,
        mission: &Mission,
        expected_mission_revision: u64,
        mission_events: &[PendingEvent],
    ) -> Result<(), StorageError> {
        if task.state_revision != expected_task_revision.saturating_add(1) {
            return Err(StorageError::UnexpectedNextRevision {
                expected: expected_task_revision.saturating_add(1),
                actual: task.state_revision,
            });
        }
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if task_event.event_type.trim().is_empty() || mission_events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        if task.tenant_id != mission.tenant_id
            || task.project_id != mission.project_id
            || task.mission_id != mission.id
        {
            return Err(StorageError::TenantScopeMismatch);
        }

        let transaction = self.connection.transaction()?;
        ensure_project_and_mission(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
        )?;
        update_creator_task_row(&transaction, task, expected_task_revision)?;
        clear_creator_children(&transaction, task)?;
        insert_creator_children(&transaction, task)?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;

        let task_payload = serde_json::to_string(&task_event.payload)?;
        append_domain_event(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
            &task_event.event_type,
            &task_payload,
            task_event.recorded_at,
        )?;
        append_outbox(
            &transaction,
            task,
            &task_event.event_type,
            &task_payload,
            task_event.recorded_at,
        )?;
        append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission",
            mission.id.as_str(),
            mission_events,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load_creator_task(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<CreatorTask, StorageError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, tenant_id, project_id, mission_id, creator_id, title, brief,
                        acceptance_criteria_json, deliverable_requirements_json,
                        bounty_minor, currency, revision_limit, usage_rights_json, due_at,
                        contract_revision, state_revision, accepted_revision, status,
                        funding_reservation_json, acceptance_json, created_at, updated_at,
                        hiring_award_json
                 FROM creator_tasks WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), task_id.as_str()],
                |row| {
                    Ok(CreatorTaskRow {
                        id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        project_id: row.get(2)?,
                        mission_id: row.get(3)?,
                        creator_id: row.get(4)?,
                        title: row.get(5)?,
                        brief: row.get(6)?,
                        acceptance_criteria_json: row.get(7)?,
                        deliverable_requirements_json: row.get(8)?,
                        bounty_minor: row.get(9)?,
                        currency: row.get(10)?,
                        revision_limit: row.get(11)?,
                        usage_rights_json: row.get(12)?,
                        due_at: row.get(13)?,
                        contract_revision: row.get(14)?,
                        state_revision: row.get(15)?,
                        accepted_revision: row.get(16)?,
                        status: row.get(17)?,
                        funding_reservation_json: row.get(18)?,
                        acceptance_json: row.get(19)?,
                        created_at: row.get(20)?,
                        updated_at: row.get(21)?,
                        hiring_award_json: row.get(22)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| StorageError::CreatorTaskNotFound {
                project_id: project_id.clone(),
                task_id: task_id.clone(),
            })?;

        let milestones = self.load_creator_milestones(project_id, task_id)?;
        let deliverables = self.load_creator_deliverables(project_id, task_id)?;
        let reviews = self.load_creator_reviews(project_id, task_id)?;
        let payout_authorizations = self.load_creator_payout_authorizations(project_id, task_id)?;
        let payouts = self.load_creator_payouts(project_id, task_id)?;

        Ok(CreatorTask {
            id: CreatorTaskId::from_stable(row.id),
            tenant_id: TenantId::from_stable(row.tenant_id),
            project_id: ProjectId::from_stable(row.project_id),
            mission_id: MissionId::from_stable(row.mission_id),
            creator_id: CreatorId::from_stable(row.creator_id),
            hiring_award: row
                .hiring_award_json
                .as_deref()
                .map(decode_json::<CreatorHiringAward>)
                .transpose()?
                .ok_or_else(|| {
                    StorageError::DomainDecode(
                        "legacy creator task has no verified hiring award; user selection is required"
                            .into(),
                    )
                })?,
            title: row.title,
            brief: row.brief,
            acceptance_criteria: decode_json(&row.acceptance_criteria_json)?,
            deliverable_requirements: decode_json(&row.deliverable_requirements_json)?,
            bounty: Money::new(row.bounty_minor, parse_currency(&row.currency)?),
            milestones,
            revision_limit: checked_u16(row.revision_limit, "revision_limit")?,
            usage_rights: decode_json::<UsageRights>(&row.usage_rights_json)?,
            due_at: parse_time(&row.due_at)?,
            contract_revision: checked_u64(row.contract_revision, "contract_revision")?,
            state_revision: checked_u64(row.state_revision, "state_revision")?,
            accepted_revision: row
                .accepted_revision
                .map(|value| checked_u64(value, "accepted_revision"))
                .transpose()?,
            status: decode_enum(&row.status)?,
            funding_reservation: row
                .funding_reservation_json
                .as_deref()
                .map(decode_json)
                .transpose()?,
            acceptance: row
                .acceptance_json
                .as_deref()
                .map(decode_json::<CreatorAcceptance>)
                .transpose()?,
            deliverables,
            reviews,
            payout_authorizations,
            payouts,
            created_at: parse_time(&row.created_at)?,
            updated_at: parse_time(&row.updated_at)?,
        })
    }

    fn persist_creator_task(
        &mut self,
        task: &CreatorTask,
        expected_revision: Option<u64>,
        event_type: &str,
        payload: &Value,
        recorded_at: DateTime<Utc>,
    ) -> Result<PersistedMutation, StorageError> {
        let transaction = self.connection.transaction()?;
        ensure_project_and_mission(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
        )?;
        match expected_revision {
            None => insert_creator_task(&transaction, task)?,
            Some(expected_revision) => {
                update_creator_task_row(&transaction, task, expected_revision)?;
                clear_creator_children(&transaction, task)?;
            }
        }
        insert_creator_children(&transaction, task)?;
        let payload_json = serde_json::to_string(payload)?;
        let event_sequence = append_domain_event(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
            event_type,
            &payload_json,
            recorded_at,
        )?;
        let outbox_sequence =
            append_outbox(&transaction, task, event_type, &payload_json, recorded_at)?;
        transaction.commit()?;
        Ok(PersistedMutation {
            event_sequence,
            outbox_sequence,
            state_revision: task.state_revision,
        })
    }

    fn load_creator_milestones(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<CreatorMilestone>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, title, amount_minor, currency, due_at, status, revisions_used
             FROM creator_milestones WHERE project_id = ?1 AND task_id = ?2
             ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), task_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, title, amount_minor, currency, due_at, status, revisions_used) = row?;
            Ok(CreatorMilestone {
                id: CreatorMilestoneId::from_stable(id),
                title,
                amount: Money::new(amount_minor, parse_currency(&currency)?),
                due_at: parse_time(&due_at)?,
                status: decode_enum(&status)?,
                revisions_used: checked_u16(revisions_used, "revisions_used")?,
            })
        })
        .collect()
    }

    fn load_creator_deliverables(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<CreatorDeliverable>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, milestone_id, revision, artifact_uri, media_type, size_bytes,
                    content_digest, uploaded_at, assessment_json, rights_json, status
             FROM creator_deliverables WHERE project_id = ?1 AND task_id = ?2
             ORDER BY milestone_id, revision ASC",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), task_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;
        rows.map(|row| {
            let (
                id,
                milestone_id,
                revision,
                artifact_uri,
                media_type,
                size_bytes,
                content_digest,
                uploaded_at,
                assessment,
                rights,
                status,
            ) = row?;
            Ok(CreatorDeliverable {
                id: DeliverableId::from_stable(id),
                task_id: task_id.clone(),
                milestone_id: CreatorMilestoneId::from_stable(milestone_id),
                revision: checked_u32(revision, "deliverable_revision")?,
                artifact_uri,
                media_type,
                size_bytes: checked_u64(size_bytes, "size_bytes")?,
                content_digest,
                uploaded_at: parse_time(&uploaded_at)?,
                assessment: decode_json::<DeliverableAssessment>(&assessment)?,
                rights: decode_json::<RightsAttestation>(&rights)?,
                status: decode_enum(&status)?,
            })
        })
        .collect()
    }

    fn load_creator_reviews(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<DeliverableReview>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT id, deliverable_id, deliverable_digest, reviewer_id, decision,
                    acceptance_checks_json, notes, reviewed_at
             FROM creator_reviews WHERE project_id = ?1 AND task_id = ?2
             ORDER BY reviewed_at, id",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), task_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        rows.map(|row| {
            let (id, deliverable_id, digest, reviewer_id, decision, checks, notes, reviewed_at) =
                row?;
            Ok(DeliverableReview {
                id: ReviewId::from_stable(id),
                task_id: task_id.clone(),
                deliverable_id: DeliverableId::from_stable(deliverable_id),
                deliverable_digest: digest,
                reviewer_id: ActorId::from_stable(reviewer_id),
                decision: decode_enum(&decision)?,
                acceptance_checks: decode_json(&checks)?,
                notes,
                reviewed_at: parse_time(&reviewed_at)?,
            })
        })
        .collect()
    }

    fn load_creator_payouts(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<CreatorPayoutRecord>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT authorization_json, confirmation_json
             FROM creator_payouts WHERE project_id = ?1 AND task_id = ?2
             ORDER BY verified_at, payout_id",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), task_id.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (authorization, confirmation) = row?;
            Ok(CreatorPayoutRecord {
                authorization: decode_json(&authorization)?,
                confirmation: decode_json(&confirmation)?,
            })
        })
        .collect()
    }

    fn load_creator_payout_authorizations(
        &self,
        project_id: &ProjectId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<PayoutAuthorization>, StorageError> {
        let mut statement = self.connection.prepare(
            "SELECT authorization_json FROM creator_payout_authorizations
             WHERE project_id = ?1 AND task_id = ?2 ORDER BY authorized_at, payout_id",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), task_id.as_str()], |row| {
            row.get::<_, String>(0)
        })?;
        rows.map(|row| decode_json(&row?)).collect()
    }
}

#[derive(Debug)]
struct CreatorTaskRow {
    id: String,
    tenant_id: String,
    project_id: String,
    mission_id: String,
    creator_id: String,
    title: String,
    brief: String,
    acceptance_criteria_json: String,
    deliverable_requirements_json: String,
    bounty_minor: i64,
    currency: String,
    revision_limit: i64,
    usage_rights_json: String,
    due_at: String,
    contract_revision: i64,
    state_revision: i64,
    accepted_revision: Option<i64>,
    status: String,
    funding_reservation_json: Option<String>,
    acceptance_json: Option<String>,
    created_at: String,
    updated_at: String,
    hiring_award_json: Option<String>,
}

pub(crate) fn ensure_project_and_mission(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<(), StorageError> {
    let exists = transaction
        .query_row(
            "SELECT 1 FROM missions
             WHERE tenant_id = ?1 AND project_id = ?2 AND id = ?3",
            params![tenant_id.as_str(), project_id.as_str(), mission_id.as_str()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Err(StorageError::MissionNotFound {
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
        });
    }
    Ok(())
}

pub(crate) fn insert_creator_task(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO creator_tasks
           (id, tenant_id, project_id, mission_id, creator_id, title, brief,
            acceptance_criteria_json, deliverable_requirements_json, bounty_minor, currency,
            revision_limit, usage_rights_json, due_at, contract_revision, state_revision,
            accepted_revision, status, funding_reservation_json, acceptance_json,
            created_at, updated_at, hiring_award_json)
         VALUES
           (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        creator_task_params(task)?,
    )?;
    Ok(())
}

pub(crate) fn update_creator_task_row(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let expected_revision = to_sql_u64(expected_revision)?;
    let updated = transaction.execute(
        "UPDATE creator_tasks SET
           tenant_id = ?2, mission_id = ?4, creator_id = ?5, title = ?6, brief = ?7,
           acceptance_criteria_json = ?8, deliverable_requirements_json = ?9,
           bounty_minor = ?10, currency = ?11, revision_limit = ?12,
           usage_rights_json = ?13, due_at = ?14, contract_revision = ?15,
           state_revision = ?16, accepted_revision = ?17, status = ?18,
           funding_reservation_json = ?19, acceptance_json = ?20,
           created_at = ?21, updated_at = ?22, hiring_award_json = ?23
         WHERE id = ?1 AND project_id = ?3 AND state_revision = ?24",
        rusqlite::params_from_iter(
            creator_task_values(task)?
                .into_iter()
                .chain([rusqlite::types::Value::Integer(expected_revision)]),
        ),
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("creator_task:{}", task.id),
            expected_revision: u64::try_from(expected_revision).unwrap_or_default(),
        });
    }
    Ok(())
}

fn creator_task_params(task: &CreatorTask) -> Result<impl rusqlite::Params + use<>, StorageError> {
    Ok(rusqlite::params_from_iter(creator_task_values(task)?))
}

fn creator_task_values(task: &CreatorTask) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    use rusqlite::types::Value as SqlValue;
    Ok(vec![
        SqlValue::Text(task.id.to_string()),
        SqlValue::Text(task.tenant_id.to_string()),
        SqlValue::Text(task.project_id.to_string()),
        SqlValue::Text(task.mission_id.to_string()),
        SqlValue::Text(task.creator_id.to_string()),
        SqlValue::Text(task.title.clone()),
        SqlValue::Text(task.brief.clone()),
        SqlValue::Text(serde_json::to_string(&task.acceptance_criteria)?),
        SqlValue::Text(serde_json::to_string(&task.deliverable_requirements)?),
        SqlValue::Integer(task.bounty.amount_minor),
        SqlValue::Text(task.bounty.currency.to_string()),
        SqlValue::Integer(i64::from(task.revision_limit)),
        SqlValue::Text(serde_json::to_string(&task.usage_rights)?),
        SqlValue::Text(task.due_at.to_rfc3339()),
        SqlValue::Integer(to_sql_u64(task.contract_revision)?),
        SqlValue::Integer(to_sql_u64(task.state_revision)?),
        task.accepted_revision.map_or(SqlValue::Null, |value| {
            to_sql_u64(value).map_or(SqlValue::Null, SqlValue::Integer)
        }),
        SqlValue::Text(enum_name(&task.status)?),
        task.funding_reservation
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?
            .map_or(SqlValue::Null, SqlValue::Text),
        task.acceptance
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?
            .map_or(SqlValue::Null, SqlValue::Text),
        SqlValue::Text(task.created_at.to_rfc3339()),
        SqlValue::Text(task.updated_at.to_rfc3339()),
        SqlValue::Text(serde_json::to_string(&task.hiring_award)?),
    ])
}

pub(crate) fn clear_creator_children(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    for table in [
        "creator_payouts",
        "creator_payout_authorizations",
        "creator_reviews",
        "creator_deliverables",
        "creator_milestones",
    ] {
        transaction.execute(
            &format!("DELETE FROM {table} WHERE project_id = ?1 AND task_id = ?2"),
            params![task.project_id.as_str(), task.id.as_str()],
        )?;
    }
    Ok(())
}

pub(crate) fn insert_creator_children(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    insert_milestones(transaction, task)?;
    insert_deliverables(transaction, task)?;
    insert_reviews(transaction, task)?;
    insert_payout_authorizations(transaction, task)?;
    insert_payouts(transaction, task)
}

fn insert_milestones(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    for (ordinal, milestone) in task.milestones.iter().enumerate() {
        transaction.execute(
            "INSERT INTO creator_milestones
               (task_id, project_id, id, ordinal, title, amount_minor, currency, due_at,
                status, revisions_used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                task.id.as_str(),
                task.project_id.as_str(),
                milestone.id.as_str(),
                i64::try_from(ordinal)
                    .map_err(|_| StorageError::DomainDecode("milestone ordinal overflow".into()))?,
                milestone.title,
                milestone.amount.amount_minor,
                milestone.amount.currency.as_str(),
                milestone.due_at.to_rfc3339(),
                enum_name(&milestone.status)?,
                i64::from(milestone.revisions_used),
            ],
        )?;
    }
    Ok(())
}

fn insert_deliverables(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    for deliverable in &task.deliverables {
        transaction.execute(
            "INSERT INTO creator_deliverables
               (task_id, project_id, id, milestone_id, revision, artifact_uri, media_type,
                size_bytes, content_digest, uploaded_at, assessment_json, rights_json, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                task.id.as_str(),
                task.project_id.as_str(),
                deliverable.id.as_str(),
                deliverable.milestone_id.as_str(),
                i64::from(deliverable.revision),
                deliverable.artifact_uri,
                deliverable.media_type,
                to_sql_u64(deliverable.size_bytes)?,
                deliverable.content_digest,
                deliverable.uploaded_at.to_rfc3339(),
                serde_json::to_string(&deliverable.assessment)?,
                serde_json::to_string(&deliverable.rights)?,
                enum_name(&deliverable.status)?,
            ],
        )?;
    }
    Ok(())
}

fn insert_reviews(transaction: &Transaction<'_>, task: &CreatorTask) -> Result<(), StorageError> {
    for review in &task.reviews {
        transaction.execute(
            "INSERT INTO creator_reviews
               (task_id, project_id, id, deliverable_id, deliverable_digest, reviewer_id,
                decision, acceptance_checks_json, notes, reviewed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                task.id.as_str(),
                task.project_id.as_str(),
                review.id.as_str(),
                review.deliverable_id.as_str(),
                review.deliverable_digest,
                review.reviewer_id.as_str(),
                enum_name(&review.decision)?,
                serde_json::to_string(&review.acceptance_checks)?,
                review.notes,
                review.reviewed_at.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

fn insert_payout_authorizations(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
) -> Result<(), StorageError> {
    for authorization in &task.payout_authorizations {
        transaction.execute(
            "INSERT INTO creator_payout_authorizations
               (task_id, project_id, payout_id, milestone_id, deliverable_id, review_id,
                scope_digest, authorization_json, authorized_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                task.id.as_str(),
                task.project_id.as_str(),
                authorization.payout_id.as_str(),
                authorization.milestone_id.as_str(),
                authorization.deliverable_id.as_str(),
                authorization.review_id.as_str(),
                authorization.scope_digest,
                serde_json::to_string(authorization)?,
                authorization.authorized_at.to_rfc3339(),
                authorization.expires_at.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

fn insert_payouts(transaction: &Transaction<'_>, task: &CreatorTask) -> Result<(), StorageError> {
    for payout in &task.payouts {
        transaction.execute(
            "INSERT INTO creator_payouts
               (task_id, project_id, payout_id, milestone_id, deliverable_id, review_id,
                amount_minor, currency, scope_digest, provider, external_id,
                authorization_json, confirmation_json, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                task.id.as_str(),
                task.project_id.as_str(),
                payout.authorization.payout_id.as_str(),
                payout.authorization.milestone_id.as_str(),
                payout.authorization.deliverable_id.as_str(),
                payout.authorization.review_id.as_str(),
                payout.authorization.amount.amount_minor,
                payout.authorization.amount.currency.as_str(),
                payout.authorization.scope_digest,
                payout.confirmation.provider,
                payout.confirmation.external_id,
                serde_json::to_string(&payout.authorization)?,
                serde_json::to_string(&payout.confirmation)?,
                payout.confirmation.verified_at.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

fn append_domain_event(
    transaction: &Transaction<'_>,
    tenant_id: &TenantId,
    project_id: &ProjectId,
    mission_id: &MissionId,
    event_type: &str,
    payload_json: &str,
    recorded_at: DateTime<Utc>,
) -> Result<i64, StorageError> {
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tenant_id.as_str(),
            project_id.as_str(),
            mission_id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn append_outbox(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
    event_type: &str,
    payload_json: &str,
    recorded_at: DateTime<Utc>,
) -> Result<i64, StorageError> {
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type, payload_json,
            available_at, created_at)
         VALUES (?1, ?2, ?3, 'creator_task', ?4, ?5, ?6, ?7, ?7)",
        params![
            task.tenant_id.as_str(),
            task.project_id.as_str(),
            task.mission_id.as_str(),
            task.id.as_str(),
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn enum_name(value: &impl Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("enum did not serialize as a string".into()))
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(Value::String(value.to_owned()))?)
}

fn decode_json<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_str(value)?)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn parse_currency(value: &str) -> Result<CurrencyCode, StorageError> {
    CurrencyCode::parse(value).map_err(|error| StorageError::DomainDecode(error.to_string()))
}

fn checked_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn checked_u32(value: i64, field: &str) -> Result<u32, StorageError> {
    u32::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn checked_u16(value: i64, field: &str) -> Result<u16, StorageError> {
    u16::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}
