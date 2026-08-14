use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ActorId, CreatorAcceptance, CreatorDeliverable, CreatorHiringAward, CreatorId,
    CreatorMilestone, CreatorMilestoneId, CreatorPayoutRecord, CreatorTask, CreatorTaskId,
    CreatorWorkExecutionReceipt, CreatorWorkExecutionStatus, CreatorWorkFulfillment,
    CreatorWorkWorkerLease, CreatorWorkWorkerStatus, CurrencyCode, DeliverableAssessment,
    DeliverableId, DeliverableReview, Mission, MissionId, Money, PayoutAuthorization, ProjectId,
    ReviewId, RightsAttestation, TenantId, UsageRights,
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

    /// Persists the current CreatorWork worker fence in the existing
    /// append-only event log. The latest lease is reconstructed after a
    /// restart, so a crashed or revoked generation cannot submit through a
    /// newly opened store.
    pub fn save_creator_work_worker_lease(
        &mut self,
        lease: &CreatorWorkWorkerLease,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let task = self.load_creator_task(&lease.project_id, &lease.task_id)?;
        let mission = self.load_mission(&lease.project_id, &lease.mission_id)?;
        validate_creator_work_lease_scope(&task, &mission, lease)?;
        if let Some(previous) = self.load_creator_work_worker_lease(
            &lease.project_id,
            &lease.mission_id,
            &lease.task_id,
        )? {
            if previous == *lease {
                return Ok(());
            }
            if lease.generation < previous.generation
                || (lease.generation == previous.generation
                    && (!same_creator_work_worker_identity(&previous, lease)
                        || lease.updated_at < previous.updated_at))
            {
                return Err(StorageError::OptimisticConflict {
                    aggregate: format!("creator_work_worker:{}", lease.task_id),
                    expected_revision: previous.generation,
                });
            }
        }
        let payload = serde_json::to_value(lease)?;
        append_creator_work_event(
            self,
            &task,
            "creator_work.worker_lease",
            &payload,
            recorded_at,
            "creator_work_worker",
            lease.task_id.as_str(),
        )?;
        Ok(())
    }

    pub fn load_creator_work_worker_lease(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
    ) -> Result<Option<CreatorWorkWorkerLease>, StorageError> {
        let mut latest: Option<(i64, CreatorWorkWorkerLease)> = None;
        for event in self.events_for_mission(project_id, mission_id)? {
            if event.event_type != "creator_work.worker_lease" {
                continue;
            }
            let lease: CreatorWorkWorkerLease = decode_value(event.payload)?;
            if lease.project_id != *project_id
                || lease.mission_id != *mission_id
                || lease.task_id != *task_id
            {
                continue;
            }
            if latest
                .as_ref()
                .is_some_and(|(_, previous): &(i64, CreatorWorkWorkerLease)| {
                    lease.generation < previous.generation
                })
            {
                return Err(StorageError::DomainDecode(
                    "CreatorWork worker generation regressed in the event log".into(),
                ));
            }
            latest = Some((event.sequence, lease));
        }
        Ok(latest.map(|(_, lease)| lease))
    }

    /// Persists the immutable request receipt before provider execution. A
    /// replayed start is idempotent; a different request under the same
    /// execution digest is an immutable-record conflict.
    pub fn save_creator_work_execution_receipt(
        &mut self,
        receipt: &CreatorWorkExecutionReceipt,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        receipt
            .validate()
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let task = self.load_creator_task(&receipt.request.project_id, &receipt.request.task_id)?;
        let mission =
            self.load_mission(&receipt.request.project_id, &receipt.request.mission_id)?;
        validate_creator_work_execution_receipt_scope(&task, &mission, receipt)?;
        if let Some(previous) = self.load_creator_work_execution_receipt(
            &receipt.request.project_id,
            &receipt.request.mission_id,
            &receipt.request.task_id,
            &receipt.request.request_digest(),
        )? {
            if previous == *receipt {
                return Ok(());
            }
            if !previous.follows(receipt) {
                return Err(StorageError::OptimisticConflict {
                    aggregate: format!("creator_work_execution:{}", receipt.request.task_id),
                    expected_revision: 1,
                });
            }
        } else if receipt.status != CreatorWorkExecutionStatus::Started {
            return Err(StorageError::ScopedRecordNotFound {
                kind: "creator work execution receipt",
                project_id: receipt.request.project_id.clone(),
                id: receipt.request.request_digest(),
            });
        } else {
            let current_worker = self
                .load_creator_work_worker_lease(
                    &receipt.request.project_id,
                    &receipt.request.mission_id,
                    &receipt.request.task_id,
                )?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "creator work worker lease",
                    project_id: receipt.request.project_id.clone(),
                    id: receipt.request.task_id.to_string(),
                })?;
            if current_worker != receipt.request.worker
                || current_worker.status != CreatorWorkWorkerStatus::Active
            {
                return Err(StorageError::OptimisticConflict {
                    aggregate: format!("creator_work_worker:{}", receipt.request.task_id),
                    expected_revision: current_worker.generation,
                });
            }
        }
        let payload = serde_json::to_value(receipt)?;
        append_creator_work_event(
            self,
            &task,
            "creator_work.execution_receipt",
            &payload,
            recorded_at,
            "creator_work_execution",
            &receipt.request.request_digest(),
        )?;
        Ok(())
    }

    pub fn load_creator_work_execution_receipt(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
        request_digest: &str,
    ) -> Result<Option<CreatorWorkExecutionReceipt>, StorageError> {
        let mut latest: Option<CreatorWorkExecutionReceipt> = None;
        for event in self.events_for_mission(project_id, mission_id)? {
            if event.event_type != "creator_work.execution_receipt" {
                continue;
            }
            let receipt: CreatorWorkExecutionReceipt = decode_value(event.payload)?;
            receipt
                .validate()
                .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
            if receipt.request.project_id != *project_id
                || receipt.request.mission_id != *mission_id
                || receipt.request.task_id != *task_id
                || receipt.request.request_digest() != request_digest
            {
                continue;
            }
            if let Some(previous) = &latest
                && !previous.follows(&receipt)
            {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "creator work execution receipt",
                    id: request_digest.into(),
                });
            }
            latest = Some(receipt);
        }
        Ok(latest)
    }

    /// Re-adopts an already durably recorded result without contacting the
    /// provider. A started or revoked execution is deliberately not
    /// replayable, and a missing linked fulfillment is treated as corruption.
    pub fn adopt_creator_work_result(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
        request_digest: &str,
    ) -> Result<Option<CreatorWorkFulfillment>, StorageError> {
        let Some(receipt) = self.load_creator_work_execution_receipt(
            project_id,
            mission_id,
            task_id,
            request_digest,
        )?
        else {
            return Ok(None);
        };
        if receipt.status != CreatorWorkExecutionStatus::ResultRecorded {
            return Ok(None);
        }
        let result_id = receipt.result_id.as_deref().ok_or_else(|| {
            StorageError::DomainDecode("recorded CreatorWork execution has no result id".into())
        })?;
        let fulfillment = self
            .load_creator_work_fulfillment(project_id, mission_id, task_id, result_id)?
            .ok_or_else(|| {
                StorageError::DomainDecode(
                    "recorded CreatorWork execution has no linked fulfillment".into(),
                )
            })?;
        if fulfillment.result.request_digest != request_digest
            || receipt.result_digest.as_deref() != Some(fulfillment.result.result_digest().as_str())
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "creator work execution result link",
                id: request_digest.into(),
            });
        }
        Ok(Some(fulfillment))
    }

    pub fn revoke_creator_work_execution(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
        request_digest: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let current = self
            .load_creator_work_execution_receipt(project_id, mission_id, task_id, request_digest)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "creator work execution receipt",
                project_id: project_id.clone(),
                id: request_digest.into(),
            })?;
        let revoked = current
            .revoke(recorded_at)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        self.save_creator_work_execution_receipt(&revoked, recorded_at)
    }

    /// Records one immutable provider result and its outcome handoff. A
    /// repeated result id with the same payload is idempotent; a reused id
    /// with different facts is rejected as an immutable-record conflict.
    #[allow(
        clippy::too_many_lines,
        reason = "CreatorWork result and execution receipt share one atomic local transaction"
    )]
    pub fn save_creator_work_fulfillment(
        &mut self,
        fulfillment: &CreatorWorkFulfillment,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let task = self.load_creator_task(&fulfillment.project_id, &fulfillment.task_id)?;
        let mission = self.load_mission(&fulfillment.project_id, &fulfillment.mission_id)?;
        validate_creator_work_fulfillment_scope(&task, &mission, fulfillment)?;
        let current_worker = self
            .load_creator_work_worker_lease(
                &fulfillment.project_id,
                &fulfillment.mission_id,
                &fulfillment.task_id,
            )?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "creator work worker lease",
                project_id: fulfillment.project_id.clone(),
                id: fulfillment.task_id.to_string(),
            })?;
        if current_worker.status != CreatorWorkWorkerStatus::Active
            || fulfillment.worker.status != CreatorWorkWorkerStatus::Active
            || current_worker != fulfillment.worker
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("creator_work_worker:{}", fulfillment.task_id),
                expected_revision: current_worker.generation,
            });
        }
        if let Some(previous) = self.load_creator_work_fulfillment(
            &fulfillment.project_id,
            &fulfillment.mission_id,
            &fulfillment.task_id,
            &fulfillment.result.result_id,
        )? {
            if previous == *fulfillment {
                return Ok(());
            }
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "creator work fulfillment result",
                id: fulfillment.result.result_id.clone(),
            });
        }
        let execution = self
            .load_creator_work_execution_receipt(
                &fulfillment.project_id,
                &fulfillment.mission_id,
                &fulfillment.task_id,
                &fulfillment.result.request_digest,
            )?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "creator work execution receipt",
                project_id: fulfillment.project_id.clone(),
                id: fulfillment.result.request_digest.clone(),
            })?;
        if fulfillment.result.protocol_version != execution.request.protocol_version
            || fulfillment.result.objective != execution.request.objective
            || fulfillment.result.capability != execution.request.capability
            || fulfillment.result.source_commit != execution.request.source_commit
            || fulfillment.result.input_digest != execution.request.input_digest
            || fulfillment.outcome_handoff.result_digest != fulfillment.result.result_digest()
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "creator work execution result",
                id: fulfillment.result.result_id.clone(),
            });
        }
        let completed = execution
            .record_result(&fulfillment.result, recorded_at)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?;
        let execution_payload = serde_json::to_string(&completed)?;
        let fulfillment_payload = serde_json::to_string(fulfillment)?;
        let transaction = self.connection.transaction()?;
        ensure_project_and_mission(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
        )?;
        append_domain_event(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
            "creator_work.execution_receipt",
            &execution_payload,
            recorded_at,
        )?;
        append_creator_work_outbox(
            &transaction,
            &task,
            "creator_work_execution",
            &fulfillment.result.request_digest,
            "creator_work.execution_receipt",
            &execution_payload,
            recorded_at,
        )?;
        append_domain_event(
            &transaction,
            &task.tenant_id,
            &task.project_id,
            &task.mission_id,
            "creator_work.fulfillment_recorded",
            &fulfillment_payload,
            recorded_at,
        )?;
        append_creator_work_outbox(
            &transaction,
            &task,
            "creator_work_fulfillment",
            &fulfillment.result.result_id,
            "creator_work.fulfillment_recorded",
            &fulfillment_payload,
            recorded_at,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load_creator_work_fulfillment(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
        result_id: &str,
    ) -> Result<Option<CreatorWorkFulfillment>, StorageError> {
        let mut found = None;
        for event in self.events_for_mission(project_id, mission_id)? {
            if event.event_type != "creator_work.fulfillment_recorded" {
                continue;
            }
            let fulfillment: CreatorWorkFulfillment = decode_value(event.payload)?;
            if fulfillment.project_id != *project_id
                || fulfillment.mission_id != *mission_id
                || fulfillment.task_id != *task_id
                || fulfillment.result.result_id != result_id
            {
                continue;
            }
            if let Some(previous) = &found {
                if previous != &fulfillment {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "creator work fulfillment result",
                        id: result_id.into(),
                    });
                }
            } else {
                found = Some(fulfillment);
            }
        }
        Ok(found)
    }

    pub fn creator_work_fulfillments_for_task(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        task_id: &CreatorTaskId,
    ) -> Result<Vec<CreatorWorkFulfillment>, StorageError> {
        let mut fulfillments = Vec::new();
        for event in self.events_for_mission(project_id, mission_id)? {
            if event.event_type != "creator_work.fulfillment_recorded" {
                continue;
            }
            let fulfillment: CreatorWorkFulfillment = decode_value(event.payload)?;
            if fulfillment.project_id == *project_id
                && fulfillment.mission_id == *mission_id
                && fulfillment.task_id == *task_id
                && !fulfillments
                    .iter()
                    .any(|previous: &CreatorWorkFulfillment| {
                        previous.result.result_id == fulfillment.result.result_id
                    })
            {
                fulfillments.push(fulfillment);
            }
        }
        Ok(fulfillments)
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

fn append_creator_work_event(
    store: &mut ProjectStore,
    task: &CreatorTask,
    event_type: &str,
    payload: &Value,
    recorded_at: DateTime<Utc>,
    aggregate_type: &str,
    aggregate_id: &str,
) -> Result<(), StorageError> {
    if event_type.trim().is_empty()
        || aggregate_type.trim().is_empty()
        || aggregate_id.trim().is_empty()
    {
        return Err(StorageError::EmptyEventType);
    }
    let payload_json = serde_json::to_string(payload)?;
    let transaction = store.connection.transaction()?;
    ensure_project_and_mission(
        &transaction,
        &task.tenant_id,
        &task.project_id,
        &task.mission_id,
    )?;
    append_domain_event(
        &transaction,
        &task.tenant_id,
        &task.project_id,
        &task.mission_id,
        event_type,
        &payload_json,
        recorded_at,
    )?;
    append_creator_work_outbox(
        &transaction,
        task,
        aggregate_type,
        aggregate_id,
        event_type,
        &payload_json,
        recorded_at,
    )?;
    transaction.commit()?;
    Ok(())
}

fn append_creator_work_outbox(
    transaction: &Transaction<'_>,
    task: &CreatorTask,
    aggregate_type: &str,
    aggregate_id: &str,
    event_type: &str,
    payload_json: &str,
    recorded_at: DateTime<Utc>,
) -> Result<i64, StorageError> {
    transaction.execute(
        "INSERT INTO outbox_messages
           (tenant_id, project_id, mission_id, aggregate_type, aggregate_id, event_type, payload_json,
            available_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            task.tenant_id.as_str(),
            task.project_id.as_str(),
            task.mission_id.as_str(),
            aggregate_type,
            aggregate_id,
            event_type,
            payload_json,
            recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(transaction.last_insert_rowid())
}

fn validate_creator_work_lease_scope(
    task: &CreatorTask,
    mission: &Mission,
    lease: &CreatorWorkWorkerLease,
) -> Result<(), StorageError> {
    if lease.tenant_id != task.tenant_id
        || lease.project_id != task.project_id
        || lease.mission_id != task.mission_id
        || lease.creator_id != task.creator_id
        || lease.task_id != task.id
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    if lease.contract_revision != task.contract_revision
        || lease.task_state_revision != task.state_revision
        || lease.mission_revision != mission.revision
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "creator work worker revision fence",
            id: lease.task_id.to_string(),
        });
    }
    Ok(())
}

fn validate_creator_work_fulfillment_scope(
    task: &CreatorTask,
    mission: &Mission,
    fulfillment: &CreatorWorkFulfillment,
) -> Result<(), StorageError> {
    if fulfillment.tenant_id != task.tenant_id
        || fulfillment.project_id != task.project_id
        || fulfillment.mission_id != task.mission_id
        || fulfillment.creator_id != task.creator_id
        || fulfillment.task_id != task.id
        || fulfillment.contract_revision != task.contract_revision
        || fulfillment.task_state_revision != task.state_revision
        || fulfillment.mission_revision != mission.revision
        || fulfillment.worker.tenant_id != task.tenant_id
        || fulfillment.worker.project_id != task.project_id
        || fulfillment.worker.mission_id != task.mission_id
        || fulfillment.worker.creator_id != task.creator_id
        || fulfillment.worker.task_id != task.id
        || fulfillment.worker.contract_revision != task.contract_revision
        || fulfillment.worker.task_state_revision != task.state_revision
        || fulfillment.worker.mission_revision != mission.revision
        || fulfillment.provider_generation != fulfillment.worker.provider_generation
        || fulfillment.result.tenant_id != task.tenant_id
        || fulfillment.result.project_id != task.project_id
        || fulfillment.result.mission_id != task.mission_id
        || fulfillment.result.creator_id != task.creator_id
        || fulfillment.result.task_id != task.id
        || fulfillment.result.contract_revision != task.contract_revision
        || fulfillment.result.task_state_revision != task.state_revision
        || fulfillment.result.mission_revision != mission.revision
        || fulfillment.result.provider_id != fulfillment.provider_id
        || fulfillment.result.provider_generation != fulfillment.provider_generation
        || fulfillment.result.worker_id != fulfillment.worker.worker_id
        || fulfillment.result.worker_generation != fulfillment.worker.generation
        || fulfillment.result.deliverable.deliverable_id
            != fulfillment.outcome_handoff.deliverable_id
        || fulfillment.result.deliverable.content_digest
            != fulfillment.outcome_handoff.deliverable_digest
        || fulfillment.payout_intent.tenant_id != task.tenant_id
        || fulfillment.payout_intent.project_id != task.project_id
        || fulfillment.payout_intent.mission_id != task.mission_id
        || fulfillment.payout_intent.creator_id != task.creator_id
        || fulfillment.payout_intent.task_id != task.id
        || fulfillment.payout_intent.contract_revision != task.contract_revision
        || fulfillment.payout_intent.contract_digest != task.contract_digest()
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn validate_creator_work_execution_receipt_scope(
    task: &CreatorTask,
    mission: &Mission,
    receipt: &CreatorWorkExecutionReceipt,
) -> Result<(), StorageError> {
    let request = &receipt.request;
    if request.tenant_id != task.tenant_id
        || request.project_id != task.project_id
        || request.mission_id != task.mission_id
        || request.creator_id != task.creator_id
        || request.task_id != task.id
        || request.contract_revision != task.contract_revision
        || request.task_state_revision != task.state_revision
        || request.mission_revision != mission.revision
        || request.objective != mission.contract.goal.trim()
        || request.capability.trim().is_empty()
        || !mission
            .contract
            .enabled_capabilities
            .contains(&request.capability)
        || mission
            .contract
            .forbidden_capabilities
            .contains(&request.capability)
        || request.worker.tenant_id != task.tenant_id
        || request.worker.project_id != task.project_id
        || request.worker.mission_id != task.mission_id
        || request.worker.creator_id != task.creator_id
        || request.worker.task_id != task.id
        || request.worker.contract_revision != task.contract_revision
        || request.worker.task_state_revision != task.state_revision
        || request.worker.mission_revision != mission.revision
        || request.worker.provider_generation != request.provider_generation
        || request.payout_intent.tenant_id != task.tenant_id
        || request.payout_intent.project_id != task.project_id
        || request.payout_intent.mission_id != task.mission_id
        || request.payout_intent.creator_id != task.creator_id
        || request.payout_intent.task_id != task.id
        || request.payout_intent.contract_revision != task.contract_revision
        || request.payout_intent.contract_digest != task.contract_digest()
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn same_creator_work_worker_identity(
    previous: &CreatorWorkWorkerLease,
    next: &CreatorWorkWorkerLease,
) -> bool {
    previous.tenant_id == next.tenant_id
        && previous.project_id == next.project_id
        && previous.mission_id == next.mission_id
        && previous.creator_id == next.creator_id
        && previous.task_id == next.task_id
        && previous.contract_revision == next.contract_revision
        && previous.task_state_revision == next.task_state_revision
        && previous.mission_revision == next.mission_revision
        && previous.provider_generation == next.provider_generation
        && previous.worker_id == next.worker_id
        && previous.generation == next.generation
        && previous.token_digest == next.token_digest
        && previous.acquired_at == next.acquired_at
        && previous.expires_at == next.expires_at
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

fn decode_value<T: DeserializeOwned>(value: Value) -> Result<T, StorageError> {
    serde_json::from_value(value).map_err(|error| StorageError::DomainDecode(error.to_string()))
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, CreatorAcceptance, CreatorApplicationId, CreatorHiringAward, CreatorMilestone,
        CreatorMilestoneId, CreatorMilestoneStatus, CreatorTaskStatus,
        CreatorWorkDeliverableReference, CreatorWorkExecutionReceipt, CreatorWorkExecutionRequest,
        CreatorWorkExecutionStatus, CreatorWorkFulfillment, CreatorWorkFulfillmentStatus,
        CreatorWorkOutcomeHandoff, CreatorWorkPayoutIntent, CreatorWorkProviderResult,
        CreatorWorkSettlementStatus, CreatorWorkWorkerLease, CreatorWorkWorkerStatus, CurrencyCode,
        EffectId, FundingReservation, MissionContract, Money, Project, StorageMode, UsageRights,
        VerificationStatus, WorkerId,
    };

    use super::*;
    use crate::DatabaseKey;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 10, 0, 0)
            .single()
            .expect("static time")
    }

    #[allow(clippy::too_many_lines)]
    fn fixture(
        root: PathBuf,
    ) -> (
        Project,
        Mission,
        CreatorTask,
        CreatorWorkWorkerLease,
        CreatorWorkExecutionReceipt,
        CreatorWorkFulfillment,
    ) {
        let now = now();
        let tenant_id = TenantId::from("tenant-storage-creator-work");
        let project_id = ProjectId::from("project-storage-creator-work");
        let mission_id = MissionId::from("mission-storage-creator-work");
        let creator_id = CreatorId::from("creator-storage-1");
        let bounty = Money::new(1_000, CurrencyCode::parse("USD").expect("currency"));
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Creator Work",
            "Creator Work persistence test",
            root,
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            tenant_id.clone(),
            mission_id.clone(),
            project_id.clone(),
            "Creator Work Mission",
            MissionContract::bootstrap(
                "creator result",
                ["creator.work.fulfillment".to_owned()],
                now - Duration::days(1),
            ),
            now - Duration::days(1),
        )
        .expect("mission");
        let mut task = CreatorTask {
            id: CreatorTaskId::from("task-storage-creator-work"),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            creator_id: creator_id.clone(),
            hiring_award: CreatorHiringAward {
                hiring_id: hartevo_domain_kernel::CreatorHiringId::from("hiring-storage"),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                creator_id: creator_id.clone(),
                partner_id: hartevo_domain_kernel::PartnerId::from("partner-storage"),
                application_id: CreatorApplicationId::from("application-storage"),
                offer_digest: "a".repeat(64),
                bounty: bounty.clone(),
                selected_by: hartevo_domain_kernel::ActorId::from("actor-storage"),
                selection_evidence_digest: "b".repeat(64),
                selected_at: now - Duration::hours(1),
            },
            title: "Result".into(),
            brief: "Bounded creator result".into(),
            acceptance_criteria: vec!["result exists".into()],
            deliverable_requirements: vec!["reference".into()],
            bounty: bounty.clone(),
            milestones: vec![CreatorMilestone {
                id: CreatorMilestoneId::from("milestone-storage"),
                title: "Result".into(),
                amount: bounty.clone(),
                due_at: now + Duration::days(2),
                status: CreatorMilestoneStatus::InProgress,
                revisions_used: 0,
            }],
            revision_limit: 2,
            usage_rights: UsageRights {
                license: "commissioned".into(),
                territories: vec!["global".into()],
                channels: vec!["owned".into()],
                exclusivity: "non_exclusive".into(),
                disclosure_required: false,
                source_manifest_required: true,
            },
            due_at: now + Duration::days(2),
            contract_revision: 1,
            state_revision: 1,
            accepted_revision: Some(1),
            status: CreatorTaskStatus::Accepted,
            funding_reservation: None,
            acceptance: Some(CreatorAcceptance {
                creator_id: creator_id.clone(),
                connected_account_id: AccountId::from("account-storage"),
                connection_id: hartevo_domain_kernel::ConnectionId::from("connection-storage"),
                contract_revision: 1,
                contract_digest: String::new(),
                accepted_at: now - Duration::minutes(10),
            }),
            deliverables: Vec::new(),
            reviews: Vec::new(),
            payout_authorizations: Vec::new(),
            payouts: Vec::new(),
            created_at: now - Duration::hours(2),
            updated_at: now,
        };
        let contract_digest = task.contract_digest();
        task.acceptance
            .as_mut()
            .expect("acceptance")
            .contract_digest = contract_digest.clone();
        task.funding_reservation = Some(FundingReservation {
            provider: "hartevo".into(),
            external_id: "reservation-storage".into(),
            connection_id: hartevo_domain_kernel::ConnectionId::from("connection-storage"),
            payer_account_id: AccountId::from("payer-storage"),
            amount: bounty,
            contract_revision: 1,
            contract_digest,
            reserved_at: now - Duration::hours(1),
            expires_at: now + Duration::days(5),
            request_digest: "c".repeat(64),
            provider_receipt_digest: "d".repeat(64),
            verification_evidence_digest: "e".repeat(64),
        });
        let worker = CreatorWorkWorkerLease::acquire(
            task.tenant_id.clone(),
            task.project_id.clone(),
            task.mission_id.clone(),
            task.creator_id.clone(),
            task.id.clone(),
            task.contract_revision,
            task.state_revision,
            mission.revision,
            1,
            WorkerId::from("worker-storage-1"),
            1,
            "f".repeat(64),
            now,
            now + Duration::minutes(10),
        )
        .expect("worker");
        let payout_intent = CreatorWorkPayoutIntent {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            contract_digest: task.contract_digest(),
            amount: task.bounty.clone(),
            funding_reservation_id: "reservation-storage".into(),
            idempotency_key: "creator-work-storage".into(),
            status: CreatorWorkSettlementStatus::Pending,
            intent_digest: "1".repeat(64),
        };
        let request = CreatorWorkExecutionRequest {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            task_state_revision: task.state_revision,
            mission_revision: mission.revision,
            protocol_version: hartevo_domain_kernel::CREATOR_WORK_PROVIDER_PROTOCOL_VERSION,
            objective: mission.contract.goal.clone(),
            capability: "creator.work.fulfillment".into(),
            source_commit: "0123456789abcdef0123456789abcdef01234567".into(),
            provider_id: "hartevo".into(),
            connection_id: hartevo_domain_kernel::ConnectionId::from("connection-storage"),
            account_id: AccountId::from("account-storage"),
            provider_generation: 1,
            effect_id: EffectId::from("effect-storage"),
            effect_approval_digest: "2".repeat(64),
            input_digest: "c".repeat(64),
            max_output_bytes: hartevo_domain_kernel::CREATOR_WORK_MAX_OUTPUT_BYTES,
            worker: worker.clone(),
            payout_intent: payout_intent.clone(),
            requested_at: now,
        };
        let execution_receipt =
            CreatorWorkExecutionReceipt::started(request.clone(), now).expect("execution receipt");
        let receipt = hartevo_domain_kernel::Receipt {
            id: hartevo_domain_kernel::ReceiptId::from("receipt-storage"),
            provider: "hartevo".into(),
            external_id: "external-storage".into(),
            accepted_at: now,
            request_digest: "2".repeat(64),
            response_digest: "3".repeat(64),
        };
        let verification = hartevo_domain_kernel::Verification {
            id: hartevo_domain_kernel::VerificationId::from("verification-storage"),
            status: VerificationStatus::Confirmed,
            verifier: "storage-checker".into(),
            independent: true,
            observed_at: now,
            evidence_digest: "4".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        let mut result = CreatorWorkProviderResult {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            task_state_revision: task.state_revision,
            mission_revision: mission.revision,
            protocol_version: request.protocol_version,
            objective: request.objective.clone(),
            capability: request.capability.clone(),
            source_commit: request.source_commit.clone(),
            input_digest: request.input_digest.clone(),
            request_digest: request.request_digest(),
            provider_id: "hartevo".into(),
            provider_generation: 1,
            effect_id: EffectId::from("effect-storage"),
            worker_id: worker.worker_id.clone(),
            worker_generation: worker.generation,
            result_id: "result-storage".into(),
            deliverable: CreatorWorkDeliverableReference {
                deliverable_id: DeliverableId::from("deliverable-storage"),
                artifact_uri: "file-broker://creator-work/storage-result".into(),
                media_type: "application/json".into(),
                size_bytes: 1,
                content_digest: "a".repeat(64),
            },
            bounded_output_digest: "5".repeat(64),
            output_size_bytes: 1,
            evidence_digest: "6".repeat(64),
            receipt: receipt.clone(),
            verification: verification.clone(),
            payout_intent: payout_intent.clone(),
            outcome_handoff: CreatorWorkOutcomeHandoff {
                tenant_id: task.tenant_id.clone(),
                project_id: task.project_id.clone(),
                mission_id: task.mission_id.clone(),
                creator_id: task.creator_id.clone(),
                task_id: task.id.clone(),
                contract_revision: task.contract_revision,
                task_state_revision: task.state_revision,
                mission_revision: mission.revision,
                result_id: "result-storage".into(),
                deliverable_id: DeliverableId::from("deliverable-storage"),
                deliverable_digest: "a".repeat(64),
                result_digest: "7".repeat(64),
                evidence_digest: "6".repeat(64),
                receipt_id: receipt.id,
                verification_id: verification.id,
                payout_intent_digest: payout_intent.intent_digest.clone(),
                outcome_key: "creator_work.result_ready".into(),
                handoff_digest: "8".repeat(64),
            },
        };
        let result_digest = result.result_digest();
        result.outcome_handoff = CreatorWorkOutcomeHandoff::new(
            result.tenant_id.clone(),
            result.project_id.clone(),
            result.mission_id.clone(),
            result.creator_id.clone(),
            result.task_id.clone(),
            result.contract_revision,
            result.task_state_revision,
            result.mission_revision,
            result.result_id.clone(),
            result.deliverable.deliverable_id.clone(),
            result.deliverable.content_digest.clone(),
            result_digest,
            result.evidence_digest.clone(),
            result.receipt.id.clone(),
            result.verification.id.clone(),
            result.payout_intent.intent_digest.clone(),
            "creator_work.result_ready",
        )
        .expect("outcome handoff");
        let result_outcome_handoff = result.outcome_handoff.clone();
        let fulfillment = CreatorWorkFulfillment {
            tenant_id: task.tenant_id.clone(),
            project_id: task.project_id.clone(),
            mission_id: task.mission_id.clone(),
            creator_id: task.creator_id.clone(),
            task_id: task.id.clone(),
            contract_revision: task.contract_revision,
            task_state_revision: task.state_revision,
            mission_revision: mission.revision,
            provider_id: "hartevo".into(),
            provider_generation: 1,
            connection_id: hartevo_domain_kernel::ConnectionId::from("connection-storage"),
            account_id: AccountId::from("account-storage"),
            effect_id: EffectId::from("effect-storage"),
            worker: worker.clone(),
            result,
            payout_intent,
            outcome_handoff: result_outcome_handoff,
            status: CreatorWorkFulfillmentStatus::OutcomeReady,
            recorded_at: now,
        };
        (
            project,
            mission,
            task,
            worker,
            execution_receipt,
            fulfillment,
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn creator_work_events_replay_after_restart_and_fence_old_generation() {
        let directory = tempfile::tempdir().expect("directory");
        let database = directory.path().join("creator-work.sqlite3");
        let (project, mission, task, mut worker, execution_receipt, fulfillment) =
            fixture(directory.path().into());
        {
            let mut store = ProjectStore::open(&database, &DatabaseKey::new([7; 32]).expect("key"))
                .expect("store");
            store.save_project(&project).expect("project");
            store.save_mission(&mission).expect("mission");
            store
                .create_creator_task(
                    &task,
                    "creator_work.task.accepted",
                    &serde_json::json!({"taskId": task.id}),
                    now(),
                )
                .expect("task");
            store
                .save_creator_work_worker_lease(&worker, now())
                .expect("lease");
            store
                .save_creator_work_worker_lease(&worker, now())
                .expect("idempotent lease");
            store
                .save_creator_work_execution_receipt(&execution_receipt, now())
                .expect("execution receipt");
            store
                .save_creator_work_execution_receipt(&execution_receipt, now())
                .expect("idempotent execution receipt");
            store
                .save_creator_work_fulfillment(&fulfillment, now())
                .expect("fulfillment");
            store
                .save_creator_work_fulfillment(&fulfillment, now())
                .expect("idempotent fulfillment");
            let mut tampered = fulfillment.clone();
            tampered.result.source_commit = "f".repeat(40);
            assert!(
                store
                    .save_creator_work_fulfillment(&tampered, now())
                    .is_err(),
                "tampered result replay must not overwrite the durable result"
            );
        }
        {
            let mut reopened =
                ProjectStore::open(&database, &DatabaseKey::new([7; 32]).expect("key"))
                    .expect("reopen");
            let loaded_lease = reopened
                .load_creator_work_worker_lease(&project.id, &mission.id, &task.id)
                .expect("lease read")
                .expect("lease");
            assert_eq!(loaded_lease, worker);
            let loaded_fulfillment = reopened
                .load_creator_work_fulfillment(&project.id, &mission.id, &task.id, "result-storage")
                .expect("fulfillment read")
                .expect("fulfillment");
            assert_eq!(loaded_fulfillment, fulfillment);
            let loaded_execution = reopened
                .load_creator_work_execution_receipt(
                    &project.id,
                    &mission.id,
                    &task.id,
                    &execution_receipt.request.request_digest(),
                )
                .expect("execution receipt read")
                .expect("execution receipt");
            assert_eq!(
                loaded_execution.status,
                CreatorWorkExecutionStatus::ResultRecorded
            );
            assert_eq!(
                reopened
                    .adopt_creator_work_result(
                        &project.id,
                        &mission.id,
                        &task.id,
                        &execution_receipt.request.request_digest(),
                    )
                    .expect("adopt result")
                    .expect("adoptable result"),
                fulfillment
            );
            assert_eq!(
                reopened
                    .creator_work_fulfillments_for_task(&project.id, &mission.id, &task.id)
                    .expect("fulfillment list")
                    .len(),
                1
            );

            worker.mark_crashed(now()).expect("crash");
            reopened
                .save_creator_work_worker_lease(&worker, now())
                .expect("persist crash");
            let recovered = worker
                .recover(
                    WorkerId::from("worker-storage-2"),
                    "9".repeat(64),
                    task.state_revision,
                    mission.revision,
                    1,
                    now() + Duration::seconds(1),
                    now() + Duration::minutes(10),
                )
                .expect("recover");
            reopened
                .save_creator_work_worker_lease(&recovered, now())
                .expect("persist recovery");
            let current = reopened
                .load_creator_work_worker_lease(&project.id, &mission.id, &task.id)
                .expect("current lease")
                .expect("current");
            assert_eq!(current.generation, 2);
            assert!(
                reopened
                    .save_creator_work_fulfillment(&fulfillment, now())
                    .is_err(),
                "old worker result must be fenced by storage"
            );
            assert_eq!(current.status, CreatorWorkWorkerStatus::Active);

            let next_request = CreatorWorkExecutionRequest {
                worker: recovered.clone(),
                requested_at: now() + Duration::seconds(2),
                ..execution_receipt.request.clone()
            };
            let next_receipt = CreatorWorkExecutionReceipt::started(
                next_request.clone(),
                now() + Duration::seconds(2),
            )
            .expect("next execution receipt");
            reopened
                .save_creator_work_execution_receipt(&next_receipt, now() + Duration::seconds(2))
                .expect("next execution");
            reopened
                .revoke_creator_work_execution(
                    &project.id,
                    &mission.id,
                    &task.id,
                    &next_request.request_digest(),
                    now() + Duration::seconds(3),
                )
                .expect("revoke execution");
            let revoked = reopened
                .load_creator_work_execution_receipt(
                    &project.id,
                    &mission.id,
                    &task.id,
                    &next_request.request_digest(),
                )
                .expect("revoked receipt read")
                .expect("revoked receipt");
            assert_eq!(revoked.status, CreatorWorkExecutionStatus::Revoked);
            assert!(
                reopened
                    .adopt_creator_work_result(
                        &project.id,
                        &mission.id,
                        &task.id,
                        &next_request.request_digest(),
                    )
                    .expect("revoked adoption")
                    .is_none(),
                "revoked execution must not become adoptable"
            );
        }
    }
}
