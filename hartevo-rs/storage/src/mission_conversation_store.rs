//! SQLCipher persistence for the private, project-scoped Mission Conversation.
//!
//! Message bodies remain inside SQLCipher. Domain events and the durable outbox
//! receive only stable identifiers, sequence numbers, and content digests.

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Mission, MissionConversation, MissionConversationId, MissionConversationMessage,
    MissionConversationMessageId, MissionId, ProjectId, TenantId, WorkProductId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::normalized::{insert_mission_normalized, update_mission_normalized_cas};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn create_catalog_mission_with_conversation_atomic(
        &mut self,
        mission: &Mission,
        conversation: &MissionConversation,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty()
            || mission.definition.is_none()
            || conversation.revision != 1
            || conversation.messages.len() != 1
        {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        conversation.validate_for(mission, conversation.updated_at)?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        insert_mission_normalized(&transaction, mission)?;
        insert_mission_conversation(&transaction, conversation)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_conversation",
            conversation.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: conversation.revision,
        })
    }

    pub fn load_mission_conversation(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<MissionConversation, StorageError> {
        let mission = self.load_mission(project_id, mission_id)?;
        let conversation =
            load_mission_conversation_record(&self.connection, project_id, mission_id)?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "mission conversation",
                    project_id: project_id.clone(),
                    id: mission_id.to_string(),
                })?;
        conversation.validate_for(&mission, conversation.updated_at)?;
        Ok(conversation)
    }

    pub fn append_mission_conversation_atomic(
        &mut self,
        conversation: &MissionConversation,
        expected_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow(expected_revision))?;
        if events.is_empty() || conversation.revision != next_revision {
            return Err(StorageError::UnexpectedNextRevision {
                expected: next_revision,
                actual: conversation.revision,
            });
        }
        let mission = self.load_mission(&conversation.project_id, &conversation.mission_id)?;
        conversation.validate_for(&mission, conversation.updated_at)?;
        let previous =
            self.load_mission_conversation(&conversation.project_id, &conversation.mission_id)?;
        if previous.revision != expected_revision || !conversation.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("mission_conversation:{}", conversation.id),
                expected_revision,
            });
        }
        let message = conversation
            .messages
            .last()
            .ok_or_else(|| StorageError::DomainDecode("missing appended message".into()))?;
        let transaction = self.connection.transaction()?;
        update_mission_conversation_append(&transaction, conversation, expected_revision, message)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            Some(conversation.mission_id.as_str()),
            "mission_conversation",
            conversation.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: conversation.revision,
        })
    }

    /// Commits a Human Checkpoint confirmation as one dual-CAS transaction.
    /// The user message, Checkpoint completion, Task transition, and optional
    /// next Checkpoint start can therefore never become partially visible.
    pub fn complete_human_checkpoint_with_conversation_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        conversation: &MissionConversation,
        expected_conversation_revision: u64,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        let next_conversation_revision =
            expected_conversation_revision
                .checked_add(1)
                .ok_or(StorageError::RevisionOverflow(
                    expected_conversation_revision,
                ))?;
        if mission.revision <= expected_mission_revision {
            return Err(StorageError::UnexpectedNewerRevision {
                expected_revision: expected_mission_revision,
                actual: mission.revision,
            });
        }
        if events.is_empty() || conversation.revision != next_conversation_revision {
            return Err(StorageError::UnexpectedNextRevision {
                expected: next_conversation_revision,
                actual: conversation.revision,
            });
        }
        conversation.validate_for(mission, conversation.updated_at)?;
        let previous =
            self.load_mission_conversation(&conversation.project_id, &conversation.mission_id)?;
        if previous.revision != expected_conversation_revision
            || !conversation.follows(&previous)?
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("mission_conversation:{}", conversation.id),
                expected_revision: expected_conversation_revision,
            });
        }
        let message = conversation
            .messages
            .last()
            .ok_or_else(|| StorageError::DomainDecode("missing confirmation message".into()))?;
        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_mission_conversation_append(
            &transaction,
            conversation,
            expected_conversation_revision,
            message,
        )?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            Some(mission.id.as_str()),
            "mission_conversation",
            conversation.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: mission.revision,
        })
    }

    pub(crate) fn backfill_mission_conversations(&mut self) -> Result<(), StorageError> {
        let mission_ids = {
            let mut statement = self.connection.prepare(
                "SELECT definitions.project_id, definitions.mission_id
                 FROM mission_definitions AS definitions
                 LEFT JOIN mission_conversations AS conversations
                   ON conversations.project_id = definitions.project_id
                  AND conversations.mission_id = definitions.mission_id
                 WHERE conversations.id IS NULL
                 ORDER BY definitions.project_id, definitions.mission_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (project_id, mission_id) in mission_ids {
            let project_id = ProjectId::from_stable(project_id);
            let mission_id = MissionId::from_stable(mission_id);
            let mission = self.load_mission(&project_id, &mission_id)?;
            let conversation = MissionConversation::start(
                MissionConversationId::from_stable(format!(
                    "mission-conversation:{}",
                    mission.id.as_str()
                )),
                MissionConversationMessageId::from_stable(format!(
                    "mission-message:goal:{}",
                    mission.id.as_str()
                )),
                &mission,
                mission.contract.goal.clone(),
                format!("migration-v37:goal:{}", mission.id.as_str()),
                mission.created_at,
            )?;
            let transaction = self.connection.transaction()?;
            insert_mission_conversation(&transaction, &conversation)?;
            transaction.commit()?;
        }
        Ok(())
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
        .ok_or_else(|| StorageError::ProjectNotFound(ProjectId::from_stable(project_id)))?;
    if stored_tenant != tenant_id {
        return Err(StorageError::TenantScopeMismatch);
    }
    Ok(())
}

fn insert_mission_conversation(
    transaction: &Transaction<'_>,
    conversation: &MissionConversation,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO mission_conversations
           (id, tenant_id, project_id, mission_id, revision, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            conversation.id.as_str(),
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            conversation.mission_id.as_str(),
            to_sql_u64(conversation.revision)?,
            conversation.created_at.to_rfc3339(),
            conversation.updated_at.to_rfc3339(),
        ],
    )?;
    for message in &conversation.messages {
        insert_mission_conversation_message(transaction, conversation, message)?;
    }
    Ok(())
}

pub(crate) fn update_mission_conversation_append(
    transaction: &Transaction<'_>,
    conversation: &MissionConversation,
    expected_revision: u64,
    message: &MissionConversationMessage,
) -> Result<(), StorageError> {
    let changed = transaction.execute(
        "UPDATE mission_conversations
         SET revision = ?4, updated_at = ?5
         WHERE project_id = ?1 AND id = ?2 AND mission_id = ?3 AND revision = ?6",
        params![
            conversation.project_id.as_str(),
            conversation.id.as_str(),
            conversation.mission_id.as_str(),
            to_sql_u64(conversation.revision)?,
            conversation.updated_at.to_rfc3339(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("mission_conversation:{}", conversation.id),
            expected_revision,
        });
    }
    insert_mission_conversation_message(transaction, conversation, message)
}

pub(crate) fn insert_mission_conversation_message(
    transaction: &Transaction<'_>,
    conversation: &MissionConversation,
    message: &MissionConversationMessage,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO mission_conversation_messages
           (id, tenant_id, project_id, mission_id, conversation_id, sequence, role, kind,
            body, content_digest, idempotency_key, mission_revision, checkpoint_id,
            work_product_id, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            message.id.as_str(),
            conversation.tenant_id.as_str(),
            conversation.project_id.as_str(),
            conversation.mission_id.as_str(),
            conversation.id.as_str(),
            to_sql_u64(message.sequence)?,
            enum_name(&message.role)?,
            enum_name(&message.kind)?,
            message.body,
            message.content_digest,
            message.idempotency_key,
            to_sql_u64(message.mission_revision)?,
            message.checkpoint_id,
            message.work_product_id.as_ref().map(WorkProductId::as_str),
            message.recorded_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn load_mission_conversation_record(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> Result<Option<MissionConversation>, StorageError> {
    let row = connection
        .query_row(
            "SELECT id, tenant_id, revision, created_at, updated_at
             FROM mission_conversations
             WHERE project_id = ?1 AND mission_id = ?2",
            params![project_id.as_str(), mission_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((id, tenant_id, revision, created_at, updated_at)) = row else {
        return Ok(None);
    };
    let conversation_id = MissionConversationId::from_stable(id);
    let messages = {
        let mut statement = connection.prepare(
            "SELECT id, sequence, role, kind, body, content_digest, idempotency_key,
                    mission_revision, checkpoint_id, work_product_id, recorded_at
             FROM mission_conversation_messages
             WHERE project_id = ?1 AND mission_id = ?2 AND conversation_id = ?3
             ORDER BY sequence",
        )?;
        statement
            .query_map(
                params![
                    project_id.as_str(),
                    mission_id.as_str(),
                    conversation_id.as_str()
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )?
            .map(|row| {
                let row = row?;
                Ok(MissionConversationMessage {
                    id: MissionConversationMessageId::from_stable(row.0),
                    sequence: from_sql_u64(row.1, "Mission Conversation sequence")?,
                    role: decode_enum(&row.2)?,
                    kind: decode_enum(&row.3)?,
                    body: row.4,
                    content_digest: row.5,
                    idempotency_key: row.6,
                    mission_revision: from_sql_u64(row.7, "Mission Conversation Mission revision")?,
                    checkpoint_id: row.8,
                    work_product_id: row.9.map(WorkProductId::from_stable),
                    recorded_at: DateTime::parse_from_rfc3339(&row.10)?.with_timezone(&Utc),
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?
    };
    Ok(Some(MissionConversation {
        id: conversation_id,
        tenant_id: TenantId::from_stable(tenant_id),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        messages,
        revision: from_sql_u64(revision, "Mission Conversation revision")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc),
        updated_at: DateTime::parse_from_rfc3339(&updated_at)?.with_timezone(&Utc),
    }))
}

fn enum_name<T: Serialize>(value: &T) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("expected string enum".into()))
}

fn decode_enum<T: DeserializeOwned>(value: &str) -> Result<T, StorageError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        value.to_owned(),
    ))?)
}

pub(crate) fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{field} must be nonnegative")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        CurrencyCode, MissionCheckpointCompletion, MissionCheckpointCompletionPolicy,
        MissionCheckpointExecutor, MissionCheckpointRoute, MissionConversationMessageKind,
        MissionDefinition, Money, OperatingContract, OperatingMode, Project, StorageMode, Task,
        TaskId, TaskStatus,
    };

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn fixture() -> (Project, Mission, MissionConversation) {
        let project = Project::create_local(
            TenantId::from("tenant-conversation"),
            ProjectId::from("project-conversation"),
            "Conversation",
            "",
            "/tmp/hartevo-mission-conversation",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut contract = OperatingContract::bootstrap(
            "private initial goal",
            ["research.discover".into()],
            now(),
        );
        contract.mode = OperatingMode::OneOffDecision;
        contract.market = "DE".into();
        contract.language = "de-DE".into();
        contract.audience = "owner".into();
        contract.budget = Money::new(100, CurrencyCode::parse("EUR").expect("EUR"));
        let definition = MissionDefinition::from_linear_manifest(
            "VM-07",
            1,
            "a".repeat(64),
            OperatingMode::OneOffDecision,
            ["research.discover".into()],
            ["market_decision".into()],
            ["goal".into(), "decision".into()],
            ["scope".into(), "decision".into()],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            project.tenant_id.clone(),
            MissionId::from("mission-conversation"),
            project.id.clone(),
            "VM-07",
            contract,
            definition,
            now(),
        )
        .expect("Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-conversation"),
                    title: "Scope".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                }],
                now(),
            )
            .expect("start");
        let conversation = MissionConversation::start(
            MissionConversationId::from("conversation"),
            MissionConversationMessageId::from("message-goal"),
            &mission,
            mission.contract.goal.clone(),
            "start:mission-conversation",
            now(),
        )
        .expect("Conversation");
        (project, mission, conversation)
    }

    fn human_fixture() -> (Project, Mission, MissionConversation) {
        let project = Project::create_local(
            TenantId::from("tenant-human-confirmation"),
            ProjectId::from("project-human-confirmation"),
            "Human confirmation",
            "",
            "/tmp/hartevo-human-confirmation",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mut contract = OperatingContract::bootstrap(
            "Confirm exact market constraints",
            ["decision.evaluate".into(), "research.discover".into()],
            now(),
        );
        contract.mode = OperatingMode::OneOffDecision;
        contract.market = "DE".into();
        contract.language = "de-DE".into();
        contract.audience = "owner".into();
        contract.budget = Money::new(100, CurrencyCode::parse("EUR").expect("EUR"));
        let definition = MissionDefinition::from_routed_linear_manifest(
            "VM-07",
            2,
            "b".repeat(64),
            OperatingMode::OneOffDecision,
            contract.enabled_capabilities.iter().cloned(),
            ["market_constraints".into(), "evidence_plan".into()],
            [
                "goal".into(),
                "decision".into(),
                "work_product".into(),
                "operating_state".into(),
            ],
            [
                (
                    "constraints".into(),
                    MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Human,
                        ["goal".into(), "decision".into(), "operating_state".into()],
                        MissionCheckpointCompletionPolicy::HumanConfirmation,
                    )
                    .expect("Human route"),
                ),
                (
                    "evidence".into(),
                    MissionCheckpointRoute::contracted(
                        "research.discover",
                        MissionCheckpointExecutor::Runtime,
                        ["work_product".into(), "operating_state".into()],
                        MissionCheckpointCompletionPolicy::WorkProduct,
                    )
                    .expect("Runtime route"),
                ),
            ],
        )
        .expect("definition");
        let mut mission = Mission::compile_catalog(
            project.tenant_id.clone(),
            MissionId::from("mission-human-confirmation"),
            project.id.clone(),
            "VM-07 Human confirmation",
            contract,
            definition,
            now(),
        )
        .expect("Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-human-confirmation"),
                    title: "Confirm constraints".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                }],
                now(),
            )
            .expect("start");
        let conversation = MissionConversation::start(
            MissionConversationId::from("conversation-human-confirmation"),
            MissionConversationMessageId::from("message-human-goal"),
            &mission,
            mission.contract.goal.clone(),
            "start:human-confirmation",
            now(),
        )
        .expect("Conversation");
        (project, mission, conversation)
    }

    #[test]
    fn conversation_and_catalog_mission_commit_atomically_and_tamper_fails_closed() {
        let mut store = ProjectStore::in_memory().expect("store");
        let (project, mission, mut conversation) = fixture();
        store.save_project(&project).expect("project");
        store
            .create_catalog_mission_with_conversation_atomic(
                &mission,
                &conversation,
                &[
                    PendingEvent::new(
                        "mission.catalog_bound",
                        serde_json::json!({"missionId": mission.id}),
                        now(),
                    ),
                    PendingEvent::new(
                        "mission.conversation_started",
                        serde_json::json!({
                            "conversationId": conversation.id,
                            "messageId": conversation.messages[0].id,
                            "sequence": 1,
                            "contentDigest": conversation.messages[0].content_digest,
                        }),
                        now(),
                    ),
                ],
            )
            .expect("atomic create");
        assert_eq!(
            store
                .load_mission_conversation(&project.id, &mission.id)
                .expect("reload"),
            conversation
        );
        let expected_revision = conversation.revision;
        let (message, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("message-steering"),
                MissionConversationMessageKind::Steering,
                "private correction 445",
                "steer:445",
                &mission,
                now() + Duration::minutes(1),
            )
            .expect("append");
        assert!(appended);
        store
            .append_mission_conversation_atomic(
                &conversation,
                expected_revision,
                &[PendingEvent::new(
                    "mission.conversation_message_recorded",
                    serde_json::json!({
                        "messageId": message.id,
                        "sequence": message.sequence,
                        "contentDigest": message.content_digest,
                    }),
                    message.recorded_at,
                )],
            )
            .expect("atomic append");
        let events_json = serde_json::to_string(
            &store
                .events_for_mission(&project.id, &mission.id)
                .expect("events"),
        )
        .expect("json");
        assert!(!events_json.contains("private correction 445"));

        store
            .connection
            .execute(
                "UPDATE mission_conversation_messages SET body = 'tampered'
                 WHERE project_id = ?1 AND conversation_id = ?2 AND sequence = 2",
                params![project.id.as_str(), conversation.id.as_str()],
            )
            .expect("tamper fixture");
        assert!(matches!(
            store.load_mission_conversation(&project.id, &mission.id),
            Err(StorageError::MissionConversation(_))
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the rollback test intentionally observes Mission, Conversation, Task, and Event state before injection, after rollback, and after one exact retry"
    )]
    fn human_confirmation_rolls_back_message_mission_task_and_events_as_one_transaction() {
        let mut store = ProjectStore::in_memory().expect("store");
        let (project, mut mission, mut conversation) = human_fixture();
        store.save_project(&project).expect("project");
        store
            .create_catalog_mission_with_conversation_atomic(
                &mission,
                &conversation,
                &[PendingEvent::new(
                    "mission.catalog_bound",
                    serde_json::json!({"missionId": mission.id}),
                    now(),
                )],
            )
            .expect("atomic create");
        let before_mission = mission.clone();
        let before_conversation = conversation.clone();
        let before_events = store
            .events_for_mission(&project.id, &mission.id)
            .expect("events before");
        let expected_mission_revision = mission.revision;
        let expected_conversation_revision = conversation.revision;
        let confirmed_at = now() + Duration::minutes(1);
        let (message, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("message-human-confirmation"),
                MissionConversationMessageKind::CheckpointConfirmation,
                "The exact market constraints are correct.",
                "confirm:constraints:v1",
                &mission,
                confirmed_at,
            )
            .expect("append confirmation");
        assert!(appended);
        mission
            .begin_checkpoint_verification("constraints", confirmed_at)
            .expect("begin verification");
        mission
            .complete_checkpoint(
                "constraints",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from([
                        "goal".into(),
                        "decision".into(),
                        "operating_state".into(),
                    ]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: "c".repeat(64),
                    verified_at: confirmed_at,
                },
            )
            .expect("complete Human Checkpoint");
        mission
            .begin_checkpoint_with_task(
                "evidence",
                Task {
                    id: TaskId::from("task-human-next-route"),
                    title: "Collect evidence".into(),
                    status: TaskStatus::Running,
                    capability: "research.discover".into(),
                },
                confirmed_at,
            )
            .expect("start next route");
        let events = [PendingEvent::new(
            "mission.human_checkpoint_confirmed",
            serde_json::json!({
                "messageId": message.id,
                "contentDigest": message.content_digest,
                "checkpointId": "constraints",
                "nextCheckpointId": "evidence",
            }),
            confirmed_at,
        )];
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_human_confirmation_message
                 BEFORE INSERT ON mission_conversation_messages
                 WHEN NEW.kind = 'checkpoint_confirmation'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected Human confirmation failure');
                 END;",
            )
            .expect("failure trigger");
        assert!(matches!(
            store.complete_human_checkpoint_with_conversation_atomic(
                &mission,
                expected_mission_revision,
                &conversation,
                expected_conversation_revision,
                &events,
            ),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("Mission rollback"),
            before_mission
        );
        assert_eq!(
            store
                .load_mission_conversation(&project.id, &mission.id)
                .expect("Conversation rollback"),
            before_conversation
        );
        assert_eq!(
            store
                .events_for_mission(&project.id, &mission.id)
                .expect("event rollback"),
            before_events
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_human_confirmation_message;")
            .expect("drop trigger");
        store
            .complete_human_checkpoint_with_conversation_atomic(
                &mission,
                expected_mission_revision,
                &conversation,
                expected_conversation_revision,
                &events,
            )
            .expect("atomic retry");
        assert_eq!(
            store
                .load_mission(&project.id, &mission.id)
                .expect("Mission committed"),
            mission
        );
        assert_eq!(
            store
                .load_mission_conversation(&project.id, &mission.id)
                .expect("Conversation committed"),
            conversation
        );
        let events_json = serde_json::to_string(
            &store
                .events_for_mission(&project.id, &mission.id)
                .expect("events committed"),
        )
        .expect("events JSON");
        assert!(!events_json.contains("The exact market constraints are correct."));
    }

    #[test]
    fn migration_v37_backs_up_v36_and_backfills_catalog_conversation_idempotently() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("hartevo.sqlite3");
        let key = DatabaseKey::new([31; 32]).expect("key");
        let (project, mission, conversation) = fixture();
        {
            let mut store = ProjectStore::open(&path, &key).expect("current store");
            store.save_project(&project).expect("project");
            store
                .create_catalog_mission_with_conversation_atomic(
                    &mission,
                    &conversation,
                    &[PendingEvent::new(
                        "mission.catalog_bound",
                        serde_json::json!({"missionId": mission.id}),
                        now(),
                    )],
                )
                .expect("Mission");
            store
                .connection
                .execute_batch(
                    "DROP TABLE runtime_turn_private_messages;
                     DROP TABLE mission_conversation_messages;
                     DROP TABLE mission_conversations;
                     DELETE FROM schema_migrations WHERE version >= 37;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("construct v36");
        }
        let store = ProjectStore::open(&path, &key).expect("migrate v36");
        assert_eq!(
            store
                .connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
                    .get::<_, i64>(
                    0
                ),)
                .expect("schema"),
            STORAGE_SCHEMA_VERSION
        );
        let restored = store
            .load_mission_conversation(&project.id, &mission.id)
            .expect("backfilled Conversation");
        assert_eq!(restored.messages.len(), 1);
        assert_eq!(restored.messages[0].body, mission.contract.goal);
        drop(store);
        let reopened = ProjectStore::open(&path, &key).expect("idempotent reopen");
        assert_eq!(
            reopened
                .load_mission_conversation(&project.id, &mission.id)
                .expect("same Conversation"),
            restored
        );
        let backup_count = fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v36")
            })
            .count();
        assert_eq!(backup_count, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration fixture must reproduce the complete v43 table constraint before proving v44 preservation, backup cardinality, and idempotent reopen"
    )]
    fn migration_v44_preserves_v43_messages_and_installs_checkpoint_confirmation_kind() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("conversation-v43.sqlite3");
        let key = DatabaseKey::new([44; 32]).expect("key");
        let (project, mission, conversation) = fixture();
        {
            let mut store = ProjectStore::open(&path, &key).expect("current store");
            store.save_project(&project).expect("project");
            store
                .create_catalog_mission_with_conversation_atomic(
                    &mission,
                    &conversation,
                    &[PendingEvent::new(
                        "mission.catalog_bound",
                        serde_json::json!({"missionId": mission.id}),
                        now(),
                    )],
                )
                .expect("Mission");
            store
                .connection
                .execute_batch(
                    "DROP INDEX mission_conversation_message_order_idx;
                     ALTER TABLE mission_conversation_messages
                       RENAME TO mission_conversation_messages_v44;
                     CREATE TABLE mission_conversation_messages (
                       id TEXT NOT NULL CHECK (length(trim(id)) > 0),
                       tenant_id TEXT NOT NULL CHECK (length(trim(tenant_id)) > 0),
                       project_id TEXT NOT NULL,
                       mission_id TEXT NOT NULL,
                       conversation_id TEXT NOT NULL,
                       sequence INTEGER NOT NULL CHECK (sequence > 0),
                       role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
                       kind TEXT NOT NULL CHECK (kind IN (
                         'goal', 'steering', 'correction', 'clarification',
                         'runtime_draft', 'system_notice'
                       )),
                       body TEXT NOT NULL CHECK (length(trim(body)) > 0),
                       content_digest TEXT NOT NULL CHECK (length(content_digest) = 64),
                       idempotency_key TEXT NOT NULL CHECK (
                         length(trim(idempotency_key)) > 0 AND length(idempotency_key) <= 512
                       ),
                       mission_revision INTEGER NOT NULL CHECK (mission_revision > 0),
                       checkpoint_id TEXT,
                       work_product_id TEXT,
                       recorded_at TEXT NOT NULL,
                       PRIMARY KEY (project_id, conversation_id, id),
                       UNIQUE (project_id, conversation_id, sequence),
                       UNIQUE (project_id, conversation_id, idempotency_key),
                       FOREIGN KEY (project_id, conversation_id)
                         REFERENCES mission_conversations(project_id, id) ON DELETE CASCADE,
                       FOREIGN KEY (mission_id, project_id)
                         REFERENCES missions(id, project_id) ON DELETE CASCADE,
                       CHECK (
                         (role = 'user' AND kind IN (
                           'goal', 'steering', 'correction', 'clarification'
                         ) AND work_product_id IS NULL)
                         OR (role = 'assistant' AND kind = 'runtime_draft'
                           AND work_product_id IS NOT NULL)
                         OR (role = 'system' AND kind = 'system_notice'
                           AND work_product_id IS NULL)
                       )
                     );
                     INSERT INTO mission_conversation_messages (
                       id, tenant_id, project_id, mission_id, conversation_id, sequence,
                       role, kind, body, content_digest, idempotency_key, mission_revision,
                       checkpoint_id, work_product_id, recorded_at
                     )
                     SELECT id, tenant_id, project_id, mission_id, conversation_id, sequence,
                       role, kind, body, content_digest, idempotency_key, mission_revision,
                       checkpoint_id, work_product_id, recorded_at
                     FROM mission_conversation_messages_v44;
                     DROP TABLE mission_conversation_messages_v44;
                     CREATE INDEX mission_conversation_message_order_idx
                       ON mission_conversation_messages(
                         project_id, mission_id, conversation_id, sequence
                       );
                     DELETE FROM schema_migrations WHERE version >= 44;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("construct v43");
            assert_eq!(store.schema_version().expect("v43 schema"), 43);
        }
        let migrated = ProjectStore::open(&path, &key).expect("migrate v43");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_mission_conversation(&project.id, &mission.id)
                .expect("v43 Conversation survives"),
            conversation
        );
        let message_schema = migrated
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'mission_conversation_messages'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("message schema");
        assert!(message_schema.contains("checkpoint_confirmation"));
        drop(migrated);
        let backup_count = fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v43")
            })
            .count();
        assert_eq!(backup_count, 1);
        let reopened = ProjectStore::open(&path, &key).expect("idempotent reopen");
        assert_eq!(
            reopened
                .load_mission_conversation(&project.id, &mission.id)
                .expect("Conversation survives reopen"),
            conversation
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v43")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }
}
