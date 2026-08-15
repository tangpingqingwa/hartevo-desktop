//! Immutable SQLCipher persistence for VM-11's frozen outcome review and the
//! following structured Human Continue/Stop/Scale/Test decision.
//!
//! The review row retains the complete deterministic projection plus every
//! source revision fence inspected by the Application handler. The decision
//! row is content-free: its private rationale remains in Mission Conversation,
//! while this ledger binds the exact message digest, actor, action and review.

use std::collections::BTreeSet;

use hartevo_domain_kernel::{
    Mission, MissionCheckpointStatus, MissionConversation, MissionConversationMessageKind,
    MissionConversationRole, MissionId, MissionStage, OutcomeReviewDecision,
    OutcomeReviewNextContractResolution, OutcomeReviewProjection, ProjectId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::aggregate::{
    ApplicationSourceKind, ApplicationSourceRevisionFence, AtomicMutation, PendingEvent,
    append_events, application_source_name, ensure_project_scope, require_application_source_fence,
};
use crate::mission_conversation_store::{to_sql_u64, update_mission_conversation_append};
use crate::normalized::{load_mission_normalized, update_mission_normalized_cas};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    /// Completes VM-11 `outcome_review` while atomically freezing the exact
    /// projection and every successful source fence used to produce it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the Application completion boundary binds Mission CAS, Outcome Ledger, source fences, immutable review projection, events, and outbox"
    )]
    pub fn complete_vm11_outcome_review_application_checkpoint_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        expected_outcome_ledger_revision: u64,
        source_fences: &[ApplicationSourceRevisionFence],
        review: &OutcomeReviewProjection,
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
        let review_binding = validate_completed_review_binding(mission, review)?;
        validate_successful_source_fences(source_fences, &review.source_mission_id)?;
        if review.source_ledger_revision != expected_outcome_ledger_revision {
            return Err(StorageError::DomainDecode(
                "outcome review source ledger revision does not match completion fence".into(),
            ));
        }

        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        require_outcome_ledger_revision(&transaction, mission, expected_outcome_ledger_revision)?;
        for fence in source_fences {
            require_application_source_fence(
                &transaction,
                mission.tenant_id.as_str(),
                mission.project_id.as_str(),
                fence,
            )?;
        }
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        insert_outcome_review(
            &transaction,
            mission,
            review,
            &review_binding,
            source_fences,
        )?;
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

    pub fn load_vm11_outcome_review(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<OutcomeReviewProjection, StorageError> {
        let mission = self.load_mission(project_id, mission_id)?;
        let cycle = mission
            .definition
            .as_ref()
            .map(|definition| definition.cycle)
            .ok_or_else(|| StorageError::DomainDecode("VM-11 definition is unavailable".into()))?;
        let review = load_outcome_review_record(&self.connection, project_id, mission_id, cycle)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "VM-11 outcome review",
            project_id: project_id.clone(),
            id: format!("{mission_id}:cycle:{cycle}"),
        })?;
        validate_completed_review_binding(&mission, &review)?;
        Ok(review)
    }

    pub fn load_vm11_outcome_review_decision(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<OutcomeReviewDecision, StorageError> {
        let mission = self.load_mission(project_id, mission_id)?;
        let cycle = mission
            .definition
            .as_ref()
            .map(|definition| definition.cycle)
            .ok_or_else(|| StorageError::DomainDecode("VM-11 definition is unavailable".into()))?;
        let review = load_outcome_review_record(&self.connection, project_id, mission_id, cycle)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "VM-11 outcome review",
            project_id: project_id.clone(),
            id: format!("{mission_id}:cycle:{cycle}"),
        })?;
        let decision =
            load_outcome_review_decision_record(&self.connection, project_id, mission_id, cycle)?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "VM-11 outcome review decision",
                project_id: project_id.clone(),
                id: format!("{mission_id}:cycle:{cycle}"),
            })?;
        decision.validate_persisted(&mission, &review)?;
        validate_decision_conversation(
            &self.load_mission_conversation(project_id, mission_id)?,
            &decision,
        )?;
        Ok(decision)
    }

    /// Persists the structured Human decision, private Conversation message,
    /// Checkpoint completion, next-route Task, Event and Outbox as one
    /// dual-CAS/source-fenced transaction.
    #[allow(
        clippy::too_many_arguments,
        reason = "the Human decision boundary binds Mission and Conversation CAS, immutable review/source fences, typed decision, events, and outbox"
    )]
    pub fn complete_vm11_outcome_review_decision_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        conversation: &MissionConversation,
        expected_conversation_revision: u64,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
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
        decision.validate_persisted(mission, review)?;
        conversation.validate_for(mission, conversation.updated_at)?;
        validate_decision_conversation(conversation, decision)?;
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
            .ok_or_else(|| StorageError::DomainDecode("missing decision message".into()))?;

        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        let stored_review = load_outcome_review_record(
            &transaction,
            &mission.project_id,
            &mission.id,
            decision.cycle,
        )?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "VM-11 outcome review",
            project_id: mission.project_id.clone(),
            id: format!("{}:cycle:{}", mission.id, decision.cycle),
        })?;
        if stored_review != *review {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "VM-11 outcome review",
                id: mission.id.to_string(),
            });
        }
        require_outcome_ledger_revision(&transaction, mission, review.source_ledger_revision)?;
        for fence in load_outcome_review_source_fences(
            &transaction,
            &mission.project_id,
            &mission.id,
            decision.cycle,
        )? {
            require_application_source_fence(
                &transaction,
                mission.tenant_id.as_str(),
                mission.project_id.as_str(),
                &fence,
            )?;
        }
        update_mission_normalized_cas(&transaction, mission, expected_mission_revision)?;
        update_mission_conversation_append(
            &transaction,
            conversation,
            expected_conversation_revision,
            message,
        )?;
        insert_outcome_review_decision(&transaction, decision)?;
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

    /// Commits the route-specific next-contract resolution, Mission
    /// Checkpoint completion, optional typed Stop terminal, Event, and Outbox
    /// behind one Mission CAS and one exact parent-Mission read fence.
    #[allow(
        clippy::too_many_arguments,
        reason = "the resolution boundary keeps VM-11 CAS, immutable review/decision, parent contract fence, typed output, events, and outbox explicit"
    )]
    pub fn complete_vm11_next_contract_or_valid_terminal_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        parent_mission: &Mission,
        expected_parent_mission_revision: u64,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
        resolution: &OutcomeReviewNextContractResolution,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        if mission.revision <= expected_mission_revision
            || parent_mission.revision != expected_parent_mission_revision
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("mission:{}", mission.id),
                expected_revision: expected_mission_revision,
            });
        }
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        resolution.validate_persisted(mission, parent_mission, review, decision)?;

        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        require_vm11_review_decision_and_parent(
            &transaction,
            mission,
            parent_mission,
            review,
            decision,
            expected_parent_mission_revision,
        )?;
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

    /// Persists the honest Scale/Test waiting boundary without creating a
    /// resolution or replacement contract. Exact replay is handled from this
    /// durable block/event; a changed decision or parent source cannot reuse it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the waiting boundary binds Mission CAS, immutable decision/review, parent contract fence, and replay event"
    )]
    pub fn wait_vm11_next_contract_authorization_atomic(
        &mut self,
        mission: &Mission,
        expected_mission_revision: u64,
        parent_mission: &Mission,
        expected_parent_mission_revision: u64,
        review: &OutcomeReviewProjection,
        decision: &OutcomeReviewDecision,
        expected_code: &str,
        events: &[PendingEvent],
    ) -> Result<AtomicMutation, StorageError> {
        let checkpoint = mission
            .definition
            .as_ref()
            .filter(|definition| definition.manifest_id == "VM-11")
            .and_then(|definition| definition.current_checkpoint())
            .ok_or_else(|| {
                StorageError::DomainDecode(
                    "VM-11 next-contract authorization Checkpoint is unavailable".into(),
                )
            })?;
        if mission.revision <= expected_mission_revision
            || parent_mission.revision != expected_parent_mission_revision
            || mission.stage != MissionStage::WaitingUser
            || checkpoint.id != "next_contract_or_valid_terminal"
            || checkpoint.status != MissionCheckpointStatus::WaitingUser
            || checkpoint.completion.is_some()
            || mission.block.as_ref().is_none_or(|block| {
                block.code != expected_code || block.observed_at < decision.decided_at
            })
            || events.is_empty()
        {
            return Err(StorageError::DomainDecode(
                "VM-11 next-contract authorization wait is inconsistent".into(),
            ));
        }
        OutcomeReviewNextContractResolution::validate_frozen_sources(
            mission,
            parent_mission,
            review,
            decision,
        )?;

        let transaction = self.connection.transaction()?;
        ensure_project_scope(
            &transaction,
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
        )?;
        require_vm11_review_decision_and_parent(
            &transaction,
            mission,
            parent_mission,
            review,
            decision,
            expected_parent_mission_revision,
        )?;
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

fn require_vm11_review_decision_and_parent(
    transaction: &Transaction<'_>,
    mission: &Mission,
    parent_mission: &Mission,
    review: &OutcomeReviewProjection,
    decision: &OutcomeReviewDecision,
    expected_parent_mission_revision: u64,
) -> Result<(), StorageError> {
    let stored_review = load_outcome_review_record(
        transaction,
        &mission.project_id,
        &mission.id,
        decision.cycle,
    )?
    .ok_or_else(|| StorageError::ScopedRecordNotFound {
        kind: "VM-11 outcome review",
        project_id: mission.project_id.clone(),
        id: format!("{}:cycle:{}", mission.id, decision.cycle),
    })?;
    let stored_decision = load_outcome_review_decision_record(
        transaction,
        &mission.project_id,
        &mission.id,
        decision.cycle,
    )?
    .ok_or_else(|| StorageError::ScopedRecordNotFound {
        kind: "VM-11 outcome review decision",
        project_id: mission.project_id.clone(),
        id: format!("{}:cycle:{}", mission.id, decision.cycle),
    })?;
    let stored_parent =
        load_mission_normalized(transaction, &mission.project_id, &parent_mission.id)?.ok_or_else(
            || StorageError::MissionNotFound {
                project_id: mission.project_id.clone(),
                mission_id: parent_mission.id.clone(),
            },
        )?;
    if stored_review != *review
        || stored_decision != *decision
        || stored_parent != *parent_mission
        || stored_parent.revision != expected_parent_mission_revision
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "VM-11 next-contract source",
            id: mission.id.to_string(),
        });
    }
    OutcomeReviewNextContractResolution::validate_frozen_sources(
        mission,
        &stored_parent,
        &stored_review,
        &stored_decision,
    )?;
    Ok(())
}

struct CompletedReviewBinding {
    cycle: u64,
    checkpoint_revision: u64,
    completion_digest: String,
}

fn validate_completed_review_binding(
    mission: &Mission,
    review: &OutcomeReviewProjection,
) -> Result<CompletedReviewBinding, StorageError> {
    let definition = mission
        .definition
        .as_ref()
        .ok_or_else(|| StorageError::DomainDecode("VM-11 definition is unavailable".into()))?;
    let checkpoint = definition
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.id == "outcome_review")
        .ok_or_else(|| StorageError::DomainDecode("VM-11 outcome_review is unavailable".into()))?;
    let completion = checkpoint
        .completion
        .as_ref()
        .ok_or_else(|| StorageError::DomainDecode("VM-11 outcome_review is incomplete".into()))?;
    let evidence = completion.application_evidence.as_ref().ok_or_else(|| {
        StorageError::DomainDecode("VM-11 outcome_review evidence is missing".into())
    })?;
    let review_source = evidence
        .sources
        .iter()
        .find(|source| source.source_kind == "outcome_review")
        .ok_or_else(|| {
            StorageError::DomainDecode("VM-11 outcome_review source is missing".into())
        })?;
    let review_digest = review.digest()?;
    if definition.manifest_id != "VM-11"
        || definition.cycle == 0
        || checkpoint.status != MissionCheckpointStatus::Completed
        || evidence.handler_id != "vm11.outcome-review/v1"
        || evidence.checkpoint_id != "outcome_review"
        || completion.evidence_digest != evidence.digest()
        || completion.verified_at != review.observed_at
        || review_source.projection_digest != review_digest
        || review_source.source_revision != review.source_ledger_revision
        || review.tenant_id != mission.tenant_id
        || review.project_id != mission.project_id
        || mission.contract.parent_mission_id.as_ref() != Some(&review.source_mission_id)
        || review.source_mission_revision == 0
        || review.source_ledger_revision == 0
    {
        return Err(StorageError::DomainDecode(
            "VM-11 outcome review is detached from its exact Application completion".into(),
        ));
    }
    Ok(CompletedReviewBinding {
        cycle: definition.cycle,
        checkpoint_revision: checkpoint.revision,
        completion_digest: completion.evidence_digest.clone(),
    })
}

fn validate_successful_source_fences(
    fences: &[ApplicationSourceRevisionFence],
    source_mission_id: &MissionId,
) -> Result<(), StorageError> {
    let mut unique = BTreeSet::new();
    if fences.is_empty()
        || fences.iter().any(|fence| {
            fence.id.trim().is_empty()
                || fence.expected_revision.is_none()
                || !unique.insert((fence.kind, fence.id.as_str()))
        })
        || !fences.iter().any(|fence| {
            fence.kind == ApplicationSourceKind::Mission && fence.id == source_mission_id.as_str()
        })
    {
        return Err(StorageError::DomainDecode(
            "VM-11 outcome review requires the exact non-empty successful source fence set".into(),
        ));
    }
    Ok(())
}

fn require_outcome_ledger_revision(
    transaction: &Transaction<'_>,
    mission: &Mission,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let stored = transaction
        .query_row(
            "SELECT tenant_id, revision FROM outcome_ledgers WHERE project_id = ?1",
            [mission.project_id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    if stored
        .as_ref()
        .is_some_and(|(tenant_id, _)| tenant_id != mission.tenant_id.as_str())
    {
        return Err(StorageError::TenantScopeMismatch);
    }
    if stored.as_ref().map(|(_, revision)| *revision) != Some(to_sql_u64(expected_revision)?) {
        return Err(StorageError::OptimisticConflict {
            aggregate: "outcome_ledger_source_fence".into(),
            expected_revision,
        });
    }
    Ok(())
}

fn insert_outcome_review(
    transaction: &Transaction<'_>,
    mission: &Mission,
    review: &OutcomeReviewProjection,
    binding: &CompletedReviewBinding,
    source_fences: &[ApplicationSourceRevisionFence],
) -> Result<(), StorageError> {
    let projection_digest = review.digest()?;
    transaction.execute(
        "INSERT INTO vm11_outcome_reviews
           (tenant_id, project_id, mission_id, cycle, source_mission_id,
            source_mission_revision, source_ledger_revision,
            source_review_checkpoint_revision, source_review_completion_digest,
            projection_digest, observed_at, projection_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            mission.tenant_id.as_str(),
            mission.project_id.as_str(),
            mission.id.as_str(),
            to_sql_u64(binding.cycle)?,
            review.source_mission_id.as_str(),
            to_sql_u64(review.source_mission_revision)?,
            to_sql_u64(review.source_ledger_revision)?,
            to_sql_u64(binding.checkpoint_revision)?,
            binding.completion_digest,
            projection_digest,
            review.observed_at.to_rfc3339(),
            serde_json::to_string(review)?,
        ],
    )?;
    for fence in source_fences {
        transaction.execute(
            "INSERT INTO vm11_outcome_review_source_fences
               (tenant_id, project_id, mission_id, cycle, source_kind,
                source_id, expected_revision)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                mission.tenant_id.as_str(),
                mission.project_id.as_str(),
                mission.id.as_str(),
                to_sql_u64(binding.cycle)?,
                application_source_name(fence.kind),
                fence.id,
                fence.expected_revision.map(to_sql_u64).transpose()?,
            ],
        )?;
    }
    Ok(())
}

fn load_outcome_review_record(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
    cycle: u64,
) -> Result<Option<OutcomeReviewProjection>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, source_mission_id, source_mission_revision,
                    source_ledger_revision, projection_digest, observed_at, projection_json
             FROM vm11_outcome_reviews
             WHERE project_id = ?1 AND mission_id = ?2 AND cycle = ?3",
            params![project_id.as_str(), mission_id.as_str(), to_sql_u64(cycle)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some((
        tenant_id,
        source_mission_id,
        source_mission_revision,
        source_ledger_revision,
        projection_digest,
        observed_at,
        projection_json,
    )) = row
    else {
        return Ok(None);
    };
    let review: OutcomeReviewProjection = serde_json::from_str(&projection_json)?;
    if review.tenant_id.as_str() != tenant_id
        || review.project_id != *project_id
        || review.source_mission_id.as_str() != source_mission_id
        || to_sql_u64(review.source_mission_revision)? != source_mission_revision
        || to_sql_u64(review.source_ledger_revision)? != source_ledger_revision
        || review.digest()? != projection_digest
        || review.observed_at.to_rfc3339() != observed_at
    {
        return Err(StorageError::DomainDecode(
            "VM-11 outcome review normalized projection is inconsistent".into(),
        ));
    }
    Ok(Some(review))
}

fn load_outcome_review_source_fences(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
    cycle: u64,
) -> Result<Vec<ApplicationSourceRevisionFence>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT source_kind, source_id, expected_revision
         FROM vm11_outcome_review_source_fences
         WHERE project_id = ?1 AND mission_id = ?2 AND cycle = ?3
         ORDER BY source_kind, source_id",
    )?;
    statement
        .query_map(
            params![project_id.as_str(), mission_id.as_str(), to_sql_u64(cycle)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )?
        .map(|row| {
            let (kind, id, revision) = row?;
            let kind = parse_application_source_kind(&kind)?;
            let expected_revision = revision
                .map(|revision| from_sql_u64(revision, "outcome review source fence"))
                .transpose()?;
            Ok(ApplicationSourceRevisionFence {
                kind,
                id,
                expected_revision,
            })
        })
        .collect()
}

fn insert_outcome_review_decision(
    transaction: &Transaction<'_>,
    decision: &OutcomeReviewDecision,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO vm11_outcome_review_decisions
           (tenant_id, project_id, mission_id, cycle, action, next_contract_intent,
            source_review_projection_digest, source_review_completion_digest,
            source_mission_id, source_mission_revision, source_ledger_revision,
            decided_by, conversation_id, conversation_revision, message_id,
            message_sequence, rationale_digest, idempotency_key_digest,
            decision_digest, decided_at, decision_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            decision.tenant_id.as_str(),
            decision.project_id.as_str(),
            decision.mission_id.as_str(),
            to_sql_u64(decision.cycle)?,
            enum_name(&decision.action)?,
            enum_name(&decision.next_contract_intent)?,
            decision.source_review_projection_digest,
            decision.source_review_completion_digest,
            decision.source_mission_id.as_str(),
            to_sql_u64(decision.source_mission_revision)?,
            to_sql_u64(decision.source_ledger_revision)?,
            decision.decided_by.as_str(),
            decision.conversation_id.as_str(),
            to_sql_u64(decision.conversation_revision)?,
            decision.message_id.as_str(),
            to_sql_u64(decision.message_sequence)?,
            decision.rationale_digest,
            decision.idempotency_key_digest,
            decision.digest()?,
            decision.decided_at.to_rfc3339(),
            serde_json::to_string(decision)?,
        ],
    )?;
    Ok(())
}

fn load_outcome_review_decision_record(
    connection: &Connection,
    project_id: &ProjectId,
    mission_id: &MissionId,
    cycle: u64,
) -> Result<Option<OutcomeReviewDecision>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, action, next_contract_intent,
                    source_review_projection_digest, source_review_completion_digest,
                    source_mission_id, source_mission_revision, source_ledger_revision,
                    decided_by, conversation_id, conversation_revision, message_id,
                    message_sequence, rationale_digest, idempotency_key_digest,
                    decision_digest, decided_at, decision_json
             FROM vm11_outcome_review_decisions
             WHERE project_id = ?1 AND mission_id = ?2 AND cycle = ?3",
            params![project_id.as_str(), mission_id.as_str(), to_sql_u64(cycle)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let decision: OutcomeReviewDecision = serde_json::from_str(&row.17)?;
    if decision.tenant_id.as_str() != row.0
        || decision.project_id != *project_id
        || decision.mission_id != *mission_id
        || enum_name(&decision.action)? != row.1
        || enum_name(&decision.next_contract_intent)? != row.2
        || decision.source_review_projection_digest != row.3
        || decision.source_review_completion_digest != row.4
        || decision.source_mission_id.as_str() != row.5
        || to_sql_u64(decision.source_mission_revision)? != row.6
        || to_sql_u64(decision.source_ledger_revision)? != row.7
        || decision.decided_by.as_str() != row.8
        || decision.conversation_id.as_str() != row.9
        || to_sql_u64(decision.conversation_revision)? != row.10
        || decision.message_id.as_str() != row.11
        || to_sql_u64(decision.message_sequence)? != row.12
        || decision.rationale_digest != row.13
        || decision.idempotency_key_digest != row.14
        || decision.digest()? != row.15
        || decision.decided_at.to_rfc3339() != row.16
    {
        return Err(StorageError::DomainDecode(
            "VM-11 outcome decision normalized projection is inconsistent".into(),
        ));
    }
    Ok(Some(decision))
}

fn validate_decision_conversation(
    conversation: &MissionConversation,
    decision: &OutcomeReviewDecision,
) -> Result<(), StorageError> {
    let message = conversation
        .messages
        .iter()
        .find(|message| message.id == decision.message_id)
        .ok_or_else(|| StorageError::DomainDecode("decision message is unavailable".into()))?;
    if conversation.id != decision.conversation_id
        || conversation.tenant_id != decision.tenant_id
        || conversation.project_id != decision.project_id
        || conversation.mission_id != decision.mission_id
        || conversation.revision < decision.conversation_revision
        || message.sequence != decision.message_sequence
        || message.role != MissionConversationRole::User
        || message.kind != MissionConversationMessageKind::CheckpointConfirmation
        || message.checkpoint_id.as_deref() != Some("continue_stop_scale_test")
        || message.content_digest != decision.rationale_digest
        || sha256(message.idempotency_key.as_bytes()) != decision.idempotency_key_digest
        || message.recorded_at != decision.decided_at
    {
        return Err(StorageError::DomainDecode(
            "structured outcome decision is detached from its private Conversation message".into(),
        ));
    }
    Ok(())
}

fn parse_application_source_kind(value: &str) -> Result<ApplicationSourceKind, StorageError> {
    match value {
        "mission" => Ok(ApplicationSourceKind::Mission),
        "connection" => Ok(ApplicationSourceKind::Connection),
        "identity_link" => Ok(ApplicationSourceKind::IdentityLink),
        "person" => Ok(ApplicationSourceKind::Person),
        "company" => Ok(ApplicationSourceKind::Company),
        "partner" => Ok(ApplicationSourceKind::Partner),
        "opportunity" => Ok(ApplicationSourceKind::Opportunity),
        _ => Err(StorageError::DomainDecode(
            "unknown VM-11 outcome review source kind".into(),
        )),
    }
}

fn enum_name(value: &impl serde::Serialize) -> Result<String, StorageError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| StorageError::DomainDecode("expected string enum".into()))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{field} must be nonnegative")))
}

fn sha256(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;

    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_domain_kernel::{
        ActorId, CurrencyCode, KpiContract, KpiDirection, MissionCheckpointApplicationEvidence,
        MissionCheckpointCompletion, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor,
        MissionCheckpointOracleSource, MissionCheckpointRoute, MissionContract,
        MissionConversationId, MissionConversationMessageId, MissionDefinition, Money,
        OperatingMode, OutcomeDecision, OutcomeLedger, OutcomeReviewCausalStatus,
        OutcomeReviewCaveat, OutcomeReviewGateStatus, OutcomeReviewLoopPolicy,
        OutcomeReviewRoiStatus, Project, ProjectId, StorageMode, Task, TaskId, TaskStatus,
        TenantId,
    };

    use super::*;
    use crate::{DatabaseKey, STORAGE_SCHEMA_VERSION};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the storage fixture recreates the complete normalized VM-11 review, Application evidence, Human route and Conversation authority"
    )]
    fn decision_fixture(
        tenant_id: &TenantId,
        project_id: &ProjectId,
    ) -> (
        Mission,
        Mission,
        MissionConversation,
        OutcomeReviewProjection,
    ) {
        let usd = CurrencyCode::parse("USD").expect("USD");
        let kpis = BTreeMap::from([(
            "lead_qualified_count".into(),
            KpiContract {
                baseline: None,
                target: rust_decimal::Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )]);
        let parent_oracles =
            BTreeSet::from(["goal".into(), "decision".into(), "operating_state".into()]);
        let parent_definition = MissionDefinition::from_routed_linear_manifest(
            "VM-07",
            3,
            "8".repeat(64),
            OperatingMode::OneOffDecision,
            ["decision.evaluate".into()],
            ["next_decision".into()],
            parent_oracles.clone(),
            [(
                "product_market_budget_constraints".into(),
                MissionCheckpointRoute::contracted(
                    "decision.evaluate",
                    MissionCheckpointExecutor::Application,
                    parent_oracles,
                    MissionCheckpointCompletionPolicy::DeterministicEvidence,
                )
                .expect("parent route"),
            )],
        )
        .expect("parent definition");
        let mut parent_contract = MissionContract::bootstrap(
            "Review one verified business outcome",
            ["decision.evaluate".into()],
            now(),
        );
        parent_contract.mode = OperatingMode::OneOffDecision;
        parent_contract.kpis = kpis.clone();
        parent_contract.budget = Money::new(500, usd.clone());
        let parent = Mission::compile_catalog(
            tenant_id.clone(),
            MissionId::from("outcome-review-parent"),
            project_id.clone(),
            "Parent Mission",
            parent_contract,
            parent_definition,
            now(),
        )
        .expect("parent Mission");
        let review = OutcomeReviewProjection {
            schema_version: OutcomeReviewProjection::SCHEMA_VERSION,
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            source_mission_id: parent.id.clone(),
            source_mission_revision: parent.revision,
            source_ledger_revision: 1,
            window_started_at: now(),
            outcome_window_ended_at: now() + Duration::minutes(1),
            observed_at: now() + Duration::minutes(2),
            measurement_count: 1,
            target_met_count: 0,
            target_gap_count: 1,
            order_count: 1,
            attributed_order_count: 0,
            unattributed_order_count: 1,
            settlement_group_count: 0,
            paid_or_no_payment_due_group_count: 0,
            outstanding_settlement_group_count: 0,
            verified_effect_count: 0,
            pending_effect_count: 0,
            unresolved_cost_effect_count: 0,
            cross_currency_cost_effect_count: 0,
            budget: Money::new(500, usd.clone()),
            budget_currency_verified_cost: Money::zero(usd.clone()),
            budget_remaining: Money::new(500, usd.clone()),
            budget_overrun: Money::zero(usd),
            kpi_status: OutcomeReviewGateStatus::Blocked,
            attribution_status: OutcomeReviewGateStatus::Blocked,
            settlement_status: OutcomeReviewGateStatus::Satisfied,
            cost_status: OutcomeReviewGateStatus::Satisfied,
            budget_status: OutcomeReviewGateStatus::Satisfied,
            scale_evidence_status: OutcomeReviewGateStatus::Blocked,
            loop_policy: OutcomeReviewLoopPolicy::Forbidden,
            causal_status: OutcomeReviewCausalStatus::NotClaimed,
            roi_status: OutcomeReviewRoiStatus::NotCalculated,
            caveats: BTreeSet::from([
                OutcomeReviewCaveat::KpiTargetGap,
                OutcomeReviewCaveat::UnattributedOrders,
                OutcomeReviewCaveat::ImplicitLoopForbidden,
            ]),
            economics: BTreeMap::new(),
            source_contract_digest: sha256(
                &serde_json::to_vec(&serde_json::json!({
                    "schemaVersion": "hartevo-mission-kpi-contract-source/v1",
                    "missionId": parent.id,
                    "missionRevision": parent.revision,
                    "contract": parent.contract,
                }))
                .expect("parent source"),
            ),
            normalization_digest: "2".repeat(64),
            identity_chain_digest: "3".repeat(64),
            kpi_projection_digest: "4".repeat(64),
            attribution_projection_digest: "5".repeat(64),
            settlement_projection_digest: "6".repeat(64),
            effect_cost_source_digest: "7".repeat(64),
        };
        let review_oracles = BTreeSet::from([
            "decision".into(),
            "operating_state".into(),
            "outcome".into(),
        ]);
        let decision_oracles = BTreeSet::from([
            "goal".into(),
            "decision".into(),
            "operating_state".into(),
            "outcome".into(),
        ]);
        let next_contract_oracles =
            BTreeSet::from(["goal".into(), "operating_state".into(), "outcome".into()]);
        let candidate_oracles = BTreeSet::from([
            "decision".into(),
            "work_product".into(),
            "operating_state".into(),
        ]);
        let definition_oracles = review_oracles
            .union(&decision_oracles)
            .cloned()
            .chain(next_contract_oracles.iter().cloned())
            .chain(candidate_oracles.iter().cloned())
            .collect::<BTreeSet<_>>();
        let definition = MissionDefinition::from_routed_linear_manifest(
            "VM-11",
            3,
            "8".repeat(64),
            OperatingMode::OneOffDecision,
            [
                "decision.evaluate".into(),
                "automation.schedule".into(),
                "candidate.propose".into(),
            ],
            ["next_decision".into()],
            definition_oracles,
            [
                (
                    "outcome_review".into(),
                    MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Application,
                        review_oracles.clone(),
                        MissionCheckpointCompletionPolicy::DeterministicEvidence,
                    )
                    .expect("review route"),
                ),
                (
                    "continue_stop_scale_test".into(),
                    MissionCheckpointRoute::contracted(
                        "decision.evaluate",
                        MissionCheckpointExecutor::Human,
                        decision_oracles,
                        MissionCheckpointCompletionPolicy::HumanConfirmation,
                    )
                    .expect("decision route"),
                ),
                (
                    "next_contract_or_valid_terminal".into(),
                    MissionCheckpointRoute::contracted(
                        "automation.schedule",
                        MissionCheckpointExecutor::Application,
                        next_contract_oracles,
                        MissionCheckpointCompletionPolicy::DeterministicEvidence,
                    )
                    .expect("next-contract route"),
                ),
                (
                    "candidate_learning".into(),
                    MissionCheckpointRoute::contracted(
                        "candidate.propose",
                        MissionCheckpointExecutor::Application,
                        candidate_oracles,
                        MissionCheckpointCompletionPolicy::DeterministicEvidence,
                    )
                    .expect("candidate route"),
                ),
            ],
        )
        .expect("VM-11 definition");
        let mut contract = MissionContract::bootstrap(
            "Choose one explicit action from the frozen outcome review",
            [
                "decision.evaluate".into(),
                "automation.schedule".into(),
                "candidate.propose".into(),
            ],
            now(),
        );
        contract.mode = OperatingMode::OneOffDecision;
        contract.parent_mission_id = Some(parent.id.clone());
        contract.market = parent.contract.market.clone();
        contract.language = parent.contract.language.clone();
        contract.audience = parent.contract.audience.clone();
        contract.timezone = parent.contract.timezone.clone();
        contract.kpis = parent.contract.kpis.clone();
        contract.budget = parent.contract.budget.clone();
        let mut mission = Mission::compile_catalog(
            tenant_id.clone(),
            MissionId::from("vm11-outcome-review-decision"),
            project_id.clone(),
            "VM-11 outcome decision",
            contract,
            definition,
            now(),
        )
        .expect("VM-11 Mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("vm11-review-task"),
                    title: "Freeze outcome review".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                }],
                now(),
            )
            .expect("start review");
        let dispatch_mission_revision = mission.revision;
        let dispatch_checkpoint_revision = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .map(|checkpoint| checkpoint.revision)
            .expect("review checkpoint");
        mission
            .begin_checkpoint_verification("outcome_review", review.observed_at)
            .expect("verify review");
        let definition = mission.definition.as_ref().expect("definition");
        let checkpoint = definition.current_checkpoint().expect("review checkpoint");
        let route = checkpoint.route.as_ref().expect("review route");
        let evidence = MissionCheckpointApplicationEvidence {
            schema_version: MissionCheckpointApplicationEvidence::SCHEMA_VERSION,
            handler_id: "vm11.outcome-review/v1".into(),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: mission.id.clone(),
            manifest_id: definition.manifest_id.clone(),
            manifest_version: definition.manifest_version,
            catalog_digest: definition.catalog_digest.clone(),
            cycle: definition.cycle,
            checkpoint_id: checkpoint.id.clone(),
            dispatch_mission_revision,
            dispatch_checkpoint_revision,
            verification_mission_revision: mission.revision,
            verification_checkpoint_revision: checkpoint.revision,
            capability_id: route.capability_id.clone(),
            executor: route.executor,
            completion_policy: route.completion_policy.expect("policy"),
            sources: BTreeSet::from([
                MissionCheckpointOracleSource {
                    source_kind: "mission_checkpoint".into(),
                    source_id: format!("{}:outcome_review", mission.id),
                    source_revision: dispatch_checkpoint_revision,
                    projection_digest: "9".repeat(64),
                    oracle_ids: BTreeSet::from(["operating_state".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "parent_mission_review".into(),
                    source_id: review.source_mission_id.to_string(),
                    source_revision: review.source_mission_revision,
                    projection_digest: "a".repeat(64),
                    oracle_ids: BTreeSet::from(["decision".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "outcome_review".into(),
                    source_id: project_id.to_string(),
                    source_revision: review.source_ledger_revision,
                    projection_digest: review.digest().expect("review digest"),
                    oracle_ids: BTreeSet::from(["outcome".into()]),
                },
            ]),
            observed_at: review.observed_at,
        };
        mission
            .complete_checkpoint(
                "outcome_review",
                MissionCheckpointCompletion {
                    oracle_ids: review_oracles,
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: Some(evidence.clone()),
                    evidence_digest: evidence.digest(),
                    verified_at: review.observed_at,
                },
            )
            .expect("complete review");
        mission
            .begin_checkpoint_with_task(
                "continue_stop_scale_test",
                Task {
                    id: TaskId::from("vm11-decision-task"),
                    title: "Choose Continue, Stop, Scale, or Test".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                },
                review.observed_at + Duration::seconds(1),
            )
            .expect("start decision");
        let conversation = MissionConversation::start(
            MissionConversationId::from("vm11-outcome-review-conversation"),
            MissionConversationMessageId::from("vm11-outcome-review-goal"),
            &mission,
            mission.contract.goal.clone(),
            "vm11-outcome-review-goal:v1",
            review.observed_at + Duration::seconds(1),
        )
        .expect("Conversation");
        (parent, mission, conversation, review)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the migration proof checks all three normalized tables, constraints, encrypted backup cardinality, data preservation, and idempotent reopen"
    )]
    fn migration_v45_installs_normalized_review_and_decision_ledgers_with_one_backup() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("outcome-review-v44.sqlite3");
        let key = DatabaseKey::new([45; 32]).expect("key");
        let project = Project::create_local(
            TenantId::from("tenant-outcome-review-migration"),
            ProjectId::from("project-outcome-review-migration"),
            "Outcome review migration",
            "",
            directory.path().join("workspace"),
            StorageMode::LocalExisting,
        )
        .expect("project");
        {
            let mut store = ProjectStore::open(&path, &key).expect("current store");
            crate::downgrade_identity_bootstrap_schema_for_test(&store.connection);
            store.save_project(&project).expect("project");
            store
                .connection
                .execute_batch(
                    "DROP TABLE vm11_outcome_review_decisions;
                     DROP TABLE vm11_outcome_review_source_fences;
                     DROP TABLE vm11_outcome_reviews;
                     DELETE FROM schema_migrations WHERE version >= 45;
                     PRAGMA wal_checkpoint(TRUNCATE);",
                )
                .expect("construct v44");
            assert_eq!(store.schema_version().expect("v44 schema"), 44);
        }

        let migrated = ProjectStore::open(&path, &key).expect("migrate v44");
        assert_eq!(
            migrated.schema_version().expect("current schema"),
            STORAGE_SCHEMA_VERSION
        );
        assert_eq!(
            migrated
                .load_project(&project.id)
                .expect("project survives"),
            project
        );
        for table in [
            "vm11_outcome_reviews",
            "vm11_outcome_review_source_fences",
            "vm11_outcome_review_decisions",
        ] {
            let schema = migrated
                .connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get::<_, String>(0),
                )
                .expect("v45 table schema");
            assert!(schema.contains("tenant_id"));
            assert!(schema.contains("project_id"));
            assert!(schema.contains("mission_id"));
            assert!(schema.contains("FOREIGN KEY"));
        }
        let decision_schema = migrated
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master
                 WHERE type = 'table' AND name = 'vm11_outcome_review_decisions'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("decision schema");
        assert!(decision_schema.contains("'continue', 'stop', 'scale', 'test'"));
        assert!(decision_schema.contains("length(rationale_digest) = 64"));
        let foreign_key_violation_count = migrated
            .connection
            .prepare("PRAGMA foreign_key_check")
            .expect("foreign key check")
            .query_map([], |_| Ok(()))
            .expect("foreign key rows")
            .count();
        assert_eq!(foreign_key_violation_count, 0);
        drop(migrated);

        let backup_count = fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v44")
            })
            .count();
        assert_eq!(backup_count, 1);
        let reopened = ProjectStore::open(&path, &key).expect("idempotent reopen");
        assert_eq!(
            reopened
                .load_project(&project.id)
                .expect("project survives reopen"),
            project
        );
        drop(reopened);
        let backups_after_reopen = fs::read_dir(directory.path())
            .expect("directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .contains("pre-migration-v44")
            })
            .count();
        assert_eq!(backups_after_reopen, 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the atomic rollback proof keeps SQL fault injection, source-fence invalidation, Mission/Conversation/Event/Outbox assertions, and immutable review retention together"
    )]
    fn decision_insert_failure_rolls_back_mission_conversation_events_and_outbox() {
        let mut store = ProjectStore::in_memory().expect("store");
        let tenant_id = TenantId::from("tenant-outcome-review-rollback");
        let project_id = ProjectId::from("project-outcome-review-rollback");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Outcome review rollback",
            "",
            "/tmp/hartevo-outcome-review-rollback",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store.save_project(&project).expect("project");
        let (parent, mut mission, mut conversation, review) =
            decision_fixture(&tenant_id, &project_id);
        store.save_mission(&parent).expect("parent Mission");
        let ledger = OutcomeLedger::new(tenant_id.clone(), project_id.clone()).expect("ledger");
        store
            .create_outcome_ledger(
                &ledger,
                "outcome.ledger_started",
                &serde_json::json!({"projectId": project_id}),
                now(),
            )
            .expect("Outcome Ledger");
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
            .expect("Mission and Conversation");
        let source_fences = [ApplicationSourceRevisionFence {
            kind: ApplicationSourceKind::Mission,
            id: parent.id.to_string(),
            expected_revision: Some(parent.revision),
        }];
        let binding = validate_completed_review_binding(&mission, &review).expect("review binding");
        {
            let transaction = store.connection.transaction().expect("transaction");
            insert_outcome_review(&transaction, &mission, &review, &binding, &source_fences)
                .expect("persist frozen review fixture");
            transaction.commit().expect("commit review fixture");
        }
        assert_eq!(
            store
                .load_vm11_outcome_review(&project_id, &mission.id)
                .expect("stored review"),
            review
        );

        let before_mission = mission.clone();
        let before_conversation = conversation.clone();
        let before_events = store
            .events_for_mission(&project_id, &mission.id)
            .expect("events before");
        let before_outbox_count = store
            .connection
            .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("outbox before");
        let expected_mission_revision = mission.revision;
        let expected_conversation_revision = conversation.revision;
        let decided_at = review.observed_at + Duration::minutes(1);
        let (message, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("vm11-outcome-review-stop-message"),
                MissionConversationMessageKind::CheckpointConfirmation,
                "Stop because the one-off contract forbids an implicit loop.",
                "vm11-outcome-review-stop:v1",
                &mission,
                decided_at,
            )
            .expect("append private decision rationale");
        assert!(appended);
        let review_checkpoint = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "outcome_review")
            })
            .expect("review checkpoint");
        let decision = OutcomeReviewDecision::decide(
            &mission,
            &review,
            review_checkpoint.revision,
            review_checkpoint
                .completion
                .as_ref()
                .expect("review completion")
                .evidence_digest
                .clone(),
            OutcomeDecision::Stop,
            ActorId::from("project-owner"),
            conversation.id.clone(),
            conversation.revision,
            message.id.clone(),
            message.sequence,
            message.content_digest.clone(),
            sha256(message.idempotency_key.as_bytes()),
            decided_at,
        )
        .expect("structured Stop");
        mission
            .begin_checkpoint_verification("continue_stop_scale_test", decided_at)
            .expect("verify decision");
        mission
            .complete_checkpoint(
                "continue_stop_scale_test",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from([
                        "goal".into(),
                        "decision".into(),
                        "operating_state".into(),
                        "outcome".into(),
                    ]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: decision.digest().expect("decision digest"),
                    verified_at: decided_at,
                },
            )
            .expect("complete decision");
        let events = [PendingEvent::new(
            "mission.outcome_review_decided",
            serde_json::json!({
                "missionId": mission.id,
                "action": decision.action,
                "decisionDigest": decision.digest().expect("decision digest"),
            }),
            decided_at,
        )];
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_vm11_outcome_decision_failure
                 BEFORE INSERT ON vm11_outcome_review_decisions
                 BEGIN
                   SELECT RAISE(ABORT, 'injected VM-11 outcome decision failure');
                 END;",
            )
            .expect("failure trigger");
        assert!(matches!(
            store.complete_vm11_outcome_review_decision_atomic(
                &mission,
                expected_mission_revision,
                &conversation,
                expected_conversation_revision,
                &review,
                &decision,
                &events,
            ),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_mission(&project_id, &mission.id)
                .expect("Mission rollback"),
            before_mission
        );
        assert_eq!(
            store
                .load_mission_conversation(&project_id, &mission.id)
                .expect("Conversation rollback"),
            before_conversation
        );
        assert_eq!(
            store
                .events_for_mission(&project_id, &mission.id)
                .expect("event rollback"),
            before_events
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| row
                    .get::<_, i64>(0))
                .expect("outbox rollback"),
            before_outbox_count
        );
        assert!(matches!(
            store.load_vm11_outcome_review_decision(&project_id, &mission.id),
            Err(StorageError::ScopedRecordNotFound {
                kind: "VM-11 outcome review decision",
                ..
            })
        ));
        assert_eq!(
            store
                .load_vm11_outcome_review(&project_id, &mission.id)
                .expect("frozen review survives rollback"),
            review
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_vm11_outcome_decision_failure;")
            .expect("drop failure trigger");
        let mut stale_parent = parent;
        stale_parent
            .start_research(
                [Task {
                    id: TaskId::from("parent-source-changed-task"),
                    title: "Change parent source revision".into(),
                    status: TaskStatus::Running,
                    capability: "decision.evaluate".into(),
                }],
                decided_at,
            )
            .expect("advance parent source revision");
        store
            .save_mission(&stale_parent)
            .expect("persist changed parent source");
        assert!(matches!(
            store.complete_vm11_outcome_review_decision_atomic(
                &mission,
                expected_mission_revision,
                &conversation,
                expected_conversation_revision,
                &review,
                &decision,
                &events,
            ),
            Err(StorageError::OptimisticConflict { aggregate, expected_revision })
                if aggregate == "mission_source_fence"
                    && expected_revision == review.source_mission_revision
        ));
        assert_eq!(
            store
                .load_mission(&project_id, &mission.id)
                .expect("Mission remains unchanged"),
            before_mission
        );
        assert_eq!(
            store
                .load_mission_conversation(&project_id, &mission.id)
                .expect("Conversation remains unchanged"),
            before_conversation
        );
        assert_eq!(
            store
                .events_for_mission(&project_id, &mission.id)
                .expect("events remain unchanged"),
            before_events
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| row
                    .get::<_, i64>(0))
                .expect("outbox remains unchanged"),
            before_outbox_count
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the route-specific rollback proof keeps frozen Human authority, parent fencing, typed Stop, candidate skip, Mission CAS, Event and Outbox in one auditable transaction"
    )]
    fn next_contract_stop_is_atomic_parent_fenced_and_rolls_back_event_failure() {
        let mut store = ProjectStore::in_memory().expect("store");
        let tenant_id = TenantId::from("tenant-next-contract-rollback");
        let project_id = ProjectId::from("project-next-contract-rollback");
        let project = Project::create_local(
            tenant_id.clone(),
            project_id.clone(),
            "Next-contract rollback",
            "",
            "/tmp/hartevo-next-contract-rollback",
            StorageMode::LocalExisting,
        )
        .expect("project");
        store.save_project(&project).expect("project");
        let (parent, mut mission, mut conversation, review) =
            decision_fixture(&tenant_id, &project_id);
        store.save_mission(&parent).expect("parent Mission");
        let ledger = OutcomeLedger::new(tenant_id.clone(), project_id.clone()).expect("ledger");
        store
            .create_outcome_ledger(
                &ledger,
                "outcome.ledger_started",
                &serde_json::json!({"projectId": project_id}),
                now(),
            )
            .expect("Outcome Ledger");
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
            .expect("Mission and Conversation");
        let source_fences = [ApplicationSourceRevisionFence::present(
            ApplicationSourceKind::Mission,
            parent.id.to_string(),
            parent.revision,
        )];
        let binding = validate_completed_review_binding(&mission, &review).expect("review binding");
        {
            let transaction = store.connection.transaction().expect("transaction");
            insert_outcome_review(&transaction, &mission, &review, &binding, &source_fences)
                .expect("persist frozen review");
            transaction.commit().expect("review transaction");
        }

        let expected_human_mission_revision = mission.revision;
        let expected_conversation_revision = conversation.revision;
        let decided_at = review.observed_at + Duration::minutes(1);
        let (message, appended) = conversation
            .append_user_message(
                MissionConversationMessageId::from("vm11-next-contract-stop-message"),
                MissionConversationMessageKind::CheckpointConfirmation,
                "Stop at the reviewed one-off terminal.",
                "vm11-next-contract-stop:v1",
                &mission,
                decided_at,
            )
            .expect("append private Stop rationale");
        assert!(appended);
        let review_checkpoint = mission
            .definition
            .as_ref()
            .and_then(|definition| {
                definition
                    .checkpoints
                    .iter()
                    .find(|checkpoint| checkpoint.id == "outcome_review")
            })
            .expect("review checkpoint");
        let decision = OutcomeReviewDecision::decide(
            &mission,
            &review,
            review_checkpoint.revision,
            review_checkpoint
                .completion
                .as_ref()
                .expect("review completion")
                .evidence_digest
                .clone(),
            OutcomeDecision::Stop,
            ActorId::from("project-owner"),
            conversation.id.clone(),
            conversation.revision,
            message.id.clone(),
            message.sequence,
            message.content_digest.clone(),
            sha256(message.idempotency_key.as_bytes()),
            decided_at,
        )
        .expect("structured Stop");
        mission
            .begin_checkpoint_verification("continue_stop_scale_test", decided_at)
            .expect("verify decision");
        mission
            .complete_checkpoint(
                "continue_stop_scale_test",
                MissionCheckpointCompletion {
                    oracle_ids: BTreeSet::from([
                        "goal".into(),
                        "decision".into(),
                        "operating_state".into(),
                        "outcome".into(),
                    ]),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: None,
                    evidence_digest: decision.digest().expect("decision digest"),
                    verified_at: decided_at,
                },
            )
            .expect("complete decision");
        mission
            .begin_checkpoint_with_task(
                "next_contract_or_valid_terminal",
                Task {
                    id: TaskId::from("vm11-next-contract-task"),
                    title: "Resolve the exact decision".into(),
                    status: TaskStatus::Running,
                    capability: "automation.schedule".into(),
                },
                decided_at,
            )
            .expect("start next-contract route");
        store
            .complete_vm11_outcome_review_decision_atomic(
                &mission,
                expected_human_mission_revision,
                &conversation,
                expected_conversation_revision,
                &review,
                &decision,
                &[PendingEvent::new(
                    "mission.outcome_review_decided",
                    serde_json::json!({
                        "missionId": mission.id,
                        "action": decision.action,
                        "decisionDigest": decision.digest().expect("decision digest"),
                    }),
                    decided_at,
                )],
            )
            .expect("persist structured decision");

        let dispatch_mission_revision = mission.revision;
        let dispatch_checkpoint_revision = mission
            .definition
            .as_ref()
            .and_then(MissionDefinition::current_checkpoint)
            .map(|checkpoint| checkpoint.revision)
            .expect("next-contract checkpoint");
        let resolved_at = decided_at + Duration::minutes(1);
        let resolution = OutcomeReviewNextContractResolution::resolve(
            &mission,
            &parent,
            &review,
            &decision,
            resolved_at,
        )
        .expect("typed Stop resolution");
        let expected_resolution_mission_revision = mission.revision;
        mission
            .begin_checkpoint_verification("next_contract_or_valid_terminal", resolved_at)
            .expect("verify next-contract route");
        let definition = mission.definition.as_ref().expect("definition");
        let checkpoint = definition
            .current_checkpoint()
            .expect("next-contract checkpoint");
        let route = checkpoint.route.as_ref().expect("next-contract route");
        let evidence = MissionCheckpointApplicationEvidence {
            schema_version: MissionCheckpointApplicationEvidence::SCHEMA_VERSION,
            handler_id: OutcomeReviewNextContractResolution::HANDLER_ID.into(),
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: mission.id.clone(),
            manifest_id: definition.manifest_id.clone(),
            manifest_version: definition.manifest_version,
            catalog_digest: definition.catalog_digest.clone(),
            cycle: definition.cycle,
            checkpoint_id: checkpoint.id.clone(),
            dispatch_mission_revision,
            dispatch_checkpoint_revision,
            verification_mission_revision: mission.revision,
            verification_checkpoint_revision: checkpoint.revision,
            capability_id: route.capability_id.clone(),
            executor: route.executor,
            completion_policy: route.completion_policy.expect("completion policy"),
            sources: BTreeSet::from([
                MissionCheckpointOracleSource {
                    source_kind: "mission_checkpoint".into(),
                    source_id: format!("{}:{}", mission.id, checkpoint.id),
                    source_revision: dispatch_checkpoint_revision,
                    projection_digest: "a".repeat(64),
                    oracle_ids: BTreeSet::from(["operating_state".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "parent_mission_contract".into(),
                    source_id: parent.id.to_string(),
                    source_revision: parent.revision,
                    projection_digest: resolution.source_contract_digest.clone(),
                    oracle_ids: BTreeSet::from(["goal".into()]),
                },
                MissionCheckpointOracleSource {
                    source_kind: "outcome_review_decision".into(),
                    source_id: resolution.decision_source_id(),
                    source_revision: resolution.cycle,
                    projection_digest: resolution.decision_digest.clone(),
                    oracle_ids: BTreeSet::from(["outcome".into()]),
                },
            ]),
            observed_at: resolved_at,
        };
        mission
            .complete_vm11_next_contract_resolution(
                &resolution,
                MissionCheckpointCompletion {
                    oracle_ids: route.oracle_ids.clone(),
                    work_product_ids: BTreeSet::new(),
                    effect_ids: BTreeSet::new(),
                    application_evidence: Some(evidence.clone()),
                    evidence_digest: evidence.digest(),
                    verified_at: resolved_at,
                },
            )
            .expect("apply typed Stop");
        resolution
            .validate_persisted(&mission, &parent, &review, &decision)
            .expect("persisted typed Stop");
        let resolution_event = PendingEvent::new(
            "mission.next_contract_or_valid_terminal_resolved",
            serde_json::json!({
                "missionId": mission.id,
                "resolutionDigest": resolution.digest().expect("resolution digest"),
            }),
            resolved_at,
        );
        let before_mission = store
            .load_mission(&project_id, &mission.id)
            .expect("pre-resolution Mission");
        let before_events = store
            .events_for_mission(&project_id, &mission.id)
            .expect("pre-resolution events");
        let before_outbox_count = store
            .connection
            .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("pre-resolution outbox");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_vm11_next_contract_event_failure
                 BEFORE INSERT ON domain_events
                 WHEN NEW.event_type = 'mission.next_contract_or_valid_terminal_resolved'
                 BEGIN
                   SELECT RAISE(ABORT, 'injected VM-11 next-contract event failure');
                 END;",
            )
            .expect("failure trigger");
        assert!(matches!(
            store.complete_vm11_next_contract_or_valid_terminal_atomic(
                &mission,
                expected_resolution_mission_revision,
                &parent,
                parent.revision,
                &review,
                &decision,
                &resolution,
                std::slice::from_ref(&resolution_event),
            ),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_mission(&project_id, &mission.id)
                .expect("Mission rollback"),
            before_mission
        );
        assert_eq!(
            store
                .events_for_mission(&project_id, &mission.id)
                .expect("Event rollback"),
            before_events
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM outbox_messages", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("Outbox rollback"),
            before_outbox_count
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_vm11_next_contract_event_failure;")
            .expect("drop failure trigger");
        let mutation = store
            .complete_vm11_next_contract_or_valid_terminal_atomic(
                &mission,
                expected_resolution_mission_revision,
                &parent,
                parent.revision,
                &review,
                &decision,
                &resolution,
                &[resolution_event],
            )
            .expect("atomic typed Stop");
        assert_eq!(
            (
                mutation.event_sequences.len(),
                mutation.outbox_sequences.len(),
                store
                    .load_mission(&project_id, &mission.id)
                    .expect("terminal Mission")
                    .stage,
            ),
            (1, 1, MissionStage::Completed)
        );
    }
}
