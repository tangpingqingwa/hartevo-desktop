use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextCheckpoint, ContextCheckpointId, ContextCompactionRecord, ContextCompactionRecordId,
    ContextContinuationLedgerId, ContextFoundationSnapshot, ContextWorkingItem, ContextWorkingSet,
    ContextWorkingSetId, ContextWorkspaceId, ContinuationEntry, ContinuationLedger, ProjectId,
    TruthFact,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn load_context_foundation_ids(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
    ) -> Result<(ContextWorkingSetId, ContextContinuationLedgerId), StorageError> {
        let working_set_id = self.connection.query_row(
            "SELECT id FROM context_working_sets WHERE project_id = ?1 AND workspace_id = ?2",
            params![project_id.as_str(), workspace_id.as_str()],
            |row| row.get::<_, String>(0),
        )?;
        let continuation_ledger_id = self.connection.query_row(
            "SELECT id FROM context_continuation_ledgers
             WHERE project_id = ?1 AND workspace_id = ?2",
            params![project_id.as_str(), workspace_id.as_str()],
            |row| row.get::<_, String>(0),
        )?;
        Ok((
            ContextWorkingSetId::from_stable(working_set_id),
            ContextContinuationLedgerId::from_stable(continuation_ledger_id),
        ))
    }

    pub fn update_context_working_set(
        &mut self,
        working_set: &ContextWorkingSet,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_context_working_set(&working_set.project_id, &working_set.id)?;
        if previous.revision != expected_revision || !working_set.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_working_set:{}", working_set.id),
                expected_revision,
            });
        }
        let workspace =
            self.load_context_workspace(&working_set.project_id, &working_set.workspace_id)?;
        working_set.validate_for(&workspace, now)?;

        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE context_working_sets
             SET revision = ?1, updated_at = ?2, record_json = ?3
             WHERE project_id = ?4 AND id = ?5 AND revision = ?6",
            params![
                to_sql_u64(working_set.revision)?,
                working_set.updated_at.to_rfc3339(),
                serde_json::to_string(working_set)?,
                working_set.project_id.as_str(),
                working_set.id.as_str(),
                to_sql_u64(expected_revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_working_set:{}", working_set.id),
                expected_revision,
            });
        }
        transaction.execute(
            "DELETE FROM context_working_items
             WHERE project_id = ?1 AND working_set_id = ?2",
            params![working_set.project_id.as_str(), working_set.id.as_str()],
        )?;
        insert_context_working_items(&transaction, working_set)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            working_set.tenant_id.as_str(),
            working_set.project_id.as_str(),
            Some(working_set.mission_id.as_str()),
            "context_working_set",
            working_set.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: working_set.revision,
        })
    }

    pub fn append_context_continuation(
        &mut self,
        ledger: &ContinuationLedger,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_context_continuation_ledger(&ledger.project_id, &ledger.id)?;
        if previous.revision != expected_revision || !ledger.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_continuation_ledger:{}", ledger.id),
                expected_revision,
            });
        }
        let workspace = self.load_context_workspace(&ledger.project_id, &ledger.workspace_id)?;
        let mission = self.load_mission(&ledger.project_id, &ledger.mission_id)?;
        ledger.validate_for(&workspace, Some(&mission), now)?;
        let entry = ledger
            .entries
            .last()
            .ok_or_else(|| StorageError::DomainDecode("continuation append has no entry".into()))?;

        let transaction = self.connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE context_continuation_ledgers
             SET revision = ?1, updated_at = ?2, record_json = ?3
             WHERE project_id = ?4 AND id = ?5 AND revision = ?6",
            params![
                to_sql_u64(ledger.revision)?,
                ledger.updated_at.to_rfc3339(),
                serde_json::to_string(ledger)?,
                ledger.project_id.as_str(),
                ledger.id.as_str(),
                to_sql_u64(expected_revision)?,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_continuation_ledger:{}", ledger.id),
                expected_revision,
            });
        }
        insert_context_continuation_entry(&transaction, ledger, entry)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            Some(ledger.mission_id.as_str()),
            "context_continuation_ledger",
            ledger.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: ledger.revision,
        })
    }

    /// Commits summary provenance and the resume closure together. A crash can
    /// expose neither record or both; it cannot leave an uncheckpointed summary.
    pub fn append_context_compaction_checkpoint(
        &mut self,
        compaction: &ContextCompactionRecord,
        checkpoint: &ContextCheckpoint,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let workspace =
            self.load_context_workspace(&compaction.project_id, &compaction.workspace_id)?;
        let mission = self.load_mission(&compaction.project_id, &compaction.mission_id)?;
        let truth_facts = self.load_current_truth_facts_for_project(&compaction.project_id)?;
        let working_set =
            self.load_context_working_set(&checkpoint.project_id, &checkpoint.working_set_id)?;
        let continuation = self.load_context_continuation_ledger(
            &checkpoint.project_id,
            &checkpoint.continuation_ledger_id,
        )?;
        let previous_compaction =
            self.load_latest_context_compaction(&compaction.project_id, &compaction.workspace_id)?;
        let previous_checkpoint =
            self.load_latest_context_checkpoint(&checkpoint.project_id, &checkpoint.workspace_id)?;
        compaction.validate_for(
            &workspace,
            &mission,
            &truth_facts,
            previous_compaction.as_ref(),
            now,
        )?;
        checkpoint.validate_for(
            &workspace,
            &mission,
            &truth_facts,
            &working_set,
            &continuation,
            compaction,
            previous_checkpoint.as_ref(),
            now,
        )?;

        let transaction = self.connection.transaction()?;
        let persisted_compaction_ordinal = latest_ordinal(
            &transaction,
            "context_compaction_records",
            &compaction.project_id,
            &compaction.workspace_id,
        )?;
        let persisted_checkpoint_ordinal = latest_ordinal(
            &transaction,
            "context_checkpoints",
            &checkpoint.project_id,
            &checkpoint.workspace_id,
        )?;
        if persisted_compaction_ordinal.checked_add(1) != Some(compaction.ordinal)
            || persisted_checkpoint_ordinal.checked_add(1) != Some(checkpoint.ordinal)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_checkpoint:{}", checkpoint.workspace_id),
                expected_revision: checkpoint.ordinal.saturating_sub(1),
            });
        }
        insert_context_compaction(&transaction, compaction)?;
        insert_context_checkpoint(&transaction, checkpoint)?;
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            checkpoint.tenant_id.as_str(),
            checkpoint.project_id.as_str(),
            Some(checkpoint.mission_id.as_str()),
            "context_checkpoint",
            checkpoint.id.as_str(),
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: checkpoint.ordinal,
        })
    }

    pub fn load_context_working_set(
        &self,
        project_id: &ProjectId,
        working_set_id: &ContextWorkingSetId,
    ) -> Result<ContextWorkingSet, StorageError> {
        let value: ContextWorkingSet = load_record(
            &self.connection,
            "SELECT record_json FROM context_working_sets WHERE project_id = ?1 AND id = ?2",
            project_id,
            working_set_id.as_str(),
            "context working set",
        )?;
        let projected = load_context_working_items(&self.connection, project_id, working_set_id)?;
        if value.items != projected {
            return Err(StorageError::DomainDecode(
                "context working-set item projection does not match its CAS header".into(),
            ));
        }
        Ok(value)
    }

    pub fn load_context_continuation_ledger(
        &self,
        project_id: &ProjectId,
        ledger_id: &ContextContinuationLedgerId,
    ) -> Result<ContinuationLedger, StorageError> {
        let value: ContinuationLedger = load_record(
            &self.connection,
            "SELECT record_json FROM context_continuation_ledgers
             WHERE project_id = ?1 AND id = ?2",
            project_id,
            ledger_id.as_str(),
            "context continuation ledger",
        )?;
        let projected = load_context_continuation_entries(&self.connection, project_id, ledger_id)?;
        if value.entries != projected {
            return Err(StorageError::DomainDecode(
                "continuation entry projection does not match append-only ledger".into(),
            ));
        }
        Ok(value)
    }

    pub fn load_latest_context_compaction(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
    ) -> Result<Option<ContextCompactionRecord>, StorageError> {
        load_optional_record(
            &self.connection,
            "SELECT record_json FROM context_compaction_records
             WHERE project_id = ?1 AND workspace_id = ?2 ORDER BY ordinal DESC LIMIT 1",
            project_id,
            workspace_id.as_str(),
        )
    }

    pub fn load_latest_context_checkpoint(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
    ) -> Result<Option<ContextCheckpoint>, StorageError> {
        load_optional_record(
            &self.connection,
            "SELECT record_json FROM context_checkpoints
             WHERE project_id = ?1 AND workspace_id = ?2 ORDER BY ordinal DESC LIMIT 1",
            project_id,
            workspace_id.as_str(),
        )
    }

    pub fn load_context_compaction(
        &self,
        project_id: &ProjectId,
        id: &ContextCompactionRecordId,
    ) -> Result<ContextCompactionRecord, StorageError> {
        load_record(
            &self.connection,
            "SELECT record_json FROM context_compaction_records WHERE project_id = ?1 AND id = ?2",
            project_id,
            id.as_str(),
            "context compaction record",
        )
    }

    pub fn load_context_checkpoint(
        &self,
        project_id: &ProjectId,
        id: &ContextCheckpointId,
    ) -> Result<ContextCheckpoint, StorageError> {
        load_record(
            &self.connection,
            "SELECT record_json FROM context_checkpoints WHERE project_id = ?1 AND id = ?2",
            project_id,
            id.as_str(),
            "context checkpoint",
        )
    }

    pub fn load_current_truth_facts_for_project(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<TruthFact>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM truth_fact_heads WHERE project_id = ?1 ORDER BY id ASC")?;
        let ids = statement
            .query_map([project_id.as_str()], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|id| {
                self.load_truth_fact(project_id, &hartevo_domain_kernel::FactId::from_stable(id))
            })
            .collect()
    }

    pub fn load_context_foundation_snapshot(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
        sync_version: u64,
        now: DateTime<Utc>,
    ) -> Result<ContextFoundationSnapshot, StorageError> {
        let workspace = self.load_context_workspace(project_id, workspace_id)?;
        let mission = self.load_mission(project_id, &workspace.mission_id)?;
        let (working_set_id, ledger_id) =
            self.load_context_foundation_ids(project_id, workspace_id)?;
        let working_set = self.load_context_working_set(project_id, &working_set_id)?;
        let continuation_ledger = self.load_context_continuation_ledger(project_id, &ledger_id)?;
        let compaction = self
            .load_latest_context_compaction(project_id, workspace_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "context compaction record",
                project_id: project_id.clone(),
                id: workspace_id.to_string(),
            })?;
        let checkpoint = self
            .load_latest_context_checkpoint(project_id, workspace_id)?
            .ok_or_else(|| StorageError::ScopedRecordNotFound {
                kind: "context checkpoint",
                project_id: project_id.clone(),
                id: workspace_id.to_string(),
            })?;
        let truth_facts = self.load_current_truth_facts_for_project(project_id)?;
        let previous_compaction = if compaction.ordinal > 1 {
            self.load_context_compaction_by_ordinal(
                project_id,
                workspace_id,
                compaction.ordinal - 1,
            )?
        } else {
            None
        };
        let previous_checkpoint = if checkpoint.ordinal > 1 {
            self.load_context_checkpoint_by_ordinal(
                project_id,
                workspace_id,
                checkpoint.ordinal - 1,
            )?
        } else {
            None
        };
        let snapshot = ContextFoundationSnapshot {
            sync_version,
            workspace,
            working_set,
            continuation_ledger,
            compaction,
            checkpoint,
            truth_facts,
        };
        snapshot.validate_for(
            &mission,
            previous_compaction.as_ref(),
            previous_checkpoint.as_ref(),
            now,
        )?;
        Ok(snapshot)
    }

    pub fn load_context_compaction_by_ordinal(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
        ordinal: u64,
    ) -> Result<Option<ContextCompactionRecord>, StorageError> {
        load_optional_record_with_ordinal(
            &self.connection,
            "SELECT record_json FROM context_compaction_records
             WHERE project_id = ?1 AND workspace_id = ?2 AND ordinal = ?3",
            project_id,
            workspace_id,
            ordinal,
        )
    }

    pub fn load_context_checkpoint_by_ordinal(
        &self,
        project_id: &ProjectId,
        workspace_id: &ContextWorkspaceId,
        ordinal: u64,
    ) -> Result<Option<ContextCheckpoint>, StorageError> {
        load_optional_record_with_ordinal(
            &self.connection,
            "SELECT record_json FROM context_checkpoints
             WHERE project_id = ?1 AND workspace_id = ?2 AND ordinal = ?3",
            project_id,
            workspace_id,
            ordinal,
        )
    }
}

pub(crate) fn insert_context_working_set(
    transaction: &Transaction<'_>,
    working_set: &ContextWorkingSet,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_working_sets
           (tenant_id, project_id, id, mission_id, workspace_id, generation,
            revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            working_set.tenant_id.as_str(),
            working_set.project_id.as_str(),
            working_set.id.as_str(),
            working_set.mission_id.as_str(),
            working_set.workspace_id.as_str(),
            to_sql_u64(working_set.generation)?,
            to_sql_u64(working_set.revision)?,
            working_set.created_at.to_rfc3339(),
            working_set.updated_at.to_rfc3339(),
            serde_json::to_string(working_set)?,
        ],
    )?;
    insert_context_working_items(transaction, working_set)
}

pub(crate) fn insert_context_continuation_ledger(
    transaction: &Transaction<'_>,
    ledger: &ContinuationLedger,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_continuation_ledgers
           (tenant_id, project_id, id, mission_id, workspace_id, generation,
            revision, created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            ledger.id.as_str(),
            ledger.mission_id.as_str(),
            ledger.workspace_id.as_str(),
            to_sql_u64(ledger.generation)?,
            to_sql_u64(ledger.revision)?,
            ledger.created_at.to_rfc3339(),
            ledger.updated_at.to_rfc3339(),
            serde_json::to_string(ledger)?,
        ],
    )?;
    for entry in &ledger.entries {
        insert_context_continuation_entry(transaction, ledger, entry)?;
    }
    Ok(())
}

fn insert_context_working_items(
    transaction: &Transaction<'_>,
    working_set: &ContextWorkingSet,
) -> Result<(), StorageError> {
    for item in working_set.items.values() {
        transaction.execute(
            "INSERT INTO context_working_items
               (tenant_id, project_id, working_set_id, item_key, item_kind,
                storage_ref, content_digest, byte_len, classification,
                provenance_digest, expires_at, created_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                working_set.tenant_id.as_str(),
                working_set.project_id.as_str(),
                working_set.id.as_str(),
                item.key,
                serde_json::to_value(item.kind)?.as_str().ok_or_else(|| {
                    StorageError::DomainDecode("working item kind is not a string".into())
                })?,
                item.storage_ref,
                item.content_digest,
                to_sql_u64(item.byte_len)?,
                serde_json::to_value(item.classification)?
                    .as_str()
                    .ok_or_else(|| StorageError::DomainDecode(
                        "data class is not a string".into()
                    ))?,
                item.provenance_digest,
                item.expires_at.map(|value| value.to_rfc3339()),
                item.created_at.to_rfc3339(),
                serde_json::to_string(item)?,
            ],
        )?;
    }
    Ok(())
}

fn insert_context_continuation_entry(
    transaction: &Transaction<'_>,
    ledger: &ContinuationLedger,
    entry: &ContinuationEntry,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_continuation_entries
           (tenant_id, project_id, ledger_id, sequence, mission_revision,
            entry_kind, subject_id, payload_ref, payload_digest, recorded_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            ledger.tenant_id.as_str(),
            ledger.project_id.as_str(),
            ledger.id.as_str(),
            to_sql_u64(entry.sequence)?,
            to_sql_u64(entry.mission_revision)?,
            serde_json::to_value(entry.kind)?
                .as_str()
                .ok_or_else(|| StorageError::DomainDecode("entry kind is not a string".into()))?,
            entry.subject_id,
            entry.payload_ref,
            entry.payload_digest,
            entry.recorded_at.to_rfc3339(),
            serde_json::to_string(entry)?,
        ],
    )?;
    Ok(())
}

fn insert_context_compaction(
    transaction: &Transaction<'_>,
    value: &ContextCompactionRecord,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_compaction_records
           (tenant_id, project_id, id, mission_id, workspace_id, generation,
            ordinal, source_first_sequence, source_last_sequence, retained_tail_start,
            source_trace_digest, summary_digest, invariant_digest, created_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            value.tenant_id.as_str(),
            value.project_id.as_str(),
            value.id.as_str(),
            value.mission_id.as_str(),
            value.workspace_id.as_str(),
            to_sql_u64(value.generation)?,
            to_sql_u64(value.ordinal)?,
            to_sql_u64(value.source_first_sequence)?,
            to_sql_u64(value.source_last_sequence)?,
            to_sql_u64(value.retained_tail_start)?,
            value.source_trace_digest,
            value.summary_digest,
            value.invariant_digest,
            value.created_at.to_rfc3339(),
            serde_json::to_string(value)?,
        ],
    )?;
    Ok(())
}

fn insert_context_checkpoint(
    transaction: &Transaction<'_>,
    value: &ContextCheckpoint,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO context_checkpoints
           (tenant_id, project_id, id, mission_id, workspace_id, generation,
            ordinal, previous_checkpoint_id, mission_revision, working_set_id,
            working_set_revision, continuation_ledger_id, continuation_ledger_revision,
            compaction_record_id, compaction_ordinal, invariant_digest,
            worker_graph_digest, resume_cursor_digest, trace_tail_sequence, created_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
        params![
            value.tenant_id.as_str(),
            value.project_id.as_str(),
            value.id.as_str(),
            value.mission_id.as_str(),
            value.workspace_id.as_str(),
            to_sql_u64(value.generation)?,
            to_sql_u64(value.ordinal)?,
            value
                .previous_checkpoint_id
                .as_ref()
                .map(ContextCheckpointId::as_str),
            to_sql_u64(value.mission_revision)?,
            value.working_set_id.as_str(),
            to_sql_u64(value.working_set_revision)?,
            value.continuation_ledger_id.as_str(),
            to_sql_u64(value.continuation_ledger_revision)?,
            value.compaction_record_id.as_str(),
            to_sql_u64(value.compaction_ordinal)?,
            value.invariant_digest,
            value.worker_graph_digest,
            value.resume_cursor_digest,
            to_sql_u64(value.trace_tail_sequence)?,
            value.created_at.to_rfc3339(),
            serde_json::to_string(value)?,
        ],
    )?;
    Ok(())
}

fn load_context_working_items(
    connection: &Connection,
    project_id: &ProjectId,
    working_set_id: &ContextWorkingSetId,
) -> Result<std::collections::BTreeMap<String, ContextWorkingItem>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT record_json FROM context_working_items
         WHERE project_id = ?1 AND working_set_id = ?2 ORDER BY item_key ASC",
    )?;
    let rows = statement.query_map(
        params![project_id.as_str(), working_set_id.as_str()],
        |row| row.get::<_, String>(0),
    )?;
    rows.map(|row| {
        let item: ContextWorkingItem = serde_json::from_str(&row?)?;
        Ok((item.key.clone(), item))
    })
    .collect()
}

fn load_context_continuation_entries(
    connection: &Connection,
    project_id: &ProjectId,
    ledger_id: &ContextContinuationLedgerId,
) -> Result<Vec<ContinuationEntry>, StorageError> {
    let mut statement = connection.prepare(
        "SELECT record_json FROM context_continuation_entries
         WHERE project_id = ?1 AND ledger_id = ?2 ORDER BY sequence ASC",
    )?;
    let rows = statement.query_map(params![project_id.as_str(), ledger_id.as_str()], |row| {
        row.get::<_, String>(0)
    })?;
    rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

fn latest_ordinal(
    transaction: &Transaction<'_>,
    table: &str,
    project_id: &ProjectId,
    workspace_id: &ContextWorkspaceId,
) -> Result<u64, StorageError> {
    let sql = match table {
        "context_compaction_records" => {
            "SELECT COALESCE(MAX(ordinal), 0) FROM context_compaction_records
             WHERE project_id = ?1 AND workspace_id = ?2"
        }
        "context_checkpoints" => {
            "SELECT COALESCE(MAX(ordinal), 0) FROM context_checkpoints
             WHERE project_id = ?1 AND workspace_id = ?2"
        }
        _ => {
            return Err(StorageError::DomainDecode(
                "unsupported context ledger".into(),
            ));
        }
    };
    let value = transaction.query_row(
        sql,
        params![project_id.as_str(), workspace_id.as_str()],
        |row| row.get::<_, i64>(0),
    )?;
    from_sql_u64(value, "context ordinal")
}

fn load_record<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    id: &str,
    kind: &'static str,
) -> Result<T, StorageError> {
    load_optional_record(connection, sql, project_id, id)?.ok_or_else(|| {
        StorageError::ScopedRecordNotFound {
            kind,
            project_id: project_id.clone(),
            id: id.to_owned(),
        }
    })
}

fn load_optional_record<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    id: &str,
) -> Result<Option<T>, StorageError> {
    let value = connection
        .query_row(sql, params![project_id.as_str(), id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    value
        .map(|record| serde_json::from_str(&record))
        .transpose()
        .map_err(StorageError::from)
}

fn load_optional_record_with_ordinal<T: serde::de::DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    project_id: &ProjectId,
    workspace_id: &ContextWorkspaceId,
    ordinal: u64,
) -> Result<Option<T>, StorageError> {
    let value = connection
        .query_row(
            sql,
            params![
                project_id.as_str(),
                workspace_id.as_str(),
                to_sql_u64(ordinal)?
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    value
        .map(|record| serde_json::from_str(&record))
        .transpose()
        .map_err(StorageError::from)
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("invalid {field}: {value}")))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ContextBudget, ContextCheckpointId, ContextCompactionRecordId, ContextContinuationLedgerId,
        ContextDataPolicy, ContextWorkingSetId, ContextWorkspace, CurrencyCode, Mission, MissionId,
        Money, OperatingContract, Project, StorageMode, TenantId,
    };

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the failure-injection test keeps setup, rollback proof, and successful replay in one atomicity narrative"
    )]
    fn checkpoint_insert_failure_rolls_back_the_compaction_and_events() {
        let tenant_id = TenantId::from("tenant-context-atomicity");
        let project = Project::create_local(
            tenant_id.clone(),
            ProjectId::from("project-context-atomicity"),
            "Context atomicity",
            "",
            "/tmp/project-context-atomicity",
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            tenant_id,
            MissionId::from("mission-context-atomicity"),
            project.id.clone(),
            "Context atomicity",
            OperatingContract::bootstrap(
                "Preserve authoritative context",
                ["market.analyze".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-atomicity"),
            &mission,
            1,
            "context-policy/v1",
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 10_000,
                cost_limit: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::days(1),
                max_depth: 4,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-context-atomicity"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation-context-atomicity"),
            &workspace,
            now(),
        )
        .expect("continuation");

        let mut store = ProjectStore::in_memory().expect("store");
        store.save_project(&project).expect("persist project");
        store.save_mission(&mission).expect("persist mission");
        store
            .create_context_workspace(
                &workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.workspace_created",
                    serde_json::json!({"workspaceId": workspace.id}),
                    now(),
                )],
                now(),
            )
            .expect("persist foundation");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-context-atomicity"),
            &workspace,
            &mission,
            &[],
            None,
            1,
            100,
            "1".repeat(64),
            4_000,
            90,
            format!("cas://{}", "2".repeat(64)),
            "3".repeat(64),
            1_024,
            500,
            BTreeSet::new(),
            "4".repeat(64),
            "5".repeat(64),
            "6".repeat(64),
            now() + Duration::seconds(1),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-context-atomicity"),
            &workspace,
            &mission,
            &[],
            &working_set,
            &continuation,
            &compaction,
            None,
            "7".repeat(64),
            "8".repeat(64),
            100,
            now() + Duration::seconds(2),
        )
        .expect("checkpoint");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_context_checkpoint_failure
                 BEFORE INSERT ON context_checkpoints
                 BEGIN
                   SELECT RAISE(ABORT, 'injected checkpoint crash gap');
                 END;",
            )
            .expect("failure trigger");
        let event_count_before: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row.get(0))
            .expect("event count");
        assert!(
            store
                .append_context_compaction_checkpoint(
                    &compaction,
                    &checkpoint,
                    &[PendingEvent::new(
                        "context.checkpoint_recorded",
                        serde_json::json!({"checkpointId": checkpoint.id}),
                        now() + Duration::seconds(2),
                    )],
                    now() + Duration::seconds(2),
                )
                .is_err()
        );
        let persisted: (i64, i64, i64) = store
            .connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM context_compaction_records),
                   (SELECT COUNT(*) FROM context_checkpoints),
                   (SELECT COUNT(*) FROM domain_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("rollback counts");
        assert_eq!(persisted, (0, 0, event_count_before));

        store
            .connection
            .execute_batch("DROP TRIGGER inject_context_checkpoint_failure;")
            .expect("remove failure injection");
        store
            .append_context_compaction_checkpoint(
                &compaction,
                &checkpoint,
                &[PendingEvent::new(
                    "context.checkpoint_recorded",
                    serde_json::json!({"checkpointId": checkpoint.id}),
                    now() + Duration::seconds(2),
                )],
                now() + Duration::seconds(2),
            )
            .expect("retry full atomic unit");
        assert_eq!(
            store
                .load_context_foundation_snapshot(
                    &project.id,
                    &workspace.id,
                    1,
                    now() + Duration::seconds(2),
                )
                .expect("closed resume snapshot")
                .checkpoint
                .id,
            checkpoint.id
        );
    }
}
