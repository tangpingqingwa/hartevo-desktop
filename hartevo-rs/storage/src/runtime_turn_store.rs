//! Durable, content-free Runtime turn dispatch and stream evidence.
//!
//! The rendered prompt and Runtime item bodies never cross this module. The
//! encrypted record contains only private Runtime identifiers required for a
//! live resume/interrupt path; Domain Events and Outbox payloads contain only
//! digests and bounded counters.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_context_fabric::ContextAssemblyStatus;
use hartevo_domain_kernel::{
    MissionId, ProjectId, RuntimeRecoveryStatus, RuntimeTurnAttempt, RuntimeTurnAttemptId,
    RuntimeTurnEvidence, RuntimeTurnEvidenceKind, RuntimeTurnPrivateMessage,
    RuntimeTurnPrivateTextDelta, RuntimeTurnRestartDisposition, RuntimeTurnStatus, TenantId,
    WorkerHandleStatus,
};
use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter,
};
use sha2::{Digest, Sha256};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTurnStartupReconciliation {
    pub scanned_attempts: usize,
    pub failed_before_dispatch: usize,
    pub frozen_uncertain: usize,
    pub already_safe: usize,
    pub event_sequences: Vec<i64>,
    pub outbox_sequences: Vec<i64>,
}

impl ProjectStore {
    pub fn insert_runtime_turn_attempt(
        &mut self,
        attempt: &RuntimeTurnAttempt,
    ) -> Result<AtomicMutation, StorageError> {
        attempt.validate()?;
        if attempt.status != RuntimeTurnStatus::Prepared
            || attempt.revision != 1
            || attempt.evidence.len() != 1
        {
            return Err(StorageError::InvalidInitialRevision(attempt.revision));
        }
        match load_runtime_turn_attempt_record(
            &self.connection,
            &attempt.scope.project_id,
            &attempt.id,
        )? {
            Some(stored) if stored == *attempt => {
                return Ok(AtomicMutation {
                    event_sequences: vec![],
                    outbox_sequences: vec![],
                    state_revision: stored.revision,
                });
            }
            Some(_) => {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "runtime turn attempt",
                    id: attempt.id.to_string(),
                });
            }
            None => {}
        }
        self.validate_runtime_turn_scope(attempt)?;
        let record_digest = runtime_turn_record_digest(attempt)?;
        let transaction = self.connection.transaction()?;
        insert_runtime_turn_row(&transaction, attempt, &record_digest)?;
        insert_runtime_turn_evidence(&transaction, attempt, &attempt.evidence[0])?;
        let event = runtime_turn_domain_event(attempt, &attempt.evidence[0], &record_digest);
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            attempt.scope.tenant_id.as_str(),
            attempt.scope.project_id.as_str(),
            Some(attempt.scope.mission_id.as_str()),
            "runtime_turn",
            attempt.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: attempt.revision,
        })
    }

    pub fn update_runtime_turn_attempt(
        &mut self,
        attempt: &RuntimeTurnAttempt,
        expected_revision: u64,
    ) -> Result<AtomicMutation, StorageError> {
        self.persist_runtime_turn_transition(attempt, expected_revision, None, None)
    }

    /// Persists the public, content-free Runtime transition and its private
    /// assistant body in one SQLCipher transaction. A committed turn can
    /// therefore always recover the body that produced its durable evidence.
    pub fn update_runtime_turn_attempt_with_private_message(
        &mut self,
        attempt: &RuntimeTurnAttempt,
        expected_revision: u64,
        message: &RuntimeTurnPrivateMessage,
    ) -> Result<AtomicMutation, StorageError> {
        message.validate_for(attempt)?;
        self.persist_runtime_turn_transition(attempt, expected_revision, Some(message), None)
    }

    /// Persists one public stream-evidence transition and its private text
    /// increment atomically. A Desktop reconnect can therefore resume from a
    /// committed evidence cursor without inventing or losing visible text.
    pub fn update_runtime_turn_attempt_with_private_text_delta(
        &mut self,
        attempt: &RuntimeTurnAttempt,
        expected_revision: u64,
        delta: &RuntimeTurnPrivateTextDelta,
    ) -> Result<AtomicMutation, StorageError> {
        let stored_deltas =
            self.load_runtime_turn_private_text_deltas(&attempt.scope.project_id, &attempt.id)?;
        if let Some(stored) = stored_deltas
            .iter()
            .find(|candidate| candidate.evidence_sequence == delta.evidence_sequence)
        {
            if stored != delta {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "runtime turn private text delta",
                    id: format!("{}:{}", attempt.id, delta.evidence_sequence),
                });
            }
            return self.persist_runtime_turn_transition(
                attempt,
                expected_revision,
                None,
                Some(delta),
            );
        }
        let previous = stored_deltas.into_iter().rfind(|candidate| {
            candidate.item_id_digest == delta.item_id_digest
                && candidate.evidence_sequence < delta.evidence_sequence
        });
        delta.validate_for(attempt, previous.as_ref())?;
        self.persist_runtime_turn_transition(attempt, expected_revision, None, Some(delta))
    }

    fn persist_runtime_turn_transition(
        &mut self,
        attempt: &RuntimeTurnAttempt,
        expected_revision: u64,
        private_message: Option<&RuntimeTurnPrivateMessage>,
        private_text_delta: Option<&RuntimeTurnPrivateTextDelta>,
    ) -> Result<AtomicMutation, StorageError> {
        attempt.validate()?;
        let previous = self.load_runtime_turn_attempt(&attempt.scope.project_id, &attempt.id)?;
        if previous == *attempt {
            if let Some(message) = private_message {
                let stored = self
                    .load_runtime_turn_private_messages(&attempt.scope.project_id, &attempt.id)?
                    .into_iter()
                    .find(|stored| stored.evidence_sequence == message.evidence_sequence);
                if stored.as_ref() != Some(message) {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "runtime turn private message",
                        id: format!("{}:{}", attempt.id, message.evidence_sequence),
                    });
                }
            }
            if let Some(delta) = private_text_delta {
                let stored = self
                    .load_runtime_turn_private_text_deltas(&attempt.scope.project_id, &attempt.id)?
                    .into_iter()
                    .find(|stored| stored.evidence_sequence == delta.evidence_sequence);
                if stored.as_ref() != Some(delta) {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "runtime turn private text delta",
                        id: format!("{}:{}", attempt.id, delta.evidence_sequence),
                    });
                }
            }
            return Ok(AtomicMutation {
                event_sequences: vec![],
                outbox_sequences: vec![],
                state_revision: attempt.revision,
            });
        }
        if previous.revision != expected_revision {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_turn:{}", attempt.id),
                expected_revision,
            });
        }
        attempt.validate_transition_from(&previous)?;
        let evidence = attempt
            .evidence
            .last()
            .ok_or(StorageError::EmptyAtomicEventSet)?;
        let record_digest = runtime_turn_record_digest(attempt)?;
        let transaction = self.connection.transaction()?;
        let changed =
            update_runtime_turn_row(&transaction, attempt, expected_revision, &record_digest)?;
        if changed != 1 {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("runtime_turn:{}", attempt.id),
                expected_revision,
            });
        }
        insert_runtime_turn_evidence(&transaction, attempt, evidence)?;
        if let Some(message) = private_message {
            insert_runtime_turn_private_message(&transaction, message)?;
        }
        if let Some(delta) = private_text_delta {
            insert_runtime_turn_private_text_delta(&transaction, delta)?;
        }
        let event = runtime_turn_domain_event(attempt, evidence, &record_digest);
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            attempt.scope.tenant_id.as_str(),
            attempt.scope.project_id.as_str(),
            Some(attempt.scope.mission_id.as_str()),
            "runtime_turn",
            attempt.id.as_str(),
            &[event],
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: attempt.revision,
        })
    }

    pub fn load_runtime_turn_attempt(
        &self,
        project_id: &ProjectId,
        id: &RuntimeTurnAttemptId,
    ) -> Result<RuntimeTurnAttempt, StorageError> {
        load_runtime_turn_attempt_record(&self.connection, project_id, id)?.ok_or_else(|| {
            StorageError::ScopedRecordNotFound {
                kind: "runtime turn attempt",
                project_id: project_id.clone(),
                id: id.to_string(),
            }
        })
    }

    pub fn load_runtime_turn_private_messages(
        &self,
        project_id: &ProjectId,
        id: &RuntimeTurnAttemptId,
    ) -> Result<Vec<RuntimeTurnPrivateMessage>, StorageError> {
        let attempt = self.load_runtime_turn_attempt(project_id, id)?;
        let mut statement = self.connection.prepare(
            "SELECT tenant_id, project_id, mission_id, runtime_turn_attempt_id,
                    evidence_sequence, worker_generation, item_id_digest, body,
                    body_digest, event_digest, observed_at
             FROM runtime_turn_private_messages
             WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2
             ORDER BY evidence_sequence",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
            ))
        })?;
        let messages = rows
            .map(|row| decode_runtime_turn_private_message(row?))
            .collect::<Result<Vec<_>, StorageError>>()?;
        for message in &messages {
            message.validate_for(&attempt)?;
        }
        Ok(messages)
    }

    pub fn load_runtime_turn_private_text_deltas(
        &self,
        project_id: &ProjectId,
        id: &RuntimeTurnAttemptId,
    ) -> Result<Vec<RuntimeTurnPrivateTextDelta>, StorageError> {
        let attempt = self.load_runtime_turn_attempt(project_id, id)?;
        let mut statement = self.connection.prepare(
            "SELECT tenant_id, project_id, mission_id, runtime_turn_attempt_id,
                    evidence_sequence, stream_sequence, worker_generation,
                    item_id_digest, delta, delta_digest, cumulative_byte_count,
                    chain_digest, event_digest, observed_at
             FROM runtime_turn_private_text_deltas
             WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2
             ORDER BY evidence_sequence",
        )?;
        let rows = statement.query_map(params![project_id.as_str(), id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
            ))
        })?;
        let deltas = rows
            .map(|row| decode_runtime_turn_private_text_delta(row?))
            .collect::<Result<Vec<_>, StorageError>>()?;
        let mut previous_by_item = BTreeMap::<String, RuntimeTurnPrivateTextDelta>::new();
        for delta in &deltas {
            let previous = previous_by_item.get(&delta.item_id_digest);
            delta.validate_for(&attempt, previous)?;
            previous_by_item.insert(delta.item_id_digest.clone(), delta.clone());
        }
        Ok(deltas)
    }

    pub fn load_latest_runtime_turn_private_message(
        &self,
        project_id: &ProjectId,
        id: &RuntimeTurnAttemptId,
    ) -> Result<Option<RuntimeTurnPrivateMessage>, StorageError> {
        Ok(self
            .load_runtime_turn_private_messages(project_id, id)?
            .into_iter()
            .next_back())
    }

    /// Returns the complete, integrity-checked Runtime turn ledger for one
    /// Project. Callers receive Domain records only after every normalized
    /// column, evidence row, and record digest has been revalidated by
    /// `load_runtime_turn_attempt_record`.
    pub fn list_runtime_turn_attempts(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<RuntimeTurnAttempt>, StorageError> {
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT id FROM runtime_turn_attempts
                 WHERE project_id = ?1 ORDER BY updated_at, created_at, id",
            )?;
            statement
                .query_map(params![project_id.as_str()], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        ids.into_iter()
            .map(|id| {
                self.load_runtime_turn_attempt(project_id, &RuntimeTurnAttemptId::from_stable(id))
            })
            .collect()
    }

    pub fn load_active_runtime_turn_for_worker(
        &self,
        project_id: &ProjectId,
        workspace_id: &hartevo_domain_kernel::ContextWorkspaceId,
        worker_id: &hartevo_domain_kernel::WorkerId,
    ) -> Result<Option<RuntimeTurnAttempt>, StorageError> {
        let ids = {
            let mut statement = self.connection.prepare(
                "SELECT id FROM runtime_turn_attempts
                 WHERE project_id = ?1 AND workspace_id = ?2 AND worker_id = ?3
                 ORDER BY created_at, id",
            )?;
            statement
                .query_map(
                    params![
                        project_id.as_str(),
                        workspace_id.as_str(),
                        worker_id.as_str()
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut active = None;
        for id in ids {
            let attempt =
                self.load_runtime_turn_attempt(project_id, &RuntimeTurnAttemptId::from_stable(id))?;
            if !attempt.status.is_active() {
                continue;
            }
            if active.replace(attempt).is_some() {
                return Err(StorageError::DomainDecode(
                    "multiple active runtime turns exist for one worker".into(),
                ));
            }
        }
        Ok(active)
    }

    pub fn reconcile_runtime_turns_after_coordinator_restart(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<RuntimeTurnStartupReconciliation, StorageError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let keys = {
            let mut statement = transaction.prepare(
                "SELECT project_id, id FROM runtime_turn_attempts ORDER BY project_id, id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut report = RuntimeTurnStartupReconciliation {
            scanned_attempts: 0,
            failed_before_dispatch: 0,
            frozen_uncertain: 0,
            already_safe: 0,
            event_sequences: Vec::new(),
            outbox_sequences: Vec::new(),
        };
        for (project_id, attempt_id) in keys {
            let project_id = ProjectId::from_stable(project_id);
            let attempt_id = RuntimeTurnAttemptId::from_stable(attempt_id);
            let mut attempt =
                load_runtime_turn_attempt_record(&transaction, &project_id, &attempt_id)?
                    .ok_or_else(|| StorageError::ScopedRecordNotFound {
                        kind: "runtime turn attempt",
                        project_id: project_id.clone(),
                        id: attempt_id.to_string(),
                    })?;
            report.scanned_attempts = report
                .scanned_attempts
                .checked_add(1)
                .ok_or(StorageError::RevisionOverflow(u64::MAX))?;
            let expected_revision = attempt.revision;
            match attempt.fence_after_coordinator_restart(now)? {
                RuntimeTurnRestartDisposition::AlreadySafe => {
                    report.already_safe = report
                        .already_safe
                        .checked_add(1)
                        .ok_or(StorageError::RevisionOverflow(u64::MAX))?;
                    continue;
                }
                RuntimeTurnRestartDisposition::FailedBeforeDispatch => {
                    report.failed_before_dispatch = report
                        .failed_before_dispatch
                        .checked_add(1)
                        .ok_or(StorageError::RevisionOverflow(u64::MAX))?;
                }
                RuntimeTurnRestartDisposition::FrozenUncertain => {
                    report.frozen_uncertain = report
                        .frozen_uncertain
                        .checked_add(1)
                        .ok_or(StorageError::RevisionOverflow(u64::MAX))?;
                }
            }
            let evidence = attempt
                .evidence
                .last()
                .ok_or(StorageError::EmptyAtomicEventSet)?;
            let record_digest = runtime_turn_record_digest(&attempt)?;
            let changed =
                update_runtime_turn_row(&transaction, &attempt, expected_revision, &record_digest)?;
            if changed != 1 {
                return Err(StorageError::OptimisticConflict {
                    aggregate: format!("runtime_turn:{}", attempt.id),
                    expected_revision,
                });
            }
            insert_runtime_turn_evidence(&transaction, &attempt, evidence)?;
            let event = runtime_turn_domain_event(&attempt, evidence, &record_digest);
            let (event_sequences, outbox_sequences) = append_events(
                &transaction,
                attempt.scope.tenant_id.as_str(),
                attempt.scope.project_id.as_str(),
                Some(attempt.scope.mission_id.as_str()),
                "runtime_turn",
                attempt.id.as_str(),
                &[event],
            )?;
            report.event_sequences.extend(event_sequences);
            report.outbox_sequences.extend(outbox_sequences);
        }
        transaction.commit()?;
        Ok(report)
    }

    fn validate_runtime_turn_scope(
        &self,
        attempt: &RuntimeTurnAttempt,
    ) -> Result<(), StorageError> {
        let scope = &attempt.scope;
        let manifest =
            self.load_context_assembly_manifest(&scope.project_id, &scope.assembly_id)?;
        manifest.validate_dispatchable()?;
        self.validate_context_assembly_scope(&manifest)?;
        let capsule = self.load_context_capsule(&scope.project_id, &scope.capsule_id)?;
        let branch = self.load_context_branch(&scope.project_id, &scope.branch_id)?;
        let lease = self.load_worker_lease(&scope.project_id, &scope.worker_lease_id)?;
        let checkpoint = self.load_context_checkpoint(&scope.project_id, &scope.checkpoint_id)?;
        let handle =
            self.load_worker_handle(&scope.project_id, &scope.workspace_id, &scope.worker_id)?;
        let recovery = self.load_runtime_recovery(&scope.project_id, &scope.recovery_id)?;
        recovery.validate_for(&handle, &checkpoint, attempt.created_at)?;
        if manifest.status != ContextAssemblyStatus::Ready
            || manifest.revision != scope.assembly_revision
            || manifest.digest()? != scope.assembly_manifest_digest
            || manifest.input_digest != scope.assembly_input_digest
            || manifest.prompt_digest.as_deref() != Some(scope.prompt_digest.as_str())
            || manifest.tenant_id != scope.tenant_id
            || manifest.project_id != scope.project_id
            || manifest.mission_id != scope.mission_id
            || manifest.workspace_id != scope.workspace_id
            || manifest.capsule_id != scope.capsule_id
            || manifest.capsule_revision != scope.capsule_revision
            || manifest.capsule_authority_digest != scope.capsule_authority_digest
            || manifest.branch_id != scope.branch_id
            || manifest.branch_revision != scope.branch_revision
            || manifest.worker_id != scope.worker_id
            || manifest.worker_generation != scope.worker_generation
            || manifest.worker_lease_id != scope.worker_lease_id
            || manifest.worker_lease_revision != scope.worker_lease_revision
            || manifest.checkpoint_id != scope.checkpoint_id
            || manifest.checkpoint_digest != scope.checkpoint_digest
            || capsule.revision != scope.capsule_revision
            || capsule.authority_digest != scope.capsule_authority_digest
            || branch.revision != scope.branch_revision
            || lease.revision != scope.worker_lease_revision
            || handle.status != WorkerHandleStatus::Attached
            || handle.generation != scope.worker_generation
            || handle.attachment_epoch != scope.attachment_epoch
            || handle.runtime_mapping_digest.as_deref()
                != Some(scope.runtime_mapping_digest.as_str())
            || recovery.status != RuntimeRecoveryStatus::Attached
            || recovery.revision != scope.recovery_revision
            || recovery.tenant_id != scope.tenant_id
            || recovery.mission_id != scope.mission_id
            || recovery.workspace_id != scope.workspace_id
            || recovery.worker_id != scope.worker_id
            || recovery.worker_generation != scope.worker_generation
            || recovery.target_attachment_epoch != scope.attachment_epoch
            || recovery.checkpoint_id != scope.checkpoint_id
            || recovery.checkpoint_digest != scope.checkpoint_digest
            || recovery.runtime_instance_digest.as_deref()
                != Some(scope.runtime_instance_digest.as_str())
            || recovery.runtime_mapping_digest.as_deref()
                != Some(scope.runtime_mapping_digest.as_str())
            || recovery.runtime_thread_id.as_deref() != Some(scope.runtime_thread_id.as_str())
            || attempt.created_at < manifest.created_at
            || attempt.created_at < recovery.updated_at
            || attempt.created_at > capsule.expires_at
            || attempt.created_at > lease.expires_at
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "runtime turn authority closure",
                id: attempt.id.to_string(),
            });
        }
        Ok(())
    }
}

fn insert_runtime_turn_row(
    transaction: &Transaction<'_>,
    attempt: &RuntimeTurnAttempt,
    record_digest: &str,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_turn_attempts
           (tenant_id, project_id, id, mission_id, workspace_id, capsule_id,
            capsule_revision, capsule_authority_digest, branch_id, branch_revision,
            worker_id, worker_generation, worker_lease_id, worker_lease_revision,
            attachment_epoch, assembly_id, assembly_revision, assembly_manifest_digest,
            assembly_input_digest, prompt_digest, checkpoint_id, checkpoint_digest,
            recovery_id, recovery_revision, runtime_instance_digest, runtime_mapping_digest,
            runtime_thread_id_digest, runtime_turn_id_digest, dispatch_request_digest,
            dispatch_response_digest, pending_approval_request_digest,
            approval_decision_digest, interrupt_request_digest, failure_count,
            evidence_count, status, revision, created_at, updated_at, record_digest, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                 ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
                 ?39, ?40, ?41)",
        params_from_iter(runtime_turn_params(attempt, record_digest)?),
    )?;
    Ok(())
}

fn update_runtime_turn_row(
    transaction: &Transaction<'_>,
    attempt: &RuntimeTurnAttempt,
    expected_revision: u64,
    record_digest: &str,
) -> Result<usize, StorageError> {
    Ok(transaction.execute(
        "UPDATE runtime_turn_attempts SET
           runtime_turn_id_digest = ?1, dispatch_request_digest = ?2,
           dispatch_response_digest = ?3, pending_approval_request_digest = ?4,
           approval_decision_digest = ?5, interrupt_request_digest = ?6,
           failure_count = ?7, evidence_count = ?8, status = ?9, revision = ?10,
           updated_at = ?11, record_digest = ?12, record_json = ?13
         WHERE project_id = ?14 AND id = ?15 AND revision = ?16",
        params![
            attempt.runtime_turn_id_digest,
            attempt.dispatch_request_digest,
            attempt.dispatch_response_digest,
            attempt.pending_approval_request_digest,
            attempt.approval_decision_digest,
            attempt.interrupt_request_digest,
            to_sql_usize(attempt.failures.len())?,
            to_sql_usize(attempt.evidence.len())?,
            status_text(attempt.status),
            to_sql_u64(attempt.revision)?,
            attempt.updated_at.to_rfc3339(),
            record_digest,
            serde_json::to_string(attempt)?,
            attempt.scope.project_id.as_str(),
            attempt.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?)
}

fn runtime_turn_params<'a>(
    attempt: &'a RuntimeTurnAttempt,
    record_digest: &'a str,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    let scope = &attempt.scope;
    Ok(vec![
        scope.tenant_id.as_str().to_owned().into(),
        scope.project_id.as_str().to_owned().into(),
        attempt.id.as_str().to_owned().into(),
        scope.mission_id.as_str().to_owned().into(),
        scope.workspace_id.as_str().to_owned().into(),
        scope.capsule_id.as_str().to_owned().into(),
        to_sql_u64(scope.capsule_revision)?.into(),
        scope.capsule_authority_digest.clone().into(),
        scope.branch_id.as_str().to_owned().into(),
        to_sql_u64(scope.branch_revision)?.into(),
        scope.worker_id.as_str().to_owned().into(),
        to_sql_u64(scope.worker_generation)?.into(),
        scope.worker_lease_id.as_str().to_owned().into(),
        to_sql_u64(scope.worker_lease_revision)?.into(),
        to_sql_u64(scope.attachment_epoch)?.into(),
        scope.assembly_id.as_str().to_owned().into(),
        to_sql_u64(scope.assembly_revision)?.into(),
        scope.assembly_manifest_digest.clone().into(),
        scope.assembly_input_digest.clone().into(),
        scope.prompt_digest.clone().into(),
        scope.checkpoint_id.as_str().to_owned().into(),
        scope.checkpoint_digest.clone().into(),
        scope.recovery_id.as_str().to_owned().into(),
        to_sql_u64(scope.recovery_revision)?.into(),
        scope.runtime_instance_digest.clone().into(),
        scope.runtime_mapping_digest.clone().into(),
        scope.runtime_thread_id_digest.clone().into(),
        attempt.runtime_turn_id_digest.clone().into(),
        attempt.dispatch_request_digest.clone().into(),
        attempt.dispatch_response_digest.clone().into(),
        attempt.pending_approval_request_digest.clone().into(),
        attempt.approval_decision_digest.clone().into(),
        attempt.interrupt_request_digest.clone().into(),
        to_sql_usize(attempt.failures.len())?.into(),
        to_sql_usize(attempt.evidence.len())?.into(),
        status_text(attempt.status).to_owned().into(),
        to_sql_u64(attempt.revision)?.into(),
        attempt.created_at.to_rfc3339().into(),
        attempt.updated_at.to_rfc3339().into(),
        record_digest.to_owned().into(),
        serde_json::to_string(attempt)?.into(),
    ])
}

fn insert_runtime_turn_evidence(
    transaction: &Transaction<'_>,
    attempt: &RuntimeTurnAttempt,
    evidence: &RuntimeTurnEvidence,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_turn_evidence
           (tenant_id, project_id, runtime_turn_attempt_id, sequence, evidence_kind,
            evidence_digest, resulting_status, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            attempt.scope.tenant_id.as_str(),
            attempt.scope.project_id.as_str(),
            attempt.id.as_str(),
            to_sql_u64(evidence.sequence)?,
            evidence_kind_text(evidence.kind),
            evidence.evidence_digest,
            status_text(evidence.resulting_status),
            evidence.observed_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn insert_runtime_turn_private_message(
    transaction: &Transaction<'_>,
    message: &RuntimeTurnPrivateMessage,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_turn_private_messages
           (tenant_id, project_id, mission_id, runtime_turn_attempt_id,
            evidence_sequence, worker_generation, item_id_digest, body,
            body_digest, event_digest, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            message.tenant_id.as_str(),
            message.project_id.as_str(),
            message.mission_id.as_str(),
            message.runtime_turn_attempt_id.as_str(),
            to_sql_u64(message.evidence_sequence)?,
            to_sql_u64(message.worker_generation)?,
            message.item_id_digest,
            message.body,
            message.body_digest,
            message.event_digest,
            message.observed_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn insert_runtime_turn_private_text_delta(
    transaction: &Transaction<'_>,
    delta: &RuntimeTurnPrivateTextDelta,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_turn_private_text_deltas
           (tenant_id, project_id, mission_id, runtime_turn_attempt_id,
            evidence_sequence, stream_sequence, worker_generation,
            item_id_digest, delta, delta_digest, cumulative_byte_count,
            chain_digest, event_digest, observed_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            delta.tenant_id.as_str(),
            delta.project_id.as_str(),
            delta.mission_id.as_str(),
            delta.runtime_turn_attempt_id.as_str(),
            to_sql_u64(delta.evidence_sequence)?,
            to_sql_u64(delta.stream_sequence)?,
            to_sql_u64(delta.worker_generation)?,
            delta.item_id_digest,
            delta.delta,
            delta.delta_digest,
            to_sql_u64(delta.cumulative_byte_count)?,
            delta.chain_digest,
            delta.event_digest,
            delta.observed_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

type RuntimeTurnPrivateMessageRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
);

fn decode_runtime_turn_private_message(
    row: RuntimeTurnPrivateMessageRow,
) -> Result<RuntimeTurnPrivateMessage, StorageError> {
    Ok(RuntimeTurnPrivateMessage {
        tenant_id: TenantId::from_stable(row.0),
        project_id: ProjectId::from_stable(row.1),
        mission_id: MissionId::from_stable(row.2),
        runtime_turn_attempt_id: RuntimeTurnAttemptId::from_stable(row.3),
        evidence_sequence: u64::try_from(row.4).map_err(|_| {
            StorageError::DomainDecode("negative Runtime private message sequence".into())
        })?,
        worker_generation: u64::try_from(row.5).map_err(|_| {
            StorageError::DomainDecode("negative Runtime private message generation".into())
        })?,
        item_id_digest: row.6,
        body: row.7,
        body_digest: row.8,
        event_digest: row.9,
        observed_at: DateTime::parse_from_rfc3339(&row.10)?.with_timezone(&Utc),
    })
}

type RuntimeTurnPrivateTextDeltaRow = (
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
);

fn decode_runtime_turn_private_text_delta(
    row: RuntimeTurnPrivateTextDeltaRow,
) -> Result<RuntimeTurnPrivateTextDelta, StorageError> {
    Ok(RuntimeTurnPrivateTextDelta {
        tenant_id: TenantId::from_stable(row.0),
        project_id: ProjectId::from_stable(row.1),
        mission_id: MissionId::from_stable(row.2),
        runtime_turn_attempt_id: RuntimeTurnAttemptId::from_stable(row.3),
        evidence_sequence: u64::try_from(row.4).map_err(|_| {
            StorageError::DomainDecode("negative Runtime delta evidence sequence".into())
        })?,
        stream_sequence: u64::try_from(row.5).map_err(|_| {
            StorageError::DomainDecode("negative Runtime delta stream sequence".into())
        })?,
        worker_generation: u64::try_from(row.6)
            .map_err(|_| StorageError::DomainDecode("negative Runtime delta generation".into()))?,
        item_id_digest: row.7,
        delta: row.8,
        delta_digest: row.9,
        cumulative_byte_count: u64::try_from(row.10)
            .map_err(|_| StorageError::DomainDecode("negative Runtime delta byte count".into()))?,
        chain_digest: row.11,
        event_digest: row.12,
        observed_at: DateTime::parse_from_rfc3339(&row.13)?.with_timezone(&Utc),
    })
}

fn runtime_turn_domain_event(
    attempt: &RuntimeTurnAttempt,
    evidence: &RuntimeTurnEvidence,
    record_digest: &str,
) -> PendingEvent {
    PendingEvent::new(
        format!("context.runtime_turn_{}", evidence_kind_text(evidence.kind)),
        serde_json::json!({
            "runtimeTurnAttemptId": attempt.id,
            "workspaceId": attempt.scope.workspace_id,
            "capsuleId": attempt.scope.capsule_id,
            "workerId": attempt.scope.worker_id,
            "workerGeneration": attempt.scope.worker_generation,
            "attachmentEpoch": attempt.scope.attachment_epoch,
            "assemblyId": attempt.scope.assembly_id,
            "assemblyManifestDigest": attempt.scope.assembly_manifest_digest,
            "checkpointId": attempt.scope.checkpoint_id,
            "checkpointDigest": attempt.scope.checkpoint_digest,
            "recoveryId": attempt.scope.recovery_id,
            "runtimeInstanceDigest": attempt.scope.runtime_instance_digest,
            "runtimeMappingDigest": attempt.scope.runtime_mapping_digest,
            "runtimeThreadIdDigest": attempt.scope.runtime_thread_id_digest,
            "runtimeTurnIdDigest": attempt.runtime_turn_id_digest,
            "evidenceSequence": evidence.sequence,
            "evidenceKind": evidence.kind,
            "evidenceDigest": evidence.evidence_digest,
            "status": attempt.status,
            "revision": attempt.revision,
            "failureCount": attempt.failures.len(),
            "recordDigest": record_digest,
        }),
        evidence.observed_at,
    )
}

fn load_runtime_turn_attempt_record(
    connection: &Connection,
    project_id: &ProjectId,
    id: &RuntimeTurnAttemptId,
) -> Result<Option<RuntimeTurnAttempt>, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, project_id, id, mission_id, workspace_id, capsule_id,
                    capsule_revision, capsule_authority_digest, branch_id, branch_revision,
                    worker_id, worker_generation, worker_lease_id, worker_lease_revision,
                    attachment_epoch, assembly_id, assembly_revision,
                    assembly_manifest_digest, assembly_input_digest, prompt_digest,
                    checkpoint_id, checkpoint_digest, recovery_id, recovery_revision,
                    runtime_instance_digest, runtime_mapping_digest, runtime_thread_id_digest,
                    runtime_turn_id_digest, dispatch_request_digest, dispatch_response_digest,
                    pending_approval_request_digest, approval_decision_digest,
                    interrupt_request_digest, failure_count, evidence_count, status, revision,
                    created_at, updated_at, record_digest, record_json
             FROM runtime_turn_attempts
             WHERE project_id = ?1 AND id = ?2",
            params![project_id.as_str(), id.as_str()],
            |row| {
                (0..41)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
            },
        )
        .optional()?;
    let Some(projection) = row else {
        return Ok(None);
    };
    let stored_digest = match projection.get(39) {
        Some(rusqlite::types::Value::Text(value)) => value.clone(),
        _ => {
            return Err(StorageError::DomainDecode(
                "runtime turn record digest projection is invalid".into(),
            ));
        }
    };
    let record = match projection.get(40) {
        Some(rusqlite::types::Value::Text(value)) => value.clone(),
        _ => {
            return Err(StorageError::DomainDecode(
                "runtime turn encrypted record projection is invalid".into(),
            ));
        }
    };
    let attempt: RuntimeTurnAttempt = serde_json::from_str(&record)?;
    attempt.validate()?;
    if runtime_turn_record_digest(&attempt)? != stored_digest {
        return Err(StorageError::DomainDecode(
            "runtime turn attempt digest mismatch".into(),
        ));
    }
    if runtime_turn_params(&attempt, &stored_digest)? != projection {
        return Err(StorageError::DomainDecode(
            "runtime turn normalized projection mismatch".into(),
        ));
    }
    let mut statement = connection.prepare(
        "SELECT sequence, evidence_kind, evidence_digest, resulting_status, observed_at
         FROM runtime_turn_evidence
         WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2 ORDER BY sequence",
    )?;
    let rows = statement.query_map(params![project_id.as_str(), id.as_str()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let normalized = rows
        .map(|row| decode_evidence_row(row?))
        .collect::<Result<Vec<_>, StorageError>>()?;
    if normalized != attempt.evidence {
        return Err(StorageError::DomainDecode(
            "runtime turn evidence projection mismatch".into(),
        ));
    }
    Ok(Some(attempt))
}

fn decode_evidence_row(
    row: (i64, String, String, String, String),
) -> Result<RuntimeTurnEvidence, StorageError> {
    Ok(RuntimeTurnEvidence {
        sequence: u64::try_from(row.0).map_err(|_| {
            StorageError::DomainDecode("negative runtime turn evidence sequence".into())
        })?,
        kind: parse_evidence_kind(&row.1)?,
        evidence_digest: row.2,
        resulting_status: parse_status(&row.3)?,
        observed_at: chrono::DateTime::parse_from_rfc3339(&row.4)
            .map_err(|error| StorageError::DomainDecode(error.to_string()))?
            .with_timezone(&chrono::Utc),
    })
}

fn runtime_turn_record_digest(attempt: &RuntimeTurnAttempt) -> Result<String, StorageError> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(attempt)?)))
}

fn status_text(status: RuntimeTurnStatus) -> &'static str {
    match status {
        RuntimeTurnStatus::Prepared => "prepared",
        RuntimeTurnStatus::Dispatching => "dispatching",
        RuntimeTurnStatus::Running => "running",
        RuntimeTurnStatus::WaitingLocalApproval => "waiting_local_approval",
        RuntimeTurnStatus::ApprovalResponding => "approval_responding",
        RuntimeTurnStatus::InterruptRequested => "interrupt_requested",
        RuntimeTurnStatus::Completed => "completed",
        RuntimeTurnStatus::Interrupted => "interrupted",
        RuntimeTurnStatus::Failed => "failed",
        RuntimeTurnStatus::Uncertain => "uncertain",
    }
}

fn parse_status(value: &str) -> Result<RuntimeTurnStatus, StorageError> {
    match value {
        "prepared" => Ok(RuntimeTurnStatus::Prepared),
        "dispatching" => Ok(RuntimeTurnStatus::Dispatching),
        "running" => Ok(RuntimeTurnStatus::Running),
        "waiting_local_approval" => Ok(RuntimeTurnStatus::WaitingLocalApproval),
        "approval_responding" => Ok(RuntimeTurnStatus::ApprovalResponding),
        "interrupt_requested" => Ok(RuntimeTurnStatus::InterruptRequested),
        "completed" => Ok(RuntimeTurnStatus::Completed),
        "interrupted" => Ok(RuntimeTurnStatus::Interrupted),
        "failed" => Ok(RuntimeTurnStatus::Failed),
        "uncertain" => Ok(RuntimeTurnStatus::Uncertain),
        _ => Err(StorageError::DomainDecode(
            "invalid runtime turn status".into(),
        )),
    }
}

fn evidence_kind_text(kind: RuntimeTurnEvidenceKind) -> &'static str {
    match kind {
        RuntimeTurnEvidenceKind::Prepared => "prepared",
        RuntimeTurnEvidenceKind::DispatchStarted => "dispatch_started",
        RuntimeTurnEvidenceKind::DispatchAccepted => "dispatch_accepted",
        RuntimeTurnEvidenceKind::TurnStarted => "turn_started",
        RuntimeTurnEvidenceKind::ItemStarted => "item_started",
        RuntimeTurnEvidenceKind::AgentMessageDelta => "agent_message_delta",
        RuntimeTurnEvidenceKind::ItemCompleted => "item_completed",
        RuntimeTurnEvidenceKind::Diagnostic => "diagnostic",
        RuntimeTurnEvidenceKind::LocalApprovalRequested => "local_approval_requested",
        RuntimeTurnEvidenceKind::LocalApprovalResponseStarted => "local_approval_response_started",
        RuntimeTurnEvidenceKind::LocalApprovalResponseSent => "local_approval_response_sent",
        RuntimeTurnEvidenceKind::InterruptRequested => "interrupt_requested",
        RuntimeTurnEvidenceKind::InterruptAccepted => "interrupt_accepted",
        RuntimeTurnEvidenceKind::Completed => "completed",
        RuntimeTurnEvidenceKind::Interrupted => "interrupted",
        RuntimeTurnEvidenceKind::Failed => "failed",
        RuntimeTurnEvidenceKind::Uncertain => "uncertain",
    }
}

fn parse_evidence_kind(value: &str) -> Result<RuntimeTurnEvidenceKind, StorageError> {
    match value {
        "prepared" => Ok(RuntimeTurnEvidenceKind::Prepared),
        "dispatch_started" => Ok(RuntimeTurnEvidenceKind::DispatchStarted),
        "dispatch_accepted" => Ok(RuntimeTurnEvidenceKind::DispatchAccepted),
        "turn_started" => Ok(RuntimeTurnEvidenceKind::TurnStarted),
        "item_started" => Ok(RuntimeTurnEvidenceKind::ItemStarted),
        "agent_message_delta" => Ok(RuntimeTurnEvidenceKind::AgentMessageDelta),
        "item_completed" => Ok(RuntimeTurnEvidenceKind::ItemCompleted),
        "diagnostic" => Ok(RuntimeTurnEvidenceKind::Diagnostic),
        "local_approval_requested" => Ok(RuntimeTurnEvidenceKind::LocalApprovalRequested),
        "local_approval_response_started" => {
            Ok(RuntimeTurnEvidenceKind::LocalApprovalResponseStarted)
        }
        "local_approval_response_sent" => Ok(RuntimeTurnEvidenceKind::LocalApprovalResponseSent),
        "interrupt_requested" => Ok(RuntimeTurnEvidenceKind::InterruptRequested),
        "interrupt_accepted" => Ok(RuntimeTurnEvidenceKind::InterruptAccepted),
        "completed" => Ok(RuntimeTurnEvidenceKind::Completed),
        "interrupted" => Ok(RuntimeTurnEvidenceKind::Interrupted),
        "failed" => Ok(RuntimeTurnEvidenceKind::Failed),
        "uncertain" => Ok(RuntimeTurnEvidenceKind::Uncertain),
        _ => Err(StorageError::DomainDecode(
            "invalid runtime turn evidence kind".into(),
        )),
    }
}

fn to_sql_usize(value: usize) -> Result<i64, StorageError> {
    to_sql_u64(u64::try_from(value).map_err(|_| StorageError::RevisionOverflow(u64::MAX))?)
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hartevo_domain_kernel::{
        RuntimeRecoveryAttempt, RuntimeRecoveryAttemptId, RuntimeResumeStrategy,
        RuntimeTurnObservedKind, RuntimeTurnScope, WorkerHandle, WorkerMailbox,
    };

    use super::*;
    use crate::context_assembly_store::tests::{AssemblyStoreFixture, fixture, now};
    use crate::context_collaboration_store::{insert_worker_handle, insert_worker_mailbox};

    const PRIVATE_RUNTIME_CONTEXT: &str =
        "PRIVATE-RUNTIME-CONTEXT::must never enter turn ledger, event, or outbox";

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture constructs the exact Assembly-to-Recovery-to-attached-Worker authority closure"
    )]
    fn turn_fixture() -> (ProjectStore, RuntimeTurnAttempt) {
        let AssemblyStoreFixture {
            mut store,
            project_id,
            manifest,
            ..
        } = fixture();
        store
            .record_context_assembly_manifest(&manifest)
            .expect("manifest");
        let workspace = store
            .load_context_workspace(&project_id, &manifest.workspace_id)
            .expect("workspace");
        let capsule = store
            .load_context_capsule(&project_id, &manifest.capsule_id)
            .expect("capsule");
        let branch = store
            .load_context_branch(&project_id, &manifest.branch_id)
            .expect("branch");
        let lease = store
            .load_worker_lease(&project_id, &manifest.worker_lease_id)
            .expect("lease");
        let checkpoint = store
            .load_context_checkpoint(&project_id, &manifest.checkpoint_id)
            .expect("checkpoint");
        let attached = WorkerHandle::create(
            &workspace,
            &branch,
            &lease,
            &capsule,
            None,
            now() + Duration::seconds(5),
        )
        .expect("handle");
        let mut mailbox = WorkerMailbox::create(
            hartevo_domain_kernel::ContextWorkerMailboxId::from("mailbox-runtime-turn-store"),
            &attached,
            8,
            now() + Duration::seconds(5),
        )
        .expect("mailbox");
        {
            let transaction = store.connection.transaction().expect("worker transaction");
            insert_worker_handle(&transaction, &attached).expect("handle row");
            insert_worker_mailbox(&transaction, &mailbox).expect("mailbox row");
            transaction.commit().expect("worker commit");
        }

        let mut detached = attached.clone();
        detached
            .detach(attached.attachment_epoch, now() + Duration::seconds(6))
            .expect("detach");
        let mut recovery = RuntimeRecoveryAttempt::prepare(
            RuntimeRecoveryAttemptId::from("recovery-runtime-turn-store"),
            &attached,
            &detached,
            &checkpoint,
            "a".repeat(64),
            RuntimeResumeStrategy::StartNew,
            None,
            3,
            now() + Duration::seconds(6),
        )
        .expect("prepare recovery");
        store
            .begin_runtime_recovery(
                &detached,
                attached.revision,
                &recovery,
                &[PendingEvent::new(
                    "context.runtime_recovery_prepared",
                    serde_json::json!({"recoveryId": recovery.id}),
                    recovery.created_at,
                )],
                recovery.created_at,
            )
            .expect("persist recovery");

        let previous = recovery.revision;
        recovery
            .mark_spawned("b".repeat(64), now() + Duration::seconds(7))
            .expect("spawned");
        store
            .update_runtime_recovery(
                &recovery,
                previous,
                &[PendingEvent::new(
                    "context.runtime_recovery_spawned",
                    serde_json::json!({"recoveryId": recovery.id}),
                    recovery.updated_at,
                )],
                recovery.updated_at,
            )
            .expect("persist spawned");
        let previous = recovery.revision;
        recovery
            .confirm_health("c".repeat(64), now() + Duration::seconds(8))
            .expect("healthy");
        store
            .update_runtime_recovery(
                &recovery,
                previous,
                &[PendingEvent::new(
                    "context.runtime_recovery_healthy",
                    serde_json::json!({"recoveryId": recovery.id}),
                    recovery.updated_at,
                )],
                recovery.updated_at,
            )
            .expect("persist healthy");
        let runtime_thread_id = "runtime-thread-private-store";
        let previous = recovery.revision;
        recovery
            .bind_thread(
                &"b".repeat(64),
                runtime_thread_id.into(),
                "d".repeat(64),
                now() + Duration::seconds(9),
            )
            .expect("thread bound");
        store
            .update_runtime_recovery(
                &recovery,
                previous,
                &[PendingEvent::new(
                    "context.runtime_recovery_thread_bound",
                    serde_json::json!({"recoveryId": recovery.id}),
                    recovery.updated_at,
                )],
                recovery.updated_at,
            )
            .expect("persist thread");

        let mut reattached = detached;
        let handle_revision = reattached.revision;
        let mailbox_revision = mailbox.revision;
        let recovery_revision = recovery.revision;
        reattached
            .reattach(
                recovery.source_attachment_epoch,
                "d".repeat(64),
                now() + Duration::seconds(10),
            )
            .expect("reattach");
        mailbox
            .recover_after_reattach(&reattached, now() + Duration::seconds(10))
            .expect("mailbox recovery");
        recovery
            .mark_attached(&reattached, now() + Duration::seconds(10))
            .expect("attached recovery");
        store
            .attach_worker_and_finish_runtime_recovery(
                &reattached,
                handle_revision,
                &mailbox,
                mailbox_revision,
                &recovery,
                recovery_revision,
                &[PendingEvent::new(
                    "context.runtime_recovery_attached",
                    serde_json::json!({"recoveryId": recovery.id}),
                    recovery.updated_at,
                )],
                recovery.updated_at,
            )
            .expect("persist attach");

        let scope = RuntimeTurnScope {
            tenant_id: manifest.tenant_id.clone(),
            project_id: manifest.project_id.clone(),
            mission_id: manifest.mission_id.clone(),
            workspace_id: manifest.workspace_id.clone(),
            capsule_id: manifest.capsule_id.clone(),
            capsule_revision: manifest.capsule_revision,
            capsule_authority_digest: manifest.capsule_authority_digest.clone(),
            branch_id: manifest.branch_id.clone(),
            branch_revision: manifest.branch_revision,
            worker_id: manifest.worker_id.clone(),
            worker_generation: manifest.worker_generation,
            worker_lease_id: manifest.worker_lease_id.clone(),
            worker_lease_revision: manifest.worker_lease_revision,
            attachment_epoch: reattached.attachment_epoch,
            assembly_id: manifest.id.clone(),
            assembly_revision: manifest.revision,
            assembly_manifest_digest: manifest.digest().expect("manifest digest"),
            assembly_input_digest: manifest.input_digest.clone(),
            prompt_digest: manifest.prompt_digest.clone().expect("prompt digest"),
            checkpoint_id: manifest.checkpoint_id.clone(),
            checkpoint_digest: manifest.checkpoint_digest.clone(),
            recovery_id: recovery.id.clone(),
            recovery_revision: recovery.revision,
            runtime_instance_digest: recovery
                .runtime_instance_digest
                .clone()
                .expect("runtime instance"),
            runtime_mapping_digest: recovery
                .runtime_mapping_digest
                .clone()
                .expect("runtime mapping"),
            runtime_thread_id: runtime_thread_id.into(),
            runtime_thread_id_digest: hex::encode(Sha256::digest(runtime_thread_id.as_bytes())),
        };
        let attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from("turn-attempt-runtime-turn-store"),
            scope,
            now() + Duration::seconds(11),
        )
        .expect("turn attempt");
        (store, attempt)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the transaction replay proves insert, transition, normalized evidence, event/outbox redaction, injected rollback, and exact retry in one authority closure"
    )]
    fn runtime_turn_record_evidence_and_outbox_are_atomic_and_content_free() {
        let (mut store, mut attempt) = turn_fixture();
        let project_id = attempt.scope.project_id.clone();
        let mission_id = attempt.scope.mission_id.clone();
        let inserted = store
            .insert_runtime_turn_attempt(&attempt)
            .expect("insert turn");
        assert_eq!(inserted.event_sequences.len(), 1);
        assert_eq!(inserted.outbox_sequences.len(), 1);
        let replay = store
            .insert_runtime_turn_attempt(&attempt)
            .expect("exact replay");
        assert!(replay.event_sequences.is_empty());

        let previous = attempt.revision;
        attempt
            .begin_dispatch(now() + Duration::seconds(12))
            .expect("dispatch");
        store
            .update_runtime_turn_attempt(&attempt, previous)
            .expect("persist dispatch");
        let previous = attempt.revision;
        attempt
            .accept_dispatch(
                "runtime-turn-private-store".into(),
                hex::encode(Sha256::digest(b"dispatch-request")),
                hex::encode(Sha256::digest(b"dispatch-response")),
                now() + Duration::seconds(13),
            )
            .expect("accepted");
        store
            .update_runtime_turn_attempt(&attempt, previous)
            .expect("persist accepted");
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("roundtrip"),
            attempt
        );
        assert_eq!(
            store
                .load_active_runtime_turn_for_worker(
                    &project_id,
                    &attempt.scope.workspace_id,
                    &attempt.scope.worker_id,
                )
                .expect("active")
                .expect("turn")
                .id,
            attempt.id
        );

        let record_json: String = store
            .connection
            .query_row(
                "SELECT record_json FROM runtime_turn_attempts WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), attempt.id.as_str()],
                |row| row.get(0),
            )
            .expect("record");
        assert!(record_json.contains("runtime-thread-private-store"));
        assert!(record_json.contains("runtime-turn-private-store"));
        assert!(!record_json.contains(PRIVATE_RUNTIME_CONTEXT));
        let events = serde_json::to_string(
            &store
                .events_for_mission(&project_id, &mission_id)
                .expect("events"),
        )
        .expect("events json");
        let outbox: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM outbox_messages WHERE project_id = ?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .expect("outbox");
        for private in [
            PRIVATE_RUNTIME_CONTEXT,
            "runtime-thread-private-store",
            "runtime-turn-private-store",
        ] {
            assert!(!events.contains(private));
            assert!(!outbox.contains(private));
        }

        let previous = attempt.clone();
        attempt
            .observe(
                RuntimeTurnObservedKind::AgentMessageDelta,
                hex::encode(Sha256::digest(b"private-text-delta-event")),
                now() + Duration::seconds(14),
            )
            .expect("text delta event");
        let private_delta = RuntimeTurnPrivateTextDelta::capture(
            &attempt,
            hex::encode(Sha256::digest(b"private-assistant-item")),
            PRIVATE_RUNTIME_CONTEXT,
            None,
        )
        .expect("private text delta");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_runtime_private_delta_failure
                 BEFORE INSERT ON runtime_turn_private_text_deltas
                 BEGIN SELECT RAISE(ABORT, 'injected Runtime private delta failure'); END;",
            )
            .expect("private delta failure trigger");
        assert!(matches!(
            store.update_runtime_turn_attempt_with_private_text_delta(
                &attempt,
                previous.revision,
                &private_delta,
            ),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("private delta rollback"),
            previous
        );
        assert!(
            store
                .load_runtime_turn_private_text_deltas(&project_id, &attempt.id)
                .expect("no partial private delta")
                .is_empty()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_runtime_private_delta_failure;")
            .expect("drop private delta trigger");
        store
            .update_runtime_turn_attempt_with_private_text_delta(
                &attempt,
                previous.revision,
                &private_delta,
            )
            .expect("atomic private delta transition");
        let replay = store
            .update_runtime_turn_attempt_with_private_text_delta(
                &attempt,
                previous.revision,
                &private_delta,
            )
            .expect("idempotent private delta replay");
        assert!(replay.event_sequences.is_empty());
        assert!(replay.outbox_sequences.is_empty());
        assert_eq!(
            store
                .load_runtime_turn_private_text_deltas(&project_id, &attempt.id)
                .expect("private delta readback"),
            vec![private_delta.clone()]
        );

        let previous = attempt.clone();
        attempt
            .observe(
                RuntimeTurnObservedKind::ItemCompleted,
                hex::encode(Sha256::digest(b"private-item-body")),
                now() + Duration::seconds(15),
            )
            .expect("item event");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_runtime_turn_evidence_failure
                 BEFORE INSERT ON runtime_turn_evidence
                 WHEN NEW.sequence = 5
                 BEGIN SELECT RAISE(ABORT, 'injected runtime turn evidence failure'); END;",
            )
            .expect("trigger");
        assert!(matches!(
            store.update_runtime_turn_attempt(&attempt, previous.revision),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("rolled back"),
            previous
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_runtime_turn_evidence_failure;")
            .expect("drop trigger");
        store
            .update_runtime_turn_attempt(&attempt, previous.revision)
            .expect("retry transition");
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("retry readback"),
            attempt
        );

        let previous = attempt.clone();
        attempt
            .observe(
                RuntimeTurnObservedKind::ItemCompleted,
                hex::encode(Sha256::digest(b"private-assistant-message-event")),
                now() + Duration::seconds(16),
            )
            .expect("private message event");
        let private_message = RuntimeTurnPrivateMessage::capture(&attempt, PRIVATE_RUNTIME_CONTEXT)
            .expect("private message");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_runtime_private_message_failure
                 BEFORE INSERT ON runtime_turn_private_messages
                 BEGIN SELECT RAISE(ABORT, 'injected Runtime private message failure'); END;",
            )
            .expect("private message failure trigger");
        assert!(matches!(
            store.update_runtime_turn_attempt_with_private_message(
                &attempt,
                previous.revision,
                &private_message,
            ),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("private message rollback"),
            previous
        );
        assert!(
            store
                .load_runtime_turn_private_messages(&project_id, &attempt.id)
                .expect("no partial private message")
                .is_empty()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_runtime_private_message_failure;")
            .expect("drop private message trigger");
        store
            .update_runtime_turn_attempt_with_private_message(
                &attempt,
                previous.revision,
                &private_message,
            )
            .expect("atomic private message transition");
        assert_eq!(
            store
                .load_latest_runtime_turn_private_message(&project_id, &attempt.id)
                .expect("latest private message"),
            Some(private_message.clone())
        );
        let events = serde_json::to_string(
            &store
                .events_for_mission(&project_id, &mission_id)
                .expect("events after private message"),
        )
        .expect("events json");
        let outbox: String = store
            .connection
            .query_row(
                "SELECT group_concat(payload_json, '') FROM outbox_messages WHERE project_id = ?1",
                [project_id.as_str()],
                |row| row.get(0),
            )
            .expect("outbox after private message");
        assert!(!events.contains(PRIVATE_RUNTIME_CONTEXT));
        assert!(!outbox.contains(PRIVATE_RUNTIME_CONTEXT));

        store
            .connection
            .execute(
                "UPDATE runtime_turn_private_messages SET body = 'tampered'
                 WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2",
                params![project_id.as_str(), attempt.id.as_str()],
            )
            .expect("tamper encrypted private body");
        assert!(matches!(
            store.load_runtime_turn_private_messages(&project_id, &attempt.id),
            Err(StorageError::RuntimeTurn(_))
        ));
        store
            .connection
            .execute(
                "UPDATE runtime_turn_private_text_deltas SET delta = 'tampered'
                 WHERE project_id = ?1 AND runtime_turn_attempt_id = ?2",
                params![project_id.as_str(), attempt.id.as_str()],
            )
            .expect("tamper encrypted private delta");
        assert!(matches!(
            store.load_runtime_turn_private_text_deltas(&project_id, &attempt.id),
            Err(StorageError::RuntimeTurn(_))
        ));
    }

    #[test]
    fn startup_reconciliation_is_atomic_idempotent_and_releases_only_unsent_turns() {
        let (mut store, attempt) = turn_fixture();
        let project_id = attempt.scope.project_id.clone();
        store
            .insert_runtime_turn_attempt(&attempt)
            .expect("insert prepared turn");
        let events_before: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row.get(0))
            .expect("event count");
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER inject_startup_runtime_turn_evidence_failure
                 BEFORE INSERT ON runtime_turn_evidence
                 WHEN NEW.sequence = 2
                 BEGIN SELECT RAISE(ABORT, 'injected startup turn evidence failure'); END;",
            )
            .expect("startup failure trigger");
        assert!(matches!(
            store.reconcile_runtime_turns_after_coordinator_restart(now() + Duration::seconds(12)),
            Err(StorageError::Sql(_))
        ));
        assert_eq!(
            store
                .load_runtime_turn_attempt(&project_id, &attempt.id)
                .expect("atomic rollback"),
            attempt
        );
        assert_eq!(
            store
                .connection
                .query_row("SELECT COUNT(*) FROM domain_events", [], |row| row
                    .get::<_, i64>(0))
                .expect("event count after rollback"),
            events_before
        );
        store
            .connection
            .execute_batch("DROP TRIGGER inject_startup_runtime_turn_evidence_failure;")
            .expect("drop startup failure trigger");

        let report = store
            .reconcile_runtime_turns_after_coordinator_restart(now() + Duration::seconds(12))
            .expect("startup reconciliation");
        assert_eq!(report.scanned_attempts, 1);
        assert_eq!(report.failed_before_dispatch, 1);
        assert_eq!(report.frozen_uncertain, 0);
        assert_eq!(report.already_safe, 0);
        assert_eq!(report.event_sequences.len(), 1);
        assert_eq!(report.outbox_sequences.len(), 1);
        let failed = store
            .load_runtime_turn_attempt(&project_id, &attempt.id)
            .expect("failed attempt");
        assert_eq!(failed.status, RuntimeTurnStatus::Failed);
        assert_eq!(
            failed.failures[0].class,
            hartevo_domain_kernel::RuntimeTurnFailureClass::DispatchNotSent
        );
        assert!(
            store
                .load_active_runtime_turn_for_worker(
                    &project_id,
                    &attempt.scope.workspace_id,
                    &attempt.scope.worker_id,
                )
                .expect("active query")
                .is_none()
        );

        let replay = store
            .reconcile_runtime_turns_after_coordinator_restart(now() + Duration::seconds(13))
            .expect("idempotent reconciliation");
        assert_eq!(replay.scanned_attempts, 1);
        assert_eq!(replay.failed_before_dispatch, 0);
        assert_eq!(replay.frozen_uncertain, 0);
        assert_eq!(replay.already_safe, 1);
        assert!(replay.event_sequences.is_empty());
        assert!(replay.outbox_sequences.is_empty());
    }

    #[test]
    fn migration_v38_creates_private_runtime_message_ledger_idempotently() {
        let (mut store, _) = turn_fixture();
        store
            .connection
            .execute_batch(
                "DROP TABLE runtime_turn_private_text_deltas;
                 DROP TABLE runtime_turn_private_messages;
                 DELETE FROM schema_migrations WHERE version >= 38;",
            )
            .expect("construct v37 schema");
        store.migrate().expect("migrate v37 to v38");
        assert_eq!(
            store.schema_version().expect("schema version"),
            crate::STORAGE_SCHEMA_VERSION
        );
        let table_count: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'runtime_turn_private_messages'",
                [],
                |row| row.get(0),
            )
            .expect("private message table");
        assert_eq!(table_count, 1);
        store.migrate().expect("idempotent v38 migration");
        assert_eq!(
            store.schema_version().expect("schema"),
            crate::STORAGE_SCHEMA_VERSION
        );
    }

    #[test]
    fn startup_reconciliation_rejects_active_index_projection_tamper() {
        let (mut store, attempt) = turn_fixture();
        let project_id = attempt.scope.project_id.clone();
        store
            .insert_runtime_turn_attempt(&attempt)
            .expect("insert prepared turn");
        store
            .connection
            .execute(
                "UPDATE runtime_turn_attempts SET status = 'failed'
                 WHERE project_id = ?1 AND id = ?2",
                params![project_id.as_str(), attempt.id.as_str()],
            )
            .expect("tamper active status projection");
        assert!(matches!(
            store.reconcile_runtime_turns_after_coordinator_restart(
                now() + Duration::seconds(12)
            ),
            Err(StorageError::DomainDecode(message))
                if message == "runtime turn normalized projection mismatch"
        ));
        assert!(matches!(
            store.load_runtime_turn_attempt(&project_id, &attempt.id),
            Err(StorageError::DomainDecode(message))
                if message == "runtime turn normalized projection mismatch"
        ));
        assert!(matches!(
            store.load_active_runtime_turn_for_worker(
                &project_id,
                &attempt.scope.workspace_id,
                &attempt.scope.worker_id,
            ),
            Err(StorageError::DomainDecode(message))
                if message == "runtime turn normalized projection mismatch"
        ));
    }
}
