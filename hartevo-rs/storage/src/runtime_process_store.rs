use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ProjectId, RuntimeProcessClaim, RuntimeProcessClaimStatus, RuntimeRecoveryAttempt,
    RuntimeRecoveryStatus,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::aggregate::{AtomicMutation, PendingEvent, append_events};
use crate::runtime_recovery_store::{
    json_enum, require_one, to_sql_u64, update_runtime_recovery_attempt,
};
use crate::{ProjectStore, StorageError};

impl ProjectStore {
    pub fn prepare_runtime_process_claim(
        &mut self,
        claim: &RuntimeProcessClaim,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty()
            || claim.revision != 1
            || claim.status != RuntimeProcessClaimStatus::Prepared
        {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        claim.validate_record()?;
        let recovery = self.load_runtime_recovery(&claim.project_id, &claim.recovery_id)?;
        validate_claim_for_recovery(claim, &recovery, now)?;
        if recovery.status != RuntimeRecoveryStatus::Prepared
            || recovery.process_attempt != claim.process_attempt
        {
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "runtime process claim recovery",
                id: format!("{}:{}", claim.recovery_id, claim.process_attempt),
            });
        }
        let transaction = self.connection.transaction()?;
        insert_runtime_process_claim(&transaction, claim)?;
        let aggregate_id = runtime_process_claim_aggregate_id(claim);
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            claim.tenant_id.as_str(),
            claim.project_id.as_str(),
            Some(claim.mission_id.as_str()),
            "runtime_process_claim",
            &aggregate_id,
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: claim.revision,
        })
    }

    pub fn mark_runtime_process_spawned(
        &mut self,
        recovery: &RuntimeRecoveryAttempt,
        expected_recovery_revision: u64,
        claim: &RuntimeProcessClaim,
        expected_claim_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty()
            || recovery.status != RuntimeRecoveryStatus::Spawned
            || claim.status != RuntimeProcessClaimStatus::Spawned
        {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous_recovery = self.load_runtime_recovery(&recovery.project_id, &recovery.id)?;
        let previous_claim = self.load_runtime_process_claim(
            &claim.project_id,
            &claim.recovery_id,
            claim.process_attempt,
        )?;
        if previous_recovery.revision != expected_recovery_revision
            || previous_claim.revision != expected_claim_revision
            || !recovery.follows(&previous_recovery)?
            || !claim.follows(&previous_claim)?
            || recovery.runtime_instance_digest
                != claim
                    .identity
                    .as_ref()
                    .map(|identity| identity.runtime_instance_digest.clone())
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!(
                    "runtime_process_spawn:{}:{}",
                    claim.recovery_id, claim.process_attempt
                ),
                expected_revision: expected_claim_revision,
            });
        }
        validate_claim_for_recovery(claim, recovery, now)?;
        let handle = self.load_worker_handle(
            &recovery.project_id,
            &recovery.workspace_id,
            &recovery.worker_id,
        )?;
        let checkpoint =
            self.load_context_checkpoint(&recovery.project_id, &recovery.checkpoint_id)?;
        recovery.validate_for(&handle, &checkpoint, now)?;

        let transaction = self.connection.transaction()?;
        update_runtime_recovery_attempt(&transaction, recovery, expected_recovery_revision)?;
        update_runtime_process_claim(&transaction, claim, expected_claim_revision)?;
        let aggregate_id = runtime_process_claim_aggregate_id(claim);
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            claim.tenant_id.as_str(),
            claim.project_id.as_str(),
            Some(claim.mission_id.as_str()),
            "runtime_process_claim",
            &aggregate_id,
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: claim.revision,
        })
    }

    pub fn update_runtime_process_claim(
        &mut self,
        claim: &RuntimeProcessClaim,
        expected_revision: u64,
        events: &[PendingEvent],
        now: DateTime<Utc>,
    ) -> Result<AtomicMutation, StorageError> {
        if events.is_empty() {
            return Err(StorageError::EmptyAtomicEventSet);
        }
        let previous = self.load_runtime_process_claim(
            &claim.project_id,
            &claim.recovery_id,
            claim.process_attempt,
        )?;
        if previous.revision != expected_revision || !claim.follows(&previous)? {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!(
                    "runtime_process_claim:{}:{}",
                    claim.recovery_id, claim.process_attempt
                ),
                expected_revision,
            });
        }
        let recovery = self.load_runtime_recovery(&claim.project_id, &claim.recovery_id)?;
        validate_claim_scope(claim, &recovery, now)?;
        let transaction = self.connection.transaction()?;
        update_runtime_process_claim(&transaction, claim, expected_revision)?;
        let aggregate_id = runtime_process_claim_aggregate_id(claim);
        let (event_sequences, outbox_sequences) = append_events(
            &transaction,
            claim.tenant_id.as_str(),
            claim.project_id.as_str(),
            Some(claim.mission_id.as_str()),
            "runtime_process_claim",
            &aggregate_id,
            events,
        )?;
        transaction.commit()?;
        Ok(AtomicMutation {
            event_sequences,
            outbox_sequences,
            state_revision: claim.revision,
        })
    }

    pub fn load_runtime_process_claim(
        &self,
        project_id: &ProjectId,
        recovery_id: &hartevo_domain_kernel::RuntimeRecoveryAttemptId,
        process_attempt: u32,
    ) -> Result<RuntimeProcessClaim, StorageError> {
        load_runtime_process_claim_record(
            &self.connection,
            project_id,
            recovery_id,
            process_attempt,
        )?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "runtime process claim",
            project_id: project_id.clone(),
            id: format!("{recovery_id}:{process_attempt}"),
        })
    }

    pub fn list_active_runtime_process_claims(
        &self,
    ) -> Result<Vec<RuntimeProcessClaim>, StorageError> {
        let keys = {
            let mut statement = self.connection.prepare(
                "SELECT project_id, recovery_id, process_attempt
                 FROM runtime_process_claims
                 WHERE status IN ('prepared', 'spawned', 'blocked')
                 ORDER BY updated_at, project_id, recovery_id, process_attempt",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        keys.into_iter()
            .map(|(project_id, recovery_id, process_attempt)| {
                self.load_runtime_process_claim(
                    &ProjectId::from_stable(project_id),
                    &hartevo_domain_kernel::RuntimeRecoveryAttemptId::from_stable(recovery_id),
                    process_attempt,
                )
            })
            .collect()
    }

    /// Returns every Claim that still requires coordinator-startup work. In
    /// addition to a live/blocked Claim, this includes a terminal Claim whose
    /// linked Recovery still points at the same non-terminal process attempt.
    /// That second arm closes the crash window between durable process cleanup
    /// and durable Recovery retry accounting.
    pub fn list_runtime_process_claims_requiring_startup_reconciliation(
        &self,
    ) -> Result<Vec<RuntimeProcessClaim>, StorageError> {
        let keys = {
            let mut statement = self.connection.prepare(
                "SELECT claim.project_id, claim.recovery_id, claim.process_attempt
                 FROM runtime_process_claims AS claim
                 INNER JOIN runtime_recovery_attempts AS recovery
                   ON recovery.project_id = claim.project_id
                  AND recovery.id = claim.recovery_id
                 WHERE claim.status IN ('prepared', 'spawned', 'blocked')
                    OR (
                        claim.status IN ('terminated', 'exited')
                        AND recovery.status NOT IN ('attached', 'failed')
                        AND recovery.process_attempt = claim.process_attempt
                    )
                 ORDER BY claim.updated_at, claim.project_id, claim.recovery_id,
                          claim.process_attempt",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u32>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        keys.into_iter()
            .map(|(project_id, recovery_id, process_attempt)| {
                self.load_runtime_process_claim(
                    &ProjectId::from_stable(project_id),
                    &hartevo_domain_kernel::RuntimeRecoveryAttemptId::from_stable(recovery_id),
                    process_attempt,
                )
            })
            .collect()
    }

    pub fn list_runtime_process_claims(
        &self,
        project_id: &ProjectId,
    ) -> Result<Vec<RuntimeProcessClaim>, StorageError> {
        let keys = {
            let mut statement = self.connection.prepare(
                "SELECT recovery_id, process_attempt
                 FROM runtime_process_claims
                 WHERE project_id = ?1
                 ORDER BY updated_at, recovery_id, process_attempt",
            )?;
            statement
                .query_map([project_id.as_str()], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        keys.into_iter()
            .map(|(recovery_id, process_attempt)| {
                self.load_runtime_process_claim(
                    project_id,
                    &hartevo_domain_kernel::RuntimeRecoveryAttemptId::from_stable(recovery_id),
                    process_attempt,
                )
            })
            .collect()
    }
}

fn validate_claim_for_recovery(
    claim: &RuntimeProcessClaim,
    recovery: &RuntimeRecoveryAttempt,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    validate_claim_scope(claim, recovery, now)?;
    if claim.process_attempt != recovery.process_attempt {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "runtime process attempt",
            id: format!("{}:{}", claim.recovery_id, claim.process_attempt),
        });
    }
    Ok(())
}

fn validate_claim_scope(
    claim: &RuntimeProcessClaim,
    recovery: &RuntimeRecoveryAttempt,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    claim.validate_record()?;
    recovery.validate_record()?;
    if claim.tenant_id != recovery.tenant_id
        || claim.project_id != recovery.project_id
        || claim.mission_id != recovery.mission_id
        || claim.recovery_id != recovery.id
        || claim.workspace_id != recovery.workspace_id
        || claim.worker_id != recovery.worker_id
        || claim.worker_generation != recovery.worker_generation
        || claim.runtime_config_digest != recovery.runtime_config_digest
        || claim.updated_at > now
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "runtime process claim scope",
            id: format!("{}:{}", claim.recovery_id, claim.process_attempt),
        });
    }
    Ok(())
}

fn load_runtime_process_claim_record(
    connection: &rusqlite::Connection,
    project_id: &ProjectId,
    recovery_id: &hartevo_domain_kernel::RuntimeRecoveryAttemptId,
    process_attempt: u32,
) -> Result<Option<RuntimeProcessClaim>, StorageError> {
    let projection = connection
        .query_row(
            "SELECT tenant_id, project_id, recovery_id, process_attempt, mission_id,
                    workspace_id, worker_id, worker_generation, runtime_config_digest,
                    program_sha256, launch_token_digest, launch_executable_path_digest, process_id,
                    started_at_epoch_seconds, executable_path_digest,
                    runtime_instance_digest, cleanup_attempt_count, status, revision,
                    created_at, updated_at, record_json
             FROM runtime_process_claims
             WHERE project_id = ?1 AND recovery_id = ?2 AND process_attempt = ?3",
            params![project_id.as_str(), recovery_id.as_str(), process_attempt],
            |row| {
                (0..22)
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<Result<Vec<_>, _>>()
            },
        )
        .optional()?;
    let Some(projection) = projection else {
        return Ok(None);
    };
    let Some(rusqlite::types::Value::Text(record)) = projection.get(21) else {
        return Err(StorageError::DomainDecode(
            "runtime process claim encrypted record projection is invalid".into(),
        ));
    };
    let claim: RuntimeProcessClaim = serde_json::from_str(record)?;
    claim.validate_record()?;
    if runtime_process_claim_values(&claim)? != projection {
        return Err(StorageError::DomainDecode(
            "runtime process claim normalized projection mismatch".into(),
        ));
    }
    Ok(Some(claim))
}

fn insert_runtime_process_claim(
    transaction: &Transaction<'_>,
    claim: &RuntimeProcessClaim,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO runtime_process_claims
           (tenant_id, project_id, recovery_id, process_attempt, mission_id,
            workspace_id, worker_id, worker_generation, runtime_config_digest,
            program_sha256, launch_token_digest, launch_executable_path_digest, process_id,
            started_at_epoch_seconds, executable_path_digest,
            runtime_instance_digest, cleanup_attempt_count, status, revision,
            created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
        rusqlite::params_from_iter(runtime_process_claim_values(claim)?),
    )?;
    Ok(())
}

fn update_runtime_process_claim(
    transaction: &Transaction<'_>,
    claim: &RuntimeProcessClaim,
    expected_revision: u64,
) -> Result<(), StorageError> {
    let identity = claim.identity.as_ref();
    let changed = transaction.execute(
        "UPDATE runtime_process_claims
         SET process_id = ?1, started_at_epoch_seconds = ?2,
             executable_path_digest = ?3, runtime_instance_digest = ?4,
             cleanup_attempt_count = ?5, status = ?6, revision = ?7,
             updated_at = ?8, record_json = ?9
         WHERE project_id = ?10 AND recovery_id = ?11 AND process_attempt = ?12
           AND revision = ?13",
        params![
            identity.map(|identity| i64::from(identity.process_id)),
            identity
                .map(|identity| to_sql_u64(identity.started_at_epoch_seconds))
                .transpose()?,
            identity.map(|identity| &identity.executable_path_digest),
            identity.map(|identity| &identity.runtime_instance_digest),
            to_sql_u64(
                u64::try_from(claim.cleanup_attempts.len())
                    .map_err(|_| { StorageError::RevisionOverflow(u64::MAX) })?
            )?,
            json_enum(&claim.status)?,
            to_sql_u64(claim.revision)?,
            claim.updated_at.to_rfc3339(),
            serde_json::to_string(claim)?,
            claim.project_id.as_str(),
            claim.recovery_id.as_str(),
            claim.process_attempt,
            to_sql_u64(expected_revision)?,
        ],
    )?;
    require_one(
        changed,
        "runtime_process_claim",
        &runtime_process_claim_aggregate_id(claim),
        expected_revision,
    )
}

fn runtime_process_claim_values(
    claim: &RuntimeProcessClaim,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    use rusqlite::types::Value;
    let identity = claim.identity.as_ref();
    Ok(vec![
        Value::Text(claim.tenant_id.to_string()),
        Value::Text(claim.project_id.to_string()),
        Value::Text(claim.recovery_id.to_string()),
        Value::Integer(to_sql_u64(u64::from(claim.process_attempt))?),
        Value::Text(claim.mission_id.to_string()),
        Value::Text(claim.workspace_id.to_string()),
        Value::Text(claim.worker_id.to_string()),
        Value::Integer(to_sql_u64(claim.worker_generation)?),
        Value::Text(claim.runtime_config_digest.clone()),
        Value::Text(claim.program_sha256.clone()),
        Value::Text(claim.launch_token_digest.clone()),
        Value::Text(claim.launch_executable_path_digest.clone()),
        identity.map_or(Value::Null, |identity| {
            Value::Integer(i64::from(identity.process_id))
        }),
        identity.map_or(Ok(Value::Null), |identity| {
            to_sql_u64(identity.started_at_epoch_seconds).map(Value::Integer)
        })?,
        identity.map_or(Value::Null, |identity| {
            Value::Text(identity.executable_path_digest.clone())
        }),
        identity.map_or(Value::Null, |identity| {
            Value::Text(identity.runtime_instance_digest.clone())
        }),
        Value::Integer(to_sql_u64(
            u64::try_from(claim.cleanup_attempts.len())
                .map_err(|_| StorageError::RevisionOverflow(u64::MAX))?,
        )?),
        Value::Text(json_enum(&claim.status)?),
        Value::Integer(to_sql_u64(claim.revision)?),
        Value::Text(claim.created_at.to_rfc3339()),
        Value::Text(claim.updated_at.to_rfc3339()),
        Value::Text(serde_json::to_string(claim)?),
    ])
}

fn runtime_process_claim_aggregate_id(claim: &RuntimeProcessClaim) -> String {
    format!("{}:{}", claim.recovery_id, claim.process_attempt)
}
