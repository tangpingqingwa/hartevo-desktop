use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextCapsule, ContextCapsuleId, ContextCapsuleStatus, DeletionReason, DeletionRecord,
    DeletionRetentionMode, DeletionTombstone, ProjectId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::aggregate::{PendingEvent, append_events};
use crate::context_store::load_context_capsule_record;
use crate::deletion_propagation::enqueue_deletion_jobs;
use crate::sync_store::{
    LocalInboundSyncObject, LocalInboundSyncStatus, LocalSyncOperation, LocalSyncPrepareOutcome,
    LocalSyncStatus, ensure_registered_sync_project, insert_operation, load_inbound_required,
    load_operation, mark_inbound_projection_conflict,
};
use crate::{ProjectStore, StorageError};

const CONTEXT_CAPSULE_KIND: &str = "context_capsule";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(
    clippy::struct_field_names,
    reason = "row counts distinguish every projection and ciphertext surface in deletion evidence"
)]
struct ProjectionDeletionEvidence {
    capsule_rows: usize,
    lease_rows: usize,
    branch_rows: usize,
    workspace_rows: usize,
    outbound_ciphertext_rows: usize,
    inbound_ciphertext_rows: usize,
}

impl ProjectStore {
    pub fn load_deletion_record(
        &self,
        project_id: &ProjectId,
        object_kind: &str,
        object_id: &str,
    ) -> Result<DeletionRecord, StorageError> {
        load_deletion_record(&self.connection, project_id, object_kind, object_id)?.ok_or_else(
            || StorageError::ScopedRecordNotFound {
                kind: "sync deletion record",
                project_id: project_id.clone(),
                id: format!("{object_kind}:{object_id}"),
            },
        )
    }

    pub fn ensure_sync_object_not_deleted(
        &self,
        project_id: &ProjectId,
        object_kind: &str,
        object_id: &str,
    ) -> Result<(), StorageError> {
        ensure_sync_object_not_deleted_in_connection(
            &self.connection,
            project_id,
            object_kind,
            object_id,
        )
    }

    pub fn prepare_local_context_capsule_deletion(
        &mut self,
        operation: &LocalSyncOperation,
        tombstone: &DeletionTombstone,
        now: DateTime<Utc>,
    ) -> Result<LocalSyncPrepareOutcome, StorageError> {
        validate_local_context_deletion(operation, tombstone, now)?;
        let transaction = self.connection.transaction()?;
        ensure_registered_sync_project(
            &transaction,
            &operation.tenant_id,
            &operation.project_id,
            &operation.cell,
        )?;

        if let Some(existing) = load_operation(
            &transaction,
            &operation.project_id,
            &operation.idempotency_key_digest,
        )? {
            if existing.intent_digest != operation.intent_digest || !existing.tombstone {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "encrypted sync deletion request",
                    id: operation.idempotency_key_digest.clone(),
                });
            }
            let deletion = load_deletion_record(
                &transaction,
                &operation.project_id,
                CONTEXT_CAPSULE_KIND,
                &operation.object_id,
            )?
            .ok_or_else(|| StorageError::DomainDecode("deletion operation lacks record".into()))?;
            if deletion.tombstone != *tombstone {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "context capsule deletion tombstone",
                    id: tombstone.id.to_string(),
                });
            }
            transaction.commit()?;
            return Ok(LocalSyncPrepareOutcome {
                operation: existing,
                duplicate: true,
                event_sequence: None,
                outbox_sequence: None,
            });
        }

        ensure_sync_object_not_deleted_in_transaction(
            &transaction,
            &operation.project_id,
            CONTEXT_CAPSULE_KIND,
            &operation.object_id,
        )?;
        let capsule_id = ContextCapsuleId::from_stable(operation.object_id.clone());
        let capsule =
            load_context_capsule_record(&transaction, &operation.project_id, &capsule_id)?
                .ok_or_else(|| StorageError::ScopedRecordNotFound {
                    kind: "context capsule",
                    project_id: operation.project_id.clone(),
                    id: operation.object_id.clone(),
                })?;
        validate_deletable_capsule(&capsule, tombstone)?;
        ensure_no_newer_local_sync_operation(&transaction, operation)?;

        let mut evidence = delete_context_capsule_projection(&transaction, &capsule)?;
        let (outbound_rows, inbound_rows) = purge_prior_local_ciphertext(
            &transaction,
            &operation.project_id,
            CONTEXT_CAPSULE_KIND,
            &operation.object_id,
            None,
        )?;
        evidence.outbound_ciphertext_rows = outbound_rows;
        evidence.inbound_ciphertext_rows = inbound_rows;
        let record = pending_record(tombstone.clone(), &evidence, now)?;

        insert_operation(&transaction, operation)?;
        insert_deletion_record(&transaction, &record)?;
        let event_payload = deletion_event_payload(&record, operation);
        let (events, outbox) = append_events(
            &transaction,
            operation.tenant_id.as_str(),
            operation.project_id.as_str(),
            None,
            "encrypted_sync_operation",
            &operation.idempotency_key_digest,
            &[
                PendingEvent::new(
                    "sync.operation.prepared",
                    sync_operation_event_payload(operation),
                    now,
                ),
                PendingEvent::new(
                    "sync.context_capsule.deletion_requested",
                    event_payload,
                    now,
                ),
            ],
        )?;
        transaction.commit()?;
        Ok(LocalSyncPrepareOutcome {
            operation: operation.clone(),
            duplicate: false,
            event_sequence: events.first().copied(),
            outbox_sequence: outbox.first().copied(),
        })
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the inbound tombstone transaction keeps validation, conflict persistence, projection cleanup, propagation evidence, and inbound-head CAS visibly atomic"
    )]
    pub fn apply_local_inbound_context_capsule_tombstone(
        &mut self,
        tombstone: &DeletionTombstone,
        object_id: &str,
        expected_local_revision: u64,
        remote_revision: u64,
        validation_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<LocalInboundSyncObject, StorageError> {
        tombstone.validate(now)?;
        if tombstone.object_kind != CONTEXT_CAPSULE_KIND
            || tombstone.object_id != object_id
            || remote_revision != tombstone_remote_revision(tombstone)?
            || !is_sha256(validation_digest)
        {
            return Err(StorageError::DomainDecode(
                "invalid inbound context capsule tombstone".into(),
            ));
        }

        let transaction = self.connection.transaction()?;
        let current = load_inbound_required(&transaction, &tombstone.project_id, object_id)?;
        if current.status == LocalInboundSyncStatus::Applied
            && current.envelope.remote_revision == remote_revision
            && current.envelope.tombstone
            && current.validation_digest.as_deref() == Some(validation_digest)
            && current.projection_digest.as_deref() == Some(validation_digest)
            && current.projection_revision == Some(remote_revision)
        {
            transaction.commit()?;
            return Ok(current);
        }
        if current.status != LocalInboundSyncStatus::Validated
            || current.revision != expected_local_revision
            || current.envelope.remote_revision != remote_revision
            || current.envelope.object_kind != CONTEXT_CAPSULE_KIND
            || !current.envelope.tombstone
            || current.validation_digest.as_deref() != Some(validation_digest)
        {
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("inbound_sync_object:{object_id}"),
                expected_revision: expected_local_revision,
            });
        }

        let capsule_id = ContextCapsuleId::from_stable(object_id.to_owned());
        let capsule =
            load_context_capsule_record(&transaction, &tombstone.project_id, &capsule_id)?;
        if capsule
            .as_ref()
            .is_some_and(|item| validate_deletable_capsule(item, tombstone).is_err())
        {
            mark_inbound_projection_conflict(
                &transaction,
                &current,
                "local_context_capsule_changed_before_deletion",
                now,
            )?;
            transaction.commit()?;
            return Err(StorageError::OptimisticConflict {
                aggregate: format!("context_capsule:{object_id}"),
                expected_revision: tombstone.prior_object_revision,
            });
        }

        let existing = load_deletion_record(
            &transaction,
            &tombstone.project_id,
            CONTEXT_CAPSULE_KIND,
            object_id,
        )?;
        if existing
            .as_ref()
            .is_some_and(|record| record.tombstone != *tombstone)
        {
            mark_inbound_projection_conflict(
                &transaction,
                &current,
                "local_deletion_tombstone_differs_from_cell",
                now,
            )?;
            transaction.commit()?;
            return Err(StorageError::ImmutableRecordMismatch {
                kind: "context capsule deletion tombstone",
                id: tombstone.id.to_string(),
            });
        }

        let mut evidence = match capsule.as_ref() {
            Some(capsule) => delete_context_capsule_projection(&transaction, capsule)?,
            None => ProjectionDeletionEvidence {
                capsule_rows: 0,
                lease_rows: 0,
                branch_rows: 0,
                workspace_rows: 0,
                outbound_ciphertext_rows: 0,
                inbound_ciphertext_rows: 0,
            },
        };
        let (outbound_rows, inbound_rows) = purge_prior_local_ciphertext(
            &transaction,
            &tombstone.project_id,
            CONTEXT_CAPSULE_KIND,
            object_id,
            Some(remote_revision),
        )?;
        evidence.outbound_ciphertext_rows = outbound_rows;
        evidence.inbound_ciphertext_rows = inbound_rows;

        let mut record = match existing {
            Some(record) => record,
            None => pending_record(tombstone.clone(), &evidence, now)?,
        };
        let cell_evidence = digest_json(&json!({
            "surface": "encrypted_cell",
            "cell": current.envelope.cell,
            "objectId": object_id,
            "remoteRevision": remote_revision,
            "contentDigest": current.envelope.content_digest,
            "tombstoneDigest": tombstone.tombstone_digest,
        }))?;
        record = record.mark_encrypted_cell_applied(cell_evidence, now)?;
        match load_deletion_record(
            &transaction,
            &tombstone.project_id,
            CONTEXT_CAPSULE_KIND,
            object_id,
        )? {
            Some(previous) => update_deletion_record(&transaction, &record, previous.revision)?,
            None => insert_deletion_record(&transaction, &record)?,
        }

        finish_inbound_deletion_projection(
            &transaction,
            &current,
            &record,
            expected_local_revision,
            remote_revision,
            validation_digest,
            now,
        )?;
        let applied = load_inbound_required(&transaction, &tombstone.project_id, object_id)?;
        transaction.commit()?;
        Ok(applied)
    }
}

pub(crate) fn ensure_sync_object_not_deleted_in_transaction(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    object_kind: &str,
    object_id: &str,
) -> Result<(), StorageError> {
    ensure_sync_object_not_deleted_in_connection(transaction, project_id, object_kind, object_id)
}

pub(crate) fn mark_encrypted_cell_applied_in_transaction(
    transaction: &Transaction<'_>,
    operation: &LocalSyncOperation,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let mut record = load_deletion_record(
        transaction,
        &operation.project_id,
        &operation.object_kind,
        &operation.object_id,
    )?
    .ok_or_else(|| {
        StorageError::DomainDecode("tombstone operation lacks deletion record".into())
    })?;
    if !operation.tombstone
        || operation.remote_revision != Some(record.remote_object_revision)
        || operation.target_revision != record.remote_object_revision
    {
        return Err(StorageError::ImmutableRecordMismatch {
            kind: "encrypted Cell deletion result",
            id: operation.idempotency_key_digest.clone(),
        });
    }
    let evidence = digest_json(&json!({
        "surface": "encrypted_cell",
        "cell": operation.cell,
        "objectId": operation.object_id,
        "remoteRevision": operation.remote_revision,
        "contentDigest": operation.content_digest,
        "tombstoneDigest": record.tombstone.tombstone_digest,
    }))?;
    let previous_revision = record.revision;
    record = record.mark_encrypted_cell_applied(evidence, now)?;
    if record.revision != previous_revision {
        update_deletion_record(transaction, &record, previous_revision)?;
    }
    Ok(())
}

fn validate_local_context_deletion(
    operation: &LocalSyncOperation,
    tombstone: &DeletionTombstone,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    operation.validate()?;
    tombstone.validate(now)?;
    if operation.revision != 1
        || operation.status != LocalSyncStatus::Prepared
        || !operation.tombstone
        || operation.tenant_id != tombstone.tenant_id
        || operation.project_id != tombstone.project_id
        || operation.object_id != tombstone.object_id
        || operation.object_kind != tombstone.object_kind
        || operation.object_kind != CONTEXT_CAPSULE_KIND
        || operation.target_revision != tombstone_remote_revision(tombstone)?
        || operation.created_at != tombstone.requested_at
    {
        return Err(StorageError::DomainDecode(
            "local context capsule deletion operation does not match tombstone".into(),
        ));
    }
    Ok(())
}

fn validate_deletable_capsule(
    capsule: &ContextCapsule,
    tombstone: &DeletionTombstone,
) -> Result<(), StorageError> {
    if capsule.tenant_id != tombstone.tenant_id
        || capsule.project_id != tombstone.project_id
        || capsule.id.as_str() != tombstone.object_id
        || capsule.revision != tombstone.prior_object_revision
        || !matches!(
            capsule.status,
            ContextCapsuleStatus::Accepted
                | ContextCapsuleStatus::Cancelled
                | ContextCapsuleStatus::Expired
        )
    {
        return Err(StorageError::DeletionRequiresTerminalContextCapsule);
    }
    Ok(())
}

fn ensure_no_newer_local_sync_operation(
    transaction: &Transaction<'_>,
    operation: &LocalSyncOperation,
) -> Result<(), StorageError> {
    let newer: Option<i64> = transaction.query_row(
        "SELECT MAX(target_revision) FROM encrypted_sync_operations
         WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3
           AND tombstone = 0",
        params![
            operation.project_id.as_str(),
            operation.object_kind,
            operation.object_id
        ],
        |row| row.get(0),
    )?;
    if newer.is_some_and(|revision| {
        u64::try_from(revision).map_or(true, |revision| revision >= operation.target_revision)
    }) {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("context_capsule:{}", operation.object_id),
            expected_revision: operation.target_revision - 1,
        });
    }
    Ok(())
}

fn pending_record(
    tombstone: DeletionTombstone,
    evidence: &ProjectionDeletionEvidence,
    now: DateTime<Utc>,
) -> Result<DeletionRecord, StorageError> {
    let local_evidence = digest_json(&json!({
        "surface": "local_projection",
        "objectId": tombstone.object_id,
        "priorRevision": tombstone.prior_object_revision,
        "deleted": evidence,
    }))?;
    let context_evidence = digest_json(&json!({
        "surface": "context_derived",
        "capsuleId": tombstone.object_id,
        "capsuleRows": evidence.capsule_rows,
        "leaseRows": evidence.lease_rows,
        "branchRows": evidence.branch_rows,
        "workspaceRows": evidence.workspace_rows,
    }))?;
    let object_storage_evidence = digest_json(&json!({
        "surface": "object_storage",
        "result": "not_applicable",
        "reason": "context_capsule_has_no_local_object_storage_body",
    }))?;
    let remote_revision = tombstone_remote_revision(&tombstone)?;
    Ok(DeletionRecord::pending(
        tombstone,
        remote_revision,
        local_evidence,
        context_evidence,
        object_storage_evidence,
        now,
    )?)
}

fn delete_context_capsule_projection(
    transaction: &Transaction<'_>,
    capsule: &ContextCapsule,
) -> Result<ProjectionDeletionEvidence, StorageError> {
    let capsule_rows = transaction.execute(
        "DELETE FROM context_capsules WHERE project_id = ?1 AND id = ?2 AND revision = ?3",
        params![
            capsule.project_id.as_str(),
            capsule.id.as_str(),
            to_sql_u64(capsule.revision)?
        ],
    )?;
    if capsule_rows != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("context_capsule:{}", capsule.id),
            expected_revision: capsule.revision,
        });
    }
    let lease_rows = transaction.execute(
        "DELETE FROM worker_leases
         WHERE project_id = ?1 AND id = ?2
           AND NOT EXISTS (
             SELECT 1 FROM context_capsules candidate
             WHERE candidate.project_id = worker_leases.project_id
               AND candidate.worker_lease_id = worker_leases.id
           )",
        params![
            capsule.project_id.as_str(),
            capsule.worker_lease_id.as_str()
        ],
    )?;

    let mut branch_rows = 0;
    let mut cursor = Some(capsule.branch_id.to_string());
    while let Some(branch_id) = cursor {
        let parent: Option<Option<String>> = transaction
            .query_row(
                "SELECT parent_branch_id FROM context_branches
                 WHERE project_id = ?1 AND id = ?2",
                params![capsule.project_id.as_str(), branch_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(parent) = parent else {
            break;
        };
        let removed = transaction.execute(
            "DELETE FROM context_branches
             WHERE project_id = ?1 AND id = ?2
               AND NOT EXISTS (
                 SELECT 1 FROM context_branches child
                 WHERE child.project_id = context_branches.project_id
                   AND child.parent_branch_id = context_branches.id
               )
               AND NOT EXISTS (
                 SELECT 1 FROM worker_leases lease
                 WHERE lease.project_id = context_branches.project_id
                   AND lease.branch_id = context_branches.id
               )
               AND NOT EXISTS (
                 SELECT 1 FROM context_capsules candidate
                 WHERE candidate.project_id = context_branches.project_id
                   AND candidate.branch_id = context_branches.id
               )",
            params![capsule.project_id.as_str(), branch_id],
        )?;
        if removed == 0 {
            break;
        }
        branch_rows += removed;
        cursor = parent;
    }
    let workspace_rows = transaction.execute(
        "DELETE FROM context_workspaces
         WHERE project_id = ?1 AND id = ?2
           AND NOT EXISTS (
             SELECT 1 FROM context_branches branch
             WHERE branch.project_id = context_workspaces.project_id
               AND branch.workspace_id = context_workspaces.id
           )
           AND NOT EXISTS (
             SELECT 1 FROM worker_leases lease
             WHERE lease.project_id = context_workspaces.project_id
               AND lease.workspace_id = context_workspaces.id
           )
           AND NOT EXISTS (
             SELECT 1 FROM context_capsules candidate
             WHERE candidate.project_id = context_workspaces.project_id
               AND candidate.workspace_id = context_workspaces.id
           )",
        params![capsule.project_id.as_str(), capsule.workspace_id.as_str()],
    )?;
    Ok(ProjectionDeletionEvidence {
        capsule_rows,
        lease_rows,
        branch_rows,
        workspace_rows,
        outbound_ciphertext_rows: 0,
        inbound_ciphertext_rows: 0,
    })
}

fn purge_prior_local_ciphertext(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    object_kind: &str,
    object_id: &str,
    keep_inbound_revision: Option<u64>,
) -> Result<(usize, usize), StorageError> {
    transaction.execute(
        "DELETE FROM outbox_messages
         WHERE aggregate_type = 'encrypted_sync_operation'
           AND aggregate_id IN (
             SELECT idempotency_key_digest FROM encrypted_sync_operations
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3
               AND tombstone = 0
           )",
        params![project_id.as_str(), object_kind, object_id],
    )?;
    let outbound_rows = transaction.execute(
        "DELETE FROM encrypted_sync_operations
         WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3
           AND tombstone = 0",
        params![project_id.as_str(), object_kind, object_id],
    )?;

    if keep_inbound_revision.is_none() {
        transaction.execute(
            "DELETE FROM encrypted_sync_inbound_heads
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3",
            params![project_id.as_str(), object_kind, object_id],
        )?;
    }
    let inbound_rows = match keep_inbound_revision {
        Some(revision) => transaction.execute(
            "DELETE FROM encrypted_sync_inbound_versions
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3
               AND remote_revision <> ?4",
            params![
                project_id.as_str(),
                object_kind,
                object_id,
                to_sql_u64(revision)?
            ],
        )?,
        None => transaction.execute(
            "DELETE FROM encrypted_sync_inbound_versions
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3",
            params![project_id.as_str(), object_kind, object_id],
        )?,
    };
    Ok((outbound_rows, inbound_rows))
}

#[allow(clippy::too_many_arguments)]
fn finish_inbound_deletion_projection(
    transaction: &Transaction<'_>,
    current: &LocalInboundSyncObject,
    record: &DeletionRecord,
    expected_local_revision: u64,
    remote_revision: u64,
    validation_digest: &str,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let next_local_revision = next_revision(expected_local_revision)?;
    let updated = transaction.execute(
        "UPDATE encrypted_sync_inbound_heads
         SET status = 'applied', projection_digest = ?4, projection_revision = ?5,
             last_error_code = NULL, revision = ?6, updated_at = ?7
         WHERE project_id = ?1 AND object_id = ?2 AND revision = ?3
           AND current_remote_revision = ?8 AND status = 'validated' AND tombstone = 1",
        params![
            record.tombstone.project_id.as_str(),
            record.tombstone.object_id,
            to_sql_u64(expected_local_revision)?,
            validation_digest,
            to_sql_u64(remote_revision)?,
            to_sql_u64(next_local_revision)?,
            now.to_rfc3339(),
            to_sql_u64(remote_revision)?,
        ],
    )?;
    if updated != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("inbound_sync_object:{}", record.tombstone.object_id),
            expected_revision: expected_local_revision,
        });
    }
    let payload = json!({
        "cell": current.envelope.cell,
        "objectId": current.envelope.object_id,
        "objectKind": current.envelope.object_kind,
        "remoteRevision": remote_revision,
        "contentDigest": current.envelope.content_digest,
        "tombstoneDigest": record.tombstone.tombstone_digest,
        "deletionRecordRevision": record.revision,
        "complete": record.is_complete(),
        "status": LocalInboundSyncStatus::Applied,
    });
    transaction.execute(
        "INSERT INTO domain_events
           (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
         VALUES (?1, ?2, NULL, 'sync.inbound.context_capsule_deleted', ?3, ?4)",
        params![
            record.tombstone.tenant_id.as_str(),
            record.tombstone.project_id.as_str(),
            serde_json::to_string(&payload)?,
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn ensure_sync_object_not_deleted_in_connection(
    connection: &Connection,
    project_id: &ProjectId,
    object_kind: &str,
    object_id: &str,
) -> Result<(), StorageError> {
    let deleted = connection
        .query_row(
            "SELECT 1 FROM sync_deletion_records
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3",
            params![project_id.as_str(), object_kind, object_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if deleted {
        Err(StorageError::SyncObjectDeleted {
            project_id: project_id.clone(),
            object_kind: object_kind.to_owned(),
            object_id: object_id.to_owned(),
        })
    } else {
        Ok(())
    }
}

pub(crate) fn insert_deletion_record(
    transaction: &Transaction<'_>,
    record: &DeletionRecord,
) -> Result<(), StorageError> {
    record.validate(record.updated_at)?;
    transaction.execute(
        "INSERT INTO sync_deletion_records
           (tenant_id, project_id, deletion_id, object_id, object_kind,
            prior_object_revision, remote_object_revision, deletion_generation,
            reason, authorized_by, authorization_evidence_digest, requested_at,
            retention_mode, tombstone_digest, surfaces_json, complete, record_revision,
            created_at, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        rusqlite::params_from_iter(deletion_record_params(record)?),
    )?;
    enqueue_deletion_jobs(transaction, record)?;
    Ok(())
}

pub(crate) fn update_deletion_record(
    transaction: &Transaction<'_>,
    record: &DeletionRecord,
    expected_revision: u64,
) -> Result<(), StorageError> {
    record.validate(record.updated_at)?;
    let changed = transaction.execute(
        "UPDATE sync_deletion_records
         SET surfaces_json = ?1, complete = ?2, record_revision = ?3,
             updated_at = ?4, record_json = ?5
         WHERE project_id = ?6 AND deletion_id = ?7 AND record_revision = ?8",
        params![
            serde_json::to_string(&record.surfaces)?,
            i64::from(record.is_complete()),
            to_sql_u64(record.revision)?,
            record.updated_at.to_rfc3339(),
            serde_json::to_string(record)?,
            record.tombstone.project_id.as_str(),
            record.tombstone.id.as_str(),
            to_sql_u64(expected_revision)?,
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::OptimisticConflict {
            aggregate: format!("sync_deletion_record:{}", record.tombstone.id),
            expected_revision,
        });
    }
    Ok(())
}

pub(crate) fn load_deletion_record(
    connection: &Connection,
    project_id: &ProjectId,
    object_kind: &str,
    object_id: &str,
) -> Result<Option<DeletionRecord>, StorageError> {
    let row = connection
        .query_row(
            "SELECT deletion_id, prior_object_revision, remote_object_revision,
                    deletion_generation, tombstone_digest, complete, record_revision,
                    record_json
             FROM sync_deletion_records
             WHERE project_id = ?1 AND object_kind = ?2 AND object_id = ?3",
            params![project_id.as_str(), object_kind, object_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    row.map(|row| {
        let record: DeletionRecord = serde_json::from_str(&row.7)?;
        record.validate(record.updated_at)?;
        let normalized_matches = record.tombstone.id.as_str() == row.0
            && record.tombstone.project_id == *project_id
            && record.tombstone.object_kind == object_kind
            && record.tombstone.object_id == object_id
            && to_sql_u64(record.tombstone.prior_object_revision)? == row.1
            && to_sql_u64(record.remote_object_revision)? == row.2
            && to_sql_u64(record.tombstone.deletion_generation)? == row.3
            && record.tombstone.tombstone_digest == row.4
            && i64::from(record.is_complete()) == row.5
            && to_sql_u64(record.revision)? == row.6;
        if !normalized_matches {
            return Err(StorageError::DomainDecode(
                "normalized deletion record differs from record body".into(),
            ));
        }
        Ok(record)
    })
    .transpose()
}

fn deletion_record_params(
    record: &DeletionRecord,
) -> Result<Vec<rusqlite::types::Value>, StorageError> {
    Ok(vec![
        record.tombstone.tenant_id.as_str().to_owned().into(),
        record.tombstone.project_id.as_str().to_owned().into(),
        record.tombstone.id.as_str().to_owned().into(),
        record.tombstone.object_id.clone().into(),
        record.tombstone.object_kind.clone().into(),
        to_sql_u64(record.tombstone.prior_object_revision)?.into(),
        to_sql_u64(record.remote_object_revision)?.into(),
        to_sql_u64(record.tombstone.deletion_generation)?.into(),
        deletion_reason_name(record.tombstone.reason)
            .to_owned()
            .into(),
        record.tombstone.authorized_by.as_str().to_owned().into(),
        record
            .tombstone
            .authorization_evidence_digest
            .clone()
            .into(),
        record.tombstone.requested_at.to_rfc3339().into(),
        retention_mode_name(record.tombstone.retention_mode)
            .to_owned()
            .into(),
        record.tombstone.tombstone_digest.clone().into(),
        serde_json::to_string(&record.surfaces)?.into(),
        i64::from(record.is_complete()).into(),
        to_sql_u64(record.revision)?.into(),
        record.created_at.to_rfc3339().into(),
        record.updated_at.to_rfc3339().into(),
        serde_json::to_string(record)?.into(),
    ])
}

fn deletion_event_payload(
    record: &DeletionRecord,
    operation: &LocalSyncOperation,
) -> serde_json::Value {
    json!({
        "deletionId": record.tombstone.id,
        "objectId": record.tombstone.object_id,
        "objectKind": record.tombstone.object_kind,
        "priorObjectRevision": record.tombstone.prior_object_revision,
        "remoteObjectRevision": record.remote_object_revision,
        "deletionGeneration": record.tombstone.deletion_generation,
        "reason": record.tombstone.reason,
        "authorizedBy": record.tombstone.authorized_by,
        "authorizationEvidenceDigest": record.tombstone.authorization_evidence_digest,
        "tombstoneDigest": record.tombstone.tombstone_digest,
        "idempotencyKeyDigest": operation.idempotency_key_digest,
        "complete": record.is_complete(),
    })
}

fn sync_operation_event_payload(operation: &LocalSyncOperation) -> serde_json::Value {
    json!({
        "idempotencyKeyDigest": operation.idempotency_key_digest,
        "intentDigest": operation.intent_digest,
        "requestDigest": operation.request_digest,
        "cell": operation.cell,
        "objectId": operation.object_id,
        "objectKind": operation.object_kind,
        "targetRevision": operation.target_revision,
        "keyVersion": operation.key_version,
        "contentDigest": operation.content_digest,
        "tombstone": operation.tombstone,
        "status": operation.status,
    })
}

const fn deletion_reason_name(reason: DeletionReason) -> &'static str {
    match reason {
        DeletionReason::UserRequest => "user_request",
        DeletionReason::ProjectDeletion => "project_deletion",
        DeletionReason::RetentionExpiry => "retention_expiry",
        DeletionReason::ConsentWithdrawal => "consent_withdrawal",
        DeletionReason::SecurityResponse => "security_response",
    }
}

const fn retention_mode_name(mode: DeletionRetentionMode) -> &'static str {
    match mode {
        DeletionRetentionMode::EraseContentRetainAudit => "erase_content_retain_audit",
    }
}

fn tombstone_remote_revision(tombstone: &DeletionTombstone) -> Result<u64, StorageError> {
    tombstone
        .prior_object_revision
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(
            tombstone.prior_object_revision,
        ))
}

fn digest_json(value: &impl Serialize) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn next_revision(value: u64) -> Result<u64, StorageError> {
    value
        .checked_add(1)
        .ok_or(StorageError::RevisionOverflow(value))
}
