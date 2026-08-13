use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    DeletionId, DeletionPropagationReceipt, DeletionPropagationStatus, DeletionReceiptId,
    DeletionRecord, DeletionSurface, PrivacyPluginScope, ProjectId, TenantId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::deletion_store::{load_deletion_record, update_deletion_record};
use crate::{ProjectStore, StorageError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionPropagationJobStatus {
    Pending,
    Leased,
    Applied,
    DeadLetter,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletionPropagationJob {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub deletion_id: DeletionId,
    pub object_id: String,
    pub object_kind: String,
    pub surface: DeletionSurface,
    pub deletion_generation: u64,
    pub tombstone_digest: String,
    pub status: DeletionPropagationJobStatus,
    pub attempts: u32,
    pub available_at: DateTime<Utc>,
    pub lease_owner: Option<String>,
    pub lease_generation: u64,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub last_error_code: Option<String>,
    pub receipt_id: Option<DeletionReceiptId>,
    pub receipt_digest: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProjectStore {
    pub fn claim_deletion_propagation_jobs(
        &mut self,
        surface: DeletionSurface,
        owner: &str,
        now: DateTime<Utc>,
        lease_for: Duration,
        limit: usize,
    ) -> Result<Vec<DeletionPropagationJob>, StorageError> {
        require_worker_surface(surface)?;
        if owner.trim().is_empty() || lease_for <= Duration::zero() || limit == 0 {
            return Err(StorageError::DomainDecode(
                "deletion propagation claim requires a worker, positive lease, and limit".into(),
            ));
        }
        let limit = i64::try_from(limit).map_err(|_| {
            StorageError::DomainDecode("deletion propagation claim limit overflow".into())
        })?;
        let transaction = self.connection.transaction()?;
        let now_text = now.to_rfc3339();
        let lease_expires_at = (now + lease_for).to_rfc3339();
        let candidates = {
            let mut statement = transaction.prepare(
                "SELECT project_id, deletion_id
                 FROM deletion_propagation_jobs
                 WHERE surface = ?1
                   AND ((status = 'pending' AND available_at <= ?2)
                     OR (status = 'leased' AND lease_expires_at <= ?2))
                 ORDER BY created_at, project_id, deletion_id
                 LIMIT ?3",
            )?;
            statement
                .query_map(params![surface_name(surface), now_text, limit], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut claimed = Vec::with_capacity(candidates.len());
        for (project_id, deletion_id) in candidates {
            let updated = transaction.execute(
                "UPDATE deletion_propagation_jobs
                 SET status = 'leased', lease_owner = ?4,
                     lease_generation = lease_generation + 1,
                     lease_expires_at = ?5, attempts = attempts + 1,
                     last_error_code = NULL, updated_at = ?2
                 WHERE project_id = ?1 AND deletion_id = ?3 AND surface = ?6
                   AND ((status = 'pending' AND available_at <= ?2)
                     OR (status = 'leased' AND lease_expires_at <= ?2))",
                params![
                    project_id,
                    now_text,
                    deletion_id,
                    owner,
                    lease_expires_at,
                    surface_name(surface),
                ],
            )?;
            if updated == 1 {
                claimed.push(load_job(
                    &transaction,
                    &ProjectId::from_stable(project_id),
                    &DeletionId::from_stable(deletion_id),
                    surface,
                )?);
            }
        }
        transaction.commit()?;
        Ok(claimed)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn heartbeat_deletion_propagation_job(
        &mut self,
        project_id: &ProjectId,
        deletion_id: &DeletionId,
        surface: DeletionSurface,
        owner: &str,
        generation: u64,
        now: DateTime<Utc>,
        extend_for: Duration,
    ) -> Result<DeletionPropagationJob, StorageError> {
        require_worker_surface(surface)?;
        if owner.trim().is_empty() || generation == 0 || extend_for <= Duration::zero() {
            return Err(StorageError::DomainDecode(
                "deletion propagation heartbeat requires a live lease".into(),
            ));
        }
        let updated = self.connection.execute(
            "UPDATE deletion_propagation_jobs
             SET lease_expires_at = ?7, updated_at = ?6
             WHERE project_id = ?1 AND deletion_id = ?2 AND surface = ?3
               AND status = 'leased' AND lease_owner = ?4 AND lease_generation = ?5
               AND lease_expires_at > ?6",
            params![
                project_id.as_str(),
                deletion_id.as_str(),
                surface_name(surface),
                owner,
                to_sql_u64(generation)?,
                now.to_rfc3339(),
                (now + extend_for).to_rfc3339(),
            ],
        )?;
        require_lease(updated, deletion_id, surface, owner, generation)?;
        load_job(&self.connection, project_id, deletion_id, surface)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn release_deletion_propagation_job(
        &mut self,
        project_id: &ProjectId,
        deletion_id: &DeletionId,
        surface: DeletionSurface,
        owner: &str,
        generation: u64,
        error_code: &str,
        available_at: DateTime<Utc>,
        now: DateTime<Utc>,
        dead_letter: bool,
    ) -> Result<DeletionPropagationJob, StorageError> {
        self.release_deletion_propagation_job_with_residual(
            project_id,
            deletion_id,
            surface,
            owner,
            generation,
            error_code,
            available_at,
            now,
            dead_letter,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn release_deletion_propagation_job_with_residual(
        &mut self,
        project_id: &ProjectId,
        deletion_id: &DeletionId,
        surface: DeletionSurface,
        owner: &str,
        generation: u64,
        error_code: &str,
        available_at: DateTime<Utc>,
        now: DateTime<Utc>,
        dead_letter: bool,
        residual_items: Option<u64>,
    ) -> Result<DeletionPropagationJob, StorageError> {
        let transaction = self.connection.transaction()?;
        let job = Self::release_deletion_propagation_job_in_transaction(
            &transaction,
            project_id,
            deletion_id,
            surface,
            owner,
            generation,
            error_code,
            available_at,
            now,
            dead_letter,
            residual_items,
            None,
        )?;
        transaction.commit()?;
        Ok(job)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn release_deletion_propagation_job_in_transaction(
        transaction: &Transaction<'_>,
        project_id: &ProjectId,
        deletion_id: &DeletionId,
        surface: DeletionSurface,
        owner: &str,
        generation: u64,
        error_code: &str,
        available_at: DateTime<Utc>,
        now: DateTime<Utc>,
        dead_letter: bool,
        residual_items: Option<u64>,
        privacy_scope: Option<&PrivacyPluginScope>,
    ) -> Result<DeletionPropagationJob, StorageError> {
        require_worker_surface(surface)?;
        if owner.trim().is_empty()
            || generation == 0
            || error_code.trim().is_empty()
            || available_at < now
        {
            return Err(StorageError::DomainDecode(
                "deletion propagation release requires exact lease and retry metadata".into(),
            ));
        }
        let status = if dead_letter {
            "dead_letter"
        } else {
            "pending"
        };
        if let Some(scope) = privacy_scope {
            require_privacy_plugin_scope(transaction, scope, now)?;
        }
        let updated = transaction.execute(
            "UPDATE deletion_propagation_jobs
             SET status = ?6, available_at = ?7, lease_owner = NULL,
                 lease_expires_at = NULL, last_error_code = ?8, updated_at = ?9
             WHERE project_id = ?1 AND deletion_id = ?2 AND surface = ?3
               AND status = 'leased' AND lease_owner = ?4 AND lease_generation = ?5
               AND lease_expires_at > ?9",
            params![
                project_id.as_str(),
                deletion_id.as_str(),
                surface_name(surface),
                owner,
                to_sql_u64(generation)?,
                status,
                available_at.to_rfc3339(),
                error_code,
                now.to_rfc3339(),
            ],
        )?;
        require_lease(updated, deletion_id, surface, owner, generation)?;
        let job = load_job(transaction, project_id, deletion_id, surface)?;
        let record =
            load_deletion_record(transaction, project_id, &job.object_kind, &job.object_id)?
                .ok_or_else(|| {
                    StorageError::DomainDecode("propagation job lacks deletion record".into())
                })?;
        if job.tenant_id != record.tombstone.tenant_id
            || job.object_id != record.tombstone.object_id
            || job.object_kind != record.tombstone.object_kind
            || job.deletion_generation != record.tombstone.deletion_generation
            || job.tombstone_digest != record.tombstone.tombstone_digest
        {
            return Err(StorageError::DomainDecode(
                "propagation job scope differs from deletion tombstone".into(),
            ));
        }
        let updated_record = if dead_letter {
            record.mark_surface_dead_letter(surface, error_code, residual_items, now)?
        } else {
            record.mark_surface_failed(surface, error_code, residual_items, now)?
        };
        if updated_record.revision != record.revision {
            update_deletion_record(transaction, &updated_record, record.revision)?;
        }
        transaction.execute(
            "INSERT INTO domain_events
               (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
             VALUES (?1, ?2, NULL, 'sync.deletion.surface_failed', ?3, ?4)",
            params![
                updated_record.tombstone.tenant_id.as_str(),
                updated_record.tombstone.project_id.as_str(),
                serde_json::to_string(&json!({
                    "deletionId": deletion_id,
                    "surface": surface,
                    "status": if dead_letter { "dead_letter" } else { "failed" },
                    "errorCode": error_code,
                    "residualItems": residual_items,
                    "recordStatus": updated_record.status(),
                }))?,
                now.to_rfc3339(),
            ],
        )?;
        Ok(job)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one transaction visibly fences the lease, persists the immutable receipt, advances the deletion surface, and emits metadata-only audit evidence"
    )]
    pub fn complete_deletion_propagation(
        &mut self,
        receipt: &DeletionPropagationReceipt,
        now: DateTime<Utc>,
    ) -> Result<DeletionRecord, StorageError> {
        let transaction = self.connection.transaction()?;
        let record =
            Self::complete_deletion_propagation_in_transaction(&transaction, receipt, now, None)?;
        transaction.commit()?;
        Ok(record)
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one scoped transaction fences the lease, receipt, deletion surface, and audit event"
    )]
    pub(crate) fn complete_deletion_propagation_in_transaction(
        transaction: &Transaction<'_>,
        receipt: &DeletionPropagationReceipt,
        now: DateTime<Utc>,
        privacy_scope: Option<&PrivacyPluginScope>,
    ) -> Result<DeletionRecord, StorageError> {
        require_worker_surface(receipt.surface)?;
        if let Some(scope) = privacy_scope {
            require_privacy_plugin_scope(transaction, scope, now)?;
        }
        if let Some(existing) = load_receipt(
            transaction,
            &receipt.project_id,
            &receipt.deletion_id,
            receipt.surface,
        )? {
            if existing != *receipt {
                return Err(StorageError::ImmutableRecordMismatch {
                    kind: "deletion propagation receipt",
                    id: receipt.id.to_string(),
                });
            }
            let record = load_deletion_record(
                transaction,
                &receipt.project_id,
                &receipt.object_kind,
                &receipt.object_id,
            )?
            .ok_or_else(|| StorageError::DomainDecode("receipt lacks deletion record".into()))?;
            return Ok(record);
        }

        let job = load_job(
            transaction,
            &receipt.project_id,
            &receipt.deletion_id,
            receipt.surface,
        )?;
        let record = load_deletion_record(
            transaction,
            &receipt.project_id,
            &receipt.object_kind,
            &receipt.object_id,
        )?
        .ok_or_else(|| {
            StorageError::DomainDecode("propagation job lacks deletion record".into())
        })?;
        receipt.validate_for(&record.tombstone, now)?;
        let lease_is_current = job.status == DeletionPropagationJobStatus::Leased
            && job.tenant_id == receipt.tenant_id
            && job.object_id == receipt.object_id
            && job.object_kind == receipt.object_kind
            && job.deletion_generation == receipt.deletion_generation
            && job.tombstone_digest == receipt.tombstone_digest
            && job.lease_owner.as_deref() == Some(receipt.worker_id.as_str())
            && job.lease_generation == receipt.lease_generation
            && job.lease_expires_at.is_some_and(|expires| expires > now);
        if !lease_is_current {
            return Err(lease_lost(receipt));
        }

        let previous_revision = record.revision;
        let updated_record = record.apply_receipt(receipt, now)?;
        let updated = transaction.execute(
            "UPDATE deletion_propagation_jobs
             SET status = 'applied', lease_owner = NULL, lease_expires_at = NULL,
                 last_error_code = NULL, receipt_id = ?6, receipt_digest = ?7,
                 updated_at = ?8
             WHERE project_id = ?1 AND deletion_id = ?2 AND surface = ?3
               AND status = 'leased' AND lease_owner = ?4 AND lease_generation = ?5
               AND lease_expires_at > ?8",
            params![
                receipt.project_id.as_str(),
                receipt.deletion_id.as_str(),
                surface_name(receipt.surface),
                receipt.worker_id.as_str(),
                to_sql_u64(receipt.lease_generation)?,
                receipt.id.as_str(),
                receipt.receipt_digest,
                now.to_rfc3339(),
            ],
        )?;
        require_lease(
            updated,
            &receipt.deletion_id,
            receipt.surface,
            receipt.worker_id.as_str(),
            receipt.lease_generation,
        )?;
        insert_receipt(transaction, receipt)?;
        update_deletion_record(transaction, &updated_record, previous_revision)?;
        transaction.execute(
            "INSERT INTO domain_events
               (tenant_id, project_id, mission_id, event_type, payload_json, recorded_at)
             VALUES (?1, ?2, NULL, 'sync.deletion.surface_applied', ?3, ?4)",
            params![
                receipt.tenant_id.as_str(),
                receipt.project_id.as_str(),
                serde_json::to_string(&json!({
                    "deletionId": receipt.deletion_id,
                    "surface": receipt.surface,
                    "deletionGeneration": receipt.deletion_generation,
                    "tombstoneDigest": receipt.tombstone_digest,
                    "receiptId": receipt.id,
                    "receiptDigest": receipt.receipt_digest,
                    "matchedItems": receipt.matched_items,
                    "deletedItems": receipt.deleted_items,
                    "residualItems": receipt.residual_items,
                    "complete": updated_record.is_complete(),
                }))?,
                now.to_rfc3339(),
            ],
        )?;
        Ok(updated_record)
    }

    pub fn load_deletion_propagation_job(
        &self,
        project_id: &ProjectId,
        deletion_id: &DeletionId,
        surface: DeletionSurface,
    ) -> Result<DeletionPropagationJob, StorageError> {
        require_worker_surface(surface)?;
        load_job(&self.connection, project_id, deletion_id, surface)
    }
}

pub(crate) fn require_privacy_plugin_scope(
    transaction: &Transaction<'_>,
    scope: &PrivacyPluginScope,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let row = transaction
        .query_row(
            "SELECT tenant_id, mission_id, scope_generation, policy_digest,
                    scope_digest, status, expires_at
             FROM privacy_plugin_scopes
             WHERE project_id = ?1 AND scope_id = ?2",
            params![scope.project_id.as_str(), scope.scope_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else {
        return Err(StorageError::PrivacyPluginScopeLost {
            scope_id: scope.scope_id.clone(),
            generation: scope.scope_generation,
        });
    };
    let generation = from_sql_u64(row.2, "privacy plugin scope generation")?;
    let expires_at = parse_time(&row.6)?;
    if row.0 != scope.tenant_id.as_str()
        || row.1 != scope.mission_id.as_str()
        || generation != scope.scope_generation
        || row.3 != scope.policy_digest
        || row.4 != scope.scope_digest
        || row.5 != "active"
        || expires_at <= now
    {
        return Err(StorageError::PrivacyPluginScopeLost {
            scope_id: scope.scope_id.clone(),
            generation: scope.scope_generation,
        });
    }
    Ok(())
}

pub(crate) fn enqueue_deletion_jobs(
    transaction: &Transaction<'_>,
    record: &DeletionRecord,
) -> Result<(), StorageError> {
    for (surface, state) in &record.surfaces {
        if state.status != DeletionPropagationStatus::Pending || !surface.is_worker_managed() {
            continue;
        }
        transaction.execute(
            "INSERT INTO deletion_propagation_jobs
               (tenant_id, project_id, deletion_id, object_id, object_kind, surface,
                deletion_generation, tombstone_digest, status, attempts, available_at,
                lease_owner, lease_generation, lease_expires_at, last_error_code,
                receipt_id, receipt_digest, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', 0, ?9,
                     NULL, 0, NULL, NULL, NULL, NULL, ?9, ?9)",
            params![
                record.tombstone.tenant_id.as_str(),
                record.tombstone.project_id.as_str(),
                record.tombstone.id.as_str(),
                record.tombstone.object_id,
                record.tombstone.object_kind,
                surface_name(*surface),
                to_sql_u64(record.tombstone.deletion_generation)?,
                record.tombstone.tombstone_digest,
                record.created_at.to_rfc3339(),
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn load_job(
    connection: &Connection,
    project_id: &ProjectId,
    deletion_id: &DeletionId,
    surface: DeletionSurface,
) -> Result<DeletionPropagationJob, StorageError> {
    let row = connection
        .query_row(
            "SELECT tenant_id, object_id, object_kind, deletion_generation,
                    tombstone_digest, status, attempts, available_at, lease_owner,
                    lease_generation, lease_expires_at, last_error_code, receipt_id,
                    receipt_digest, created_at, updated_at
             FROM deletion_propagation_jobs
             WHERE project_id = ?1 AND deletion_id = ?2 AND surface = ?3",
            params![
                project_id.as_str(),
                deletion_id.as_str(),
                surface_name(surface)
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, String>(15)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StorageError::ScopedRecordNotFound {
            kind: "deletion propagation job",
            project_id: project_id.clone(),
            id: format!("{}:{}", deletion_id, surface_name(surface)),
        })?;
    Ok(DeletionPropagationJob {
        tenant_id: TenantId::from_stable(row.0),
        project_id: project_id.clone(),
        deletion_id: deletion_id.clone(),
        object_id: row.1,
        object_kind: row.2,
        surface,
        deletion_generation: from_sql_u64(row.3, "deletion generation")?,
        tombstone_digest: row.4,
        status: decode_status(&row.5)?,
        attempts: u32::try_from(row.6)
            .map_err(|_| StorageError::DomainDecode("propagation attempts overflow".into()))?,
        available_at: parse_time(&row.7)?,
        lease_owner: row.8,
        lease_generation: from_sql_u64(row.9, "lease generation")?,
        lease_expires_at: row.10.as_deref().map(parse_time).transpose()?,
        last_error_code: row.11,
        receipt_id: row.12.map(DeletionReceiptId::from_stable),
        receipt_digest: row.13,
        created_at: parse_time(&row.14)?,
        updated_at: parse_time(&row.15)?,
    })
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    receipt: &DeletionPropagationReceipt,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO deletion_propagation_receipts
           (tenant_id, project_id, deletion_id, receipt_id, object_id, object_kind,
            surface, deletion_generation, tombstone_digest, worker_id, lease_generation,
            inventory_digest, matched_items, deleted_items, residual_items,
            verification_digest, completed_at, receipt_digest, receipt_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        params![
            receipt.tenant_id.as_str(),
            receipt.project_id.as_str(),
            receipt.deletion_id.as_str(),
            receipt.id.as_str(),
            receipt.object_id,
            receipt.object_kind,
            surface_name(receipt.surface),
            to_sql_u64(receipt.deletion_generation)?,
            receipt.tombstone_digest,
            receipt.worker_id.as_str(),
            to_sql_u64(receipt.lease_generation)?,
            receipt.inventory_digest,
            to_sql_u64(receipt.matched_items)?,
            to_sql_u64(receipt.deleted_items)?,
            to_sql_u64(receipt.residual_items)?,
            receipt.verification_digest,
            receipt.completed_at.to_rfc3339(),
            receipt.receipt_digest,
            serde_json::to_string(receipt)?,
        ],
    )?;
    Ok(())
}

fn load_receipt(
    connection: &Connection,
    project_id: &ProjectId,
    deletion_id: &DeletionId,
    surface: DeletionSurface,
) -> Result<Option<DeletionPropagationReceipt>, StorageError> {
    connection
        .query_row(
            "SELECT receipt_json FROM deletion_propagation_receipts
             WHERE project_id = ?1 AND deletion_id = ?2 AND surface = ?3",
            params![
                project_id.as_str(),
                deletion_id.as_str(),
                surface_name(surface)
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|json| Ok(serde_json::from_str(&json)?))
        .transpose()
}

fn require_worker_surface(surface: DeletionSurface) -> Result<(), StorageError> {
    if surface.is_worker_managed() {
        Ok(())
    } else {
        Err(StorageError::DeletionSurfaceNotWorkerManaged(
            surface_name(surface).to_owned(),
        ))
    }
}

fn require_lease(
    updated: usize,
    deletion_id: &DeletionId,
    surface: DeletionSurface,
    owner: &str,
    generation: u64,
) -> Result<(), StorageError> {
    if updated == 1 {
        Ok(())
    } else {
        Err(StorageError::DeletionPropagationLeaseLost {
            deletion_id: deletion_id.to_string(),
            surface: surface_name(surface).to_owned(),
            owner: owner.to_owned(),
            generation,
        })
    }
}

fn lease_lost(receipt: &DeletionPropagationReceipt) -> StorageError {
    StorageError::DeletionPropagationLeaseLost {
        deletion_id: receipt.deletion_id.to_string(),
        surface: surface_name(receipt.surface).to_owned(),
        owner: receipt.worker_id.to_string(),
        generation: receipt.lease_generation,
    }
}

const fn surface_name(surface: DeletionSurface) -> &'static str {
    match surface {
        DeletionSurface::LocalProjection => "local_projection",
        DeletionSurface::EncryptedCell => "encrypted_cell",
        DeletionSurface::ContextDerived => "context_derived",
        DeletionSurface::Cache => "cache",
        DeletionSurface::Replay => "replay",
        DeletionSurface::ObjectStorage => "object_storage",
    }
}

fn decode_status(value: &str) -> Result<DeletionPropagationJobStatus, StorageError> {
    match value {
        "pending" => Ok(DeletionPropagationJobStatus::Pending),
        "leased" => Ok(DeletionPropagationJobStatus::Leased),
        "applied" => Ok(DeletionPropagationJobStatus::Applied),
        "dead_letter" => Ok(DeletionPropagationJobStatus::DeadLetter),
        other => Err(StorageError::DomainDecode(format!(
            "unknown deletion propagation status {other}"
        ))),
    }
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, StorageError> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn to_sql_u64(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::RevisionOverflow(value))
}

fn from_sql_u64(value: i64, label: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::DomainDecode(format!("{label} cannot be negative")))
}
