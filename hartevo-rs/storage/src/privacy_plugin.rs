use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    DeletionPropagationReceipt, DeletionRecord, DeletionSurface, DeletionTombstone,
    PrivacyDeletionRequest, PrivacyLocalDeletionReceipt, PrivacyPluginError,
    PrivacyPluginRepository, PrivacyPluginScope, PrivacyPluginScopeStatus, PrivacyPropagationClaim,
    PrivacyPropagationResult, PrivacyProviderFailure, WorkerId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::deletion_propagation::load_job;
use crate::deletion_store::load_deletion_record;
use crate::sync_store::{LocalSyncOperation, LocalSyncStatus};
use crate::{ProjectStore, StorageError};

/// Storage-side adapter for the domain privacy plugin boundary.
///
/// The on-demand service and consumer depend only on
/// `PrivacyPluginRepository`; this adapter is the one place that translates
/// that boundary to the existing ProjectStore/deletion ledger. It never hands
/// a Store, keyring, database key, or secret reference to a provider.
#[derive(Debug)]
pub struct LocalPrivacyPluginLedger<'a> {
    store: &'a mut ProjectStore,
}

impl<'a> LocalPrivacyPluginLedger<'a> {
    pub fn new(store: &'a mut ProjectStore) -> Self {
        Self { store }
    }
}

impl PrivacyPluginRepository for LocalPrivacyPluginLedger<'_> {
    type Error = StorageError;

    fn open_scope(
        &mut self,
        scope: &PrivacyPluginScope,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        scope
            .validate(now)
            .map_err(|error| privacy_plugin_domain_error(&error))?;
        let project = self.store.load_project(&scope.project_id)?;
        let mission = self
            .store
            .load_mission(&scope.project_id, &scope.mission_id)?;
        let policy = self
            .store
            .ensure_local_retention_policy(&scope.project_id, now)?;
        if project.tenant_id != scope.tenant_id
            || mission.tenant_id != scope.tenant_id
            || mission.project_id != scope.project_id
        {
            return Err(StorageError::TenantScopeMismatch);
        }
        if policy.policy_digest != scope.policy_digest {
            return Err(StorageError::DomainDecode(
                "privacy plugin scope does not match the persisted retention policy".into(),
            ));
        }
        let transaction = self.store.connection.transaction()?;
        let existing = load_scope_row(&transaction, scope)?;
        match existing {
            None => insert_scope(&transaction, scope, now)?,
            Some(existing) if existing.is_exact_active(scope, now) => {}
            Some(existing)
                if existing.base_matches(scope)
                    && existing.status != PrivacyPluginScopeStatus::Active
                    && scope.scope_generation == existing.scope_generation + 1 =>
            {
                transaction.execute(
                    "UPDATE privacy_plugin_scopes
                     SET scope_generation = ?3, policy_digest = ?4, scope_digest = ?5,
                         status = 'active', issued_at = ?6, expires_at = ?7, updated_at = ?8
                     WHERE project_id = ?1 AND scope_id = ?2",
                    params![
                        scope.project_id.as_str(),
                        scope.scope_id,
                        to_sql_u64(scope.scope_generation)?,
                        scope.policy_digest,
                        scope.scope_digest,
                        scope.issued_at.to_rfc3339(),
                        scope.expires_at.to_rfc3339(),
                        now.to_rfc3339(),
                    ],
                )?;
            }
            Some(_) => {
                return Err(StorageError::PrivacyPluginScopeConflict {
                    scope_id: scope.scope_id.clone(),
                });
            }
        }
        transaction.commit()?;
        Ok(())
    }

    fn suspend_scope(
        &mut self,
        scope: &PrivacyPluginScope,
        status: PrivacyPluginScopeStatus,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        if !matches!(
            status,
            PrivacyPluginScopeStatus::Unmounted | PrivacyPluginScopeStatus::Revoked
        ) {
            return Err(StorageError::DomainDecode(
                "privacy plugin scope can only be suspended or revoked".into(),
            ));
        }
        let changed = self.store.connection.execute(
            "UPDATE privacy_plugin_scopes
             SET status = ?5, updated_at = ?6
             WHERE project_id = ?1 AND scope_id = ?2 AND scope_generation = ?3
               AND scope_digest = ?4 AND status = 'active'",
            params![
                scope.project_id.as_str(),
                scope.scope_id,
                to_sql_u64(scope.scope_generation)?,
                scope.scope_digest,
                scope_status_name(status),
                now.to_rfc3339(),
            ],
        )?;
        if changed != 1 {
            return Err(scope_lost(scope));
        }
        Ok(())
    }

    fn begin_local_deletion(
        &mut self,
        scope: &PrivacyPluginScope,
        request: &PrivacyDeletionRequest,
        tombstone: &DeletionTombstone,
        now: DateTime<Utc>,
    ) -> Result<PrivacyLocalDeletionReceipt, Self::Error> {
        request
            .validate_for(scope, now)
            .map_err(|error| privacy_plugin_domain_error(&error))?;
        if request.retention.action != hartevo_domain_kernel::RetentionAction::Delete {
            return Err(StorageError::DomainDecode(
                "privacy retention policy blocks local deletion".into(),
            ));
        }
        let policy = self.store.load_retention_policy(&scope.project_id)?;
        if policy.policy_digest != scope.policy_digest
            || request.retention.policy_digest != policy.policy_digest
        {
            return Err(StorageError::DomainDecode(
                "privacy plugin scope does not match the persisted retention policy".into(),
            ));
        }
        let operation = local_deletion_operation(scope, request, tombstone)?;
        let binding_operation = operation.clone();
        let binding_scope = scope.clone();
        let binding_request = request.clone();
        let binding_tombstone = tombstone.clone();
        let outcome = self
            .store
            .prepare_local_context_capsule_deletion_with_binding(
                &operation,
                tombstone,
                now,
                move |transaction, record| {
                    require_active_scope(transaction, &binding_scope, now)?;
                    ensure_plugin_deletion_binding(
                        transaction,
                        &binding_scope,
                        &binding_request,
                        &binding_tombstone,
                        record,
                        &binding_operation,
                    )
                },
            )?;
        let record = self.store.load_deletion_record(
            &scope.project_id,
            &request.object_kind,
            &request.object_id,
        )?;
        if let Some(existing) =
            load_plugin_local_receipt(&self.store.connection, scope, request, tombstone, now)?
        {
            return Ok(existing);
        }
        let receipt = PrivacyLocalDeletionReceipt::create(
            scope,
            request,
            tombstone,
            record.revision,
            outcome.operation.revision,
            outcome.duplicate,
            now,
        )
        .map_err(|error| privacy_plugin_domain_error(&error))?;
        finalize_plugin_local_receipt(&self.store.connection, scope, request, &receipt, now)?;
        Ok(receipt)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the scoped claim transaction keeps job lease, tombstone, request, and policy fences together"
    )]
    fn claim_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        surface: DeletionSurface,
        worker_id: &WorkerId,
        now: DateTime<Utc>,
        lease_for: Duration,
    ) -> Result<Option<PrivacyPropagationClaim>, Self::Error> {
        if !surface.is_worker_managed() || worker_id.as_str().trim().is_empty() {
            return Err(StorageError::DomainDecode(
                "privacy plugin claim requires a worker-managed surface and worker".into(),
            ));
        }
        if lease_for <= Duration::zero() {
            return Err(StorageError::DomainDecode(
                "privacy plugin claim requires a positive lease".into(),
            ));
        }
        let transaction = self.store.connection.transaction()?;
        require_active_scope(&transaction, scope, now)?;
        let candidate = transaction
            .query_row(
                "SELECT jobs.deletion_id
                 FROM deletion_propagation_jobs jobs
                 INNER JOIN privacy_plugin_deletion_requests requests
                   ON requests.project_id = jobs.project_id
                  AND requests.deletion_id = jobs.deletion_id
                 WHERE jobs.project_id = ?1 AND requests.scope_id = ?2
                   AND requests.tenant_id = ?3 AND requests.mission_id = ?4
                   AND requests.policy_digest = ?5
                   AND jobs.surface = ?6
                   AND ((jobs.status = 'pending' AND jobs.available_at <= ?7)
                     OR (jobs.status = 'leased' AND jobs.lease_expires_at <= ?7))
                 ORDER BY jobs.created_at, jobs.deletion_id
                 LIMIT 1",
                params![
                    scope.project_id.as_str(),
                    scope.scope_id,
                    scope.tenant_id.as_str(),
                    scope.mission_id.as_str(),
                    scope.policy_digest,
                    surface_name(surface),
                    now.to_rfc3339(),
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(deletion_id) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        let lease_expires_at = (now + lease_for).to_rfc3339();
        let changed = transaction.execute(
            "UPDATE deletion_propagation_jobs
             SET status = 'leased', lease_owner = ?4,
                 lease_generation = lease_generation + 1,
                 lease_expires_at = ?5, attempts = attempts + 1,
                 last_error_code = NULL, updated_at = ?2
             WHERE project_id = ?1 AND deletion_id = ?3 AND surface = ?6
               AND ((status = 'pending' AND available_at <= ?2)
                 OR (status = 'leased' AND lease_expires_at <= ?2))",
            params![
                scope.project_id.as_str(),
                now.to_rfc3339(),
                deletion_id,
                worker_id.as_str(),
                lease_expires_at,
                surface_name(surface),
            ],
        )?;
        if changed != 1 {
            transaction.commit()?;
            return Ok(None);
        }
        let job = load_job(
            &transaction,
            &scope.project_id,
            &hartevo_domain_kernel::DeletionId::from_stable(deletion_id),
            surface,
        )?;
        let record = load_deletion_record(
            &transaction,
            &scope.project_id,
            &job.object_kind,
            &job.object_id,
        )?
        .ok_or_else(|| {
            StorageError::DomainDecode("privacy plugin job lacks deletion record".into())
        })?;
        if record.tombstone.tenant_id != scope.tenant_id
            || record.tombstone.project_id != scope.project_id
            || record.tombstone.id != job.deletion_id
            || record.tombstone.tombstone_digest != job.tombstone_digest
        {
            return Err(StorageError::PrivacyPluginRequestScopeMismatch);
        }
        let claim = PrivacyPropagationClaim::create(
            scope.clone(),
            job.deletion_id.clone(),
            job.tenant_id.clone(),
            job.project_id.clone(),
            job.object_id.clone(),
            job.object_kind.clone(),
            surface,
            record.tombstone.clone(),
            worker_id.clone(),
            job.lease_generation,
            job.lease_expires_at.ok_or_else(|| {
                StorageError::DomainDecode("leased privacy plugin job lacks expiry".into())
            })?,
            job.attempts,
        )
        .map_err(|error| privacy_plugin_domain_error(&error))?;
        transaction.commit()?;
        Ok(Some(claim))
    }

    fn complete_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        claim: &PrivacyPropagationClaim,
        receipt: &DeletionPropagationReceipt,
        now: DateTime<Utc>,
    ) -> Result<PrivacyPropagationResult, Self::Error> {
        claim
            .validate()
            .map_err(|error| privacy_plugin_domain_error(&error))?;
        if claim.scope != *scope
            || claim.deletion_id != receipt.deletion_id
            || claim.project_id != receipt.project_id
            || claim.object_id != receipt.object_id
            || claim.object_kind != receipt.object_kind
            || claim.surface != receipt.surface
            || claim.deletion_generation != receipt.deletion_generation
            || claim.tombstone_digest != receipt.tombstone_digest
            || claim.worker_id != receipt.worker_id
            || claim.lease_generation != receipt.lease_generation
        {
            return Err(StorageError::PrivacyPluginRequestScopeMismatch);
        }
        let transaction = self.store.connection.transaction()?;
        require_active_scope(&transaction, scope, now)?;
        let record = ProjectStore::complete_deletion_propagation_in_transaction(
            &transaction,
            receipt,
            now,
            Some(scope),
        )?;
        let result = propagation_result(&record, receipt.surface)?;
        transaction.commit()?;
        Ok(result)
    }

    fn release_propagation(
        &mut self,
        scope: &PrivacyPluginScope,
        claim: &PrivacyPropagationClaim,
        failure: &PrivacyProviderFailure,
        dead_letter: bool,
        available_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        claim
            .validate()
            .map_err(|error| privacy_plugin_domain_error(&error))?;
        if claim.scope != *scope {
            return Err(StorageError::PrivacyPluginRequestScopeMismatch);
        }
        let transaction = self.store.connection.transaction()?;
        require_active_scope(&transaction, scope, now)?;
        ProjectStore::release_deletion_propagation_job_in_transaction(
            &transaction,
            &claim.project_id,
            &claim.deletion_id,
            claim.surface,
            claim.worker_id.as_str(),
            claim.lease_generation,
            &failure.error_code,
            available_at,
            now,
            dead_letter,
            failure.residual_items,
            Some(scope),
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct StoredScope {
    tenant_id: String,
    project_id: String,
    mission_id: String,
    scope_id: String,
    scope_generation: u64,
    policy_digest: String,
    scope_digest: String,
    status: PrivacyPluginScopeStatus,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl StoredScope {
    fn base_matches(&self, scope: &PrivacyPluginScope) -> bool {
        self.tenant_id == scope.tenant_id.as_str()
            && self.project_id == scope.project_id.as_str()
            && self.mission_id == scope.mission_id.as_str()
            && self.scope_id == scope.scope_id
            && self.policy_digest == scope.policy_digest
    }

    fn is_exact_active(&self, scope: &PrivacyPluginScope, now: DateTime<Utc>) -> bool {
        self.base_matches(scope)
            && self.scope_generation == scope.scope_generation
            && self.scope_digest == scope.scope_digest
            && self.status == PrivacyPluginScopeStatus::Active
            && self.issued_at == scope.issued_at
            && self.expires_at == scope.expires_at
            && self.expires_at > now
    }
}

fn load_scope_row(
    connection: &Connection,
    scope: &PrivacyPluginScope,
) -> Result<Option<StoredScope>, StorageError> {
    connection
        .query_row(
            "SELECT tenant_id, project_id, mission_id, scope_id, scope_generation,
                    policy_digest, scope_digest, status, issued_at, expires_at
             FROM privacy_plugin_scopes
             WHERE project_id = ?1 AND scope_id = ?2",
            params![scope.project_id.as_str(), scope.scope_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(StoredScope {
                tenant_id: row.0,
                project_id: row.1,
                mission_id: row.2,
                scope_id: row.3,
                scope_generation: from_sql_u64(row.4, "privacy plugin scope generation")?,
                policy_digest: row.5,
                scope_digest: row.6,
                status: decode_scope_status(&row.7)?,
                issued_at: parse_time(&row.8)?,
                expires_at: parse_time(&row.9)?,
            })
        })
        .transpose()
}

fn insert_scope(
    transaction: &Transaction<'_>,
    scope: &PrivacyPluginScope,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    transaction.execute(
        "INSERT INTO privacy_plugin_scopes
           (tenant_id, project_id, mission_id, scope_id, scope_generation,
            policy_digest, scope_digest, status, issued_at, expires_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', ?8, ?9, ?10)",
        params![
            scope.tenant_id.as_str(),
            scope.project_id.as_str(),
            scope.mission_id.as_str(),
            scope.scope_id,
            to_sql_u64(scope.scope_generation)?,
            scope.policy_digest,
            scope.scope_digest,
            scope.issued_at.to_rfc3339(),
            scope.expires_at.to_rfc3339(),
            now.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn require_active_scope(
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
        return Err(scope_lost(scope));
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
        return Err(scope_lost(scope));
    }
    Ok(())
}

fn local_deletion_operation(
    scope: &PrivacyPluginScope,
    request: &PrivacyDeletionRequest,
    tombstone: &DeletionTombstone,
) -> Result<LocalSyncOperation, StorageError> {
    let request_body = json!({
        "schemaVersion": 1,
        "scopeDigest": scope.scope_digest,
        "missionId": request.mission_id,
        "deletion": tombstone,
        "policyDigest": request.retention.policy_digest,
        "consentId": request.consent.id,
    });
    let intent_digest = digest_json(&(
        &scope.scope_digest,
        &request.id,
        &request.idempotency_key_digest,
        &request.retention.policy_digest,
        &request.consent.id,
        &tombstone.tombstone_digest,
    ))?;
    Ok(LocalSyncOperation {
        tenant_id: scope.tenant_id.clone(),
        project_id: scope.project_id.clone(),
        idempotency_key_digest: request.idempotency_key_digest.clone(),
        intent_digest,
        request_digest: digest_json(&request_body)?,
        cell: request.local_plan.cell.clone(),
        object_id: request.object_id.clone(),
        object_kind: request.object_kind.clone(),
        target_revision: request.prior_object_revision.checked_add(1).ok_or(
            StorageError::RevisionOverflow(request.prior_object_revision),
        )?,
        key_version: request.local_plan.key_version,
        content_digest: tombstone.tombstone_digest.clone(),
        tombstone: true,
        request: request_body,
        status: LocalSyncStatus::Prepared,
        remote_revision: None,
        remote_duplicate: false,
        last_error_code: None,
        revision: 1,
        created_at: request.requested_at,
        updated_at: request.requested_at,
    })
}

fn ensure_plugin_deletion_binding(
    transaction: &Transaction<'_>,
    scope: &PrivacyPluginScope,
    request: &PrivacyDeletionRequest,
    tombstone: &DeletionTombstone,
    record: &DeletionRecord,
    operation: &LocalSyncOperation,
) -> Result<(), StorageError> {
    let existing = transaction
        .query_row(
            "SELECT tenant_id, scope_id, mission_id, idempotency_key_digest, object_id,
                    object_kind, scope_generation, policy_digest, consent_id,
                    tombstone_digest, local_record_revision, operation_revision
             FROM privacy_plugin_deletion_requests
             WHERE project_id = ?1 AND deletion_id = ?2",
            params![scope.project_id.as_str(), request.id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?;
    if let Some(row) = existing {
        let exact = row.0 == scope.tenant_id.as_str()
            && row.1 == scope.scope_id
            && row.2 == scope.mission_id.as_str()
            && row.3 == request.idempotency_key_digest
            && row.4 == request.object_id
            && row.5 == request.object_kind
            && from_sql_u64(row.6, "privacy plugin scope generation")? == scope.scope_generation
            && row.7 == request.retention.policy_digest
            && row.8 == request.consent.id.as_str()
            && row.9 == tombstone.tombstone_digest
            && record.revision >= from_sql_u64(row.10, "privacy plugin local record revision")?
            && operation.revision >= from_sql_u64(row.11, "privacy plugin operation revision")?;
        if !exact {
            return Err(StorageError::PrivacyPluginRequestScopeMismatch);
        }
        return Ok(());
    }
    transaction.execute(
        "INSERT INTO privacy_plugin_deletion_requests
           (tenant_id, project_id, scope_id, mission_id, deletion_id,
            idempotency_key_digest, object_id, object_kind, scope_generation,
            policy_digest, consent_id, tombstone_digest, local_record_revision,
            operation_revision, local_receipt_digest, local_receipt_json,
            requested_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, NULL, NULL, ?15, ?16)",
        params![
            scope.tenant_id.as_str(),
            scope.project_id.as_str(),
            scope.scope_id,
            scope.mission_id.as_str(),
            request.id.as_str(),
            request.idempotency_key_digest,
            request.object_id,
            request.object_kind,
            to_sql_u64(scope.scope_generation)?,
            request.retention.policy_digest,
            request.consent.id.as_str(),
            tombstone.tombstone_digest,
            to_sql_u64(record.revision)?,
            to_sql_u64(operation.revision)?,
            request.requested_at.to_rfc3339(),
            request.requested_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn load_plugin_local_receipt(
    connection: &Connection,
    scope: &PrivacyPluginScope,
    request: &PrivacyDeletionRequest,
    tombstone: &DeletionTombstone,
    now: DateTime<Utc>,
) -> Result<Option<PrivacyLocalDeletionReceipt>, StorageError> {
    let value = connection
        .query_row(
            "SELECT local_receipt_json FROM privacy_plugin_deletion_requests
             WHERE project_id = ?1 AND deletion_id = ?2
               AND scope_id = ?3 AND scope_generation = ?4
               AND tombstone_digest = ?5",
            params![
                scope.project_id.as_str(),
                request.id.as_str(),
                scope.scope_id,
                to_sql_u64(scope.scope_generation)?,
                tombstone.tombstone_digest,
            ],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?;
    value
        .flatten()
        .map(|json| {
            let receipt: PrivacyLocalDeletionReceipt = serde_json::from_str(&json)?;
            receipt
                .validate_for(scope, request, tombstone, now)
                .map_err(|error| privacy_plugin_domain_error(&error))?;
            Ok(receipt)
        })
        .transpose()
}

fn finalize_plugin_local_receipt(
    connection: &Connection,
    scope: &PrivacyPluginScope,
    request: &PrivacyDeletionRequest,
    receipt: &PrivacyLocalDeletionReceipt,
    now: DateTime<Utc>,
) -> Result<(), StorageError> {
    let transaction = connection.unchecked_transaction()?;
    let existing = transaction
        .query_row(
            "SELECT local_receipt_digest, local_receipt_json
             FROM privacy_plugin_deletion_requests
             WHERE project_id = ?1 AND deletion_id = ?2 AND scope_id = ?3
               AND scope_generation = ?4",
            params![
                scope.project_id.as_str(),
                request.id.as_str(),
                scope.scope_id,
                to_sql_u64(scope.scope_generation)?,
            ],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?;
    if let Some((digest, json)) = existing.as_ref() {
        match (digest, json) {
            (Some(digest), Some(json)) => {
                let stored: PrivacyLocalDeletionReceipt = serde_json::from_str(json)?;
                if digest != &receipt.receipt_digest || stored != *receipt {
                    return Err(StorageError::ImmutableRecordMismatch {
                        kind: "privacy plugin local deletion receipt",
                        id: request.id.to_string(),
                    });
                }
                transaction.commit()?;
                return Ok(());
            }
            (None, None) => {}
            _ => {
                return Err(StorageError::DomainDecode(
                    "privacy plugin local deletion receipt is partially persisted".into(),
                ));
            }
        }
    }
    if existing.is_none() {
        return Err(StorageError::PrivacyPluginRequestScopeMismatch);
    }
    let changed = transaction.execute(
        "UPDATE privacy_plugin_deletion_requests
         SET local_receipt_digest = ?5, local_receipt_json = ?6, updated_at = ?7
         WHERE project_id = ?1 AND deletion_id = ?2 AND scope_id = ?3
           AND scope_generation = ?4
           AND (local_receipt_digest IS NULL OR local_receipt_digest = ?5)",
        params![
            scope.project_id.as_str(),
            request.id.as_str(),
            scope.scope_id,
            to_sql_u64(scope.scope_generation)?,
            receipt.receipt_digest,
            serde_json::to_string(receipt)?,
            now.to_rfc3339(),
        ],
    )?;
    if changed != 1 {
        return Err(StorageError::PrivacyPluginRequestScopeMismatch);
    }
    transaction.commit()?;
    Ok(())
}

fn propagation_result(
    record: &DeletionRecord,
    surface: DeletionSurface,
) -> Result<PrivacyPropagationResult, StorageError> {
    let state = record.surfaces.get(&surface).ok_or_else(|| {
        StorageError::DomainDecode("deletion record lacks propagation surface".into())
    })?;
    Ok(PrivacyPropagationResult {
        deletion_id: record.tombstone.id.clone(),
        project_id: record.tombstone.project_id.clone(),
        surface,
        surface_status: state.status,
        request_status: record.status(),
        residual_items: state.residual_items,
        receipt_digest: state.evidence_digest.clone(),
        record_revision: record.revision,
    })
}

fn scope_lost(scope: &PrivacyPluginScope) -> StorageError {
    StorageError::PrivacyPluginScopeLost {
        scope_id: scope.scope_id.clone(),
        generation: scope.scope_generation,
    }
}

fn privacy_plugin_domain_error(error: &PrivacyPluginError) -> StorageError {
    StorageError::DomainDecode(error.to_string())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, StorageError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

const fn scope_status_name(status: PrivacyPluginScopeStatus) -> &'static str {
    match status {
        PrivacyPluginScopeStatus::Active => "active",
        PrivacyPluginScopeStatus::Unmounted => "unmounted",
        PrivacyPluginScopeStatus::Revoked => "revoked",
    }
}

fn decode_scope_status(value: &str) -> Result<PrivacyPluginScopeStatus, StorageError> {
    match value {
        "active" => Ok(PrivacyPluginScopeStatus::Active),
        "unmounted" => Ok(PrivacyPluginScopeStatus::Unmounted),
        "revoked" => Ok(PrivacyPluginScopeStatus::Revoked),
        other => Err(StorageError::DomainDecode(format!(
            "unknown privacy plugin scope status {other}"
        ))),
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ActorId, ConsentRecordId, ContextBranch, ContextBranchId, ContextBudget, ContextCapsule,
        ContextCapsuleId, ContextDataPolicy, ContextInputRefs, ContextMergePolicy,
        ContextReturnContract, ContextWorkerMailboxId, ContextWorkingSet, ContextWorkingSetId,
        ContextWorkspace, ContextWorkspaceId, ContinuationLedger, CurrencyCode, DataClassification,
        DeletionId, DeletionPropagationReceipt, DeletionPropagationStatus, DeletionReason,
        DeletionRecord, DeletionSurface, Mission, MissionContract, MissionId, Money,
        PrivacyConsentPurpose, PrivacyDeletionConsent, PrivacyDeletionRequest,
        PrivacyLocalDeletionPlan, PrivacyPluginConsumer, PrivacyPluginRepository,
        PrivacyPluginScope, PrivacyPluginScopeStatus, PrivacyPluginService,
        PrivacyPropagationClaim, PrivacyPropagationEvidence, PrivacyPropagationProvider,
        PrivacyProviderFailure, Project, ProjectDataCell, ProjectId, RetentionAction,
        RetentionDecision, RetentionPolicy, StorageMode, Task, TaskId, TaskStatus, TenantId,
        WorkerHandle, WorkerId, WorkerLease, WorkerLeaseId, WorkerMailbox,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{
        DeletionPropagationJobStatus, LocalProjectCloudRegistration, PendingEvent,
        ProjectCloudRegistrationStatus,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn project(store: &mut ProjectStore, id: &str, tenant: &str, mission_id: &str) -> ProjectId {
        let project = Project::create_local(
            TenantId::from(tenant),
            ProjectId::from(id),
            "privacy plugin fixture",
            "",
            PathBuf::from(format!("/tmp/{id}")),
            StorageMode::LocalExisting,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        let mission = Mission::compile(
            TenantId::from(tenant),
            MissionId::from(mission_id),
            project.id.clone(),
            "privacy deletion mission",
            MissionContract::bootstrap("delete one scoped object", [], now()),
            now(),
        )
        .expect("mission");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.created", json!({}), now())],
            )
            .expect("persist mission");
        project.id
    }

    fn local_registration(project: &Project) -> LocalProjectCloudRegistration {
        let request = json!({
            "scope": {"cell": "eu", "tenantId": project.tenant_id},
            "projectId": project.id,
            "encryptionMode": "team_envelope",
            "remoteExecutionOptIn": false,
            "metadataDigest": "c".repeat(64),
            "initialPayload": {
                "keyVersion": 1,
                "nonce": vec![7; 12],
                "ciphertext": vec![9; 32],
                "aadDigest": "a".repeat(64),
                "contentDigest": "c".repeat(64),
            },
            "idempotencyKeyDigest": "d".repeat(64),
            "createdAt": now(),
        });
        LocalProjectCloudRegistration {
            tenant_id: project.tenant_id.clone(),
            project_id: project.id.clone(),
            cell: "eu".into(),
            encryption_mode: "team_envelope".into(),
            remote_execution_opt_in: false,
            idempotency_key_digest: "d".repeat(64),
            intent_digest: "e".repeat(64),
            request_digest: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&request).expect("request"))
            ),
            key_version: 1,
            content_digest: "c".repeat(64),
            request,
            authorized_by: "privacy-owner".into(),
            authorization_evidence_digest: "f".repeat(64),
            status: ProjectCloudRegistrationStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixture exercises the real local context deletion path and keeps every authority dependency explicit"
    )]
    fn local_context_fixture() -> (ProjectStore, ProjectId, ContextCapsule) {
        let mut store = ProjectStore::in_memory().expect("store");
        let mut project = Project::create_local(
            TenantId::from("tenant-local-plugin"),
            ProjectId::from("project-local-plugin"),
            "local privacy plugin project",
            "",
            PathBuf::from("/tmp/hartevo-local-plugin"),
            StorageMode::LocalEncryptedSync,
        )
        .expect("project");
        store
            .create_project_atomic(
                &project,
                &[PendingEvent::new("project.created", json!({}), now())],
            )
            .expect("persist project");
        project
            .select_data_cell(ProjectDataCell::Eu)
            .expect("EU cell");
        let registration = local_registration(&project);
        store
            .prepare_project_cloud_registration(&project, 1, &registration, now())
            .expect("prepare registration");
        store
            .record_project_cloud_registration_applied(&project.id, 1, 1, false, now())
            .expect("apply registration");

        let mut contract = MissionContract::bootstrap(
            "Delete one local context capsule",
            ["privacy.read".to_owned()],
            now(),
        );
        contract.budget = Money::new(5_000, CurrencyCode::parse("USD").expect("USD"));
        let mut mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-local-plugin"),
            project.id.clone(),
            "local deletion mission",
            contract,
            now(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-local-plugin"),
                    title: "Delete the local capsule".into(),
                    status: TaskStatus::Ready,
                    capability: "privacy.read".into(),
                }],
                now(),
            )
            .expect("mission task");
        store
            .create_mission_atomic(
                &mission,
                &[PendingEvent::new("mission.created", json!({}), now())],
            )
            .expect("persist mission");

        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-local-plugin"),
            &mission,
            1,
            "privacy-policy/v1",
            BTreeSet::from(["privacy.read".to_owned()]),
            ContextBudget {
                token_limit: 5_000,
                cost_limit: Money::new(500, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::minutes(15),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace");
        let working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-set-local-plugin"),
            &workspace,
            now(),
        )
        .expect("working set");
        let continuation = ContinuationLedger::create(
            hartevo_domain_kernel::ContextContinuationLedgerId::from("continuation-local-plugin"),
            &workspace,
            now(),
        )
        .expect("continuation");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-local-plugin"),
            &workspace,
            None,
            "local deletion branch",
            "1".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            now(),
        )
        .expect("branch");
        let lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-local-plugin"),
            &workspace,
            &branch,
            WorkerId::from("worker-local-plugin"),
            1,
            "2".repeat(64),
            Some("3".repeat(64)),
            now() + Duration::minutes(14),
            now(),
        )
        .expect("lease");
        let capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-local-plugin"),
            &workspace,
            &branch,
            &lease,
            &mission,
            "Delete the local capsule",
            TaskId::from("task-local-plugin"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["privacy.read".to_owned()]),
            ContextBudget {
                token_limit: 1_000,
                cost_limit: Money::new(100, CurrencyCode::parse("USD").expect("USD")),
                deadline_at: now() + Duration::minutes(10),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.privacy.deletion".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["result".to_owned()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 4_096,
            },
            now() + Duration::minutes(9),
            now(),
        )
        .expect("capsule");
        let handle = WorkerHandle::create(&workspace, &branch, &lease, &capsule, None, now())
            .expect("worker handle");
        let mailbox = WorkerMailbox::create(
            ContextWorkerMailboxId::from("mailbox-local-plugin"),
            &handle,
            4,
            now(),
        )
        .expect("mailbox");
        store
            .create_context_workspace(
                &workspace,
                &working_set,
                &continuation,
                &[PendingEvent::new(
                    "context.workspace.created",
                    json!({}),
                    now(),
                )],
                now(),
            )
            .expect("persist workspace");
        store
            .issue_context_capsule_bundle(
                &workspace,
                std::slice::from_ref(&branch),
                &lease,
                &capsule,
                &handle,
                &mailbox,
                &[],
                &[PendingEvent::new(
                    "context.capsule.issued",
                    json!({}),
                    now(),
                )],
                now(),
            )
            .expect("persist capsule");
        let mut cancelled = capsule;
        cancelled
            .cancel(now() + Duration::seconds(1))
            .expect("cancel capsule");
        store
            .update_context_capsule(
                &cancelled,
                1,
                &[PendingEvent::new(
                    "context.capsule.cancelled",
                    json!({}),
                    now(),
                )],
                now() + Duration::seconds(1),
            )
            .expect("persist cancellation");
        (store, project.id, cancelled)
    }

    fn scope(
        tenant: &str,
        project_id: &ProjectId,
        mission_id: &str,
        scope_id: &str,
    ) -> PrivacyPluginScope {
        let policy = RetentionPolicy::local_default(now()).expect("default policy");
        PrivacyPluginScope::issue(
            TenantId::from(tenant),
            project_id.clone(),
            MissionId::from(mission_id),
            scope_id,
            policy.policy_digest,
            now(),
            now() + Duration::minutes(30),
        )
        .expect("scope")
    }

    fn request(scope: &PrivacyPluginScope, suffix: &str) -> PrivacyDeletionRequest {
        PrivacyDeletionRequest {
            id: DeletionId::from_stable(format!("deletion-{suffix}")),
            mission_id: scope.mission_id.clone(),
            object_id: format!("object-{suffix}"),
            object_kind: "context_capsule".into(),
            prior_object_revision: 1,
            deletion_generation: 1,
            reason: DeletionReason::UserRequest,
            consent: PrivacyDeletionConsent {
                id: ConsentRecordId::from_stable(format!("consent-{suffix}")),
                purpose: PrivacyConsentPurpose::MissionDeletion,
                actor_id: ActorId::from("privacy-owner"),
                evidence_digest: "b".repeat(64),
                granted_at: now(),
                expires_at: now() + Duration::minutes(20),
            },
            retention: RetentionDecision {
                classification: DataClassification::Restricted,
                action: RetentionAction::Delete,
                due_at: now(),
                legal_hold: false,
                policy_digest: scope.policy_digest.clone(),
            },
            idempotency_key_digest: format!("{:x}", Sha256::digest(suffix.as_bytes())),
            local_plan: PrivacyLocalDeletionPlan {
                cell: "us".into(),
                key_version: 1,
            },
            requested_at: now(),
        }
    }

    fn seed_record(
        store: &mut ProjectStore,
        scope: &PrivacyPluginScope,
        request: &PrivacyDeletionRequest,
    ) -> DeletionTombstone {
        let tombstone = request.tombstone(scope).expect("tombstone");
        let record = DeletionRecord::pending(
            tombstone.clone(),
            2,
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            now(),
        )
        .expect("deletion record");
        let operation = LocalSyncOperation {
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            idempotency_key_digest: request.idempotency_key_digest.clone(),
            intent_digest: "f".repeat(64),
            request_digest: "1".repeat(64),
            cell: "us".into(),
            object_id: request.object_id.clone(),
            object_kind: request.object_kind.clone(),
            target_revision: 2,
            key_version: 1,
            content_digest: tombstone.tombstone_digest.clone(),
            tombstone: true,
            request: json!({"scopeDigest": scope.scope_digest}),
            status: LocalSyncStatus::Prepared,
            remote_revision: None,
            remote_duplicate: false,
            last_error_code: None,
            revision: 1,
            created_at: now(),
            updated_at: now(),
        };
        let transaction = store.connection.transaction().expect("transaction");
        crate::deletion_store::insert_deletion_record(&transaction, &record)
            .expect("insert deletion record");
        ensure_plugin_deletion_binding(
            &transaction,
            scope,
            request,
            &tombstone,
            &record,
            &operation,
        )
        .expect("insert plugin binding");
        transaction.commit().expect("commit seed");
        tombstone
    }

    fn receipt_for(
        claim: &PrivacyPropagationClaim,
        completed_at: DateTime<Utc>,
    ) -> DeletionPropagationReceipt {
        DeletionPropagationReceipt::create(
            hartevo_domain_kernel::DeletionReceiptId::from_stable(format!(
                "privacy-plugin:{}",
                claim.operation_digest
            )),
            &claim.tombstone,
            claim.surface,
            claim.worker_id.clone(),
            claim.lease_generation,
            "1".repeat(64),
            0,
            0,
            0,
            "2".repeat(64),
            completed_at,
        )
        .expect("receipt")
    }

    #[test]
    fn scoped_claim_restart_and_exact_receipt_replay_fence_stale_lease() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project_id = project(
            &mut store,
            "project-plugin-lease",
            "tenant-plugin-lease",
            "mission-plugin-lease",
        );
        let scope = scope(
            "tenant-plugin-lease",
            &project_id,
            "mission-plugin-lease",
            "mission-deletion",
        );
        let request = request(&scope, "lease");
        {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger.open_scope(&scope, now()).expect("open scope");
        }
        seed_record(&mut store, &scope, &request);

        let old_claim = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .claim_propagation(
                    &scope,
                    DeletionSurface::Cache,
                    &WorkerId::from("worker-old"),
                    now(),
                    Duration::seconds(5),
                )
                .expect("old claim")
                .expect("pending job")
        };
        let new_claim = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .claim_propagation(
                    &scope,
                    DeletionSurface::Cache,
                    &WorkerId::from("worker-new"),
                    now() + Duration::seconds(6),
                    Duration::seconds(5),
                )
                .expect("restart claim")
                .expect("expired job reclaimed")
        };
        assert_eq!(old_claim.lease_generation, 1);
        assert_eq!(new_claim.lease_generation, 2);

        let stale_receipt = receipt_for(&old_claim, now() + Duration::seconds(6));
        let stale = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger.complete_propagation(
                &scope,
                &old_claim,
                &stale_receipt,
                now() + Duration::seconds(6),
            )
        };
        assert!(matches!(
            stale,
            Err(StorageError::DeletionPropagationLeaseLost { .. })
        ));

        let receipt = receipt_for(&new_claim, now() + Duration::seconds(6));
        let applied = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .complete_propagation(&scope, &new_claim, &receipt, now() + Duration::seconds(6))
                .expect("apply current receipt")
        };
        assert_eq!(applied.surface_status, DeletionPropagationStatus::Applied);
        let replay = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .complete_propagation(&scope, &new_claim, &receipt, now() + Duration::seconds(7))
                .expect("exact receipt replay")
        };
        assert_eq!(replay, applied);
    }

    #[test]
    fn unmount_and_revoke_fence_old_claim_without_dropping_job() {
        for (status, suffix) in [
            (PrivacyPluginScopeStatus::Unmounted, "unmounted"),
            (PrivacyPluginScopeStatus::Revoked, "revoked"),
        ] {
            let mut store = ProjectStore::in_memory().expect("store");
            let mission_id = format!("mission-{suffix}");
            let project_id = project(
                &mut store,
                &format!("project-{suffix}"),
                "tenant-fence",
                &mission_id,
            );
            let scope = scope("tenant-fence", &project_id, &mission_id, suffix);
            let request = request(&scope, suffix);
            {
                let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
                ledger.open_scope(&scope, now()).expect("open scope");
            }
            seed_record(&mut store, &scope, &request);
            let claim = {
                let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
                ledger
                    .claim_propagation(
                        &scope,
                        DeletionSurface::Replay,
                        &WorkerId::from("worker-fenced"),
                        now(),
                        Duration::minutes(5),
                    )
                    .expect("claim")
                    .expect("job")
            };
            {
                let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
                ledger
                    .suspend_scope(&scope, status, now() + Duration::seconds(1))
                    .expect("fence scope");
                let error = ledger.complete_propagation(
                    &scope,
                    &claim,
                    &receipt_for(&claim, now() + Duration::seconds(1)),
                    now() + Duration::seconds(1),
                );
                assert!(matches!(
                    error,
                    Err(StorageError::PrivacyPluginScopeLost { .. })
                ));
            }
            let job = store
                .load_deletion_propagation_job(
                    &project_id,
                    &claim.deletion_id,
                    DeletionSurface::Replay,
                )
                .expect("durable job remains");
            assert_eq!(job.status, DeletionPropagationJobStatus::Leased);
        }
    }

    #[test]
    fn scoped_claim_never_crosses_projects() {
        let mut store = ProjectStore::in_memory().expect("store");
        let project_a = project(&mut store, "project-plugin-a", "tenant-a", "mission-a");
        let project_b = project(&mut store, "project-plugin-b", "tenant-b", "mission-b");
        let scope_a = scope("tenant-a", &project_a, "mission-a", "scope-a");
        let scope_b = scope("tenant-b", &project_b, "mission-b", "scope-b");
        let request_a = request(&scope_a, "a");
        let request_b = request(&scope_b, "b");
        {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger.open_scope(&scope_a, now()).expect("open A");
            ledger.open_scope(&scope_b, now()).expect("open B");
        }
        seed_record(&mut store, &scope_a, &request_a);
        seed_record(&mut store, &scope_b, &request_b);

        let claim_a = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .claim_propagation(
                    &scope_a,
                    DeletionSurface::Cache,
                    &WorkerId::from("worker-a"),
                    now(),
                    Duration::minutes(5),
                )
                .expect("claim A")
                .expect("A job")
        };
        assert_eq!(claim_a.project_id, project_a);
        let claim_b = {
            let mut ledger = LocalPrivacyPluginLedger::new(&mut store);
            ledger
                .claim_propagation(
                    &scope_b,
                    DeletionSurface::Cache,
                    &WorkerId::from("worker-b"),
                    now(),
                    Duration::minutes(5),
                )
                .expect("claim B")
                .expect("B job")
        };
        assert_eq!(claim_b.project_id, project_b);
    }

    #[derive(Debug)]
    struct EmptySurfaceProvider;

    impl PrivacyPropagationProvider for EmptySurfaceProvider {
        fn propagate(
            &mut self,
            _claim: &PrivacyPropagationClaim,
        ) -> Result<PrivacyPropagationEvidence, PrivacyProviderFailure> {
            Ok(PrivacyPropagationEvidence {
                inventory_digest: "9".repeat(64),
                matched_items: 0,
                deleted_items: 0,
                residual_items: 0,
                verification_digest: "a".repeat(64),
            })
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the integration test proves the full local receipt, Cell result, worker propagation, and restart replay chain"
    )]
    fn real_local_deletion_writes_receipt_then_completes_durable_surfaces() {
        let (mut store, project_id, capsule) = local_context_fixture();
        let policy = store
            .save_retention_policy(
                &project_id,
                &RetentionPolicy::local_default(now() - Duration::days(2)).expect("local policy"),
                now(),
            )
            .expect("persist local policy");
        let scope = PrivacyPluginScope::issue(
            TenantId::from("tenant-local-plugin"),
            project_id.clone(),
            capsule.mission_id.clone(),
            "mission-local-deletion",
            policy.policy_digest,
            now(),
            now() + Duration::minutes(20),
        )
        .expect("scope");
        let mut deletion_request = request(&scope, "local-real");
        deletion_request.object_id = capsule.id.to_string();
        deletion_request.prior_object_revision = capsule.revision;
        deletion_request.local_plan.cell = "eu".into();
        deletion_request.requested_at = now() + Duration::seconds(2);
        deletion_request.consent.expires_at = now() + Duration::minutes(10);
        let idempotency_key_digest = deletion_request.idempotency_key_digest.clone();
        let replay_request = deletion_request.clone();
        let acceptance = {
            let mut service = PrivacyPluginService::mount(
                LocalPrivacyPluginLedger::new(&mut store),
                scope.clone(),
                now() + Duration::seconds(2),
            )
            .expect("mount local service");
            service
                .request_deletion(deletion_request, now() + Duration::seconds(2))
                .expect("local deletion receipt")
        };
        assert_eq!(
            acceptance.local_receipt.tombstone_digest,
            acceptance.tombstone.tombstone_digest
        );
        assert_eq!(acceptance.local_receipt.local_record_revision, 1);
        store
            .record_local_sync_applied(
                &project_id,
                &idempotency_key_digest,
                1,
                acceptance.tombstone.prior_object_revision + 1,
                false,
                now() + Duration::seconds(3),
            )
            .expect("record encrypted-cell receipt");
        let mut cache_consumer = PrivacyPluginConsumer::mount(
            LocalPrivacyPluginLedger::new(&mut store),
            scope.clone(),
            DeletionSurface::Cache,
            WorkerId::from("local-cache-consumer"),
            3,
            Duration::minutes(5),
            Duration::seconds(1),
            now() + Duration::seconds(2),
        )
        .expect("cache consumer");
        let mut provider = EmptySurfaceProvider;
        assert!(matches!(
            cache_consumer
                .consume_once(&mut provider, now() + Duration::seconds(4))
                .expect("cache propagation"),
            hartevo_domain_kernel::PrivacyConsumeOutcome::Applied(_)
        ));
        drop(cache_consumer);

        let mut replay_consumer = PrivacyPluginConsumer::mount(
            LocalPrivacyPluginLedger::new(&mut store),
            scope.clone(),
            DeletionSurface::Replay,
            WorkerId::from("local-replay-consumer"),
            3,
            Duration::minutes(5),
            Duration::seconds(1),
            now() + Duration::seconds(5),
        )
        .expect("replay consumer");
        assert!(matches!(
            replay_consumer
                .consume_once(&mut EmptySurfaceProvider, now() + Duration::seconds(5))
                .expect("replay propagation"),
            hartevo_domain_kernel::PrivacyConsumeOutcome::Applied(_)
        ));
        drop(replay_consumer);

        let replay_acceptance = {
            let mut restarted_service = PrivacyPluginService::mount(
                LocalPrivacyPluginLedger::new(&mut store),
                scope,
                now() + Duration::seconds(6),
            )
            .expect("restart local service");
            restarted_service
                .request_deletion(replay_request, now() + Duration::seconds(6))
                .expect("exact local deletion replay")
        };
        assert_eq!(
            replay_acceptance.local_receipt.receipt_digest,
            acceptance.local_receipt.receipt_digest
        );

        let record = store
            .load_deletion_record(&project_id, "context_capsule", capsule.id.as_str())
            .expect("deletion record");
        assert!(record.is_complete());
        assert_eq!(record.residual_item_count(), Some(0));
    }
}
