use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Effect, ExecutionAttemptId, ProjectEncryptionMode, ProjectId, Receipt, Verification,
    VerificationStatus,
};
use hartevo_effect_broker::{
    DurableClaimDirective, DurableRateLimitDirective, ExecutionClaimContext, ExecutionLease,
    LedgerClaim, LedgerError, PermissionEvidence, PermissionFence, PersistedClaimState,
    RateLimitRequest, ReconciliationClaim, ReconciliationDisposition, ReconciliationLease,
    ReconciliationObservation, ReconciliationPolicy, decide_durable_claim,
    decide_durable_rate_limit,
};
use serde_json::Value;
use tokio_postgres::{Client, Transaction};

use super::{
    CellScope, CloudStorageError, MutationPrecondition, PostgresCellStore, canonical_digest,
    ensure_database_cell, from_sql_u64, is_sha256, lock_project, set_scope, to_sql_u64,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudPermissionFenceMutation {
    pub scope: CellScope,
    pub project_id: ProjectId,
    pub fence: PermissionFence,
    pub precondition: MutationPrecondition,
    pub evidence_digest: String,
    pub active: bool,
    pub idempotency_key_digest: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudPermissionFenceResult {
    pub registry_revision: u64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FenceKey {
    kind: &'static str,
    primary_id: String,
    secondary_id: String,
    primary_revision: u64,
    secondary_revision: u64,
    control_generation: u64,
}

impl CloudPermissionFenceMutation {
    fn validate(&self, store: PostgresCellStore) -> Result<FenceKey, CloudStorageError> {
        self.scope.validate(store.cell())?;
        let key = fence_key(&self.fence)?;
        if self.project_id.as_str().trim().is_empty()
            || !is_sha256(&self.evidence_digest)
            || !is_sha256(&self.idempotency_key_digest)
            || matches!(self.precondition, MutationPrecondition::ExactRevision(0))
        {
            return Err(CloudStorageError::InvalidEffectPermissionFence);
        }
        Ok(key)
    }

    fn request_digest(&self, key: &FenceKey) -> Result<String, CloudStorageError> {
        canonical_digest(&serde_json::json!({
            "cell": self.scope.cell,
            "tenantId": self.scope.tenant_id,
            "projectId": self.project_id,
            "fenceKind": key.kind,
            "primaryId": key.primary_id,
            "secondaryId": key.secondary_id,
            "primaryRevision": key.primary_revision,
            "secondaryRevision": key.secondary_revision,
            "controlGeneration": key.control_generation,
            "precondition": self.precondition,
            "evidenceDigest": self.evidence_digest,
            "active": self.active,
            "recordedAt": self.recorded_at,
        }))
    }
}

impl PostgresCellStore {
    pub async fn publish_effect_permission_fence(
        &self,
        client: &mut Client,
        mutation: &CloudPermissionFenceMutation,
    ) -> Result<CloudPermissionFenceResult, CloudStorageError> {
        let key = mutation.validate(*self)?;
        let request_digest = mutation.request_digest(&key)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &mutation.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &mutation.scope, &mutation.project_id).await?;
        ensure_team_project(&transaction, &mutation.scope, &mutation.project_id, false).await?;

        if let Some(existing) =
            load_permission_idempotency(&transaction, mutation, &request_digest).await?
        {
            transaction.commit().await?;
            return Ok(existing);
        }

        let current = load_permission_head(&transaction, mutation, &key).await?;
        validate_permission_precondition(mutation.precondition, current.as_ref())?;
        let registry_revision = current.as_ref().map_or(Ok(1), |head| {
            head.registry_revision
                .checked_add(1)
                .ok_or(CloudStorageError::RevisionOverflow)
        })?;
        if current
            .as_ref()
            .is_some_and(|head| mutation.recorded_at < head.updated_at)
        {
            return Err(CloudStorageError::InvalidEffectPermissionFence);
        }
        insert_permission_version(
            &transaction,
            mutation,
            &key,
            registry_revision,
            &request_digest,
        )
        .await?;
        update_permission_head(
            &transaction,
            mutation,
            &key,
            current.as_ref(),
            registry_revision,
        )
        .await?;
        transaction.commit().await?;
        Ok(CloudPermissionFenceResult {
            registry_revision,
            duplicate: false,
        })
    }

    pub async fn claim_effect(
        &self,
        client: &mut Client,
        effect: &Effect,
        context: Option<&ExecutionClaimContext>,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<LedgerClaim, CloudStorageError> {
        let request =
            EffectClaimRequest::new(*self, effect, context, owner, now, lease_expires_at)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &request.scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &request.scope, &effect.project_id).await?;
        if let Some(claim) =
            load_remote_terminal_reconciliation_claim(&transaction, &request.scope, effect).await?
        {
            ensure_team_project(&transaction, &request.scope, &effect.project_id, false).await?;
            transaction.commit().await?;
            return Ok(claim);
        }
        let (directive, latest, existing) =
            load_effect_claim_decision(&transaction, &request).await?;
        ensure_team_project(
            &transaction,
            &request.scope,
            &effect.project_id,
            existing.is_none(),
        )
        .await?;
        let claim =
            materialize_effect_claim(&transaction, &request, directive, latest, existing.as_ref())
                .await?;
        transaction.commit().await?;
        Ok(claim)
    }

    pub async fn claim_effect_reconciliation(
        &self,
        client: &mut Client,
        effect: &Effect,
        policy: &ReconciliationPolicy,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<ReconciliationClaim, CloudStorageError> {
        policy.validate()?;
        if owner.trim().is_empty() || lease_expires_at <= now {
            return Err(CloudStorageError::EffectLedger(LedgerError::Persistence(
                "remote reconciliation requires a non-empty owner and positive lease".into(),
            )));
        }
        let scope = effect_scope(*self, effect)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &scope, &effect.project_id).await?;
        ensure_team_project(&transaction, &scope, &effect.project_id, false).await?;
        let claim = claim_remote_reconciliation(
            &transaction,
            &scope,
            effect,
            policy,
            owner,
            now,
            lease_expires_at,
        )
        .await?;
        transaction.commit().await?;
        Ok(claim)
    }

    pub async fn record_effect_reconciliation(
        &self,
        client: &mut Client,
        effect: &Effect,
        lease: &ReconciliationLease,
        observation: &ReconciliationObservation,
        now: DateTime<Utc>,
    ) -> Result<ReconciliationDisposition, CloudStorageError> {
        let scope = effect_scope(*self, effect)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &scope, &effect.project_id).await?;
        ensure_team_project(&transaction, &scope, &effect.project_id, false).await?;
        let disposition =
            finish_remote_reconciliation(&transaction, &scope, effect, lease, observation, now)
                .await?;
        transaction.commit().await?;
        Ok(disposition)
    }

    pub async fn record_effect_receipt(
        &self,
        client: &mut Client,
        effect: &Effect,
        lease: &ExecutionLease,
        receipt: &Receipt,
        operation_at: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        let scope = effect_scope(*self, effect)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &scope, &effect.project_id).await?;
        ensure_team_project(&transaction, &scope, &effect.project_id, false).await?;
        require_current_effect_lease(
            &transaction,
            &scope,
            effect,
            lease,
            &["executing"],
            operation_at,
        )
        .await?;
        let execution_started_at =
            initial_execution_started_at(&transaction, &scope, effect).await?;
        validate_durable_receipt(effect, receipt, execution_started_at)?;
        let receipt_json = serde_json::to_value(receipt)?;
        let attempt_updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_execution_attempts
                 SET status = 'receipt_recorded', receipt_json = $10, updated_at = $11
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND attempt_id = $4 AND effect_id = $5 AND generation = $6
                   AND lease_owner = $7 AND lease_expires_at = $8
                   AND lease_expires_at > $9 AND status = 'executing'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &lease.attempt_id.as_str(),
                    &effect.id.as_str(),
                    &to_sql_u64(lease.generation)?,
                    &lease.owner,
                    &lease.expires_at,
                    &operation_at,
                    &receipt_json,
                    &operation_at,
                ],
            )
            .await?;
        let ledger_updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_idempotency
                 SET status = 'receipt_recorded', receipt_json = $6, updated_at = $7
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4 AND approval_digest = $5
                   AND status = 'executing'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &effect.idempotency_key,
                    &effect.approval_digest(),
                    &receipt_json,
                    &operation_at,
                ],
            )
            .await?;
        if attempt_updated != 1 || ledger_updated != 1 {
            return Err(CloudStorageError::EffectLeaseLost);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn record_effect_verification(
        &self,
        client: &mut Client,
        effect: &Effect,
        lease: &ExecutionLease,
        verification: &Verification,
        operation_at: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        let scope = effect_scope(*self, effect)?;
        let transaction = client.transaction().await?;
        set_scope(&transaction, &scope).await?;
        ensure_database_cell(&transaction, self.cell()).await?;
        lock_project(&transaction, &scope, &effect.project_id).await?;
        ensure_team_project(&transaction, &scope, &effect.project_id, false).await?;
        require_current_effect_lease(
            &transaction,
            &scope,
            effect,
            lease,
            &["receipt_recorded", "verifying"],
            operation_at,
        )
        .await?;
        let record = load_effect_record(&transaction, &scope, effect)
            .await?
            .ok_or(CloudStorageError::EffectLeaseLost)?;
        let execution_started_at =
            initial_execution_started_at(&transaction, &scope, effect).await?;
        let receipt = decode_receipt(effect, &record, execution_started_at)?;
        validate_verification(&receipt, verification)?;
        let (status, failure_class) = match verification.status {
            VerificationStatus::Confirmed => ("verified", None),
            VerificationStatus::Rejected => ("failed", Some("verification_rejected")),
            VerificationStatus::Inconclusive => {
                ("verification_required", Some("verification_inconclusive"))
            }
        };
        let verification_json = serde_json::to_value(verification)?;
        let attempt_updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_execution_attempts
                 SET status = $10, verification_json = $11, failure_class = $12,
                     updated_at = $13
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND attempt_id = $4 AND effect_id = $5 AND generation = $6
                   AND lease_owner = $7 AND lease_expires_at = $8
                   AND lease_expires_at > $9
                   AND status IN ('receipt_recorded', 'verifying')",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &lease.attempt_id.as_str(),
                    &effect.id.as_str(),
                    &to_sql_u64(lease.generation)?,
                    &lease.owner,
                    &lease.expires_at,
                    &operation_at,
                    &status,
                    &verification_json,
                    &failure_class,
                    &operation_at,
                ],
            )
            .await?;
        let ledger_updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_idempotency
                 SET status = $6, verification_json = $7, terminal_reason = $8,
                     updated_at = $9
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4 AND approval_digest = $5
                   AND status = 'receipt_recorded'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &effect.idempotency_key,
                    &effect.approval_digest(),
                    &status,
                    &verification_json,
                    &failure_class,
                    &operation_at,
                ],
            )
            .await?;
        if attempt_updated != 1 || ledger_updated != 1 {
            return Err(CloudStorageError::EffectLeaseLost);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn record_effect_failed(
        &self,
        client: &mut Client,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        operation_at: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        finish_effect_without_receipt(self, client, effect, lease, "failed", reason, operation_at)
            .await
    }

    pub async fn record_effect_uncertain(
        &self,
        client: &mut Client,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        operation_at: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        finish_effect_without_receipt(
            self,
            client,
            effect,
            lease,
            "uncertain",
            reason,
            operation_at,
        )
        .await
    }
}

#[derive(Clone, Debug)]
struct PermissionHead {
    registry_revision: u64,
    updated_at: DateTime<Utc>,
}

async fn load_permission_idempotency(
    transaction: &Transaction<'_>,
    mutation: &CloudPermissionFenceMutation,
    request_digest: &str,
) -> Result<Option<CloudPermissionFenceResult>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT request_digest, registry_revision
             FROM hartevo_cell.effect_permission_fence_versions
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4",
            &[
                &mutation.scope.cell.as_str(),
                &mutation.scope.tenant_id.as_str(),
                &mutation.project_id.as_str(),
                &mutation.idempotency_key_digest,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != request_digest {
        return Err(CloudStorageError::IdempotencyConflict);
    }
    Ok(Some(CloudPermissionFenceResult {
        registry_revision: from_sql_u64(row.get(1), "permission registry revision")?,
        duplicate: true,
    }))
}

async fn load_permission_head(
    transaction: &Transaction<'_>,
    mutation: &CloudPermissionFenceMutation,
    key: &FenceKey,
) -> Result<Option<PermissionHead>, CloudStorageError> {
    transaction
        .query_opt(
            "SELECT current_registry_revision, updated_at
             FROM hartevo_cell.effect_permission_fence_heads
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND fence_kind = $4 AND primary_id = $5 AND secondary_id = $6
             FOR UPDATE",
            &[
                &mutation.scope.cell.as_str(),
                &mutation.scope.tenant_id.as_str(),
                &mutation.project_id.as_str(),
                &key.kind,
                &key.primary_id,
                &key.secondary_id,
            ],
        )
        .await?
        .map(|row| {
            Ok(PermissionHead {
                registry_revision: from_sql_u64(row.get(0), "permission registry revision")?,
                updated_at: row.get(1),
            })
        })
        .transpose()
}

fn validate_permission_precondition(
    expected: MutationPrecondition,
    current: Option<&PermissionHead>,
) -> Result<(), CloudStorageError> {
    let actual = current.map(|head| head.registry_revision);
    let matches = match expected {
        MutationPrecondition::CreateOnly => actual.is_none(),
        MutationPrecondition::ExactRevision(revision) => actual == Some(revision),
    };
    if matches {
        Ok(())
    } else {
        Err(CloudStorageError::EffectPermissionFenceConflict { expected, actual })
    }
}

async fn insert_permission_version(
    transaction: &Transaction<'_>,
    mutation: &CloudPermissionFenceMutation,
    key: &FenceKey,
    registry_revision: u64,
    request_digest: &str,
) -> Result<(), CloudStorageError> {
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_permission_fence_versions
               (cell, tenant_id, project_id, fence_kind, primary_id, secondary_id,
                registry_revision, primary_revision, secondary_revision, control_generation,
                evidence_digest, active, idempotency_key, request_digest, recorded_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
            &[
                &mutation.scope.cell.as_str(),
                &mutation.scope.tenant_id.as_str(),
                &mutation.project_id.as_str(),
                &key.kind,
                &key.primary_id,
                &key.secondary_id,
                &to_sql_u64(registry_revision)?,
                &to_sql_u64(key.primary_revision)?,
                &to_sql_u64(key.secondary_revision)?,
                &to_sql_u64(key.control_generation)?,
                &mutation.evidence_digest,
                &mutation.active,
                &mutation.idempotency_key_digest,
                &request_digest,
                &mutation.recorded_at,
            ],
        )
        .await?;
    Ok(())
}

async fn update_permission_head(
    transaction: &Transaction<'_>,
    mutation: &CloudPermissionFenceMutation,
    key: &FenceKey,
    previous: Option<&PermissionHead>,
    registry_revision: u64,
) -> Result<(), CloudStorageError> {
    let changed = match previous {
        None => {
            transaction
                .execute(
                    "INSERT INTO hartevo_cell.effect_permission_fence_heads
                       (cell, tenant_id, project_id, fence_kind, primary_id, secondary_id,
                        current_registry_revision, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    &[
                        &mutation.scope.cell.as_str(),
                        &mutation.scope.tenant_id.as_str(),
                        &mutation.project_id.as_str(),
                        &key.kind,
                        &key.primary_id,
                        &key.secondary_id,
                        &to_sql_u64(registry_revision)?,
                        &mutation.recorded_at,
                    ],
                )
                .await?
        }
        Some(previous) => {
            transaction
                .execute(
                    "UPDATE hartevo_cell.effect_permission_fence_heads
                     SET current_registry_revision = $7, updated_at = $8
                     WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                       AND fence_kind = $4 AND primary_id = $5 AND secondary_id = $6
                       AND current_registry_revision = $9",
                    &[
                        &mutation.scope.cell.as_str(),
                        &mutation.scope.tenant_id.as_str(),
                        &mutation.project_id.as_str(),
                        &key.kind,
                        &key.primary_id,
                        &key.secondary_id,
                        &to_sql_u64(registry_revision)?,
                        &mutation.recorded_at,
                        &to_sql_u64(previous.registry_revision)?,
                    ],
                )
                .await?
        }
    };
    if changed != 1 {
        return Err(CloudStorageError::EffectPermissionFenceConflict {
            expected: mutation.precondition,
            actual: previous.map(|head| head.registry_revision),
        });
    }
    Ok(())
}

fn fence_key(fence: &PermissionFence) -> Result<FenceKey, CloudStorageError> {
    let key = match fence {
        PermissionFence::Connection {
            connection_id,
            revision,
        } => FenceKey {
            kind: "connection",
            primary_id: connection_id.to_string(),
            secondary_id: String::new(),
            primary_revision: *revision,
            secondary_revision: 0,
            control_generation: 0,
        },
        PermissionFence::Consent {
            consent_record_id,
            revision,
        } => FenceKey {
            kind: "consent",
            primary_id: consent_record_id.to_string(),
            secondary_id: String::new(),
            primary_revision: *revision,
            secondary_revision: 0,
            control_generation: 0,
        },
        PermissionFence::Conversation {
            conversation_id,
            revision,
            control_generation,
        } => FenceKey {
            kind: "conversation",
            primary_id: conversation_id.to_string(),
            secondary_id: String::new(),
            primary_revision: *revision,
            secondary_revision: 0,
            control_generation: *control_generation,
        },
        PermissionFence::CreatorContact {
            hiring_id,
            hiring_revision,
            partner_id,
            partner_revision,
        } => FenceKey {
            kind: "creator_contact",
            primary_id: hiring_id.to_string(),
            secondary_id: partner_id.to_string(),
            primary_revision: *hiring_revision,
            secondary_revision: *partner_revision,
            control_generation: 0,
        },
    };
    if key.primary_id.trim().is_empty()
        || key.primary_revision == 0
        || (key.kind == "creator_contact"
            && (key.secondary_id.trim().is_empty() || key.secondary_revision == 0))
        || (key.kind == "conversation" && key.control_generation == 0)
    {
        return Err(CloudStorageError::InvalidEffectPermissionFence);
    }
    Ok(key)
}

struct EffectClaimRequest<'a> {
    scope: CellScope,
    effect: &'a Effect,
    context: Option<&'a ExecutionClaimContext>,
    owner: &'a str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
}

impl<'a> EffectClaimRequest<'a> {
    fn new(
        store: PostgresCellStore,
        effect: &'a Effect,
        context: Option<&'a ExecutionClaimContext>,
        owner: &'a str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<Self, CloudStorageError> {
        if owner.trim().is_empty() || lease_expires_at <= now {
            return Err(CloudStorageError::EffectLedger(LedgerError::Persistence(
                "remote effect claim requires a non-empty owner and positive lease".into(),
            )));
        }
        Ok(Self {
            scope: effect_scope(store, effect)?,
            effect,
            context,
            owner,
            now,
            lease_expires_at,
        })
    }
}

fn effect_scope(store: PostgresCellStore, effect: &Effect) -> Result<CellScope, CloudStorageError> {
    if effect.tenant_id.as_str().trim().is_empty()
        || effect.project_id.as_str().trim().is_empty()
        || effect.mission_id.as_str().trim().is_empty()
        || effect.id.as_str().trim().is_empty()
        || effect.idempotency_key.trim().is_empty()
        || !is_sha256(&effect.approval_digest())
    {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    Ok(CellScope {
        cell: store.cell(),
        tenant_id: effect.tenant_id.clone(),
    })
}

async fn ensure_team_project(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    project_id: &ProjectId,
    require_opt_in: bool,
) -> Result<(), CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT encryption_mode, remote_execution_opt_in
             FROM hartevo_cell.projects
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
             FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &project_id.as_str(),
            ],
        )
        .await?
        .ok_or(CloudStorageError::ProjectNotFound)?;
    let encryption_mode = row.get::<_, String>(0);
    let opted_in = row.get::<_, bool>(1);
    if encryption_mode != encryption_mode_name(&ProjectEncryptionMode::TeamEnvelope)
        || (require_opt_in && !opted_in)
    {
        return Err(CloudStorageError::RemoteEffectExecutionNotAllowed);
    }
    Ok(())
}

fn encryption_mode_name(mode: &ProjectEncryptionMode) -> &'static str {
    match mode {
        ProjectEncryptionMode::PersonalE2ee => "personal_e2ee",
        ProjectEncryptionMode::TeamEnvelope => "team_envelope",
    }
}

#[derive(Clone, Debug)]
struct EffectRecord {
    status: String,
    receipt_json: Option<Value>,
    verification_json: Option<Value>,
    terminal_reason: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct LatestAttempt {
    attempt_id: String,
    lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct RemoteReconciliationHead {
    policy: ReconciliationPolicy,
    policy_digest: String,
    attempts: u32,
    generation: u64,
    status: String,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    retry_at: Option<DateTime<Utc>>,
    evidence_digest: Option<String>,
    observation_json: Option<Value>,
    execution_started_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

async fn load_remote_reconciliation_head(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<Option<RemoteReconciliationHead>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT mission_id, idempotency_key, approval_digest,
                    policy_version, policy_digest, max_attempts, retry_delay_seconds,
                    attempts, generation, status, lease_owner, lease_expires_at,
                    retry_at, evidence_digest, observation_json,
                    initial_execution_started_at, updated_at
             FROM hartevo_cell.effect_reconciliation_heads
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
             FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != effect.mission_id.as_str()
        || row.get::<_, String>(1) != effect.idempotency_key
        || row.get::<_, String>(2) != effect.approval_digest()
    {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    let max_attempts = u32::try_from(from_sql_u64(row.get(5), "reconciliation maximum")?)
        .map_err(|_| CloudStorageError::RevisionOverflow)?;
    let attempts = u32::try_from(from_sql_u64(row.get(7), "reconciliation attempts")?)
        .map_err(|_| CloudStorageError::RevisionOverflow)?;
    Ok(Some(RemoteReconciliationHead {
        policy: ReconciliationPolicy {
            version: row.get(3),
            max_attempts,
            retry_delay_seconds: from_sql_u64(row.get(6), "reconciliation retry delay")?,
        },
        policy_digest: row.get(4),
        attempts,
        generation: from_sql_u64(row.get(8), "reconciliation generation")?,
        status: row.get(9),
        lease_owner: row.get(10),
        lease_expires_at: row.get(11),
        retry_at: row.get(12),
        evidence_digest: row.get(13),
        observation_json: row.get(14),
        execution_started_at: row.get(15),
        updated_at: row.get(16),
    }))
}

async fn load_remote_terminal_reconciliation_claim(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<Option<LedgerClaim>, CloudStorageError> {
    let Some(head) = load_remote_reconciliation_head(transaction, scope, effect).await? else {
        return Ok(None);
    };
    let Some(observation_json) = head.observation_json.clone() else {
        return if matches!(head.status.as_str(), "leased" | "retry_wait") {
            Ok(None)
        } else {
            Err(CloudStorageError::StoredValueInvalid(
                "remote terminal reconciliation has no observation".into(),
            ))
        };
    };
    let observation: ReconciliationObservation = serde_json::from_value(observation_json)?;
    observation.validate_for(effect, head.execution_started_at)?;
    if head.evidence_digest.as_deref() != Some(observation.evidence_digest()) {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote reconciliation evidence projection diverged".into(),
        ));
    }
    match (head.status.as_str(), observation) {
        (
            "not_executed",
            ReconciliationObservation::NotExecuted {
                evidence_digest,
                observed_at,
            },
        ) => Ok(Some(LedgerClaim::ReconciledNotExecuted {
            evidence_digest,
            observed_at,
            execution_started_at: head.execution_started_at,
        })),
        (
            "provider_rejected",
            ReconciliationObservation::ProviderRejected {
                reason,
                observed_at,
                ..
            },
        ) => Ok(Some(LedgerClaim::ProviderRejected {
            reason,
            execution_started_at: head.execution_started_at,
            recorded_at: observed_at,
        })),
        (
            "dead_letter",
            ReconciliationObservation::StillUncertain {
                reason,
                evidence_digest,
                ..
            },
        ) => Ok(Some(LedgerClaim::DeadLetter {
            reason,
            evidence_digest,
            dead_lettered_at: head.updated_at,
            attempts: head.attempts,
            execution_started_at: head.execution_started_at,
        })),
        ("receipt_found" | "leased" | "retry_wait", _) => Ok(None),
        (status, _) => Err(CloudStorageError::StoredValueInvalid(format!(
            "remote reconciliation state {status} does not match its observation"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
async fn claim_remote_reconciliation(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    policy: &ReconciliationPolicy,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, CloudStorageError> {
    if let Some(claim) =
        load_remote_terminal_reconciliation_claim(transaction, scope, effect).await?
    {
        return Ok(ReconciliationClaim::Resolved(claim));
    }
    let Some(record) = load_effect_record(transaction, scope, effect).await? else {
        return Ok(ReconciliationClaim::NotRequired);
    };
    if record.status != "uncertain" {
        return Ok(ReconciliationClaim::NotRequired);
    }
    let execution_started_at = initial_execution_started_at(transaction, scope, effect).await?;
    let Some(head) = load_remote_reconciliation_head(transaction, scope, effect).await? else {
        return insert_initial_remote_reconciliation(
            transaction,
            scope,
            effect,
            policy,
            owner,
            now,
            lease_expires_at,
            execution_started_at,
        )
        .await;
    };
    validate_remote_reconciliation_policy(&head, policy)?;
    match head.status.as_str() {
        "leased" if head.lease_expires_at.is_some_and(|expires| expires > now) => {
            Ok(ReconciliationClaim::Busy)
        }
        "leased" => {
            expire_remote_reconciliation_lease(transaction, scope, effect, &head, now).await
        }
        "retry_wait" if head.retry_at.is_some_and(|retry_at| retry_at > now) => {
            Ok(ReconciliationClaim::NotReady {
                retry_at: head.retry_at.ok_or_else(|| {
                    CloudStorageError::StoredValueInvalid(
                        "remote retry state has no retry time".into(),
                    )
                })?,
            })
        }
        "retry_wait" => {
            issue_remote_reconciliation_lease(
                transaction,
                scope,
                effect,
                &head,
                owner,
                now,
                lease_expires_at,
            )
            .await
        }
        "receipt_found" | "provider_rejected" => Ok(ReconciliationClaim::NotRequired),
        "not_executed" | "dead_letter" => {
            load_remote_terminal_reconciliation_claim(transaction, scope, effect)
                .await?
                .map_or_else(
                    || {
                        Err(CloudStorageError::StoredValueInvalid(
                            "remote terminal reconciliation projection is missing".into(),
                        ))
                    },
                    |claim| Ok(ReconciliationClaim::Resolved(claim)),
                )
        }
        status => Err(CloudStorageError::StoredValueInvalid(format!(
            "unknown remote reconciliation status {status}"
        ))),
    }
}

fn validate_remote_reconciliation_policy(
    head: &RemoteReconciliationHead,
    policy: &ReconciliationPolicy,
) -> Result<(), CloudStorageError> {
    if head.policy != *policy || head.policy_digest != policy.canonical_digest()? {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_initial_remote_reconciliation(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    policy: &ReconciliationPolicy,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, CloudStorageError> {
    let policy_digest = policy.canonical_digest()?;
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_reconciliation_heads
               (cell, tenant_id, project_id, mission_id, effect_id, idempotency_key,
                approval_digest, policy_version, policy_digest, max_attempts,
                retry_delay_seconds, attempts, generation, status, lease_owner,
                lease_expires_at, initial_execution_started_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                     1, 1, 'leased', $12, $13, $14, $15, $15)",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.mission_id.as_str(),
                &effect.id.as_str(),
                &effect.idempotency_key,
                &effect.approval_digest(),
                &policy.version,
                &policy_digest,
                &to_sql_u64(u64::from(policy.max_attempts))?,
                &to_sql_u64(policy.retry_delay_seconds)?,
                &owner,
                &lease_expires_at,
                &execution_started_at,
                &now,
            ],
        )
        .await?;
    let lease = insert_remote_reconciliation_attempt(
        transaction,
        scope,
        effect,
        owner,
        1,
        1,
        policy.max_attempts,
        now,
        lease_expires_at,
    )
    .await?;
    Ok(ReconciliationClaim::Acquired {
        lease,
        execution_started_at,
    })
}

#[allow(clippy::too_many_arguments)]
async fn issue_remote_reconciliation_lease(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    head: &RemoteReconciliationHead,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, CloudStorageError> {
    let attempt_no = head
        .attempts
        .checked_add(1)
        .ok_or(CloudStorageError::RevisionOverflow)?;
    if attempt_no > head.policy.max_attempts {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote reconciliation exceeded its frozen attempt budget".into(),
        ));
    }
    let generation = head
        .generation
        .checked_add(1)
        .ok_or(CloudStorageError::RevisionOverflow)?;
    let updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_reconciliation_heads
             SET attempts = $5, generation = $6, status = 'leased', lease_owner = $7,
                 lease_expires_at = $8, retry_at = NULL, evidence_digest = NULL,
                 observation_json = NULL, terminal_reason = NULL, updated_at = $9
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
               AND generation = $10 AND status = 'retry_wait'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
                &to_sql_u64(u64::from(attempt_no))?,
                &to_sql_u64(generation)?,
                &owner,
                &lease_expires_at,
                &now,
                &to_sql_u64(head.generation)?,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(CloudStorageError::EffectLedger(LedgerError::LeaseLost));
    }
    let lease = insert_remote_reconciliation_attempt(
        transaction,
        scope,
        effect,
        owner,
        attempt_no,
        generation,
        head.policy.max_attempts,
        now,
        lease_expires_at,
    )
    .await?;
    Ok(ReconciliationClaim::Acquired {
        lease,
        execution_started_at: head.execution_started_at,
    })
}

#[allow(clippy::too_many_arguments)]
async fn insert_remote_reconciliation_attempt(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    owner: &str,
    attempt_no: u32,
    generation: u64,
    max_attempts: u32,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> Result<ReconciliationLease, CloudStorageError> {
    let attempt_id = ExecutionAttemptId::from_stable(format!(
        "cell-reconciliation:{}:{attempt_no}:{generation}",
        effect.id
    ));
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_reconciliation_attempts
               (attempt_id, cell, tenant_id, project_id, mission_id, effect_id,
                attempt_no, generation, status, lease_owner, lease_expires_at, started_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'leased', $9, $10, $11)",
            &[
                &attempt_id.as_str(),
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.mission_id.as_str(),
                &effect.id.as_str(),
                &to_sql_u64(u64::from(attempt_no))?,
                &to_sql_u64(generation)?,
                &owner,
                &lease_expires_at,
                &now,
            ],
        )
        .await?;
    Ok(ReconciliationLease {
        attempt_id,
        owner: owner.into(),
        generation,
        attempt_no,
        max_attempts,
        expires_at: lease_expires_at,
    })
}

async fn expire_remote_reconciliation_lease(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    head: &RemoteReconciliationHead,
    now: DateTime<Utc>,
) -> Result<ReconciliationClaim, CloudStorageError> {
    let reason = "reconciliation lease expired before a durable Provider observation";
    let evidence_digest = canonical_digest(&serde_json::json!({
        "effectId": effect.id,
        "generation": head.generation,
        "attempt": head.attempts,
        "expiredAt": now,
    }))?;
    let observation = ReconciliationObservation::StillUncertain {
        reason: reason.into(),
        evidence_digest: evidence_digest.clone(),
        observed_at: now,
    };
    if head.attempts >= head.policy.max_attempts {
        complete_remote_reconciliation_rows(
            transaction,
            scope,
            effect,
            head,
            "dead_letter",
            reason,
            &observation,
            None,
            now,
        )
        .await?;
        return Ok(ReconciliationClaim::Resolved(LedgerClaim::DeadLetter {
            reason: reason.into(),
            evidence_digest,
            dead_lettered_at: now,
            attempts: head.attempts,
            execution_started_at: head.execution_started_at,
        }));
    }
    let retry_at = remote_reconciliation_retry_at(now, head.policy.retry_delay_seconds)?;
    complete_remote_reconciliation_rows(
        transaction,
        scope,
        effect,
        head,
        "retry_wait",
        reason,
        &observation,
        Some(retry_at),
        now,
    )
    .await?;
    Ok(ReconciliationClaim::NotReady { retry_at })
}

async fn finish_remote_reconciliation(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    lease: &ReconciliationLease,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<ReconciliationDisposition, CloudStorageError> {
    let head = load_remote_reconciliation_head(transaction, scope, effect)
        .await?
        .ok_or(CloudStorageError::EffectLedger(LedgerError::LeaseLost))?;
    require_current_remote_reconciliation_lease(&head, lease, now)?;
    observation.validate_for(effect, head.execution_started_at)?;
    if observation.observed_at() > now {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    match observation {
        ReconciliationObservation::ReceiptFound { .. } => {
            finish_remote_reconciled_receipt(
                transaction,
                scope,
                effect,
                lease,
                &head,
                observation,
                now,
            )
            .await
        }
        ReconciliationObservation::NotExecuted {
            evidence_digest,
            observed_at,
        } => {
            let reason = "Provider reconciliation confirmed that no external effect occurred";
            complete_remote_reconciliation_rows(
                transaction,
                scope,
                effect,
                &head,
                "not_executed",
                reason,
                observation,
                None,
                now,
            )
            .await?;
            Ok(ReconciliationDisposition::ReconciledNotExecuted {
                evidence_digest: evidence_digest.clone(),
                observed_at: *observed_at,
                execution_started_at: head.execution_started_at,
            })
        }
        ReconciliationObservation::ProviderRejected { .. } => {
            finish_remote_reconciled_rejection(transaction, scope, effect, &head, observation, now)
                .await
        }
        ReconciliationObservation::StillUncertain { .. } => {
            finish_remote_still_uncertain(
                transaction,
                scope,
                effect,
                lease,
                &head,
                observation,
                now,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_remote_still_uncertain(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    lease: &ReconciliationLease,
    head: &RemoteReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<ReconciliationDisposition, CloudStorageError> {
    let ReconciliationObservation::StillUncertain {
        reason,
        evidence_digest,
        observed_at,
    } = observation
    else {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    };
    if lease.attempt_no >= lease.max_attempts {
        complete_remote_reconciliation_rows(
            transaction,
            scope,
            effect,
            head,
            "dead_letter",
            reason,
            observation,
            None,
            now,
        )
        .await?;
        return Ok(ReconciliationDisposition::DeadLetter {
            reason: reason.clone(),
            evidence_digest: evidence_digest.clone(),
            dead_lettered_at: now,
            attempts: lease.attempt_no,
            execution_started_at: head.execution_started_at,
        });
    }
    let retry_at = remote_reconciliation_retry_at(now, head.policy.retry_delay_seconds)?;
    complete_remote_reconciliation_rows(
        transaction,
        scope,
        effect,
        head,
        "retry_wait",
        reason,
        observation,
        Some(retry_at),
        now,
    )
    .await?;
    Ok(ReconciliationDisposition::RetryScheduled {
        reason: reason.clone(),
        evidence_digest: evidence_digest.clone(),
        observed_at: *observed_at,
        retry_at,
        attempt_no: lease.attempt_no,
        execution_started_at: head.execution_started_at,
    })
}

fn require_current_remote_reconciliation_lease(
    head: &RemoteReconciliationHead,
    lease: &ReconciliationLease,
    now: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    if head.status != "leased"
        || head.lease_owner.as_deref() != Some(lease.owner.as_str())
        || head.lease_expires_at != Some(lease.expires_at)
        || head.generation != lease.generation
        || head.attempts != lease.attempt_no
        || head.policy.max_attempts != lease.max_attempts
        || lease.expires_at <= now
    {
        return Err(CloudStorageError::EffectLedger(LedgerError::LeaseLost));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn finish_remote_reconciled_receipt(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    lease: &ReconciliationLease,
    head: &RemoteReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<ReconciliationDisposition, CloudStorageError> {
    let ReconciliationObservation::ReceiptFound { receipt, .. } = observation else {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    };
    complete_remote_reconciliation_rows(
        transaction,
        scope,
        effect,
        head,
        "receipt_found",
        "",
        observation,
        None,
        now,
    )
    .await?;
    let receipt_json = serde_json::to_value(receipt)?;
    let updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_idempotency
             SET status = 'receipt_recorded', receipt_json = $6,
                 terminal_reason = NULL, updated_at = $7
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4 AND approval_digest = $5
               AND status = 'uncertain'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.idempotency_key,
                &effect.approval_digest(),
                &receipt_json,
                &now,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    let (attempt_no, generation) = next_effect_attempt(transaction, scope, effect).await?;
    let owner = format!("{}:verification", lease.owner);
    let request = EffectClaimRequest {
        scope: scope.clone(),
        effect,
        context: None,
        owner: &owner,
        now,
        lease_expires_at: lease.expires_at,
    };
    let verification_lease = insert_effect_attempt(
        transaction,
        &request,
        attempt_no,
        generation,
        "receipt_recorded",
        Some(&receipt_json),
    )
    .await?;
    Ok(ReconciliationDisposition::ReceiptReadyForVerification {
        lease: verification_lease,
        receipt: receipt.clone(),
        execution_started_at: head.execution_started_at,
    })
}

async fn finish_remote_reconciled_rejection(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    head: &RemoteReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<ReconciliationDisposition, CloudStorageError> {
    let ReconciliationObservation::ProviderRejected {
        reason,
        evidence_digest,
        observed_at,
    } = observation
    else {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    };
    complete_remote_reconciliation_rows(
        transaction,
        scope,
        effect,
        head,
        "provider_rejected",
        reason,
        observation,
        None,
        now,
    )
    .await?;
    let updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_idempotency
             SET status = 'failed', terminal_reason = $6, updated_at = $7
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4 AND approval_digest = $5
               AND status = 'uncertain'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.idempotency_key,
                &effect.approval_digest(),
                &reason,
                &now,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    Ok(ReconciliationDisposition::ProviderRejected {
        reason: reason.clone(),
        evidence_digest: evidence_digest.clone(),
        observed_at: *observed_at,
        execution_started_at: head.execution_started_at,
    })
}

#[allow(clippy::too_many_arguments)]
async fn complete_remote_reconciliation_rows(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    head: &RemoteReconciliationHead,
    status: &str,
    reason: &str,
    observation: &ReconciliationObservation,
    retry_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let observation_json = serde_json::to_value(observation)?;
    let terminal_reason = match status {
        "receipt_found" => None,
        _ => Some(reason),
    };
    let attempt_id = ExecutionAttemptId::from_stable(format!(
        "cell-reconciliation:{}:{}:{}",
        effect.id, head.attempts, head.generation
    ));
    let attempt_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_reconciliation_attempts
             SET status = $8, evidence_digest = $9, observation_json = $10,
                 failure_class = $11, completed_at = $12
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND effect_id = $4 AND attempt_id = $5 AND generation = $6
               AND lease_owner = $7 AND status = 'leased'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
                &attempt_id.as_str(),
                &to_sql_u64(head.generation)?,
                &head.lease_owner,
                &status,
                &observation.evidence_digest(),
                &observation_json,
                &status,
                &now,
            ],
        )
        .await?;
    let head_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_reconciliation_heads
             SET status = $7, lease_owner = NULL, lease_expires_at = NULL,
                 retry_at = $8, evidence_digest = $9, observation_json = $10,
                 terminal_reason = $11, updated_at = $12
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
               AND generation = $5 AND lease_owner = $6 AND status = 'leased'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
                &to_sql_u64(head.generation)?,
                &head.lease_owner,
                &status,
                &retry_at,
                &observation.evidence_digest(),
                &observation_json,
                &terminal_reason,
                &now,
            ],
        )
        .await?;
    if attempt_updated != 1 || head_updated != 1 {
        return Err(CloudStorageError::EffectLedger(LedgerError::LeaseLost));
    }
    Ok(())
}

fn remote_reconciliation_retry_at(
    now: DateTime<Utc>,
    retry_delay_seconds: u64,
) -> Result<DateTime<Utc>, CloudStorageError> {
    let delay =
        i64::try_from(retry_delay_seconds).map_err(|_| CloudStorageError::RevisionOverflow)?;
    now.checked_add_signed(chrono::Duration::seconds(delay))
        .ok_or(CloudStorageError::RevisionOverflow)
}

async fn load_effect_claim_decision(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
) -> Result<
    (
        DurableClaimDirective,
        Option<LatestAttempt>,
        Option<EffectRecord>,
    ),
    CloudStorageError,
> {
    let existing = load_effect_record(transaction, &request.scope, request.effect).await?;
    let Some(record) = existing.as_ref() else {
        return Ok((decide_durable_claim(None, false), None, existing));
    };
    let state = PersistedClaimState::from_storage_name(&record.status).ok_or_else(|| {
        CloudStorageError::StoredValueInvalid(format!(
            "unknown remote effect status {}",
            record.status
        ))
    })?;
    let latest = if state == PersistedClaimState::Executing {
        Some(
            latest_effect_attempt(transaction, &request.scope, request.effect)
                .await?
                .ok_or_else(|| {
                    CloudStorageError::StoredValueInvalid(
                        "remote executing effect has no attempt".into(),
                    )
                })?,
        )
    } else {
        None
    };
    let lease_live = latest
        .as_ref()
        .is_some_and(|attempt| attempt.lease_expires_at > request.now);
    Ok((
        decide_durable_claim(Some(state), lease_live),
        latest,
        existing,
    ))
}

async fn load_effect_record(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<Option<EffectRecord>, CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT mission_id, effect_id, approval_digest, status, receipt_json,
                    verification_json, terminal_reason, updated_at
             FROM hartevo_cell.effect_idempotency
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4
             FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.idempotency_key,
            ],
        )
        .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != effect.mission_id.as_str()
        || row.get::<_, String>(1) != effect.id.as_str()
        || row.get::<_, String>(2) != effect.approval_digest()
    {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    Ok(Some(EffectRecord {
        status: row.get(3),
        receipt_json: row.get(4),
        verification_json: row.get(5),
        terminal_reason: row.get(6),
        updated_at: row.get(7),
    }))
}

async fn materialize_effect_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    directive: DurableClaimDirective,
    latest: Option<LatestAttempt>,
    existing: Option<&EffectRecord>,
) -> Result<LedgerClaim, CloudStorageError> {
    match directive {
        DurableClaimDirective::BeginProviderExecution => {
            begin_remote_execution_claim(transaction, request).await
        }
        DurableClaimDirective::ResumeVerificationFromReceipt => {
            resume_remote_verification_claim(
                transaction,
                request,
                require_effect_record(existing, "verification")?,
            )
            .await
        }
        DurableClaimDirective::ReturnVerified => {
            let record = require_effect_record(existing, "verified")?;
            let (receipt, verification, execution_started_at) =
                decode_durable_verification(transaction, request, record).await?;
            Ok(LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at,
            })
        }
        DurableClaimDirective::ReturnProviderFailed => {
            provider_failed_claim(
                transaction,
                request,
                require_effect_record(existing, "failed")?,
            )
            .await
        }
        DurableClaimDirective::ReturnUncertain => {
            uncertain_claim(
                transaction,
                request,
                require_effect_record(existing, "uncertain")?,
            )
            .await
        }
        DurableClaimDirective::ReturnVerification => {
            let record = require_effect_record(existing, "verification")?;
            let (receipt, verification, execution_started_at) =
                decode_durable_verification(transaction, request, record).await?;
            Ok(LedgerClaim::DurableVerification {
                receipt,
                verification,
                execution_started_at,
            })
        }
        DurableClaimDirective::ReturnBusy => Ok(LedgerClaim::Busy),
        DurableClaimDirective::FreezeExpiredExecution => {
            freeze_expired_remote_execution(transaction, request, latest).await
        }
    }
}

fn require_effect_record<'a>(
    existing: Option<&'a EffectRecord>,
    directive: &str,
) -> Result<&'a EffectRecord, CloudStorageError> {
    existing.ok_or_else(|| {
        CloudStorageError::StoredValueInvalid(format!(
            "{directive} directive has no remote effect record"
        ))
    })
}

async fn begin_remote_execution_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
) -> Result<LedgerClaim, CloudStorageError> {
    let Some(context) = request.context else {
        return Ok(LedgerClaim::AuthorizationRequired);
    };
    context.validate_dispatch_at(request.effect, request.now)?;
    validate_remote_permission_fences(transaction, request, &context.permission_evidence).await?;
    match reserve_remote_rate_limit(transaction, request, &context.rate_limit).await? {
        RateLimitReservation::Reserved => insert_initial_execution(transaction, request).await,
        RateLimitReservation::Limited { retry_at } => Ok(LedgerClaim::RateLimited { retry_at }),
    }
}

async fn validate_remote_permission_fences(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    evidence: &PermissionEvidence,
) -> Result<(), CloudStorageError> {
    evidence
        .validate_for_effect(request.effect)
        .map_err(|_| CloudStorageError::EffectLedger(LedgerError::ScopeConflict))?;
    for fence in &evidence.fences {
        let key = fence_key(fence)?;
        let expected_digest = permission_component_digest(evidence, key.kind)
            .ok_or(CloudStorageError::EffectLedger(LedgerError::ScopeConflict))?;
        let row = transaction
            .query_opt(
                "SELECT version.primary_revision, version.secondary_revision,
                        version.control_generation, version.evidence_digest, version.active
                 FROM hartevo_cell.effect_permission_fence_heads AS head
                 JOIN hartevo_cell.effect_permission_fence_versions AS version
                   ON version.cell = head.cell AND version.tenant_id = head.tenant_id
                  AND version.project_id = head.project_id
                  AND version.fence_kind = head.fence_kind
                  AND version.primary_id = head.primary_id
                  AND version.secondary_id = head.secondary_id
                  AND version.registry_revision = head.current_registry_revision
                 WHERE head.cell = $1 AND head.tenant_id = $2 AND head.project_id = $3
                   AND head.fence_kind = $4 AND head.primary_id = $5
                   AND head.secondary_id = $6
                 FOR UPDATE OF head",
                &[
                    &request.scope.cell.as_str(),
                    &request.scope.tenant_id.as_str(),
                    &request.effect.project_id.as_str(),
                    &key.kind,
                    &key.primary_id,
                    &key.secondary_id,
                ],
            )
            .await?
            .ok_or(CloudStorageError::EffectLedger(LedgerError::ScopeConflict))?;
        if from_sql_u64(row.get(0), "permission primary revision")? != key.primary_revision
            || from_sql_u64(row.get(1), "permission secondary revision")? != key.secondary_revision
            || from_sql_u64(row.get(2), "permission control generation")? != key.control_generation
            || row.get::<_, String>(3) != expected_digest
            || !row.get::<_, bool>(4)
        {
            return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
        }
    }
    Ok(())
}

fn permission_component_digest<'a>(
    evidence: &'a PermissionEvidence,
    kind: &str,
) -> Option<&'a str> {
    match kind {
        "connection" => evidence.connection_evidence_digest.as_deref(),
        "consent" => evidence.consent_evidence_digest.as_deref(),
        "conversation" => evidence.conversation_evidence_digest.as_deref(),
        "creator_contact" => evidence.creator_contact_evidence_digest.as_deref(),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RateLimitReservation {
    Reserved,
    Limited { retry_at: DateTime<Utc> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RateLimitWindow {
    started_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
}

async fn reserve_remote_rate_limit(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    rate: &RateLimitRequest,
) -> Result<RateLimitReservation, CloudStorageError> {
    rate.validate_for(request.effect)?;
    let window = fixed_rate_limit_window(request.now, rate.window_seconds)?;
    let existing = transaction
        .query_opt(
            "SELECT rule_id, policy_version, policy_digest, provider, account_id,
                    capability, window_ends_at, max_executions, window_seconds,
                    consumed, revision
             FROM hartevo_cell.effect_rate_limit_buckets
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND scope_digest = $4 AND window_started_at = $5
             FOR UPDATE",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &rate.scope_digest,
                &window.started_at,
            ],
        )
        .await?;
    let (consumed, revision) = existing.as_ref().map_or(Ok((0, 0)), |row| {
        validate_rate_limit_row(row, rate, window.ends_at)
    })?;
    match decide_durable_rate_limit(consumed, rate.max_executions) {
        DurableRateLimitDirective::Reserve { next_consumed } => {
            persist_remote_rate_reservation(
                transaction,
                request,
                rate,
                consumed,
                revision,
                next_consumed,
                window,
            )
            .await?;
            Ok(RateLimitReservation::Reserved)
        }
        DurableRateLimitDirective::Deny => {
            insert_remote_rate_decision(
                transaction,
                request,
                rate,
                "denied",
                consumed,
                consumed,
                window,
            )
            .await?;
            Ok(RateLimitReservation::Limited {
                retry_at: window.ends_at,
            })
        }
    }
}

fn validate_rate_limit_row(
    row: &tokio_postgres::Row,
    rate: &RateLimitRequest,
    window_ends_at: DateTime<Utc>,
) -> Result<(u64, u64), CloudStorageError> {
    let consumed = from_sql_u64(row.get(9), "rate limit consumed")?;
    let revision = from_sql_u64(row.get(10), "rate limit revision")?;
    if row.get::<_, String>(0) != rate.rule_id
        || row.get::<_, String>(1) != rate.policy_version
        || row.get::<_, String>(2) != rate.policy_digest
        || row.get::<_, String>(3) != rate.provider
        || row.get::<_, Option<String>>(4).as_deref()
            != rate
                .account_id
                .as_ref()
                .map(hartevo_domain_kernel::AccountId::as_str)
        || row.get::<_, String>(5) != rate.capability
        || row.get::<_, DateTime<Utc>>(6) != window_ends_at
        || from_sql_u64(row.get(7), "rate limit maximum")? != rate.max_executions
        || from_sql_u64(row.get(8), "rate limit window")? != rate.window_seconds
        || consumed > rate.max_executions
        || revision == 0
    {
        return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
    }
    Ok((consumed, revision))
}

async fn persist_remote_rate_reservation(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    rate: &RateLimitRequest,
    consumed: u64,
    revision: u64,
    next_consumed: u64,
    window: RateLimitWindow,
) -> Result<(), CloudStorageError> {
    if revision == 0 {
        transaction
            .execute(
                "INSERT INTO hartevo_cell.effect_rate_limit_buckets
                   (cell, tenant_id, project_id, scope_digest, rule_id, policy_version,
                    policy_digest, provider, account_id, capability, window_started_at,
                    window_ends_at, max_executions, window_seconds, consumed, revision,
                    created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                         $13, $14, $15, 1, $16, $16)",
                &[
                    &request.scope.cell.as_str(),
                    &request.scope.tenant_id.as_str(),
                    &request.effect.project_id.as_str(),
                    &rate.scope_digest,
                    &rate.rule_id,
                    &rate.policy_version,
                    &rate.policy_digest,
                    &rate.provider,
                    &rate
                        .account_id
                        .as_ref()
                        .map(hartevo_domain_kernel::AccountId::as_str),
                    &rate.capability,
                    &window.started_at,
                    &window.ends_at,
                    &to_sql_u64(rate.max_executions)?,
                    &to_sql_u64(rate.window_seconds)?,
                    &to_sql_u64(next_consumed)?,
                    &request.now,
                ],
            )
            .await?;
    } else {
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_rate_limit_buckets
                 SET consumed = $6, revision = $7, updated_at = $8
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND scope_digest = $4 AND window_started_at = $5
                   AND consumed = $9 AND revision = $10",
                &[
                    &request.scope.cell.as_str(),
                    &request.scope.tenant_id.as_str(),
                    &request.effect.project_id.as_str(),
                    &rate.scope_digest,
                    &window.started_at,
                    &to_sql_u64(next_consumed)?,
                    &to_sql_u64(
                        revision
                            .checked_add(1)
                            .ok_or(CloudStorageError::RevisionOverflow)?,
                    )?,
                    &request.now,
                    &to_sql_u64(consumed)?,
                    &to_sql_u64(revision)?,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict));
        }
    }
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_rate_limit_reservations
               (cell, tenant_id, project_id, mission_id, effect_id, idempotency_key,
                approval_digest, scope_digest, rule_id, window_started_at, window_ends_at,
                reserved_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &request.effect.mission_id.as_str(),
                &request.effect.id.as_str(),
                &request.effect.idempotency_key,
                &request.effect.approval_digest(),
                &rate.scope_digest,
                &rate.rule_id,
                &window.started_at,
                &window.ends_at,
                &request.now,
            ],
        )
        .await?;
    insert_remote_rate_decision(
        transaction,
        request,
        rate,
        "reserved",
        consumed,
        next_consumed,
        window,
    )
    .await
}

async fn insert_remote_rate_decision(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    rate: &RateLimitRequest,
    decision: &str,
    consumed_before: u64,
    consumed_after: u64,
    window: RateLimitWindow,
) -> Result<(), CloudStorageError> {
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_rate_limit_decisions
               (cell, tenant_id, project_id, mission_id, effect_id, approval_digest,
                scope_digest, rule_id, decision, consumed_before, consumed_after,
                window_started_at, window_ends_at, decided_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &request.effect.mission_id.as_str(),
                &request.effect.id.as_str(),
                &request.effect.approval_digest(),
                &rate.scope_digest,
                &rate.rule_id,
                &decision,
                &to_sql_u64(consumed_before)?,
                &to_sql_u64(consumed_after)?,
                &window.started_at,
                &window.ends_at,
                &request.now,
            ],
        )
        .await?;
    Ok(())
}

async fn insert_initial_execution(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
) -> Result<LedgerClaim, CloudStorageError> {
    transaction
        .execute(
            "INSERT INTO hartevo_cell.effect_idempotency
               (cell, tenant_id, project_id, mission_id, idempotency_key, effect_id,
                approval_digest, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'executing', $8, $8)",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &request.effect.mission_id.as_str(),
                &request.effect.idempotency_key,
                &request.effect.id.as_str(),
                &request.effect.approval_digest(),
                &request.now,
            ],
        )
        .await?;
    let lease = insert_effect_attempt(transaction, request, 1, 1, "executing", None).await?;
    Ok(LedgerClaim::Acquired {
        lease,
        receipt: None,
        execution_started_at: request.now,
    })
}

async fn resume_remote_verification_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    record: &EffectRecord,
) -> Result<LedgerClaim, CloudStorageError> {
    let (receipt, execution_started_at) =
        decode_receipt_for_claim(transaction, request, record).await?;
    let (attempt_no, generation) =
        next_effect_attempt(transaction, &request.scope, request.effect).await?;
    let receipt_json = serde_json::to_value(&receipt)?;
    let lease = insert_effect_attempt(
        transaction,
        request,
        attempt_no,
        generation,
        "receipt_recorded",
        Some(&receipt_json),
    )
    .await?;
    Ok(LedgerClaim::Acquired {
        lease,
        receipt: Some(receipt),
        execution_started_at,
    })
}

async fn provider_failed_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    record: &EffectRecord,
) -> Result<LedgerClaim, CloudStorageError> {
    if record.verification_json.is_some() {
        let (receipt, verification, execution_started_at) =
            decode_durable_verification(transaction, request, record).await?;
        return Ok(LedgerClaim::DurableVerification {
            receipt,
            verification,
            execution_started_at,
        });
    }
    if record.receipt_json.is_some() {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote provider rejection carries an unverified receipt".into(),
        ));
    }
    Ok(LedgerClaim::ProviderRejected {
        reason: record
            .terminal_reason
            .clone()
            .unwrap_or_else(|| "provider rejected without a recorded reason".into()),
        execution_started_at: initial_execution_started_at(
            transaction,
            &request.scope,
            request.effect,
        )
        .await?,
        recorded_at: record.updated_at,
    })
}

async fn uncertain_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    record: &EffectRecord,
) -> Result<LedgerClaim, CloudStorageError> {
    if record.receipt_json.is_some() || record.verification_json.is_some() {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote Provider uncertainty carries receipt or verification data".into(),
        ));
    }
    Ok(LedgerClaim::Uncertain {
        reason: record
            .terminal_reason
            .clone()
            .unwrap_or_else(|| "provider state is durably uncertain".into()),
        execution_started_at: initial_execution_started_at(
            transaction,
            &request.scope,
            request.effect,
        )
        .await?,
        recorded_at: record.updated_at,
    })
}

async fn freeze_expired_remote_execution(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    latest: Option<LatestAttempt>,
) -> Result<LedgerClaim, CloudStorageError> {
    let latest = latest.ok_or_else(|| {
        CloudStorageError::StoredValueInvalid(
            "expired remote execution has no latest attempt".into(),
        )
    })?;
    let reason =
        "execution lease expired without a durable provider receipt; reconciliation required";
    let attempt_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_execution_attempts
             SET status = 'uncertain', failure_class = $6, updated_at = $7
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND attempt_id = $4 AND effect_id = $5 AND status = 'executing'",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &latest.attempt_id,
                &request.effect.id.as_str(),
                &reason,
                &request.now,
            ],
        )
        .await?;
    let ledger_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_idempotency
             SET status = 'uncertain', terminal_reason = $5, updated_at = $6
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4 AND status = 'executing'",
            &[
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &request.effect.idempotency_key,
                &reason,
                &request.now,
            ],
        )
        .await?;
    if attempt_updated != 1 || ledger_updated != 1 {
        return Err(CloudStorageError::EffectLeaseLost);
    }
    Ok(LedgerClaim::Uncertain {
        reason: reason.into(),
        execution_started_at: initial_execution_started_at(
            transaction,
            &request.scope,
            request.effect,
        )
        .await?,
        recorded_at: request.now,
    })
}

async fn insert_effect_attempt(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    attempt_no: u64,
    generation: u64,
    status: &str,
    receipt_json: Option<&Value>,
) -> Result<ExecutionLease, CloudStorageError> {
    let attempt_id = ExecutionAttemptId::from_stable(format!(
        "cell-attempt:{}:{attempt_no}:{generation}",
        request.effect.id
    ));
    let row = transaction
        .query_one(
            "INSERT INTO hartevo_cell.effect_execution_attempts
               (attempt_id, cell, tenant_id, project_id, mission_id, effect_id,
                attempt_no, generation, status, lease_owner, lease_expires_at,
                request_digest, receipt_json, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
             RETURNING lease_expires_at",
            &[
                &attempt_id.as_str(),
                &request.scope.cell.as_str(),
                &request.scope.tenant_id.as_str(),
                &request.effect.project_id.as_str(),
                &request.effect.mission_id.as_str(),
                &request.effect.id.as_str(),
                &to_sql_u64(attempt_no)?,
                &to_sql_u64(generation)?,
                &status,
                &request.owner,
                &request.lease_expires_at,
                &request.effect.approval_digest(),
                &receipt_json,
                &request.now,
            ],
        )
        .await?;
    let stored_expires_at = row.get(0);
    Ok(ExecutionLease {
        attempt_id,
        owner: request.owner.into(),
        generation,
        expires_at: stored_expires_at,
    })
}

async fn latest_effect_attempt(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<Option<LatestAttempt>, CloudStorageError> {
    transaction
        .query_opt(
            "SELECT attempt_id, lease_expires_at
             FROM hartevo_cell.effect_execution_attempts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
             ORDER BY generation DESC LIMIT 1 FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
            ],
        )
        .await?
        .map(|row| {
            Ok(LatestAttempt {
                attempt_id: row.get(0),
                lease_expires_at: row.get(1),
            })
        })
        .transpose()
}

async fn next_effect_attempt(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<(u64, u64), CloudStorageError> {
    let row = transaction
        .query_one(
            "SELECT COALESCE(MAX(attempt_no), 0), COALESCE(MAX(generation), 0)
             FROM hartevo_cell.effect_execution_attempts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
            ],
        )
        .await?;
    let attempt = from_sql_u64(row.get(0), "effect attempt number")?;
    let generation = from_sql_u64(row.get(1), "effect attempt generation")?;
    Ok((
        attempt
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow)?,
        generation
            .checked_add(1)
            .ok_or(CloudStorageError::RevisionOverflow)?,
    ))
}

async fn initial_execution_started_at(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
) -> Result<DateTime<Utc>, CloudStorageError> {
    transaction
        .query_opt(
            "SELECT created_at FROM hartevo_cell.effect_execution_attempts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND effect_id = $4 AND attempt_no = 1",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
            ],
        )
        .await?
        .map(|row| row.get(0))
        .ok_or_else(|| {
            CloudStorageError::StoredValueInvalid(
                "remote effect ledger has no initial execution attempt".into(),
            )
        })
}

async fn decode_receipt_for_claim(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    record: &EffectRecord,
) -> Result<(Receipt, DateTime<Utc>), CloudStorageError> {
    let execution_started_at =
        initial_execution_started_at(transaction, &request.scope, request.effect).await?;
    Ok((
        decode_receipt(request.effect, record, execution_started_at)?,
        execution_started_at,
    ))
}

fn decode_receipt(
    effect: &Effect,
    record: &EffectRecord,
    execution_started_at: DateTime<Utc>,
) -> Result<Receipt, CloudStorageError> {
    let receipt: Receipt = serde_json::from_value(
        record
            .receipt_json
            .clone()
            .ok_or_else(|| CloudStorageError::StoredValueInvalid("missing receipt".into()))?,
    )?;
    validate_durable_receipt(effect, &receipt, execution_started_at)?;
    Ok(receipt)
}

async fn decode_durable_verification(
    transaction: &Transaction<'_>,
    request: &EffectClaimRequest<'_>,
    record: &EffectRecord,
) -> Result<(Receipt, Verification, DateTime<Utc>), CloudStorageError> {
    let (receipt, execution_started_at) =
        decode_receipt_for_claim(transaction, request, record).await?;
    let verification: Verification =
        serde_json::from_value(record.verification_json.clone().ok_or_else(|| {
            CloudStorageError::StoredValueInvalid("missing verification".into())
        })?)?;
    let expected_status = match record.status.as_str() {
        "verified" => VerificationStatus::Confirmed,
        "failed" => VerificationStatus::Rejected,
        "verification_required" => VerificationStatus::Inconclusive,
        other => {
            return Err(CloudStorageError::StoredValueInvalid(format!(
                "remote state {other} cannot carry final verification"
            )));
        }
    };
    if verification.status != expected_status {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote verification status does not match ledger state".into(),
        ));
    }
    validate_verification(&receipt, &verification)?;
    Ok((receipt, verification, execution_started_at))
}

fn validate_durable_receipt(
    effect: &Effect,
    receipt: &Receipt,
    execution_started_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let approval = effect.approval.as_ref().ok_or_else(|| {
        CloudStorageError::StoredValueInvalid("remote durable receipt has no exact approval".into())
    })?;
    if approval.scope_digest != effect.approval_digest()
        || execution_started_at < approval.decided_at
        || execution_started_at >= approval.valid_until
        || execution_started_at >= effect.expires_at
        || receipt.provider != effect.provider
        || receipt.external_id.trim().is_empty()
        || receipt.request_digest != effect.approval_digest()
        || !is_sha256(&receipt.response_digest)
        || receipt.accepted_at < execution_started_at
        || receipt.accepted_at >= effect.expires_at
    {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote durable receipt integrity check failed".into(),
        ));
    }
    Ok(())
}

fn validate_verification(
    receipt: &Receipt,
    verification: &Verification,
) -> Result<(), CloudStorageError> {
    if verification.receipt_id != receipt.id
        || verification.verifier.trim().is_empty()
        || !verification.independent
        || !is_sha256(&verification.evidence_digest)
        || verification.observed_at < receipt.accepted_at
    {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote durable verification integrity check failed".into(),
        ));
    }
    Ok(())
}

async fn require_current_effect_lease(
    transaction: &Transaction<'_>,
    scope: &CellScope,
    effect: &Effect,
    lease: &ExecutionLease,
    allowed_statuses: &[&str],
    operation_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    let row = transaction
        .query_opt(
            "SELECT attempt_id, lease_owner, generation, status, lease_expires_at
             FROM hartevo_cell.effect_execution_attempts
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
             ORDER BY generation DESC LIMIT 1 FOR UPDATE",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.id.as_str(),
            ],
        )
        .await?
        .ok_or(CloudStorageError::EffectLeaseLost)?;
    let stored_expires_at = row.get::<_, DateTime<Utc>>(4);
    if row.get::<_, String>(0) != lease.attempt_id.as_str()
        || row.get::<_, String>(1) != lease.owner
        || from_sql_u64(row.get(2), "effect lease generation")? != lease.generation
        || !allowed_statuses.contains(&row.get::<_, String>(3).as_str())
        || stored_expires_at != lease.expires_at
        || stored_expires_at <= operation_at
    {
        return Err(CloudStorageError::EffectLeaseLost);
    }
    Ok(())
}

async fn finish_effect_without_receipt(
    store: &PostgresCellStore,
    client: &mut Client,
    effect: &Effect,
    lease: &ExecutionLease,
    status: &str,
    reason: &str,
    operation_at: DateTime<Utc>,
) -> Result<(), CloudStorageError> {
    if !matches!(status, "failed" | "uncertain") || reason.trim().is_empty() {
        return Err(CloudStorageError::StoredValueInvalid(
            "remote effect terminal state or reason is invalid".into(),
        ));
    }
    let scope = effect_scope(*store, effect)?;
    let transaction = client.transaction().await?;
    set_scope(&transaction, &scope).await?;
    ensure_database_cell(&transaction, store.cell()).await?;
    lock_project(&transaction, &scope, &effect.project_id).await?;
    ensure_team_project(&transaction, &scope, &effect.project_id, false).await?;
    require_current_effect_lease(
        &transaction,
        &scope,
        effect,
        lease,
        &["executing"],
        operation_at,
    )
    .await?;
    let attempt_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_execution_attempts
             SET status = $10, failure_class = $11, updated_at = $12
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND attempt_id = $4 AND effect_id = $5 AND generation = $6
               AND lease_owner = $7 AND lease_expires_at = $8
               AND lease_expires_at > $9 AND status = 'executing'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &lease.attempt_id.as_str(),
                &effect.id.as_str(),
                &to_sql_u64(lease.generation)?,
                &lease.owner,
                &lease.expires_at,
                &operation_at,
                &status,
                &reason,
                &operation_at,
            ],
        )
        .await?;
    let ledger_updated = transaction
        .execute(
            "UPDATE hartevo_cell.effect_idempotency
             SET status = $6, terminal_reason = $7, updated_at = $8
             WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
               AND idempotency_key = $4 AND approval_digest = $5
               AND status = 'executing'",
            &[
                &scope.cell.as_str(),
                &scope.tenant_id.as_str(),
                &effect.project_id.as_str(),
                &effect.idempotency_key,
                &effect.approval_digest(),
                &status,
                &reason,
                &operation_at,
            ],
        )
        .await?;
    if attempt_updated != 1 || ledger_updated != 1 {
        return Err(CloudStorageError::EffectLeaseLost);
    }
    transaction.commit().await?;
    Ok(())
}

fn fixed_rate_limit_window(
    now: DateTime<Utc>,
    window_seconds: u64,
) -> Result<RateLimitWindow, CloudStorageError> {
    let window_seconds =
        i64::try_from(window_seconds).map_err(|_| CloudStorageError::RevisionOverflow)?;
    if window_seconds <= 0 {
        return Err(CloudStorageError::EffectLedger(LedgerError::Persistence(
            "rate-limit window must be positive".into(),
        )));
    }
    let start = now
        .timestamp()
        .div_euclid(window_seconds)
        .checked_mul(window_seconds)
        .ok_or(CloudStorageError::RevisionOverflow)?;
    let end = start
        .checked_add(window_seconds)
        .ok_or(CloudStorageError::RevisionOverflow)?;
    Ok(RateLimitWindow {
        started_at: DateTime::from_timestamp(start, 0)
            .ok_or(CloudStorageError::RevisionOverflow)?,
        ends_at: DateTime::from_timestamp(end, 0).ok_or(CloudStorageError::RevisionOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        AccountId, ActorId, ConnectionId, ConsentState, CurrencyCode, EffectClass, EffectId,
        EffectRisk, EffectSpec, Mission, MissionContract, MissionId, Money, ReceiptId, TenantId,
        VerificationId,
    };
    use hartevo_effect_broker::{
        EffectBroker, EffectPermissionResolver, EffectPolicy, EffectRateLimit, ExecutionLease,
        PermissionFailure,
    };
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{CloudProjectRegistration, DataCell, EncryptedPayload, POSTGRES_L2_URL_ENV};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 4, 0, 0)
            .single()
            .expect("valid time")
    }

    fn payload(seed: u8) -> EncryptedPayload {
        let ciphertext = vec![seed; 32];
        EncryptedPayload {
            key_version: 1,
            nonce: vec![seed; 12],
            content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
            ciphertext,
            aad_digest: format!("{:x}", Sha256::digest([seed, 1])),
        }
    }

    #[derive(Clone)]
    struct FixturePermissionResolver(PermissionEvidence);

    impl EffectPermissionResolver for FixturePermissionResolver {
        fn authorize(
            &self,
            _effect: &Effect,
            _now: DateTime<Utc>,
        ) -> Result<PermissionEvidence, PermissionFailure> {
            Ok(self.0.clone())
        }
    }

    fn approved_remote_effect(
        tenant_id: &TenantId,
        project_id: &ProjectId,
        mission_id: &str,
        effect_id: &str,
        idempotency_key: &str,
    ) -> (Effect, ExecutionClaimContext, PermissionEvidence) {
        let connection_id = ConnectionId::from("remote-connection-1");
        let account_id = AccountId::from("remote-account-1");
        let mut contract = MissionContract::bootstrap(
            "Execute one remotely authorized preview",
            ["channel.preview".into()],
            now(),
        );
        contract.approval_policy.validity_seconds = 3_600;
        let mut mission = Mission::compile(
            tenant_id.clone(),
            MissionId::from(mission_id),
            project_id.clone(),
            "Remote preview",
            contract,
            now(),
        )
        .expect("remote mission");
        mission.start_research([], now()).expect("research");
        let effect_id = mission
            .propose_effect(
                EffectSpec {
                    id: EffectId::from(effect_id),
                    actor_id: ActorId::from("remote-user-1"),
                    capability: "channel.preview".into(),
                    provider: "fixture-provider".into(),
                    connection_id: Some(connection_id.clone()),
                    account_id: Some(account_id),
                    required_scopes: BTreeSet::from(["preview.publish".into()]),
                    effect_class: EffectClass::ExternalWrite,
                    description: "Publish a controlled remote preview".into(),
                    target_resource: "preview://remote".into(),
                    audience_digest: None,
                    payload_digest: "1".repeat(64),
                    asset_digests: BTreeSet::new(),
                    scheduled_for: None,
                    timezone: "UTC".into(),
                    consent: ConsentState::NotRequired,
                    consent_record_id: None,
                    consent_requirement: None,
                    conversation_guard: None,
                    creator_contact_guard: None,
                    policy_version: "remote-policy-v1".into(),
                    risk: EffectRisk::Low,
                    idempotency_key: idempotency_key.into(),
                    amount: Money::zero(CurrencyCode::parse("USD").expect("USD")),
                    expires_at: now() + Duration::hours(2),
                },
                now(),
            )
            .expect("remote effect");
        let evidence = PermissionEvidence {
            connection_evidence_digest: Some("2".repeat(64)),
            consent_evidence_digest: None,
            conversation_evidence_digest: None,
            creator_contact_evidence_digest: None,
            fences: BTreeSet::from([PermissionFence::Connection {
                connection_id,
                revision: 1,
            }]),
        };
        let policy = EffectPolicy {
            version: "remote-policy-v1".into(),
            allowed_capabilities: BTreeSet::from(["channel.preview".into()]),
            allowed_classes: BTreeSet::from([EffectClass::ExternalWrite]),
            max_amounts_minor: BTreeMap::from([(CurrencyCode::parse("USD").expect("USD"), 0)]),
            rate_limits: vec![EffectRateLimit {
                rule_id: "remote-preview-per-minute".into(),
                provider: "fixture-provider".into(),
                capability: "channel.preview".into(),
                max_executions: 1,
                window_seconds: 60,
            }],
        };
        let broker = EffectBroker::new(policy.clone(), "remote-test-broker");
        broker
            .approve(
                &mut mission,
                &effect_id,
                ActorId::from("remote-approver"),
                &FixturePermissionResolver(evidence.clone()),
                now(),
            )
            .expect("remote approval");
        let effect = mission.effect(&effect_id).expect("effect").clone();
        let context = policy
            .execution_claim_context(&effect, evidence.clone())
            .expect("remote execution context");
        (effect, context, evidence)
    }

    #[test]
    fn permission_fence_request_digest_binds_revision_activity_and_precondition() {
        let mutation = CloudPermissionFenceMutation {
            scope: CellScope {
                cell: DataCell::Us,
                tenant_id: TenantId::from("tenant-1"),
            },
            project_id: ProjectId::from("project-1"),
            fence: PermissionFence::Connection {
                connection_id: ConnectionId::from("connection-1"),
                revision: 1,
            },
            precondition: MutationPrecondition::CreateOnly,
            evidence_digest: "a".repeat(64),
            active: true,
            idempotency_key_digest: "b".repeat(64),
            recorded_at: now(),
        };
        let key = mutation
            .validate(PostgresCellStore::new(DataCell::Us))
            .expect("valid fence");
        let digest = mutation.request_digest(&key).expect("request digest");
        let mut changed = mutation.clone();
        changed.active = false;
        assert_ne!(
            digest,
            changed
                .request_digest(&fence_key(&changed.fence).expect("changed key"))
                .expect("changed digest")
        );
        changed = mutation.clone();
        changed.precondition = MutationPrecondition::ExactRevision(1);
        assert_ne!(
            digest,
            changed
                .request_digest(&fence_key(&changed.fence).expect("changed key"))
                .expect("changed digest")
        );
        changed = mutation;
        changed.fence = PermissionFence::Connection {
            connection_id: ConnectionId::from("connection-1"),
            revision: 2,
        };
        assert_ne!(
            digest,
            changed
                .request_digest(&fence_key(&changed.fence).expect("changed key"))
                .expect("changed digest")
        );
    }

    #[test]
    fn durable_receipt_requires_the_original_exact_approval_dispatch_window() {
        let (effect, _, _) = approved_remote_effect(
            &TenantId::from("tenant-receipt-window"),
            &ProjectId::from("project-receipt-window"),
            "mission-receipt-window",
            "effect-receipt-window",
            "idempotency-receipt-window",
        );
        let approval = effect.approval.as_ref().expect("approval");
        let receipt = Receipt {
            id: ReceiptId::from("receipt-window"),
            provider: effect.provider.clone(),
            external_id: "external-window".into(),
            accepted_at: approval.decided_at + Duration::seconds(2),
            request_digest: effect.approval_digest(),
            response_digest: "f".repeat(64),
        };
        validate_durable_receipt(
            &effect,
            &receipt,
            approval.decided_at + Duration::seconds(1),
        )
        .expect("dispatch inside exact approval window");
        assert!(matches!(
            validate_durable_receipt(&effect, &receipt, approval.valid_until),
            Err(CloudStorageError::StoredValueInvalid(_))
        ));
        assert!(matches!(
            validate_durable_receipt(
                &effect,
                &receipt,
                approval.decided_at - Duration::milliseconds(1),
            ),
            Err(CloudStorageError::StoredValueInvalid(_))
        ));
    }

    async fn prepare_remote_project(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
    ) -> (CellScope, ProjectId) {
        store.migrate(client, now()).await.expect("migrate");
        let scope = CellScope {
            cell: DataCell::Us,
            tenant_id: TenantId::new(),
        };
        store
            .register_tenant(client, &scope, now())
            .await
            .expect("tenant");
        let project_id = ProjectId::new();
        let initial_payload = payload(31);
        store
            .create_project(
                client,
                &CloudProjectRegistration {
                    scope: scope.clone(),
                    project_id: project_id.clone(),
                    encryption_mode: ProjectEncryptionMode::TeamEnvelope,
                    remote_execution_opt_in: true,
                    metadata_digest: initial_payload.content_digest.clone(),
                    initial_payload,
                    idempotency_key_digest: "3".repeat(64),
                    created_at: now(),
                },
            )
            .await
            .expect("team project");
        (scope, project_id)
    }

    async fn publish_active_fixture_fence(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        evidence: &PermissionEvidence,
    ) {
        let mutation = CloudPermissionFenceMutation {
            scope: scope.clone(),
            project_id: project_id.clone(),
            fence: evidence.fences.iter().next().expect("fence").clone(),
            precondition: MutationPrecondition::CreateOnly,
            evidence_digest: evidence
                .connection_evidence_digest
                .clone()
                .expect("evidence digest"),
            active: true,
            idempotency_key_digest: "4".repeat(64),
            recorded_at: now(),
        };
        assert!(
            !store
                .publish_effect_permission_fence(client, &mutation)
                .await
                .expect("publish permission fence")
                .duplicate
        );
    }

    async fn assert_effect_has_no_durable_state(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
        effect: &Effect,
    ) {
        let inspection = client.transaction().await.expect("effect state inspection");
        set_scope(&inspection, scope).await.expect("scope");
        let counts = inspection
            .query_one(
                "SELECT
                   (SELECT count(*) FROM hartevo_cell.effect_idempotency
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_reservations
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_decisions
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &effect.id.as_str(),
                ],
            )
            .await
            .expect("effect state counts");
        assert_eq!(
            [
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2),
                counts.get::<_, i64>(3),
            ],
            [0, 0, 0, 0]
        );
        inspection.commit().await.expect("inspection commit");
    }

    async fn claim_initial_effect_and_assert_rate_limit(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> (Effect, ExecutionLease, DateTime<Utc>, Effect) {
        let (effect, context, evidence) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            "remote-mission-1",
            "remote-effect-1",
            "remote-effect-idempotency-1",
        );
        publish_active_fixture_fence(client, store, scope, project_id, &evidence).await;
        assert_eq!(
            store
                .claim_effect(
                    client,
                    &effect,
                    None,
                    "recovery-probe",
                    now() + Duration::seconds(1),
                    now() + Duration::seconds(31),
                )
                .await
                .expect("read-only recovery probe"),
            LedgerClaim::AuthorizationRequired
        );
        assert_effect_has_no_durable_state(client, scope, project_id, &effect).await;
        let LedgerClaim::Acquired {
            lease,
            receipt: None,
            execution_started_at,
        } = store
            .claim_effect(
                client,
                &effect,
                Some(&context),
                "execution-worker",
                now() + Duration::seconds(1),
                now() + Duration::seconds(31),
            )
            .await
            .expect("authorized remote execution claim")
        else {
            panic!("expected remote execution lease")
        };
        assert_eq!(execution_started_at, now() + Duration::seconds(1));
        let (limited_effect, limited_context, _) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            "remote-mission-2",
            "remote-effect-2",
            "remote-effect-idempotency-2",
        );
        assert!(matches!(
            store
                .claim_effect(
                    client,
                    &limited_effect,
                    Some(&limited_context),
                    "rate-limited-worker",
                    now() + Duration::seconds(2),
                    now() + Duration::seconds(32),
                )
                .await
                .expect("durable rate-limit decision"),
            LedgerClaim::RateLimited { .. }
        ));
        (effect, lease, execution_started_at, limited_effect)
    }

    async fn revoke_fixture_fence(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) {
        store
            .publish_effect_permission_fence(
                client,
                &CloudPermissionFenceMutation {
                    scope: scope.clone(),
                    project_id: project_id.clone(),
                    fence: PermissionFence::Connection {
                        connection_id: ConnectionId::from("remote-connection-1"),
                        revision: 2,
                    },
                    precondition: MutationPrecondition::ExactRevision(1),
                    evidence_digest: "6".repeat(64),
                    active: false,
                    idempotency_key_digest: "7".repeat(64),
                    recorded_at: now() + Duration::seconds(4),
                },
            )
            .await
            .expect("revoke permission after dispatch");
    }

    async fn persist_receipt_and_complete_recovery(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        effect: &Effect,
        lease: &ExecutionLease,
        execution_started_at: DateTime<Utc>,
    ) {
        let receipt = Receipt {
            id: ReceiptId::from("remote-receipt-1"),
            provider: effect.provider.clone(),
            external_id: "remote-external-1".into(),
            accepted_at: now() + Duration::seconds(3),
            request_digest: effect.approval_digest(),
            response_digest: "5".repeat(64),
        };
        store
            .record_effect_receipt(
                client,
                effect,
                lease,
                &receipt,
                now() + Duration::seconds(3),
            )
            .await
            .expect("durable remote receipt");
        revoke_fixture_fence(client, store, scope, project_id).await;
        let LedgerClaim::Acquired {
            lease: verification_lease,
            receipt: Some(reused),
            execution_started_at: recovered_start,
        } = store
            .claim_effect(
                client,
                effect,
                None,
                "verification-worker",
                now() + Duration::seconds(5),
                now() + Duration::seconds(35),
            )
            .await
            .expect("recover receipt without current authorization")
        else {
            panic!("expected verification-only lease")
        };
        assert_eq!(reused, receipt);
        assert_eq!(recovered_start, execution_started_at);
        let verification = Verification {
            id: VerificationId::from("remote-verification-1"),
            status: VerificationStatus::Confirmed,
            verifier: "remote-independent-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(6),
            evidence_digest: "8".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        store
            .record_effect_verification(
                client,
                effect,
                &verification_lease,
                &verification,
                now() + Duration::seconds(6),
            )
            .await
            .expect("durable remote verification");
        assert_eq!(
            store
                .claim_effect(
                    client,
                    effect,
                    None,
                    "final-recovery-probe",
                    now() + Duration::seconds(7),
                    now() + Duration::seconds(37),
                )
                .await
                .expect("already verified recovery"),
            LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at,
            }
        );
    }

    async fn assert_revoked_fence_blocks_fresh_effect_without_side_effects(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) {
        let (effect, context, _) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            "remote-mission-stale",
            "remote-effect-stale",
            "remote-effect-idempotency-stale",
        );
        assert!(matches!(
            store
                .claim_effect(
                    client,
                    &effect,
                    Some(&context),
                    "stale-fence-worker",
                    now() + Duration::seconds(8),
                    now() + Duration::seconds(38),
                )
                .await,
            Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict))
        ));
        assert_effect_has_no_durable_state(client, scope, project_id, &effect).await;
    }

    async fn assert_personal_project_remote_effect_fails_closed(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
    ) {
        let project_id = ProjectId::new();
        let initial_payload = payload(41);
        store
            .create_project(
                client,
                &CloudProjectRegistration {
                    scope: scope.clone(),
                    project_id: project_id.clone(),
                    encryption_mode: ProjectEncryptionMode::PersonalE2ee,
                    remote_execution_opt_in: false,
                    metadata_digest: initial_payload.content_digest.clone(),
                    initial_payload,
                    idempotency_key_digest: "9".repeat(64),
                    created_at: now(),
                },
            )
            .await
            .expect("personal project");
        let (effect, context, _) = approved_remote_effect(
            &scope.tenant_id,
            &project_id,
            "personal-remote-mission",
            "personal-remote-effect",
            "personal-remote-idempotency",
        );
        assert!(matches!(
            store
                .claim_effect(
                    client,
                    &effect,
                    Some(&context),
                    "forbidden-personal-worker",
                    now() + Duration::seconds(1),
                    now() + Duration::seconds(31),
                )
                .await,
            Err(CloudStorageError::RemoteEffectExecutionNotAllowed)
        ));
        assert_effect_has_no_durable_state(client, scope, &project_id, &effect).await;
    }

    async fn assert_rate_limited_effect_has_no_ledger(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
        limited_effect: &Effect,
    ) {
        let inspection = client.transaction().await.expect("inspection");
        set_scope(&inspection, scope).await.expect("scope");
        let counts = inspection
            .query_one(
                "SELECT
                   (SELECT count(*) FROM hartevo_cell.effect_idempotency
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_reservations
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_decisions
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
                      AND decision = 'denied')",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &limited_effect.id.as_str(),
                ],
            )
            .await
            .expect("limited effect state counts");
        assert_eq!(
            [
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2),
                counts.get::<_, i64>(3),
            ],
            [0, 0, 0, 1]
        );
        inspection.commit().await.expect("inspection commit");
    }

    type TestConnectionTask = tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>;

    #[derive(Debug)]
    struct ClaimedRemoteEffect {
        effect: Effect,
        lease: ExecutionLease,
        execution_started_at: DateTime<Utc>,
    }

    #[derive(Debug)]
    struct DurableReceiptScenario {
        effect: Effect,
        receipt: Receipt,
        execution_started_at: DateTime<Utc>,
    }

    #[derive(Clone, Copy, Debug)]
    enum RemoteEffectCompletionPath {
        Receipt,
        Verification,
        Failed,
        Uncertain,
    }

    impl RemoteEffectCompletionPath {
        const fn label(self) -> &'static str {
            match self {
                Self::Receipt => "receipt",
                Self::Verification => "verification",
                Self::Failed => "failed",
                Self::Uncertain => "uncertain",
            }
        }

        const fn completed_status(self) -> &'static str {
            match self {
                Self::Receipt => "receipt_recorded",
                Self::Verification => "verified",
                Self::Failed => "failed",
                Self::Uncertain => "uncertain",
            }
        }

        const fn matrix_index(self) -> i64 {
            match self {
                Self::Receipt => 0,
                Self::Verification => 1,
                Self::Failed => 2,
                Self::Uncertain => 3,
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum RemoteEffectLeaseFenceCase {
        Before,
        Equality,
        After,
        TamperedExpiry,
    }

    impl RemoteEffectLeaseFenceCase {
        const fn label(self) -> &'static str {
            match self {
                Self::Before => "before",
                Self::Equality => "equality",
                Self::After => "after",
                Self::TamperedExpiry => "tampered_expiry",
            }
        }

        const fn expects_success(self) -> bool {
            matches!(self, Self::Before)
        }

        const fn matrix_index(self) -> i64 {
            match self {
                Self::Before => 0,
                Self::Equality => 1,
                Self::After => 2,
                Self::TamperedExpiry => 3,
            }
        }

        fn operation_at(self, expires_at: DateTime<Utc>) -> DateTime<Utc> {
            match self {
                Self::Before | Self::TamperedExpiry => expires_at - Duration::seconds(1),
                Self::Equality => expires_at,
                Self::After => expires_at + Duration::seconds(1),
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RemoteEffectAttemptCompletionSnapshot {
        attempt_id: String,
        cell: String,
        tenant_id: String,
        project_id: String,
        mission_id: String,
        effect_id: String,
        attempt_no: i64,
        generation: i64,
        status: String,
        lease_owner: String,
        lease_expires_at: DateTime<Utc>,
        request_digest: String,
        receipt_json: Option<serde_json::Value>,
        verification_json: Option<serde_json::Value>,
        failure_class: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RemoteEffectIdempotencyCompletionSnapshot {
        cell: String,
        tenant_id: String,
        project_id: String,
        mission_id: String,
        idempotency_key: String,
        effect_id: String,
        approval_digest: String,
        status: String,
        receipt_json: Option<serde_json::Value>,
        verification_json: Option<serde_json::Value>,
        terminal_reason: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RemoteEffectCompletionSnapshot {
        attempts: Vec<RemoteEffectAttemptCompletionSnapshot>,
        idempotency: RemoteEffectIdempotencyCompletionSnapshot,
    }

    struct RemoteEffectCompletionFixture {
        effect: Effect,
        lease: ExecutionLease,
        receipt: Receipt,
        verification: Verification,
    }

    async fn connect_test_client(
        database_url: &str,
    ) -> (tokio_postgres::Client, TestConnectionTask) {
        let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls)
            .await
            .expect("connect disposable PostgreSQL L2 database");
        let connection_task = tokio::spawn(connection);
        let role = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect PostgreSQL test role");
        assert!(!role.get::<_, bool>(0) && !role.get::<_, bool>(1));
        (client, connection_task)
    }

    async fn close_test_client(
        client: tokio_postgres::Client,
        connection_task: TestConnectionTask,
    ) {
        drop(client);
        connection_task
            .await
            .expect("PostgreSQL connection task")
            .expect("PostgreSQL connection clean shutdown");
    }

    async fn remote_effect_attempt_completion_snapshot(
        inspection: &Transaction<'_>,
        scope: &CellScope,
        effect: &Effect,
    ) -> Vec<RemoteEffectAttemptCompletionSnapshot> {
        inspection
            .query(
                "SELECT attempt_id, cell, tenant_id, project_id, mission_id, effect_id,
                        attempt_no, generation, status, lease_owner, lease_expires_at,
                        request_digest, receipt_json, verification_json, failure_class,
                        created_at, updated_at
                 FROM hartevo_cell.effect_execution_attempts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4
                 ORDER BY generation ASC",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &effect.id.as_str(),
                ],
            )
            .await
            .expect("completion attempt snapshot")
            .into_iter()
            .map(|row| RemoteEffectAttemptCompletionSnapshot {
                attempt_id: row.get(0),
                cell: row.get(1),
                tenant_id: row.get(2),
                project_id: row.get(3),
                mission_id: row.get(4),
                effect_id: row.get(5),
                attempt_no: row.get(6),
                generation: row.get(7),
                status: row.get(8),
                lease_owner: row.get(9),
                lease_expires_at: row.get(10),
                request_digest: row.get(11),
                receipt_json: row.get(12),
                verification_json: row.get(13),
                failure_class: row.get(14),
                created_at: row.get(15),
                updated_at: row.get(16),
            })
            .collect()
    }

    async fn remote_effect_idempotency_completion_snapshot(
        inspection: &Transaction<'_>,
        scope: &CellScope,
        effect: &Effect,
    ) -> RemoteEffectIdempotencyCompletionSnapshot {
        let row = inspection
            .query_one(
                "SELECT cell, tenant_id, project_id, mission_id, idempotency_key, effect_id,
                        approval_digest, status, receipt_json, verification_json,
                        terminal_reason, created_at, updated_at
                 FROM hartevo_cell.effect_idempotency
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND idempotency_key = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &effect.project_id.as_str(),
                    &effect.idempotency_key,
                ],
            )
            .await
            .expect("completion idempotency snapshot");
        RemoteEffectIdempotencyCompletionSnapshot {
            cell: row.get(0),
            tenant_id: row.get(1),
            project_id: row.get(2),
            mission_id: row.get(3),
            idempotency_key: row.get(4),
            effect_id: row.get(5),
            approval_digest: row.get(6),
            status: row.get(7),
            receipt_json: row.get(8),
            verification_json: row.get(9),
            terminal_reason: row.get(10),
            created_at: row.get(11),
            updated_at: row.get(12),
        }
    }

    async fn remote_effect_completion_snapshot(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        effect: &Effect,
    ) -> RemoteEffectCompletionSnapshot {
        let inspection = client.transaction().await.expect("completion inspection");
        set_scope(&inspection, scope)
            .await
            .expect("completion inspection scope");
        let attempts = remote_effect_attempt_completion_snapshot(&inspection, scope, effect).await;
        let idempotency =
            remote_effect_idempotency_completion_snapshot(&inspection, scope, effect).await;
        inspection
            .commit()
            .await
            .expect("completion inspection commit");
        RemoteEffectCompletionSnapshot {
            attempts,
            idempotency,
        }
    }

    async fn claim_remote_effect(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        tag: &str,
        claim_at: DateTime<Utc>,
    ) -> ClaimedRemoteEffect {
        let (effect, context, _) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            format!("mission-{tag}").as_str(),
            format!("effect-{tag}").as_str(),
            format!("idempotency-{tag}").as_str(),
        );
        let LedgerClaim::Acquired {
            lease,
            receipt: None,
            execution_started_at,
        } = store
            .claim_effect(
                client,
                &effect,
                Some(&context),
                format!("worker-{tag}").as_str(),
                claim_at,
                claim_at + Duration::seconds(30),
            )
            .await
            .expect("claim fresh remote Effect")
        else {
            panic!("expected a fresh provider execution lease")
        };
        assert_eq!(execution_started_at, claim_at);
        ClaimedRemoteEffect {
            effect,
            lease,
            execution_started_at,
        }
    }

    async fn remote_effect_completion_fixture(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        path: RemoteEffectCompletionPath,
        case: RemoteEffectLeaseFenceCase,
        claim_at: DateTime<Utc>,
    ) -> RemoteEffectCompletionFixture {
        let tag = format!("completion-{}-{}", path.label(), case.label());
        let claimed = claim_remote_effect(client, store, scope, project_id, &tag, claim_at).await;
        let receipt = scenario_receipt(&claimed.effect, &tag, claim_at + Duration::seconds(1));
        let lease = if matches!(path, RemoteEffectCompletionPath::Verification) {
            store
                .record_effect_receipt(
                    client,
                    &claimed.effect,
                    &claimed.lease,
                    &receipt,
                    claim_at + Duration::seconds(1),
                )
                .await
                .expect("valid remote receipt before verification lease");
            let LedgerClaim::Acquired {
                lease,
                receipt: Some(reused),
                ..
            } = store
                .claim_effect(
                    client,
                    &claimed.effect,
                    None,
                    "completion-verification-worker",
                    claim_at + Duration::seconds(2),
                    claim_at + Duration::seconds(32),
                )
                .await
                .expect("remote completion verification claim")
            else {
                panic!("expected remote completion verification lease")
            };
            assert_eq!(reused, receipt);
            lease
        } else {
            claimed.lease
        };
        let verification = Verification {
            id: VerificationId::from_stable(format!("verification-{tag}")),
            status: VerificationStatus::Confirmed,
            verifier: "remote-independent-completion-readback".into(),
            independent: true,
            observed_at: claim_at + Duration::seconds(3),
            evidence_digest: "c".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        RemoteEffectCompletionFixture {
            effect: claimed.effect,
            lease,
            receipt,
            verification,
        }
    }

    async fn complete_remote_effect(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        fixture: &RemoteEffectCompletionFixture,
        path: RemoteEffectCompletionPath,
        lease: &ExecutionLease,
        operation_at: DateTime<Utc>,
    ) -> Result<(), CloudStorageError> {
        match path {
            RemoteEffectCompletionPath::Receipt => {
                store
                    .record_effect_receipt(
                        client,
                        &fixture.effect,
                        lease,
                        &fixture.receipt,
                        operation_at,
                    )
                    .await
            }
            RemoteEffectCompletionPath::Verification => {
                store
                    .record_effect_verification(
                        client,
                        &fixture.effect,
                        lease,
                        &fixture.verification,
                        operation_at,
                    )
                    .await
            }
            RemoteEffectCompletionPath::Failed => {
                store
                    .record_effect_failed(
                        client,
                        &fixture.effect,
                        lease,
                        "remote provider rejected completion fixture",
                        operation_at,
                    )
                    .await
            }
            RemoteEffectCompletionPath::Uncertain => {
                store
                    .record_effect_uncertain(
                        client,
                        &fixture.effect,
                        lease,
                        "remote provider completion fixture is uncertain",
                        operation_at,
                    )
                    .await
            }
        }
    }

    async fn assert_remote_effect_completion_fences(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) {
        for path in [
            RemoteEffectCompletionPath::Receipt,
            RemoteEffectCompletionPath::Verification,
            RemoteEffectCompletionPath::Failed,
            RemoteEffectCompletionPath::Uncertain,
        ] {
            for case in [
                RemoteEffectLeaseFenceCase::Before,
                RemoteEffectLeaseFenceCase::Equality,
                RemoteEffectLeaseFenceCase::After,
                RemoteEffectLeaseFenceCase::TamperedExpiry,
            ] {
                let scenario_index = path.matrix_index() * 4 + case.matrix_index();
                let claim_at = now()
                    + Duration::seconds(1 + scenario_index * 61)
                    + Duration::nanoseconds(123_456_789);
                let fixture = remote_effect_completion_fixture(
                    client, store, scope, project_id, path, case, claim_at,
                )
                .await;
                let operation_at = case.operation_at(fixture.lease.expires_at);
                let mut presented_lease = fixture.lease.clone();
                if matches!(case, RemoteEffectLeaseFenceCase::TamperedExpiry) {
                    presented_lease.expires_at += Duration::seconds(1);
                }
                let before =
                    remote_effect_completion_snapshot(client, scope, &fixture.effect).await;
                assert_eq!(
                    before
                        .attempts
                        .last()
                        .expect("remote leased attempt")
                        .lease_expires_at,
                    fixture.lease.expires_at,
                    "{path:?}/{case:?}: returned lease expiry must equal the stored value",
                );
                let result = complete_remote_effect(
                    client,
                    store,
                    &fixture,
                    path,
                    &presented_lease,
                    operation_at,
                )
                .await;
                let after = remote_effect_completion_snapshot(client, scope, &fixture.effect).await;
                if case.expects_success() {
                    assert!(result.is_ok(), "{path:?}/{case:?}: {result:?}");
                    assert_ne!(after, before, "{path:?}/{case:?}");
                    assert_eq!(
                        after
                            .attempts
                            .last()
                            .expect("remote completed attempt")
                            .status,
                        path.completed_status(),
                        "{path:?}/{case:?}",
                    );
                    assert_eq!(
                        after.idempotency.status,
                        path.completed_status(),
                        "{path:?}/{case:?}",
                    );
                } else {
                    assert!(
                        matches!(&result, Err(CloudStorageError::EffectLeaseLost)),
                        "{path:?}/{case:?}: {result:?}",
                    );
                    assert_eq!(after, before, "{path:?}/{case:?}");
                }
            }
        }
    }

    fn scenario_receipt(effect: &Effect, tag: &str, accepted_at: DateTime<Utc>) -> Receipt {
        Receipt {
            id: ReceiptId::from(format!("receipt-{tag}").as_str()),
            provider: effect.provider.clone(),
            external_id: format!("external-{tag}"),
            accepted_at,
            request_digest: effect.approval_digest(),
            response_digest: "a".repeat(64),
        }
    }

    async fn persist_receipt_scenario(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        tag: &str,
        claim_at: DateTime<Utc>,
    ) -> DurableReceiptScenario {
        let claimed = claim_remote_effect(client, store, scope, project_id, tag, claim_at).await;
        let receipt = scenario_receipt(&claimed.effect, tag, claim_at + Duration::seconds(1));
        store
            .record_effect_receipt(
                client,
                &claimed.effect,
                &claimed.lease,
                &receipt,
                receipt.accepted_at,
            )
            .await
            .expect("persist durable Provider receipt");
        DurableReceiptScenario {
            effect: claimed.effect,
            receipt,
            execution_started_at: claimed.execution_started_at,
        }
    }

    async fn run_concurrent_quota_claims(
        first: &mut tokio_postgres::Client,
        second: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> (ClaimedRemoteEffect, Effect) {
        let (left_effect, left_context, evidence) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            "mission-concurrent-left",
            "effect-concurrent-left",
            "idempotency-concurrent-left",
        );
        let (right_effect, right_context, _) = approved_remote_effect(
            &scope.tenant_id,
            project_id,
            "mission-concurrent-right",
            "effect-concurrent-right",
            "idempotency-concurrent-right",
        );
        publish_active_fixture_fence(first, store, scope, project_id, &evidence).await;
        let claimed_at = now() + Duration::seconds(1);
        let lease_until = claimed_at + Duration::seconds(30);
        let (left, right) = tokio::join!(
            store.claim_effect(
                first,
                &left_effect,
                Some(&left_context),
                "concurrent-left",
                claimed_at,
                lease_until,
            ),
            store.claim_effect(
                second,
                &right_effect,
                Some(&right_context),
                "concurrent-right",
                claimed_at,
                lease_until,
            )
        );
        let left = left.expect("left concurrent claim");
        let right = right.expect("right concurrent claim");
        match (left, right) {
            (
                LedgerClaim::Acquired {
                    lease,
                    receipt: None,
                    execution_started_at,
                },
                LedgerClaim::RateLimited { retry_at },
            ) => {
                assert_eq!(retry_at, now() + Duration::seconds(60));
                (
                    ClaimedRemoteEffect {
                        effect: left_effect,
                        lease,
                        execution_started_at,
                    },
                    right_effect,
                )
            }
            (
                LedgerClaim::RateLimited { retry_at },
                LedgerClaim::Acquired {
                    lease,
                    receipt: None,
                    execution_started_at,
                },
            ) => {
                assert_eq!(retry_at, now() + Duration::seconds(60));
                (
                    ClaimedRemoteEffect {
                        effect: right_effect,
                        lease,
                        execution_started_at,
                    },
                    left_effect,
                )
            }
            claims => panic!("expected exactly one execution permit and one denial: {claims:?}"),
        }
    }

    async fn assert_concurrent_quota_state(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
    ) {
        let inspection = client.transaction().await.expect("quota inspection");
        set_scope(&inspection, scope).await.expect("scope");
        let counts = inspection
            .query_one(
                "SELECT
                   (SELECT count(*) FROM hartevo_cell.effect_idempotency
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                   (SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_reservations
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_decisions
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                      AND decision = 'reserved'),
                   (SELECT count(*) FROM hartevo_cell.effect_rate_limit_decisions
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                      AND decision = 'denied'),
                   (SELECT COALESCE(max(consumed), 0)
                    FROM hartevo_cell.effect_rate_limit_buckets
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                ],
            )
            .await
            .expect("concurrent quota counts");
        assert_eq!(
            [
                counts.get::<_, i64>(0),
                counts.get::<_, i64>(1),
                counts.get::<_, i64>(2),
                counts.get::<_, i64>(3),
                counts.get::<_, i64>(4),
                counts.get::<_, i64>(5),
            ],
            [1, 1, 1, 1, 1, 1]
        );
        inspection.commit().await.expect("quota inspection commit");
    }

    async fn effect_attempt_count(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
        effect: &Effect,
    ) -> i64 {
        let inspection = client.transaction().await.expect("attempt inspection");
        set_scope(&inspection, scope).await.expect("scope");
        let count = inspection
            .query_one(
                "SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &effect.id.as_str(),
                ],
            )
            .await
            .expect("effect attempt count")
            .get(0);
        inspection
            .commit()
            .await
            .expect("attempt inspection commit");
        count
    }

    async fn corrupt_receipt_request_digest(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
        effect: &Effect,
        corrupted_at: DateTime<Utc>,
    ) {
        let transaction = client.transaction().await.expect("corruption transaction");
        set_scope(&transaction, scope).await.expect("scope");
        let corrupted_digest = "0".repeat(64);
        let updated = transaction
            .execute(
                "UPDATE hartevo_cell.effect_idempotency
                 SET receipt_json = jsonb_set(
                       receipt_json, '{requestDigest}', to_jsonb($5::text), false
                     ), updated_at = $6
                 WHERE cell = $1 AND tenant_id = $2 AND project_id = $3
                   AND effect_id = $4 AND status = 'receipt_recorded'",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &effect.id.as_str(),
                    &corrupted_digest,
                    &corrupted_at,
                ],
            )
            .await
            .expect("inject structurally valid Receipt corruption");
        assert_eq!(updated, 1);
        transaction.commit().await.expect("corruption commit");
    }

    async fn recover_receipt_and_record_verification(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scenario: &DurableReceiptScenario,
        tag: &str,
        status: VerificationStatus,
        recovered_at: DateTime<Utc>,
    ) -> Verification {
        let LedgerClaim::Acquired {
            lease,
            receipt: Some(receipt),
            execution_started_at,
        } = store
            .claim_effect(
                client,
                &scenario.effect,
                None,
                format!("verification-worker-{tag}").as_str(),
                recovered_at,
                recovered_at + Duration::seconds(30),
            )
            .await
            .expect("recover durable Receipt on a restarted connection")
        else {
            panic!("Receipt recovery must issue only a Verification lease")
        };
        assert_eq!(receipt, scenario.receipt);
        assert_eq!(execution_started_at, scenario.execution_started_at);
        let verification = Verification {
            id: VerificationId::from(format!("verification-{tag}").as_str()),
            status,
            verifier: format!("independent-readback-{tag}"),
            independent: true,
            observed_at: recovered_at + Duration::seconds(1),
            evidence_digest: "b".repeat(64),
            receipt_id: receipt.id,
        };
        store
            .record_effect_verification(
                client,
                &scenario.effect,
                &lease,
                &verification,
                verification.observed_at,
            )
            .await
            .expect("persist exact Verification terminal state");
        verification
    }

    async fn assert_terminal_claim(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        effect: &Effect,
        claimed_at: DateTime<Utc>,
        expected: &LedgerClaim,
    ) {
        let actual = store
            .claim_effect(
                client,
                effect,
                None,
                "terminal-recovery-probe",
                claimed_at,
                claimed_at + Duration::seconds(30),
            )
            .await
            .expect("read durable terminal projection");
        assert_eq!(&actual, expected);
    }

    async fn assert_corrupted_receipt_fails_before_new_attempt(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        scenario: &DurableReceiptScenario,
        claimed_at: DateTime<Utc>,
    ) {
        let before =
            effect_attempt_count(client, scope, &scenario.effect.project_id, &scenario.effect)
                .await;
        assert!(matches!(
            store
                .claim_effect(
                    client,
                    &scenario.effect,
                    None,
                    "corrupt-receipt-recovery",
                    claimed_at,
                    claimed_at + Duration::seconds(30),
                )
                .await,
            Err(CloudStorageError::StoredValueInvalid(_))
        ));
        assert_eq!(
            effect_attempt_count(client, scope, &scenario.effect.project_id, &scenario.effect,)
                .await,
            before
        );
    }

    #[tokio::test]
    async fn postgres_effect_completion_expiry_fence_reports_blocked_or_executes_matrix() {
        let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL Effect completion before/equality/after/tampered-expiry matrix did not execute"
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let (mut client, connection_task) = connect_test_client(&database_url).await;
        let store = PostgresCellStore::new(DataCell::Us);
        let (scope, project_id) = prepare_remote_project(&mut client, &store).await;
        let (_, _, evidence) = approved_remote_effect(
            &scope.tenant_id,
            &project_id,
            "mission-completion-fence",
            "effect-completion-fence",
            "idempotency-completion-fence",
        );
        publish_active_fixture_fence(&mut client, &store, &scope, &project_id, &evidence).await;
        assert_remote_effect_completion_fences(&mut client, &store, &scope, &project_id).await;
        close_test_client(client, connection_task).await;
    }

    #[tokio::test]
    async fn postgres_effect_claim_contract_reports_blocked_or_executes_full_recovery() {
        let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL Effect fence/rate-limit/recovery replay did not execute"
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let (mut client, connection) =
            tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                .await
                .expect("connect disposable PostgreSQL L2 database");
        let connection_task = tokio::spawn(connection);
        let role = client
            .query_one(
                "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .expect("inspect PostgreSQL test role");
        assert!(!role.get::<_, bool>(0) && !role.get::<_, bool>(1));

        let store = PostgresCellStore::new(DataCell::Us);
        let (scope, project_id) = prepare_remote_project(&mut client, &store).await;
        let (effect, lease, execution_started_at, limited_effect) =
            claim_initial_effect_and_assert_rate_limit(&mut client, &store, &scope, &project_id)
                .await;
        persist_receipt_and_complete_recovery(
            &mut client,
            &store,
            &scope,
            &project_id,
            &effect,
            &lease,
            execution_started_at,
        )
        .await;
        assert_revoked_fence_blocks_fresh_effect_without_side_effects(
            &mut client,
            &store,
            &scope,
            &project_id,
        )
        .await;
        assert_rate_limited_effect_has_no_ledger(&mut client, &scope, &project_id, &limited_effect)
            .await;
        assert_personal_project_remote_effect_fails_closed(&mut client, &store, &scope).await;

        drop(client);
        connection_task
            .await
            .expect("PostgreSQL connection task")
            .expect("PostgreSQL connection clean shutdown");
    }

    const PROVIDER_REJECTED_REASON: &str = "fixture Provider rejected exact payload";
    const PROVIDER_UNCERTAIN_REASON: &str = "timeout after Provider accepted request boundary";

    #[derive(Debug)]
    struct ProviderTerminalScenarios {
        rejected: ClaimedRemoteEffect,
        rejected_at: DateTime<Utc>,
        uncertain: ClaimedRemoteEffect,
        uncertain_at: DateTime<Utc>,
    }

    #[derive(Debug)]
    struct ReceiptTerminalScenarios {
        rejected: DurableReceiptScenario,
        inconclusive: DurableReceiptScenario,
        corrupted: DurableReceiptScenario,
    }

    #[derive(Debug)]
    struct TerminalRecoveryFixture {
        scope: CellScope,
        project_id: ProjectId,
        provider: ProviderTerminalScenarios,
        receipts: ReceiptTerminalScenarios,
    }

    #[derive(Debug)]
    struct VerificationTerminalEvidence {
        rejected: Verification,
        inconclusive: Verification,
    }

    async fn seed_provider_terminal_states(
        first: &mut tokio_postgres::Client,
        second: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> ProviderTerminalScenarios {
        let (rejected, rate_limited) =
            run_concurrent_quota_claims(first, second, store, scope, project_id).await;
        assert_concurrent_quota_state(first, scope, project_id).await;
        assert_rate_limited_effect_has_no_ledger(first, scope, project_id, &rate_limited).await;
        let rejected_at = now() + Duration::seconds(2);
        store
            .record_effect_failed(
                first,
                &rejected.effect,
                &rejected.lease,
                PROVIDER_REJECTED_REASON,
                rejected_at,
            )
            .await
            .expect("persist Provider rejection");
        let uncertain = claim_remote_effect(
            first,
            store,
            scope,
            project_id,
            "provider-uncertain",
            now() + Duration::seconds(61),
        )
        .await;
        let uncertain_at = now() + Duration::seconds(62);
        store
            .record_effect_uncertain(
                first,
                &uncertain.effect,
                &uncertain.lease,
                PROVIDER_UNCERTAIN_REASON,
                uncertain_at,
            )
            .await
            .expect("persist non-replayable Provider uncertainty");
        ProviderTerminalScenarios {
            rejected,
            rejected_at,
            uncertain,
            uncertain_at,
        }
    }

    async fn seed_receipt_terminal_states(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
    ) -> ReceiptTerminalScenarios {
        let rejected = persist_receipt_scenario(
            client,
            store,
            scope,
            project_id,
            "verification-rejected",
            now() + Duration::seconds(121),
        )
        .await;
        let inconclusive = persist_receipt_scenario(
            client,
            store,
            scope,
            project_id,
            "verification-inconclusive",
            now() + Duration::seconds(181),
        )
        .await;
        let corrupted = persist_receipt_scenario(
            client,
            store,
            scope,
            project_id,
            "receipt-corrupted",
            now() + Duration::seconds(241),
        )
        .await;
        corrupt_receipt_request_digest(
            client,
            scope,
            project_id,
            &corrupted.effect,
            now() + Duration::seconds(243),
        )
        .await;
        assert_eq!(
            effect_attempt_count(client, scope, project_id, &corrupted.effect).await,
            1
        );
        ReceiptTerminalScenarios {
            rejected,
            inconclusive,
            corrupted,
        }
    }

    async fn seed_terminal_recovery_fixture(
        database_url: &str,
        store: &PostgresCellStore,
    ) -> TerminalRecoveryFixture {
        let (mut first, first_task) = connect_test_client(database_url).await;
        let (mut second, second_task) = connect_test_client(database_url).await;
        let (scope, project_id) = prepare_remote_project(&mut first, store).await;
        let provider =
            seed_provider_terminal_states(&mut first, &mut second, store, &scope, &project_id)
                .await;
        let receipts = seed_receipt_terminal_states(&mut first, store, &scope, &project_id).await;
        close_test_client(first, first_task).await;
        close_test_client(second, second_task).await;
        TerminalRecoveryFixture {
            scope,
            project_id,
            provider,
            receipts,
        }
    }

    async fn materialize_verification_terminals_after_restart(
        database_url: &str,
        store: &PostgresCellStore,
        fixture: &TerminalRecoveryFixture,
    ) -> VerificationTerminalEvidence {
        let (mut verifier, verifier_task) = connect_test_client(database_url).await;
        let rejected = recover_receipt_and_record_verification(
            &mut verifier,
            store,
            &fixture.receipts.rejected,
            "rejected",
            VerificationStatus::Rejected,
            now() + Duration::seconds(301),
        )
        .await;
        let inconclusive = recover_receipt_and_record_verification(
            &mut verifier,
            store,
            &fixture.receipts.inconclusive,
            "inconclusive",
            VerificationStatus::Inconclusive,
            now() + Duration::seconds(303),
        )
        .await;
        assert_corrupted_receipt_fails_before_new_attempt(
            &mut verifier,
            store,
            &fixture.scope,
            &fixture.receipts.corrupted,
            now() + Duration::seconds(305),
        )
        .await;
        close_test_client(verifier, verifier_task).await;
        VerificationTerminalEvidence {
            rejected,
            inconclusive,
        }
    }

    async fn assert_provider_terminal_projections(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        fixture: &TerminalRecoveryFixture,
    ) {
        assert_terminal_claim(
            client,
            store,
            &fixture.provider.rejected.effect,
            now() + Duration::seconds(310),
            &LedgerClaim::ProviderRejected {
                reason: PROVIDER_REJECTED_REASON.into(),
                execution_started_at: fixture.provider.rejected.execution_started_at,
                recorded_at: fixture.provider.rejected_at,
            },
        )
        .await;
        assert_terminal_claim(
            client,
            store,
            &fixture.provider.uncertain.effect,
            now() + Duration::seconds(311),
            &LedgerClaim::Uncertain {
                reason: PROVIDER_UNCERTAIN_REASON.into(),
                execution_started_at: fixture.provider.uncertain.execution_started_at,
                recorded_at: fixture.provider.uncertain_at,
            },
        )
        .await;
    }

    async fn assert_verification_terminal_projections(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        fixture: &TerminalRecoveryFixture,
        evidence: VerificationTerminalEvidence,
    ) {
        assert_terminal_claim(
            client,
            store,
            &fixture.receipts.rejected.effect,
            now() + Duration::seconds(312),
            &LedgerClaim::DurableVerification {
                receipt: fixture.receipts.rejected.receipt.clone(),
                verification: evidence.rejected,
                execution_started_at: fixture.receipts.rejected.execution_started_at,
            },
        )
        .await;
        assert_terminal_claim(
            client,
            store,
            &fixture.receipts.inconclusive.effect,
            now() + Duration::seconds(313),
            &LedgerClaim::DurableVerification {
                receipt: fixture.receipts.inconclusive.receipt.clone(),
                verification: evidence.inconclusive,
                execution_started_at: fixture.receipts.inconclusive.execution_started_at,
            },
        )
        .await;
    }

    async fn assert_terminal_attempt_counts(
        client: &mut tokio_postgres::Client,
        fixture: &TerminalRecoveryFixture,
    ) {
        let scope = &fixture.scope;
        let project_id = &fixture.project_id;
        let counts = [
            effect_attempt_count(client, scope, project_id, &fixture.provider.rejected.effect)
                .await,
            effect_attempt_count(
                client,
                scope,
                project_id,
                &fixture.provider.uncertain.effect,
            )
            .await,
            effect_attempt_count(client, scope, project_id, &fixture.receipts.rejected.effect)
                .await,
            effect_attempt_count(
                client,
                scope,
                project_id,
                &fixture.receipts.inconclusive.effect,
            )
            .await,
            effect_attempt_count(
                client,
                scope,
                project_id,
                &fixture.receipts.corrupted.effect,
            )
            .await,
        ];
        assert_eq!(counts, [1, 1, 2, 2, 1]);
    }

    async fn assert_all_terminals_after_second_restart(
        database_url: &str,
        store: &PostgresCellStore,
        fixture: &TerminalRecoveryFixture,
        evidence: VerificationTerminalEvidence,
    ) {
        let (mut recovery, recovery_task) = connect_test_client(database_url).await;
        assert_provider_terminal_projections(&mut recovery, store, fixture).await;
        assert_verification_terminal_projections(&mut recovery, store, fixture, evidence).await;
        assert_corrupted_receipt_fails_before_new_attempt(
            &mut recovery,
            store,
            &fixture.scope,
            &fixture.receipts.corrupted,
            now() + Duration::seconds(314),
        )
        .await;
        assert_terminal_attempt_counts(&mut recovery, fixture).await;
        close_test_client(recovery, recovery_task).await;
    }

    #[tokio::test]
    async fn postgres_effect_concurrency_and_terminal_recovery_reports_blocked_or_executes() {
        let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL concurrent quota and terminal recovery contract did not execute"
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let store = PostgresCellStore::new(DataCell::Us);
        let fixture = Box::pin(seed_terminal_recovery_fixture(&database_url, &store)).await;
        let evidence = Box::pin(materialize_verification_terminals_after_restart(
            &database_url,
            &store,
            &fixture,
        ))
        .await;
        Box::pin(assert_all_terminals_after_second_restart(
            &database_url,
            &store,
            &fixture,
            evidence,
        ))
        .await;
    }

    #[derive(Debug)]
    struct RemoteReconciledReceiptEvidence {
        effect: Effect,
        receipt: Receipt,
        verification: Verification,
        execution_started_at: DateTime<Utc>,
    }

    #[derive(Debug)]
    struct RemoteDeadLetterEvidence {
        effect: Effect,
        claim: LedgerClaim,
    }

    async fn seed_remote_uncertain_effect(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        scope: &CellScope,
        project_id: &ProjectId,
        tag: &str,
        claim_at: DateTime<Utc>,
    ) -> ClaimedRemoteEffect {
        let claimed = claim_remote_effect(client, store, scope, project_id, tag, claim_at).await;
        store
            .record_effect_uncertain(
                client,
                &claimed.effect,
                &claimed.lease,
                "Provider acceptance boundary timed out",
                claim_at + Duration::seconds(1),
            )
            .await
            .expect("persist remote Provider uncertainty");
        claimed
    }

    async fn claim_remote_reconciliation_concurrently(
        first: &mut tokio_postgres::Client,
        second: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        effect: &Effect,
        policy: &ReconciliationPolicy,
        claim_at: DateTime<Utc>,
    ) -> ReconciliationLease {
        let lease_until = claim_at + Duration::seconds(30);
        let (left, right) = tokio::join!(
            store.claim_effect_reconciliation(
                first,
                effect,
                policy,
                "reconciliation-left",
                claim_at,
                lease_until,
            ),
            store.claim_effect_reconciliation(
                second,
                effect,
                policy,
                "reconciliation-right",
                claim_at,
                lease_until,
            )
        );
        let left = left.expect("left reconciliation claim");
        let right = right.expect("right reconciliation claim");
        match (left, right) {
            (ReconciliationClaim::Acquired { lease, .. }, ReconciliationClaim::Busy)
            | (ReconciliationClaim::Busy, ReconciliationClaim::Acquired { lease, .. }) => lease,
            claims => panic!("expected one read-only lease and one busy result: {claims:?}"),
        }
    }

    async fn reconcile_remote_receipt(
        first: &mut tokio_postgres::Client,
        second: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        claimed: ClaimedRemoteEffect,
    ) -> RemoteReconciledReceiptEvidence {
        let policy = ReconciliationPolicy {
            version: "cell-reconciliation-v1".into(),
            max_attempts: 3,
            retry_delay_seconds: 10,
        };
        let lease =
            schedule_remote_reconciliation_retry(first, second, store, &claimed.effect, &policy)
                .await;
        persist_remote_reconciled_receipt(second, store, claimed, &lease).await
    }

    async fn schedule_remote_reconciliation_retry(
        first: &mut tokio_postgres::Client,
        second: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        effect: &Effect,
        policy: &ReconciliationPolicy,
    ) -> ReconciliationLease {
        let first_lease = claim_remote_reconciliation_concurrently(
            first,
            second,
            store,
            effect,
            policy,
            now() + Duration::seconds(3),
        )
        .await;
        let mut incompatible = policy.clone();
        incompatible.max_attempts = 4;
        assert!(matches!(
            store
                .claim_effect_reconciliation(
                    second,
                    effect,
                    &incompatible,
                    "policy-expander",
                    now() + Duration::seconds(3),
                    now() + Duration::seconds(33),
                )
                .await,
            Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict))
        ));
        assert!(matches!(
            store
                .record_effect_reconciliation(
                    first,
                    effect,
                    &first_lease,
                    &ReconciliationObservation::StillUncertain {
                        reason: "Provider lookup has not converged".into(),
                        evidence_digest: "c".repeat(64),
                        observed_at: now() + Duration::seconds(3),
                    },
                    now() + Duration::seconds(3),
                )
                .await
                .expect("schedule bounded retry"),
            ReconciliationDisposition::RetryScheduled { retry_at, .. }
                if retry_at == now() + Duration::seconds(13)
        ));
        assert_eq!(
            store
                .claim_effect_reconciliation(
                    second,
                    effect,
                    policy,
                    "too-early-reconciler",
                    now() + Duration::seconds(4),
                    now() + Duration::seconds(34),
                )
                .await
                .expect("durable retry boundary"),
            ReconciliationClaim::NotReady {
                retry_at: now() + Duration::seconds(13)
            }
        );
        let ReconciliationClaim::Acquired { lease, .. } = store
            .claim_effect_reconciliation(
                second,
                effect,
                policy,
                "receipt-reconciler",
                now() + Duration::seconds(13),
                now() + Duration::seconds(43),
            )
            .await
            .expect("second reconciliation attempt")
        else {
            panic!("expected second reconciliation lease")
        };
        lease
    }

    async fn persist_remote_reconciled_receipt(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        claimed: ClaimedRemoteEffect,
        lease: &ReconciliationLease,
    ) -> RemoteReconciledReceiptEvidence {
        let receipt = scenario_receipt(
            &claimed.effect,
            "reconciled-cell",
            claimed.execution_started_at + Duration::seconds(1),
        );
        let mut corrupted = receipt.clone();
        corrupted.request_digest = "0".repeat(64);
        assert!(matches!(
            store
                .record_effect_reconciliation(
                    client,
                    &claimed.effect,
                    lease,
                    &ReconciliationObservation::ReceiptFound {
                        receipt: corrupted,
                        evidence_digest: "d".repeat(64),
                        observed_at: now() + Duration::seconds(13),
                    },
                    now() + Duration::seconds(13),
                )
                .await,
            Err(CloudStorageError::EffectLedger(LedgerError::ScopeConflict))
        ));
        let ReconciliationDisposition::ReceiptReadyForVerification {
            lease: verification_lease,
            receipt: found,
            execution_started_at,
        } = store
            .record_effect_reconciliation(
                client,
                &claimed.effect,
                lease,
                &ReconciliationObservation::ReceiptFound {
                    receipt: receipt.clone(),
                    evidence_digest: "e".repeat(64),
                    observed_at: now() + Duration::seconds(13),
                },
                now() + Duration::seconds(13),
            )
            .await
            .expect("reconcile exact Receipt")
        else {
            panic!("Receipt reconciliation must grant Verification only")
        };
        assert_eq!(
            (found, execution_started_at),
            (receipt.clone(), claimed.execution_started_at)
        );
        let verification = Verification {
            id: VerificationId::from("verification-reconciled-cell"),
            status: VerificationStatus::Confirmed,
            verifier: "independent-cell-readback".into(),
            independent: true,
            observed_at: now() + Duration::seconds(14),
            evidence_digest: "f".repeat(64),
            receipt_id: receipt.id.clone(),
        };
        store
            .record_effect_verification(
                client,
                &claimed.effect,
                &verification_lease,
                &verification,
                verification.observed_at,
            )
            .await
            .expect("verify reconciled Receipt");
        RemoteReconciledReceiptEvidence {
            effect: claimed.effect,
            receipt,
            verification,
            execution_started_at: claimed.execution_started_at,
        }
    }

    async fn dead_letter_remote_reconciliation(
        client: &mut tokio_postgres::Client,
        store: &PostgresCellStore,
        claimed: ClaimedRemoteEffect,
    ) -> RemoteDeadLetterEvidence {
        let policy = ReconciliationPolicy {
            version: "cell-dead-letter-v1".into(),
            max_attempts: 1,
            retry_delay_seconds: 60,
        };
        let ReconciliationClaim::Acquired { lease, .. } = store
            .claim_effect_reconciliation(
                client,
                &claimed.effect,
                &policy,
                "dead-letter-reconciler",
                now() + Duration::seconds(63),
                now() + Duration::seconds(93),
            )
            .await
            .expect("dead-letter reconciliation claim")
        else {
            panic!("expected read-only reconciliation lease")
        };
        let observation = ReconciliationObservation::StillUncertain {
            reason: "Provider remains ambiguous after bounded lookup".into(),
            evidence_digest: "9".repeat(64),
            observed_at: now() + Duration::seconds(64),
        };
        let ReconciliationDisposition::DeadLetter {
            reason,
            evidence_digest,
            dead_lettered_at,
            attempts,
            execution_started_at,
        } = store
            .record_effect_reconciliation(
                client,
                &claimed.effect,
                &lease,
                &observation,
                now() + Duration::seconds(64),
            )
            .await
            .expect("bounded dead letter")
        else {
            panic!("single-attempt policy must dead-letter")
        };
        assert!(matches!(
            store
                .record_effect_reconciliation(
                    client,
                    &claimed.effect,
                    &lease,
                    &observation,
                    now() + Duration::seconds(65),
                )
                .await,
            Err(CloudStorageError::EffectLedger(LedgerError::LeaseLost))
        ));
        RemoteDeadLetterEvidence {
            effect: claimed.effect,
            claim: LedgerClaim::DeadLetter {
                reason,
                evidence_digest,
                dead_lettered_at,
                attempts,
                execution_started_at,
            },
        }
    }

    async fn assert_remote_reconciliation_counts(
        client: &mut tokio_postgres::Client,
        scope: &CellScope,
        project_id: &ProjectId,
        receipt_effect: &Effect,
        dead_effect: &Effect,
    ) {
        let transaction = client.transaction().await.expect("reconciliation audit");
        set_scope(&transaction, scope).await.expect("scope");
        let row = transaction
            .query_one(
                "SELECT
                   (SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_reconciliation_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $4),
                   (SELECT count(*) FROM hartevo_cell.effect_execution_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $5),
                   (SELECT count(*) FROM hartevo_cell.effect_reconciliation_attempts
                    WHERE cell = $1 AND tenant_id = $2 AND project_id = $3 AND effect_id = $5)",
                &[
                    &scope.cell.as_str(),
                    &scope.tenant_id.as_str(),
                    &project_id.as_str(),
                    &receipt_effect.id.as_str(),
                    &dead_effect.id.as_str(),
                ],
            )
            .await
            .expect("reconciliation counts");
        assert_eq!(
            [
                row.get::<_, i64>(0),
                row.get::<_, i64>(1),
                row.get::<_, i64>(2),
                row.get::<_, i64>(3),
            ],
            [2, 2, 1, 1]
        );
        transaction.commit().await.expect("audit commit");
    }

    #[tokio::test]
    async fn postgres_effect_reconciliation_reports_blocked_or_executes_bounded_recovery() {
        let Some(database_url) = std::env::var_os(POSTGRES_L2_URL_ENV) else {
            eprintln!(
                "BLOCKED_ENV: {POSTGRES_L2_URL_ENV} is absent; PostgreSQL bounded Effect reconciliation did not execute"
            );
            return;
        };
        let database_url = database_url
            .into_string()
            .expect("PostgreSQL test URL must be valid Unicode");
        let store = PostgresCellStore::new(DataCell::Us);
        let (mut first, first_task) = connect_test_client(&database_url).await;
        let (mut second, second_task) = connect_test_client(&database_url).await;
        let (scope, project_id) = prepare_remote_project(&mut first, &store).await;
        let (_, _, permission) = approved_remote_effect(
            &scope.tenant_id,
            &project_id,
            "reconciliation-permission",
            "reconciliation-permission-effect",
            "reconciliation-permission-idempotency",
        );
        publish_active_fixture_fence(&mut first, &store, &scope, &project_id, &permission).await;
        let receipt_claimed = seed_remote_uncertain_effect(
            &mut first,
            &store,
            &scope,
            &project_id,
            "reconciliation-receipt",
            now() + Duration::seconds(1),
        )
        .await;
        let receipt_evidence =
            reconcile_remote_receipt(&mut first, &mut second, &store, receipt_claimed).await;
        let dead_claimed = seed_remote_uncertain_effect(
            &mut first,
            &store,
            &scope,
            &project_id,
            "reconciliation-dead",
            now() + Duration::seconds(61),
        )
        .await;
        let dead_evidence =
            dead_letter_remote_reconciliation(&mut first, &store, dead_claimed).await;
        close_test_client(first, first_task).await;
        close_test_client(second, second_task).await;

        let (mut recovery, recovery_task) = connect_test_client(&database_url).await;
        assert_terminal_claim(
            &mut recovery,
            &store,
            &receipt_evidence.effect,
            now() + Duration::seconds(70),
            &LedgerClaim::AlreadyVerified {
                receipt: receipt_evidence.receipt.clone(),
                verification: receipt_evidence.verification.clone(),
                execution_started_at: receipt_evidence.execution_started_at,
            },
        )
        .await;
        assert_terminal_claim(
            &mut recovery,
            &store,
            &dead_evidence.effect,
            now() + Duration::seconds(71),
            &dead_evidence.claim,
        )
        .await;
        assert_remote_reconciliation_counts(
            &mut recovery,
            &scope,
            &project_id,
            &receipt_evidence.effect,
            &dead_evidence.effect,
        )
        .await;
        close_test_client(recovery, recovery_task).await;
    }
}
