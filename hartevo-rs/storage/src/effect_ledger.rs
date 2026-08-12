use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Effect, ExecutionAttemptId, Receipt, Verification, VerificationStatus,
};
use hartevo_effect_broker::{
    DurableClaimDirective, DurableEffectLedger, DurableRateLimitDirective, ExecutionClaimContext,
    ExecutionLease, LedgerClaim, LedgerError, PersistedClaimState, RateLimitRequest,
    ReconciliationClaim, ReconciliationDisposition, ReconciliationLease, ReconciliationObservation,
    ReconciliationPolicy, decide_durable_claim, decide_durable_rate_limit,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::ProjectStore;

impl DurableEffectLedger for ProjectStore {
    fn claim(
        &mut self,
        effect: &Effect,
        context: Option<&ExecutionClaimContext>,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<LedgerClaim, LedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let request = ClaimRequest {
            effect,
            context,
            owner,
            now,
            lease_expires_at,
        };
        if let Some(claim) = load_terminal_reconciliation_claim(&transaction, effect)? {
            transaction.commit().map_err(persistence)?;
            return Ok(claim);
        }
        let (directive, latest, existing) = load_claim_decision(&transaction, &request)?;
        let claim =
            materialize_claim(&transaction, &request, directive, latest, existing.as_ref())?;
        transaction.commit().map_err(persistence)?;
        Ok(claim)
    }

    fn record_receipt(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        receipt: &Receipt,
        operation_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        let transaction = self.connection.transaction().map_err(persistence)?;
        require_current_lease(&transaction, effect, lease, &["executing"], operation_at)?;
        let receipt_json = serde_json::to_string(receipt).map_err(persistence)?;
        let attempt_updated = transaction
            .execute(
                "UPDATE execution_attempts SET status = 'receipt_recorded', receipt_json = ?8,
                   updated_at = ?9
                 WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
                   AND generation = ?4 AND lease_owner = ?5
                   AND lease_expires_at = ?6 AND lease_expires_at > ?7
                   AND status = 'executing'",
                params![
                    lease.attempt_id.as_str(),
                    effect.project_id.as_str(),
                    effect.id.as_str(),
                    to_sql_u64(lease.generation)?,
                    lease.owner,
                    lease.expires_at.to_rfc3339(),
                    operation_at.to_rfc3339(),
                    receipt_json,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if attempt_updated != 1 {
            return Err(LedgerError::LeaseLost);
        }
        let ledger_updated = transaction
            .execute(
                "UPDATE effect_idempotency SET status = 'receipt_recorded', receipt_json = ?4,
                   updated_at = ?5
                 WHERE project_id = ?1 AND idempotency_key = ?2 AND approval_digest = ?3",
                params![
                    effect.project_id.as_str(),
                    effect.idempotency_key,
                    effect.approval_digest(),
                    receipt_json,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if ledger_updated != 1 {
            return Err(LedgerError::ScopeConflict);
        }
        transaction.commit().map_err(persistence)
    }

    fn record_verification(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        verification: &Verification,
        operation_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        let transaction = self.connection.transaction().map_err(persistence)?;
        require_current_lease(
            &transaction,
            effect,
            lease,
            &["receipt_recorded", "verifying"],
            operation_at,
        )?;
        let (status, failure_class) = match verification.status {
            VerificationStatus::Confirmed => ("verified", None),
            VerificationStatus::Rejected => ("failed", Some("verification_rejected")),
            VerificationStatus::Inconclusive => {
                ("verification_required", Some("verification_inconclusive"))
            }
        };
        let verification_json = serde_json::to_string(verification).map_err(persistence)?;
        let attempt_updated = transaction
            .execute(
                "UPDATE execution_attempts SET status = ?8, verification_json = ?9,
                   failure_class = ?10, updated_at = ?11
                 WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
                   AND generation = ?4 AND lease_owner = ?5
                   AND lease_expires_at = ?6 AND lease_expires_at > ?7
                   AND status IN ('receipt_recorded', 'verifying')",
                params![
                    lease.attempt_id.as_str(),
                    effect.project_id.as_str(),
                    effect.id.as_str(),
                    to_sql_u64(lease.generation)?,
                    lease.owner,
                    lease.expires_at.to_rfc3339(),
                    operation_at.to_rfc3339(),
                    status,
                    verification_json,
                    failure_class,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if attempt_updated != 1 {
            return Err(LedgerError::LeaseLost);
        }
        let ledger_updated = transaction
            .execute(
                "UPDATE effect_idempotency SET status = ?4, verification_json = ?5,
                   uncertain_reason = ?6, updated_at = ?7
                 WHERE project_id = ?1 AND idempotency_key = ?2 AND approval_digest = ?3",
                params![
                    effect.project_id.as_str(),
                    effect.idempotency_key,
                    effect.approval_digest(),
                    status,
                    verification_json,
                    failure_class,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if ledger_updated != 1 {
            return Err(LedgerError::ScopeConflict);
        }
        transaction.commit().map_err(persistence)
    }

    fn record_failed(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        operation_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        finish_without_receipt(self, effect, lease, "failed", reason, operation_at)
    }

    fn record_uncertain(
        &mut self,
        effect: &Effect,
        lease: &ExecutionLease,
        reason: &str,
        operation_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        finish_without_receipt(self, effect, lease, "uncertain", reason, operation_at)
    }

    fn claim_reconciliation(
        &mut self,
        effect: &Effect,
        policy: &ReconciliationPolicy,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<ReconciliationClaim, LedgerError> {
        claim_effect_reconciliation(self, effect, policy, owner, now, lease_expires_at)
    }

    fn record_reconciliation(
        &mut self,
        effect: &Effect,
        lease: &ReconciliationLease,
        observation: &ReconciliationObservation,
        now: DateTime<Utc>,
    ) -> Result<ReconciliationDisposition, LedgerError> {
        record_effect_reconciliation(self, effect, lease, observation, now)
    }
}

#[derive(Debug)]
struct IdempotencyRecord {
    status: String,
    receipt_json: Option<String>,
    verification_json: Option<String>,
    uncertain_reason: Option<String>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug)]
struct LatestAttempt {
    id: String,
    lease_expires_at: DateTime<Utc>,
}

struct ClaimRequest<'a> {
    effect: &'a Effect,
    context: Option<&'a ExecutionClaimContext>,
    owner: &'a str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
}

#[derive(Debug)]
struct ReconciliationHead {
    policy: ReconciliationPolicy,
    policy_digest: String,
    status: String,
    attempts: u32,
    lease_owner: Option<String>,
    lease_generation: u64,
    lease_expires_at: Option<DateTime<Utc>>,
    retry_at: Option<DateTime<Utc>>,
    terminal_reason: Option<String>,
    evidence_digest: Option<String>,
    observation: Option<ReconciliationObservation>,
    updated_at: DateTime<Utc>,
}

fn load_claim_decision(
    transaction: &Transaction<'_>,
    request: &ClaimRequest<'_>,
) -> Result<
    (
        DurableClaimDirective,
        Option<LatestAttempt>,
        Option<IdempotencyRecord>,
    ),
    LedgerError,
> {
    let existing = load_idempotency(transaction, request.effect)?;
    let Some(record) = existing.as_ref() else {
        return Ok((decide_durable_claim(None, false), None, existing));
    };
    let state = PersistedClaimState::from_storage_name(&record.status).ok_or_else(|| {
        LedgerError::Persistence(format!("unknown effect ledger status {}", record.status))
    })?;
    let latest = if state == PersistedClaimState::Executing {
        Some(
            latest_attempt(transaction, request.effect)?
                .ok_or_else(|| LedgerError::Persistence("missing execution attempt".into()))?,
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

fn materialize_claim(
    transaction: &Transaction<'_>,
    request: &ClaimRequest<'_>,
    directive: DurableClaimDirective,
    latest: Option<LatestAttempt>,
    existing: Option<&IdempotencyRecord>,
) -> Result<LedgerClaim, LedgerError> {
    match directive {
        DurableClaimDirective::BeginProviderExecution => {
            begin_authorized_claim(transaction, request)
        }
        DurableClaimDirective::ReturnVerified => {
            let record = require_idempotency(existing, "verified")?;
            let (receipt, verification, execution_started_at) =
                decode_durable_verification(transaction, request.effect, record)?;
            Ok(LedgerClaim::AlreadyVerified {
                receipt,
                verification,
                execution_started_at,
            })
        }
        DurableClaimDirective::ReturnProviderFailed => provider_failed_claim(
            transaction,
            request.effect,
            require_idempotency(existing, "failed")?,
        ),
        DurableClaimDirective::ReturnUncertain => uncertain_claim(
            transaction,
            request.effect,
            require_idempotency(existing, "uncertain")?,
        ),
        DurableClaimDirective::ReturnVerification => durable_verification_claim(
            transaction,
            request.effect,
            require_idempotency(existing, "verification")?,
        ),
        DurableClaimDirective::ResumeVerificationFromReceipt => resume_verification_claim(
            transaction,
            request.effect,
            require_idempotency(existing, "verification")?,
            request.owner,
            request.lease_expires_at,
            request.now,
        ),
        DurableClaimDirective::ReturnBusy => Ok(LedgerClaim::Busy),
        DurableClaimDirective::FreezeExpiredExecution => {
            freeze_expired_claim(transaction, request, latest)
        }
    }
}

fn begin_authorized_claim(
    transaction: &Transaction<'_>,
    request: &ClaimRequest<'_>,
) -> Result<LedgerClaim, LedgerError> {
    let Some(context) = request.context else {
        return Ok(LedgerClaim::AuthorizationRequired);
    };
    context.validate_dispatch_at(request.effect, request.now)?;
    crate::authorization::validate_permission_fences(
        transaction,
        request.effect,
        &context.permission_evidence,
    )?;
    match reserve_rate_limit(
        transaction,
        request.effect,
        &context.rate_limit,
        request.now,
    )? {
        RateLimitReservationOutcome::Reserved => begin_execution_claim(
            transaction,
            request.effect,
            request.owner,
            request.lease_expires_at,
            request.now,
        ),
        RateLimitReservationOutcome::Limited { retry_at } => {
            Ok(LedgerClaim::RateLimited { retry_at })
        }
    }
}

fn provider_failed_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<LedgerClaim, LedgerError> {
    if record.verification_json.is_some() {
        return durable_verification_claim(transaction, effect, record);
    }
    if record.receipt_json.is_some() {
        return Err(LedgerError::Persistence(
            "provider rejection cannot carry an unverified receipt".into(),
        ));
    }
    Ok(LedgerClaim::ProviderRejected {
        reason: record
            .uncertain_reason
            .clone()
            .unwrap_or_else(|| "provider rejected without a recorded reason".into()),
        execution_started_at: initial_execution_started_at(transaction, effect)?,
        recorded_at: record.updated_at,
    })
}

fn uncertain_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<LedgerClaim, LedgerError> {
    if record.receipt_json.is_some() || record.verification_json.is_some() {
        return Err(LedgerError::Persistence(
            "provider uncertainty cannot carry receipt or verification data".into(),
        ));
    }
    Ok(LedgerClaim::Uncertain {
        reason: record
            .uncertain_reason
            .clone()
            .unwrap_or_else(|| "provider state is durably uncertain".into()),
        execution_started_at: initial_execution_started_at(transaction, effect)?,
        recorded_at: record.updated_at,
    })
}

fn freeze_expired_claim(
    transaction: &Transaction<'_>,
    request: &ClaimRequest<'_>,
    latest: Option<LatestAttempt>,
) -> Result<LedgerClaim, LedgerError> {
    let latest = latest.ok_or_else(|| {
        LedgerError::Persistence("expired execution directive has no latest attempt".into())
    })?;
    let reason =
        "execution lease expired without a durable provider receipt; reconciliation required";
    freeze_expired_attempt(transaction, request.effect, &latest.id, reason, request.now)?;
    Ok(LedgerClaim::Uncertain {
        reason: reason.into(),
        execution_started_at: initial_execution_started_at(transaction, request.effect)?,
        recorded_at: request.now,
    })
}

fn require_idempotency<'a>(
    existing: Option<&'a IdempotencyRecord>,
    directive: &str,
) -> Result<&'a IdempotencyRecord, LedgerError> {
    existing.ok_or_else(|| {
        LedgerError::Persistence(format!("{directive} directive has no ledger record"))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RateLimitReservationOutcome {
    Reserved,
    Limited { retry_at: DateTime<Utc> },
}

#[derive(Clone, Debug)]
struct RateLimitBucket {
    consumed: u64,
    revision: u64,
    window_ends_at: DateTime<Utc>,
    tenant_id: String,
    rule_id: String,
    policy_version: String,
    policy_digest: String,
    provider: String,
    account_id: Option<String>,
    capability: String,
    max_executions: u64,
    window_seconds: u64,
}

fn reserve_rate_limit(
    transaction: &Transaction<'_>,
    effect: &Effect,
    request: &RateLimitRequest,
    now: DateTime<Utc>,
) -> Result<RateLimitReservationOutcome, LedgerError> {
    let (window_started_at, window_ends_at) = fixed_rate_limit_window(now, request.window_seconds)?;
    let existing = load_rate_limit_bucket(transaction, request, window_started_at)?;
    if let Some(bucket) = &existing {
        validate_rate_limit_bucket(bucket, request, window_ends_at)?;
    }
    let consumed = existing.as_ref().map_or(0, |bucket| bucket.consumed);
    match decide_durable_rate_limit(consumed, request.max_executions) {
        DurableRateLimitDirective::Reserve { next_consumed } => {
            persist_rate_limit_reservation(
                transaction,
                effect,
                request,
                existing.as_ref(),
                next_consumed,
                window_started_at,
                window_ends_at,
                now,
            )?;
            Ok(RateLimitReservationOutcome::Reserved)
        }
        DurableRateLimitDirective::Deny => {
            insert_rate_limit_decision(
                transaction,
                effect,
                request,
                "denied",
                consumed,
                consumed,
                window_started_at,
                window_ends_at,
                now,
            )?;
            Ok(RateLimitReservationOutcome::Limited {
                retry_at: window_ends_at,
            })
        }
    }
}

fn fixed_rate_limit_window(
    now: DateTime<Utc>,
    window_seconds: u64,
) -> Result<(DateTime<Utc>, DateTime<Utc>), LedgerError> {
    let window_seconds = i64::try_from(window_seconds)
        .map_err(|_| LedgerError::Persistence("rate-limit window overflow".into()))?;
    if window_seconds <= 0 {
        return Err(LedgerError::Persistence(
            "rate-limit window must be positive".into(),
        ));
    }
    let window_start_epoch = now
        .timestamp()
        .div_euclid(window_seconds)
        .checked_mul(window_seconds)
        .ok_or_else(|| LedgerError::Persistence("rate-limit window overflow".into()))?;
    let window_end_epoch = window_start_epoch
        .checked_add(window_seconds)
        .ok_or_else(|| LedgerError::Persistence("rate-limit window overflow".into()))?;
    let window_started_at = DateTime::from_timestamp(window_start_epoch, 0)
        .ok_or_else(|| LedgerError::Persistence("invalid rate-limit window start".into()))?;
    let window_ends_at = DateTime::from_timestamp(window_end_epoch, 0)
        .ok_or_else(|| LedgerError::Persistence("invalid rate-limit window end".into()))?;
    Ok((window_started_at, window_ends_at))
}

fn load_rate_limit_bucket(
    transaction: &Transaction<'_>,
    request: &RateLimitRequest,
    window_started_at: DateTime<Utc>,
) -> Result<Option<RateLimitBucket>, LedgerError> {
    transaction
        .query_row(
            "SELECT consumed, revision, window_ends_at, tenant_id, rule_id, policy_version,
                    policy_digest, provider, account_id, capability, max_executions, window_seconds
             FROM effect_rate_limit_buckets
             WHERE project_id = ?1 AND scope_digest = ?2 AND window_started_at = ?3",
            params![
                request.project_id.as_str(),
                request.scope_digest,
                window_started_at.to_rfc3339(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()
        .map_err(persistence)?
        .map(|row| {
            Ok(RateLimitBucket {
                consumed: from_sql_u64(row.0, "rate-limit consumed")?,
                revision: from_sql_u64(row.1, "rate-limit revision")?,
                window_ends_at: parse_time(&row.2)?,
                tenant_id: row.3,
                rule_id: row.4,
                policy_version: row.5,
                policy_digest: row.6,
                provider: row.7,
                account_id: row.8,
                capability: row.9,
                max_executions: from_sql_u64(row.10, "rate-limit maximum")?,
                window_seconds: from_sql_u64(row.11, "rate-limit window")?,
            })
        })
        .transpose()
}

fn validate_rate_limit_bucket(
    bucket: &RateLimitBucket,
    request: &RateLimitRequest,
    window_ends_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    if bucket.tenant_id != request.tenant_id.as_str()
        || bucket.rule_id != request.rule_id
        || bucket.policy_version != request.policy_version
        || bucket.policy_digest != request.policy_digest
        || bucket.provider != request.provider
        || bucket.account_id.as_deref()
            != request
                .account_id
                .as_ref()
                .map(hartevo_domain_kernel::AccountId::as_str)
        || bucket.capability != request.capability
        || bucket.max_executions != request.max_executions
        || bucket.window_seconds != request.window_seconds
        || bucket.window_ends_at != window_ends_at
        || bucket.consumed > bucket.max_executions
        || bucket.revision == 0
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_rate_limit_reservation(
    transaction: &Transaction<'_>,
    effect: &Effect,
    request: &RateLimitRequest,
    existing: Option<&RateLimitBucket>,
    next_consumed: u64,
    window_started_at: DateTime<Utc>,
    window_ends_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    match existing {
        None => insert_rate_limit_bucket(
            transaction,
            request,
            next_consumed,
            window_started_at,
            window_ends_at,
            now,
        )?,
        Some(bucket) => update_rate_limit_bucket(
            transaction,
            request,
            bucket,
            next_consumed,
            window_started_at,
            now,
        )?,
    }
    transaction
        .execute(
            "INSERT INTO effect_rate_limit_reservations
               (tenant_id, project_id, mission_id, effect_id, idempotency_key,
                approval_digest, scope_digest, rule_id, window_started_at, window_ends_at,
                reserved_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.id.as_str(),
                effect.idempotency_key,
                effect.approval_digest(),
                request.scope_digest,
                request.rule_id,
                window_started_at.to_rfc3339(),
                window_ends_at.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    insert_rate_limit_decision(
        transaction,
        effect,
        request,
        "reserved",
        next_consumed.saturating_sub(1),
        next_consumed,
        window_started_at,
        window_ends_at,
        now,
    )
}

fn insert_rate_limit_bucket(
    transaction: &Transaction<'_>,
    request: &RateLimitRequest,
    consumed: u64,
    window_started_at: DateTime<Utc>,
    window_ends_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    transaction
        .execute(
            "INSERT INTO effect_rate_limit_buckets
               (tenant_id, project_id, scope_digest, rule_id, policy_version, policy_digest,
                provider, account_id, capability, window_started_at, window_ends_at,
                max_executions, window_seconds, consumed, revision, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 1, ?15, ?15)",
            params![
                request.tenant_id.as_str(),
                request.project_id.as_str(),
                request.scope_digest,
                request.rule_id,
                request.policy_version,
                request.policy_digest,
                request.provider,
                request
                    .account_id
                    .as_ref()
                    .map(hartevo_domain_kernel::AccountId::as_str),
                request.capability,
                window_started_at.to_rfc3339(),
                window_ends_at.to_rfc3339(),
                to_sql_u64(request.max_executions)?,
                to_sql_u64(request.window_seconds)?,
                to_sql_u64(consumed)?,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(())
}

fn update_rate_limit_bucket(
    transaction: &Transaction<'_>,
    request: &RateLimitRequest,
    bucket: &RateLimitBucket,
    next_consumed: u64,
    window_started_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let next_revision = bucket
        .revision
        .checked_add(1)
        .ok_or_else(|| LedgerError::Persistence("rate-limit revision overflow".into()))?;
    let updated = transaction
        .execute(
            "UPDATE effect_rate_limit_buckets
             SET consumed = ?4, revision = ?5, updated_at = ?6
             WHERE project_id = ?1 AND scope_digest = ?2 AND window_started_at = ?3
               AND consumed = ?7 AND revision = ?8",
            params![
                request.project_id.as_str(),
                request.scope_digest,
                window_started_at.to_rfc3339(),
                to_sql_u64(next_consumed)?,
                to_sql_u64(next_revision)?,
                now.to_rfc3339(),
                to_sql_u64(bucket.consumed)?,
                to_sql_u64(bucket.revision)?,
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::Persistence(
            "rate-limit bucket compare-and-swap failed".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_rate_limit_decision(
    transaction: &Transaction<'_>,
    effect: &Effect,
    request: &RateLimitRequest,
    decision: &str,
    consumed_before: u64,
    consumed_after: u64,
    window_started_at: DateTime<Utc>,
    window_ends_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    transaction
        .execute(
            "INSERT INTO effect_rate_limit_decisions
               (tenant_id, project_id, mission_id, effect_id, approval_digest,
                scope_digest, rule_id, decision, consumed_before, consumed_after,
                window_started_at, window_ends_at, decided_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.id.as_str(),
                effect.approval_digest(),
                request.scope_digest,
                request.rule_id,
                decision,
                to_sql_u64(consumed_before)?,
                to_sql_u64(consumed_after)?,
                window_started_at.to_rfc3339(),
                window_ends_at.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(())
}

fn begin_execution_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    owner: &str,
    lease_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<LedgerClaim, LedgerError> {
    transaction
        .execute(
            "INSERT INTO effect_idempotency
               (tenant_id, project_id, mission_id, idempotency_key, effect_id,
                approval_digest, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'executing', ?7, ?7)",
            params![
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.idempotency_key,
                effect.id.as_str(),
                effect.approval_digest(),
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(LedgerClaim::Acquired {
        lease: insert_attempt(
            transaction,
            effect,
            owner,
            1,
            1,
            "executing",
            lease_expires_at,
            now,
        )?,
        receipt: None,
        execution_started_at: now,
    })
}

fn resume_verification_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
    owner: &str,
    lease_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<LedgerClaim, LedgerError> {
    let (receipt, execution_started_at) = decode_durable_receipt(transaction, effect, record)?;
    let (attempt_no, generation) = next_attempt(transaction, effect)?;
    Ok(LedgerClaim::Acquired {
        lease: insert_attempt(
            transaction,
            effect,
            owner,
            attempt_no,
            generation,
            "receipt_recorded",
            lease_expires_at,
            now,
        )?,
        receipt: Some(receipt),
        execution_started_at,
    })
}

fn durable_verification_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<LedgerClaim, LedgerError> {
    let (receipt, verification, execution_started_at) =
        decode_durable_verification(transaction, effect, record)?;
    Ok(LedgerClaim::DurableVerification {
        receipt,
        verification,
        execution_started_at,
    })
}

fn decode_durable_verification(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<(Receipt, Verification, DateTime<Utc>), LedgerError> {
    let (receipt, execution_started_at) = decode_durable_receipt(transaction, effect, record)?;
    let verification: Verification =
        decode_required(record.verification_json.as_deref(), "verification")?;
    let expected_status = match record.status.as_str() {
        "verified" => VerificationStatus::Confirmed,
        "failed" => VerificationStatus::Rejected,
        "verification_required" => VerificationStatus::Inconclusive,
        status => {
            return Err(LedgerError::Persistence(format!(
                "stored state {status} cannot carry a terminal verification"
            )));
        }
    };
    if verification.status != expected_status
        || verification.receipt_id != receipt.id
        || verification.verifier.trim().is_empty()
        || !verification.independent
        || !is_sha256(&verification.evidence_digest)
        || verification.observed_at < receipt.accepted_at
    {
        return Err(LedgerError::Persistence(
            "durable receipt or verification integrity check failed".into(),
        ));
    }
    Ok((receipt, verification, execution_started_at))
}

fn decode_durable_receipt(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<(Receipt, DateTime<Utc>), LedgerError> {
    let receipt: Receipt = decode_required(record.receipt_json.as_deref(), "receipt")?;
    let execution_started_at = initial_execution_started_at(transaction, effect)?;
    if receipt.provider != effect.provider
        || receipt.external_id.trim().is_empty()
        || receipt.request_digest != effect.approval_digest()
        || !is_sha256(&receipt.response_digest)
        || receipt.accepted_at < execution_started_at
    {
        return Err(LedgerError::Persistence(
            "durable receipt integrity check failed".into(),
        ));
    }
    Ok((receipt, execution_started_at))
}

fn initial_execution_started_at(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<DateTime<Utc>, LedgerError> {
    let created_at = transaction
        .query_row(
            "SELECT created_at FROM execution_attempts
             WHERE project_id = ?1 AND effect_id = ?2 AND attempt_no = 1",
            params![effect.project_id.as_str(), effect.id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(persistence)?
        .ok_or_else(|| LedgerError::Persistence("missing initial execution attempt".into()))?;
    parse_time(&created_at)
}

fn load_idempotency(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<Option<IdempotencyRecord>, LedgerError> {
    let row = transaction
        .query_row(
            "SELECT tenant_id, mission_id, effect_id, approval_digest, status,
                    receipt_json, verification_json, uncertain_reason, updated_at
             FROM effect_idempotency WHERE project_id = ?1 AND idempotency_key = ?2",
            params![effect.project_id.as_str(), effect.idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
        .map_err(persistence)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.0 != effect.tenant_id.as_str()
        || row.1 != effect.mission_id.as_str()
        || row.2 != effect.id.as_str()
        || row.3 != effect.approval_digest()
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(Some(IdempotencyRecord {
        status: row.4,
        receipt_json: row.5,
        verification_json: row.6,
        uncertain_reason: row.7,
        updated_at: parse_time(&row.8)?,
    }))
}

#[allow(clippy::too_many_arguments)]
fn insert_attempt(
    transaction: &Transaction<'_>,
    effect: &Effect,
    owner: &str,
    attempt_no: u64,
    generation: u64,
    status: &str,
    lease_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<ExecutionLease, LedgerError> {
    let attempt_id =
        ExecutionAttemptId::from_stable(format!("attempt:{}:{attempt_no}:{generation}", effect.id));
    transaction
        .execute(
            "INSERT INTO execution_attempts
               (id, tenant_id, project_id, mission_id, effect_id, attempt_no, generation,
                status, lease_owner, lease_expires_at, request_digest, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
            params![
                attempt_id.as_str(),
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.id.as_str(),
                to_sql_u64(attempt_no)?,
                to_sql_u64(generation)?,
                status,
                owner,
                lease_expires_at.to_rfc3339(),
                effect.approval_digest(),
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(ExecutionLease {
        attempt_id,
        owner: owner.into(),
        generation,
        expires_at: lease_expires_at,
    })
}

fn next_attempt(transaction: &Transaction<'_>, effect: &Effect) -> Result<(u64, u64), LedgerError> {
    let (attempt, generation) = transaction
        .query_row(
            "SELECT COALESCE(MAX(attempt_no), 0), COALESCE(MAX(generation), 0)
             FROM execution_attempts WHERE project_id = ?1 AND effect_id = ?2",
            params![effect.project_id.as_str(), effect.id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(persistence)?;
    let attempt = u64::try_from(attempt)
        .map_err(|_| LedgerError::Persistence("attempt number overflow".into()))?;
    let generation = u64::try_from(generation)
        .map_err(|_| LedgerError::Persistence("generation overflow".into()))?;
    Ok((
        attempt
            .checked_add(1)
            .ok_or_else(|| LedgerError::Persistence("attempt number overflow".into()))?,
        generation
            .checked_add(1)
            .ok_or_else(|| LedgerError::Persistence("generation overflow".into()))?,
    ))
}

fn latest_attempt(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<Option<LatestAttempt>, LedgerError> {
    let row = transaction
        .query_row(
            "SELECT id, lease_expires_at FROM execution_attempts
             WHERE project_id = ?1 AND effect_id = ?2
             ORDER BY attempt_no DESC LIMIT 1",
            params![effect.project_id.as_str(), effect.id.as_str()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(persistence)?;
    row.map(|(id, expires_at)| {
        Ok(LatestAttempt {
            id,
            lease_expires_at: parse_time(&expires_at)?,
        })
    })
    .transpose()
}

fn freeze_expired_attempt(
    transaction: &Transaction<'_>,
    effect: &Effect,
    attempt_id: &str,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    transaction
        .execute(
            "UPDATE execution_attempts SET status = 'uncertain', failure_class = ?3,
               updated_at = ?4 WHERE id = ?1 AND project_id = ?2 AND status = 'executing'",
            params![
                attempt_id,
                effect.project_id.as_str(),
                reason,
                now.to_rfc3339()
            ],
        )
        .map_err(persistence)?;
    transaction
        .execute(
            "UPDATE effect_idempotency SET status = 'uncertain', uncertain_reason = ?3,
               updated_at = ?4 WHERE project_id = ?1 AND idempotency_key = ?2",
            params![
                effect.project_id.as_str(),
                effect.idempotency_key,
                reason,
                now.to_rfc3339()
            ],
        )
        .map_err(persistence)?;
    Ok(())
}

fn require_current_lease(
    transaction: &Transaction<'_>,
    effect: &Effect,
    lease: &ExecutionLease,
    statuses: &[&str],
    operation_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let row = transaction
        .query_row(
            "SELECT lease_owner, generation, status, lease_expires_at FROM execution_attempts
             WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
               AND generation = (
                 SELECT MAX(current.generation) FROM execution_attempts current
                 WHERE current.project_id = ?2 AND current.effect_id = ?3
               )",
            params![
                lease.attempt_id.as_str(),
                effect.project_id.as_str(),
                effect.id.as_str()
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(persistence)?;
    let Some((owner, generation, status, stored_expires_at)) = row else {
        return Err(LedgerError::LeaseLost);
    };
    let stored_expires_at = parse_time(&stored_expires_at)?;
    if owner != lease.owner
        || u64::try_from(generation).ok() != Some(lease.generation)
        || stored_expires_at != lease.expires_at
        || stored_expires_at <= operation_at
        || !statuses.contains(&status.as_str())
    {
        return Err(LedgerError::LeaseLost);
    }
    Ok(())
}

fn finish_without_receipt(
    store: &mut ProjectStore,
    effect: &Effect,
    lease: &ExecutionLease,
    status: &str,
    reason: &str,
    operation_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let transaction = store.connection.transaction().map_err(persistence)?;
    require_current_lease(&transaction, effect, lease, &["executing"], operation_at)?;
    let updated = transaction
        .execute(
            "UPDATE execution_attempts SET status = ?8, failure_class = ?9, updated_at = ?10
             WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
               AND generation = ?4 AND lease_owner = ?5
               AND lease_expires_at = ?6 AND lease_expires_at > ?7
               AND status = 'executing'",
            params![
                lease.attempt_id.as_str(),
                effect.project_id.as_str(),
                effect.id.as_str(),
                to_sql_u64(lease.generation)?,
                lease.owner,
                lease.expires_at.to_rfc3339(),
                operation_at.to_rfc3339(),
                status,
                reason,
                operation_at.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::LeaseLost);
    }
    let updated = transaction
        .execute(
            "UPDATE effect_idempotency SET status = ?4, uncertain_reason = ?5, updated_at = ?6
             WHERE project_id = ?1 AND idempotency_key = ?2 AND approval_digest = ?3",
            params![
                effect.project_id.as_str(),
                effect.idempotency_key,
                effect.approval_digest(),
                status,
                reason,
                operation_at.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::ScopeConflict);
    }
    transaction.commit().map_err(persistence)
}

fn claim_effect_reconciliation(
    store: &mut ProjectStore,
    effect: &Effect,
    policy: &ReconciliationPolicy,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, LedgerError> {
    policy.validate()?;
    let policy_digest = policy.canonical_digest()?;
    if owner.trim().is_empty() || lease_expires_at <= now {
        return Err(LedgerError::Persistence(
            "reconciliation claim requires a non-empty owner and positive lease".into(),
        ));
    }
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(persistence)?;
    if let Some(claim) = load_terminal_reconciliation_claim(&transaction, effect)? {
        transaction.commit().map_err(persistence)?;
        return Ok(ReconciliationClaim::Resolved(claim));
    }
    let record = load_idempotency(&transaction, effect)?;
    if record
        .as_ref()
        .is_none_or(|record| record.status != "uncertain")
    {
        transaction.commit().map_err(persistence)?;
        return Ok(ReconciliationClaim::NotRequired);
    }
    let execution_started_at = initial_execution_started_at(&transaction, effect)?;
    let head = load_reconciliation_head(&transaction, effect)?;
    let claim = match head.as_ref() {
        None => issue_reconciliation_lease(
            &transaction,
            effect,
            policy,
            &policy_digest,
            None,
            owner,
            now,
            lease_expires_at,
            execution_started_at,
        )?,
        Some(head) => claim_existing_reconciliation(
            &transaction,
            effect,
            policy,
            &policy_digest,
            head,
            owner,
            now,
            lease_expires_at,
            execution_started_at,
        )?,
    };
    transaction.commit().map_err(persistence)?;
    Ok(claim)
}

#[allow(clippy::too_many_arguments)]
fn claim_existing_reconciliation(
    transaction: &Transaction<'_>,
    effect: &Effect,
    policy: &ReconciliationPolicy,
    policy_digest: &str,
    head: &ReconciliationHead,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, LedgerError> {
    validate_reconciliation_policy(head, policy, policy_digest)?;
    match head.status.as_str() {
        "leased" if head.lease_expires_at.is_some_and(|expires| expires > now) => {
            Ok(ReconciliationClaim::Busy)
        }
        "leased" => {
            let observation = expired_reconciliation_observation(effect, head, now);
            observation.validate_for(effect, execution_started_at)?;
            if head.attempts >= head.policy.max_attempts {
                finish_reconciliation_rows(
                    transaction,
                    effect,
                    head,
                    "dead_letter",
                    "reconciliation lease expired without a durable observation",
                    &observation,
                    None,
                    now,
                )?;
                Ok(ReconciliationClaim::Resolved(
                    reconciliation_dead_letter_claim(
                        head.attempts,
                        &observation,
                        now,
                        execution_started_at,
                    )?,
                ))
            } else {
                finish_reconciliation_attempt_only(
                    transaction,
                    effect,
                    head,
                    "retry_wait",
                    "reconciliation lease expired without a durable observation",
                    &observation,
                    now,
                )?;
                issue_reconciliation_lease(
                    transaction,
                    effect,
                    policy,
                    policy_digest,
                    Some(head),
                    owner,
                    now,
                    lease_expires_at,
                    execution_started_at,
                )
            }
        }
        "retry_wait" if head.retry_at.is_some_and(|retry_at| retry_at > now) => {
            Ok(ReconciliationClaim::NotReady {
                retry_at: head.retry_at.expect("validated retry time"),
            })
        }
        "retry_wait" => issue_reconciliation_lease(
            transaction,
            effect,
            policy,
            policy_digest,
            Some(head),
            owner,
            now,
            lease_expires_at,
            execution_started_at,
        ),
        "receipt_found" | "provider_rejected" => Ok(ReconciliationClaim::NotRequired),
        "not_executed" | "dead_letter" => {
            let claim =
                load_terminal_reconciliation_claim(transaction, effect)?.ok_or_else(|| {
                    LedgerError::Persistence("missing terminal reconciliation projection".into())
                })?;
            Ok(ReconciliationClaim::Resolved(claim))
        }
        status => Err(LedgerError::Persistence(format!(
            "invalid reconciliation head status {status}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn issue_reconciliation_lease(
    transaction: &Transaction<'_>,
    effect: &Effect,
    policy: &ReconciliationPolicy,
    policy_digest: &str,
    previous: Option<&ReconciliationHead>,
    owner: &str,
    now: DateTime<Utc>,
    lease_expires_at: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationClaim, LedgerError> {
    let (attempt_no, generation) = previous.map_or(Ok((1_u32, 1_u64)), |head| {
        Ok((
            head.attempts
                .checked_add(1)
                .ok_or_else(|| LedgerError::Persistence("attempt overflow".into()))?,
            head.lease_generation
                .checked_add(1)
                .ok_or_else(|| LedgerError::Persistence("generation overflow".into()))?,
        ))
    })?;
    if attempt_no > policy.max_attempts {
        return Err(LedgerError::ScopeConflict);
    }
    let changed = if let Some(head) = previous {
        transaction
            .execute(
                "UPDATE effect_reconciliation_heads
                 SET status = 'leased', attempts = ?3, lease_owner = ?4,
                     lease_generation = ?5, lease_expires_at = ?6, retry_at = NULL,
                     terminal_reason = NULL, evidence_digest = NULL,
                     observation_json = NULL, updated_at = ?7
                 WHERE project_id = ?1 AND effect_id = ?2
                   AND lease_generation = ?8 AND status IN ('leased', 'retry_wait')",
                params![
                    effect.project_id.as_str(),
                    effect.id.as_str(),
                    i64::from(attempt_no),
                    owner,
                    to_sql_u64(generation)?,
                    lease_expires_at.to_rfc3339(),
                    now.to_rfc3339(),
                    to_sql_u64(head.lease_generation)?,
                ],
            )
            .map_err(persistence)?
    } else {
        transaction
            .execute(
                "INSERT INTO effect_reconciliation_heads
                   (tenant_id, project_id, mission_id, effect_id, policy_version,
                    policy_digest, max_attempts, retry_delay_seconds, status, attempts,
                    lease_owner, lease_generation, lease_expires_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'leased', 1,
                         ?9, 1, ?10, ?11, ?11)",
                params![
                    effect.tenant_id.as_str(),
                    effect.project_id.as_str(),
                    effect.mission_id.as_str(),
                    effect.id.as_str(),
                    policy.version,
                    policy_digest,
                    i64::from(policy.max_attempts),
                    to_sql_u64(policy.retry_delay_seconds)?,
                    owner,
                    lease_expires_at.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )
            .map_err(persistence)?
    };
    if changed != 1 {
        return Err(LedgerError::LeaseLost);
    }
    let attempt_id = ExecutionAttemptId::from_stable(format!(
        "reconciliation:{}:{attempt_no}:{generation}",
        effect.id
    ));
    transaction
        .execute(
            "INSERT INTO effect_reconciliation_attempts
               (attempt_id, tenant_id, project_id, mission_id, effect_id, attempt_no,
                generation, policy_digest, status, lease_owner, lease_expires_at,
                created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'leased', ?9, ?10, ?11, ?11)",
            params![
                attempt_id.as_str(),
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.id.as_str(),
                i64::from(attempt_no),
                to_sql_u64(generation)?,
                policy_digest,
                owner,
                lease_expires_at.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(ReconciliationClaim::Acquired {
        lease: ReconciliationLease {
            attempt_id,
            owner: owner.into(),
            generation,
            attempt_no,
            max_attempts: policy.max_attempts,
            expires_at: lease_expires_at,
        },
        execution_started_at,
    })
}

fn record_effect_reconciliation(
    store: &mut ProjectStore,
    effect: &Effect,
    lease: &ReconciliationLease,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<ReconciliationDisposition, LedgerError> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(persistence)?;
    let head = load_reconciliation_head(&transaction, effect)?.ok_or(LedgerError::LeaseLost)?;
    require_current_reconciliation_lease(&head, lease, now)?;
    let execution_started_at = initial_execution_started_at(&transaction, effect)?;
    observation.validate_for(effect, execution_started_at)?;
    if now < observation.observed_at() {
        return Err(LedgerError::ScopeConflict);
    }
    let disposition = apply_reconciliation_observation(
        &transaction,
        effect,
        lease,
        &head,
        observation,
        now,
        execution_started_at,
    )?;
    transaction.commit().map_err(persistence)?;
    Ok(disposition)
}

#[allow(clippy::too_many_arguments)]
fn apply_reconciliation_observation(
    transaction: &Transaction<'_>,
    effect: &Effect,
    lease: &ReconciliationLease,
    head: &ReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationDisposition, LedgerError> {
    match observation {
        ReconciliationObservation::ReceiptFound { .. } => apply_reconciled_receipt(
            transaction,
            effect,
            lease,
            head,
            observation,
            now,
            execution_started_at,
        ),
        ReconciliationObservation::NotExecuted {
            evidence_digest,
            observed_at,
        } => {
            let reason = "Provider reconciliation confirmed that no external effect occurred";
            finish_reconciliation_rows(
                transaction,
                effect,
                head,
                "not_executed",
                reason,
                observation,
                None,
                now,
            )?;
            Ok(ReconciliationDisposition::ReconciledNotExecuted {
                evidence_digest: evidence_digest.clone(),
                observed_at: *observed_at,
                execution_started_at,
            })
        }
        ReconciliationObservation::ProviderRejected { .. } => apply_reconciled_rejection(
            transaction,
            effect,
            head,
            observation,
            now,
            execution_started_at,
        ),
        ReconciliationObservation::StillUncertain {
            reason,
            evidence_digest,
            observed_at,
        } if lease.attempt_no >= lease.max_attempts => {
            finish_reconciliation_rows(
                transaction,
                effect,
                head,
                "dead_letter",
                reason,
                observation,
                None,
                now,
            )?;
            Ok(ReconciliationDisposition::DeadLetter {
                reason: reason.clone(),
                evidence_digest: evidence_digest.clone(),
                dead_lettered_at: now,
                attempts: lease.attempt_no,
                execution_started_at,
            })
        }
        ReconciliationObservation::StillUncertain {
            reason,
            evidence_digest,
            observed_at,
        } => {
            let retry_at = reconciliation_retry_at(now, head.policy.retry_delay_seconds)?;
            finish_reconciliation_rows(
                transaction,
                effect,
                head,
                "retry_wait",
                reason,
                observation,
                Some(retry_at),
                now,
            )?;
            Ok(ReconciliationDisposition::RetryScheduled {
                reason: reason.clone(),
                evidence_digest: evidence_digest.clone(),
                observed_at: *observed_at,
                retry_at,
                attempt_no: lease.attempt_no,
                execution_started_at,
            })
        }
    }
}

fn apply_reconciled_receipt(
    transaction: &Transaction<'_>,
    effect: &Effect,
    lease: &ReconciliationLease,
    head: &ReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationDisposition, LedgerError> {
    let ReconciliationObservation::ReceiptFound { receipt, .. } = observation else {
        return Err(LedgerError::ScopeConflict);
    };
    finish_reconciliation_rows(
        transaction,
        effect,
        head,
        "receipt_found",
        "",
        observation,
        None,
        now,
    )?;
    let receipt_json = serde_json::to_string(receipt).map_err(persistence)?;
    let updated = transaction
        .execute(
            "UPDATE effect_idempotency
             SET status = 'receipt_recorded', receipt_json = ?4,
                 uncertain_reason = NULL, updated_at = ?5
             WHERE project_id = ?1 AND effect_id = ?2
               AND approval_digest = ?3 AND status = 'uncertain'",
            params![
                effect.project_id.as_str(),
                effect.id.as_str(),
                effect.approval_digest(),
                receipt_json,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::ScopeConflict);
    }
    let (attempt_no, generation) = next_attempt(transaction, effect)?;
    let verification_lease = insert_attempt(
        transaction,
        effect,
        format!("{}:verification", lease.owner).as_str(),
        attempt_no,
        generation,
        "receipt_recorded",
        lease.expires_at,
        now,
    )?;
    Ok(ReconciliationDisposition::ReceiptReadyForVerification {
        lease: verification_lease,
        receipt: receipt.clone(),
        execution_started_at,
    })
}

fn apply_reconciled_rejection(
    transaction: &Transaction<'_>,
    effect: &Effect,
    head: &ReconciliationHead,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<ReconciliationDisposition, LedgerError> {
    let ReconciliationObservation::ProviderRejected {
        reason,
        evidence_digest,
        observed_at,
    } = observation
    else {
        return Err(LedgerError::ScopeConflict);
    };
    finish_reconciliation_rows(
        transaction,
        effect,
        head,
        "provider_rejected",
        reason,
        observation,
        None,
        now,
    )?;
    let updated = transaction
        .execute(
            "UPDATE effect_idempotency
             SET status = 'failed', uncertain_reason = ?4, updated_at = ?5
             WHERE project_id = ?1 AND effect_id = ?2
               AND approval_digest = ?3 AND status = 'uncertain'",
            params![
                effect.project_id.as_str(),
                effect.id.as_str(),
                effect.approval_digest(),
                reason,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(ReconciliationDisposition::ProviderRejected {
        reason: reason.clone(),
        evidence_digest: evidence_digest.clone(),
        observed_at: *observed_at,
        execution_started_at,
    })
}

fn require_current_reconciliation_lease(
    head: &ReconciliationHead,
    lease: &ReconciliationLease,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    if head.status != "leased"
        || head.attempts != lease.attempt_no
        || head.policy.max_attempts != lease.max_attempts
        || head.lease_generation != lease.generation
        || head.lease_owner.as_deref() != Some(lease.owner.as_str())
        || head.lease_expires_at != Some(lease.expires_at)
        || lease.expires_at <= now
    {
        return Err(LedgerError::LeaseLost);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_reconciliation_rows(
    transaction: &Transaction<'_>,
    effect: &Effect,
    head: &ReconciliationHead,
    status: &str,
    reason: &str,
    observation: &ReconciliationObservation,
    retry_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    finish_reconciliation_attempt_only(
        transaction,
        effect,
        head,
        status,
        reason,
        observation,
        now,
    )?;
    let observation_json = serde_json::to_string(observation).map_err(persistence)?;
    let terminal_reason = if status == "receipt_found" {
        None
    } else {
        Some(reason)
    };
    let updated = transaction
        .execute(
            "UPDATE effect_reconciliation_heads
             SET status = ?4, lease_owner = NULL, lease_expires_at = NULL,
                 retry_at = ?5, terminal_reason = ?6, evidence_digest = ?7,
                 observation_json = ?8, updated_at = ?9
             WHERE project_id = ?1 AND effect_id = ?2
               AND lease_generation = ?3 AND status = 'leased'",
            params![
                effect.project_id.as_str(),
                effect.id.as_str(),
                to_sql_u64(head.lease_generation)?,
                status,
                retry_at.map(|value| value.to_rfc3339()),
                terminal_reason,
                observation.evidence_digest(),
                observation_json,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::LeaseLost);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_reconciliation_attempt_only(
    transaction: &Transaction<'_>,
    effect: &Effect,
    head: &ReconciliationHead,
    status: &str,
    reason: &str,
    observation: &ReconciliationObservation,
    now: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let observation_json = serde_json::to_string(observation).map_err(persistence)?;
    let terminal_reason = if status == "receipt_found" {
        None
    } else {
        Some(reason)
    };
    let updated = transaction
        .execute(
            "UPDATE effect_reconciliation_attempts
             SET status = ?5, terminal_reason = ?6, evidence_digest = ?7,
                 observed_at = ?8, observation_json = ?9, updated_at = ?10
             WHERE project_id = ?1 AND effect_id = ?2 AND generation = ?3
               AND attempt_no = ?4 AND status = 'leased'",
            params![
                effect.project_id.as_str(),
                effect.id.as_str(),
                to_sql_u64(head.lease_generation)?,
                i64::from(head.attempts),
                status,
                terminal_reason,
                observation.evidence_digest(),
                observation.observed_at().to_rfc3339(),
                observation_json,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    if updated != 1 {
        return Err(LedgerError::LeaseLost);
    }
    Ok(())
}

fn load_reconciliation_head(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<Option<ReconciliationHead>, LedgerError> {
    let row = transaction
        .query_row(
            "SELECT tenant_id, mission_id, policy_version, policy_digest, max_attempts,
                    retry_delay_seconds, status, attempts, lease_owner, lease_generation,
                    lease_expires_at, retry_at, terminal_reason, evidence_digest,
                    observation_json, updated_at
             FROM effect_reconciliation_heads
             WHERE project_id = ?1 AND effect_id = ?2",
            params![effect.project_id.as_str(), effect.id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, String>(15)?,
                ))
            },
        )
        .optional()
        .map_err(persistence)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.0 != effect.tenant_id.as_str() || row.1 != effect.mission_id.as_str() {
        return Err(LedgerError::ScopeConflict);
    }
    let policy = ReconciliationPolicy {
        version: row.2,
        max_attempts: u32::try_from(row.4)
            .map_err(|_| LedgerError::Persistence("invalid max attempts".into()))?,
        retry_delay_seconds: from_sql_u64(row.5, "reconciliation retry delay")?,
    };
    policy.validate()?;
    if policy.canonical_digest()? != row.3 {
        return Err(LedgerError::ScopeConflict);
    }
    let observation = row
        .14
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(persistence)?;
    Ok(Some(ReconciliationHead {
        policy,
        policy_digest: row.3,
        status: row.6,
        attempts: u32::try_from(row.7)
            .map_err(|_| LedgerError::Persistence("invalid reconciliation attempts".into()))?,
        lease_owner: row.8,
        lease_generation: from_sql_u64(row.9, "reconciliation generation")?,
        lease_expires_at: row.10.as_deref().map(parse_time).transpose()?,
        retry_at: row.11.as_deref().map(parse_time).transpose()?,
        terminal_reason: row.12,
        evidence_digest: row.13,
        observation,
        updated_at: parse_time(&row.15)?,
    }))
}

fn validate_reconciliation_policy(
    head: &ReconciliationHead,
    policy: &ReconciliationPolicy,
    policy_digest: &str,
) -> Result<(), LedgerError> {
    if &head.policy != policy || head.policy_digest != policy_digest {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn load_terminal_reconciliation_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<Option<LedgerClaim>, LedgerError> {
    let Some(head) = load_reconciliation_head(transaction, effect)? else {
        return Ok(None);
    };
    if !matches!(
        head.status.as_str(),
        "not_executed" | "provider_rejected" | "dead_letter"
    ) {
        return Ok(None);
    }
    let execution_started_at = initial_execution_started_at(transaction, effect)?;
    let observation = head.observation.as_ref().ok_or_else(|| {
        LedgerError::Persistence("terminal reconciliation has no observation".into())
    })?;
    observation.validate_for(effect, execution_started_at)?;
    if head.evidence_digest.as_deref() != Some(observation.evidence_digest())
        || head.updated_at < observation.observed_at()
        || head
            .terminal_reason
            .as_deref()
            .is_none_or(|reason| reason.trim().is_empty())
    {
        return Err(LedgerError::ScopeConflict);
    }
    match (head.status.as_str(), observation) {
        (
            "not_executed",
            ReconciliationObservation::NotExecuted {
                evidence_digest,
                observed_at,
            },
        ) => Ok(Some(LedgerClaim::ReconciledNotExecuted {
            evidence_digest: evidence_digest.clone(),
            observed_at: *observed_at,
            execution_started_at,
        })),
        ("provider_rejected", ReconciliationObservation::ProviderRejected { reason, .. }) => {
            Ok(Some(LedgerClaim::ProviderRejected {
                reason: reason.clone(),
                execution_started_at,
                recorded_at: head.updated_at,
            }))
        }
        ("dead_letter", _) => Ok(Some(reconciliation_dead_letter_claim(
            head.attempts,
            observation,
            head.updated_at,
            execution_started_at,
        )?)),
        _ => Err(LedgerError::ScopeConflict),
    }
}

fn reconciliation_dead_letter_claim(
    attempts: u32,
    observation: &ReconciliationObservation,
    dead_lettered_at: DateTime<Utc>,
    execution_started_at: DateTime<Utc>,
) -> Result<LedgerClaim, LedgerError> {
    let reason = match observation {
        ReconciliationObservation::ProviderRejected { reason, .. }
        | ReconciliationObservation::StillUncertain { reason, .. } => reason.clone(),
        ReconciliationObservation::ReceiptFound { .. }
        | ReconciliationObservation::NotExecuted { .. } => {
            "reconciliation exhausted without a retry-safe Provider result".into()
        }
    };
    if reason.trim().is_empty() || attempts == 0 {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(LedgerClaim::DeadLetter {
        reason,
        evidence_digest: observation.evidence_digest().into(),
        dead_lettered_at,
        attempts,
        execution_started_at,
    })
}

fn expired_reconciliation_observation(
    effect: &Effect,
    head: &ReconciliationHead,
    observed_at: DateTime<Utc>,
) -> ReconciliationObservation {
    let mut digest = Sha256::new();
    digest.update(b"hartevo-expired-reconciliation-lease/v1");
    digest.update(effect.tenant_id.as_str().as_bytes());
    digest.update(effect.project_id.as_str().as_bytes());
    digest.update(effect.id.as_str().as_bytes());
    digest.update(head.attempts.to_be_bytes());
    digest.update(head.lease_generation.to_be_bytes());
    digest.update(observed_at.timestamp_micros().to_be_bytes());
    ReconciliationObservation::StillUncertain {
        reason: "reconciliation lease expired without a durable observation".into(),
        evidence_digest: format!("{:x}", digest.finalize()),
        observed_at,
    }
}

fn reconciliation_retry_at(
    now: DateTime<Utc>,
    retry_delay_seconds: u64,
) -> Result<DateTime<Utc>, LedgerError> {
    let seconds = i64::try_from(retry_delay_seconds)
        .map_err(|_| LedgerError::Persistence("retry delay overflow".into()))?;
    now.checked_add_signed(chrono::Duration::seconds(seconds))
        .ok_or_else(|| LedgerError::Persistence("retry timestamp overflow".into()))
}

fn decode_required<T: serde::de::DeserializeOwned>(
    value: Option<&str>,
    label: &str,
) -> Result<T, LedgerError> {
    let value = value.ok_or_else(|| LedgerError::Persistence(format!("missing {label}")))?;
    serde_json::from_str(value).map_err(persistence)
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, LedgerError> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(persistence)?
        .with_timezone(&Utc))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn to_sql_u64(value: u64) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::Persistence("integer overflow".into()))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|_| LedgerError::Persistence(format!("invalid {field}: {value}")))
}

fn persistence(error: impl std::fmt::Display) -> LedgerError {
    LedgerError::Persistence(error.to_string())
}
