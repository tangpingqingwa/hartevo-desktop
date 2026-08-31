use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Effect, ExecutionAttemptId, Receipt, Verification, VerificationStatus,
};
use hartevo_effect_broker::{
    DurableClaimDirective, DurableEffectLedger, DurableRateLimitDirective,
    DurableReceiptReconciliation, ExecutionClaimContext, ExecutionLease, LedgerClaim, LedgerError,
    PersistedClaimState, PersistedCompletionPoint, RateLimitRequest,
    ReceiptReconciliationInfrastructure, ReceiptVerificationClaimBinding,
    ReceiptVerificationInfrastructure, ReconciliationClaim, ReconciliationDisposition,
    ReconciliationLease, ReconciliationObservation, ReconciliationPolicy, StagedReceiptFound,
    VerificationClaim, VerificationLease, canonical_verifier_id, decide_durable_claim,
    decide_durable_rate_limit, independent_verification_id,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::provider_recovery_store::{
    fail_provider_recovery_closed_in_transaction, load_provider_recovery_in_transaction,
    record_provider_recovery_receipt_in_transaction,
    record_provider_recovery_verified_in_transaction,
};
use crate::{ProjectStore, ProviderRecoveryHead, ProviderRecoveryState, authorization, normalized};

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

impl ReceiptVerificationInfrastructure for ProjectStore {
    // Keep the claim's validation and immediate transaction in one audit
    // boundary so no partially authenticated lease can escape.
    #[allow(clippy::too_many_lines)]
    fn claim_verification(
        &mut self,
        effect: &Effect,
        binding: &ReceiptVerificationClaimBinding,
        expected_mission_revision: u64,
        owner: &str,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<VerificationClaim, LedgerError> {
        if owner.trim().is_empty() || lease_expires_at <= now {
            return Err(LedgerError::Persistence(
                "verification claim requires a non-empty owner and positive lease".into(),
            ));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let record = load_idempotency(&transaction, effect)?.ok_or(LedgerError::ScopeConflict)?;
        let (receipt, execution_started_at) =
            decode_durable_receipt(&transaction, effect, &record)?;
        let durable_verification = record
            .verification_json
            .as_deref()
            .map(|_| decode_durable_verification(&transaction, effect, &record))
            .transpose()?
            .map(|(_, verification, _)| verification);
        validate_current_verification_mission(
            &transaction,
            effect,
            expected_mission_revision,
            &record,
            &receipt,
            durable_verification.as_ref(),
        )?;
        binding.validate_for(effect, &receipt)?;
        // The N15 reconciliation head is immutable input to N16. Keep this
        // check inside the same transaction as the verification claim so a
        // forged receipt/provider head can never acquire a verification
        // lease without the original receipt_found triad.
        let reconciliation_head =
            load_reconciliation_head(&transaction, effect)?.ok_or(LedgerError::ScopeConflict)?;
        validate_receipt_found_head(effect, &reconciliation_head, &receipt, execution_started_at)?;
        let receipt_completion = PersistedCompletionPoint::reconciliation_head_receipt_found(
            reconciliation_head.updated_at,
        );
        let recovery_head =
            load_provider_recovery_in_transaction(&transaction, &effect.project_id, &effect.id)
                .map_err(storage_persistence)?
                .ok_or(LedgerError::ScopeConflict)?;
        validate_verification_prestate(effect, &record, &recovery_head, &receipt)?;
        ensure_verification_attempt_bindings(&transaction, effect, &binding.digest())?;

        if matches!(
            record.status.as_str(),
            "verified" | "failed" | "verification_required"
        ) && record.verification_json.is_some()
        {
            let expected_state = match record.status.as_str() {
                "verified" => ProviderRecoveryState::Verified,
                "failed" => ProviderRecoveryState::FailedClosed,
                "verification_required" => ProviderRecoveryState::ReceiptObserved,
                _ => unreachable!(),
            };
            let latest = latest_verification_attempt(&transaction, effect)?
                .ok_or(LedgerError::ScopeConflict)?;
            if latest.request_digest != binding.digest()
                || latest.status != record.status
                || latest.receipt_json.as_deref() != record.receipt_json.as_deref()
                || latest.verification_json.as_deref() != record.verification_json.as_deref()
                || latest.failure_class != record.uncertain_reason
                || latest.updated_at != record.updated_at
            {
                return Err(LedgerError::ScopeConflict);
            }
            let verification = durable_verification
                .clone()
                .ok_or(LedgerError::ScopeConflict)?;
            validate_durable_verification_status_shape(&record, &verification)?;
            if independent_verification_id(
                effect,
                &receipt,
                &verification.verifier,
                &verification.evidence_digest,
            ) != verification.id
                || recovery_head.state != expected_state
                || (expected_state == ProviderRecoveryState::Verified
                    && recovery_head.verification_evidence_digest.as_deref()
                        != Some(verification.evidence_digest.as_str()))
                || (expected_state != ProviderRecoveryState::Verified
                    && recovery_head.verification_evidence_digest.is_some())
                || match expected_state {
                    ProviderRecoveryState::Verified | ProviderRecoveryState::FailedClosed => {
                        recovery_head.updated_at != record.updated_at
                    }
                    ProviderRecoveryState::ReceiptObserved => {
                        recovery_head.updated_at != reconciliation_head.updated_at
                    }
                    _ => true,
                }
            {
                return Err(LedgerError::ScopeConflict);
            }
            transaction.commit().map_err(persistence)?;
            return Ok(VerificationClaim::AlreadyCompleted {
                receipt,
                verification,
                execution_started_at,
                operation_at: record.updated_at,
                receipt_completion,
            });
        }
        if record.status != "receipt_recorded"
            || record.receipt_json.is_none()
            || record.verification_json.is_some()
            || record.uncertain_reason.is_some()
        {
            return Err(LedgerError::ScopeConflict);
        }
        if recovery_head.state != ProviderRecoveryState::ReceiptObserved
            || recovery_head.verification_evidence_digest.is_some()
            || record.updated_at != reconciliation_head.updated_at
            || recovery_head.updated_at != reconciliation_head.updated_at
        {
            return Err(LedgerError::ScopeConflict);
        }
        validate_verification_connection(&transaction, effect, &recovery_head, now)?;
        if let Some(attempt) = latest_verification_attempt(&transaction, effect)? {
            if attempt.status != "verifying"
                || attempt.request_digest != binding.digest()
                || attempt.receipt_json.as_deref() != record.receipt_json.as_deref()
                || attempt.verification_json.is_some()
                || attempt.failure_class.is_some()
            {
                return Err(LedgerError::ScopeConflict);
            }
            if attempt.lease_expires_at > now {
                transaction.commit().map_err(persistence)?;
                return Ok(VerificationClaim::Busy);
            }
        }
        let (attempt_no, generation) = next_attempt(&transaction, effect)?;
        let lease = insert_verification_attempt(
            &transaction,
            effect,
            &receipt,
            owner,
            attempt_no,
            generation,
            lease_expires_at,
            now,
            &binding.digest(),
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(VerificationClaim::Acquired {
            lease,
            receipt,
            execution_started_at,
            receipt_completion,
        })
    }

    // Keep the three durable heads and their preconditions in one immediate
    // transaction; splitting this path would obscure its atomicity proof.
    #[allow(clippy::too_many_lines)]
    fn commit_verification(
        &mut self,
        effect: &Effect,
        binding: &ReceiptVerificationClaimBinding,
        lease: &VerificationLease,
        verification: &Verification,
        expected_mission_revision: u64,
        operation_at: DateTime<Utc>,
    ) -> Result<(), LedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        if lease.binding_digest != binding.digest() {
            return Err(LedgerError::LeaseLost);
        }
        let record = load_idempotency(&transaction, effect)?.ok_or(LedgerError::ScopeConflict)?;
        let (receipt, execution_started_at) =
            decode_durable_receipt(&transaction, effect, &record)?;
        let receipt_json = serde_json::to_string(&receipt).map_err(persistence)?;
        require_current_verification_lease(
            &transaction,
            effect,
            lease,
            binding,
            &receipt_json,
            operation_at,
        )?;
        let durable_verification = record
            .verification_json
            .as_deref()
            .map(|_| decode_durable_verification(&transaction, effect, &record))
            .transpose()?
            .map(|(_, verification, _)| verification);
        validate_current_verification_mission(
            &transaction,
            effect,
            expected_mission_revision,
            &record,
            &receipt,
            durable_verification.as_ref(),
        )?;
        // Re-authenticate the immutable N15 receipt_found row while the
        // verification lease and all three durable heads are locked.
        let reconciliation_head =
            load_reconciliation_head(&transaction, effect)?.ok_or(LedgerError::ScopeConflict)?;
        validate_receipt_found_head(effect, &reconciliation_head, &receipt, execution_started_at)?;
        let recovery_head =
            load_provider_recovery_in_transaction(&transaction, &effect.project_id, &effect.id)
                .map_err(storage_persistence)?
                .ok_or(LedgerError::ScopeConflict)?;
        validate_verification_prestate(effect, &record, &recovery_head, &receipt)?;
        if record.status != "receipt_recorded"
            || record.receipt_json.is_none()
            || record.verification_json.is_some()
            || record.uncertain_reason.is_some()
            || recovery_head.state != ProviderRecoveryState::ReceiptObserved
            || recovery_head.verification_evidence_digest.is_some()
            || record.updated_at != reconciliation_head.updated_at
            || recovery_head.updated_at != reconciliation_head.updated_at
            || operation_at < reconciliation_head.updated_at
        {
            return Err(LedgerError::ScopeConflict);
        }
        validate_verification_connection(&transaction, effect, &recovery_head, operation_at)?;
        if verification.receipt_id != receipt.id
            || canonical_verifier_id(&verification.verifier).as_deref()
                != Some(verification.verifier.as_str())
            || !verification.independent
            || !is_sha256(&verification.evidence_digest)
            || verification.evidence_digest == receipt.response_digest
            || verification.observed_at < receipt.accepted_at
            || operation_at < verification.observed_at
            || independent_verification_id(
                effect,
                &receipt,
                &verification.verifier,
                &verification.evidence_digest,
            ) != verification.id
        {
            return Err(LedgerError::ScopeConflict);
        }
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
                "UPDATE execution_attempts SET status = ?8, receipt_json = ?9,
                   verification_json = ?10, failure_class = ?11, updated_at = ?12
                 WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
                   AND generation = ?4 AND lease_owner = ?5
                   AND lease_expires_at = ?6 AND lease_expires_at > ?7
                   AND status = 'verifying' AND receipt_json = ?13
                   AND verification_json IS NULL AND failure_class IS NULL",
                params![
                    lease.attempt_id.as_str(),
                    effect.project_id.as_str(),
                    effect.id.as_str(),
                    to_sql_u64(lease.generation)?,
                    lease.owner,
                    lease.expires_at.to_rfc3339(),
                    operation_at.to_rfc3339(),
                    status,
                    &receipt_json,
                    verification_json,
                    failure_class,
                    operation_at.to_rfc3339(),
                    &receipt_json,
                ],
            )
            .map_err(persistence)?;
        if attempt_updated != 1 {
            return Err(LedgerError::LeaseLost);
        }
        let idempotency_updated = transaction
            .execute(
                "UPDATE effect_idempotency SET status = ?4, receipt_json = ?5,
                   verification_json = ?6, uncertain_reason = ?7, updated_at = ?8
                 WHERE project_id = ?1 AND idempotency_key = ?2
                   AND approval_digest = ?3
                   AND status = 'receipt_recorded'
                   AND verification_json IS NULL AND uncertain_reason IS NULL",
                params![
                    effect.project_id.as_str(),
                    effect.idempotency_key,
                    effect.approval_digest(),
                    status,
                    &receipt_json,
                    verification_json,
                    failure_class,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if idempotency_updated != 1 {
            return Err(LedgerError::ScopeConflict);
        }
        match verification.status {
            VerificationStatus::Confirmed => {
                let committed = record_provider_recovery_verified_in_transaction(
                    &transaction,
                    &effect.project_id,
                    &effect.id,
                    recovery_head.revision,
                    &recovery_head.binding.binding_digest,
                    verification.evidence_digest.clone(),
                    operation_at,
                )
                .map_err(storage_persistence)?;
                if committed.state != ProviderRecoveryState::Verified
                    || committed.verification_evidence_digest.as_deref()
                        != Some(verification.evidence_digest.as_str())
                {
                    return Err(LedgerError::ScopeConflict);
                }
            }
            VerificationStatus::Rejected => {
                let committed = fail_provider_recovery_closed_in_transaction(
                    &transaction,
                    &effect.project_id,
                    &effect.id,
                    recovery_head.revision,
                    &recovery_head.binding.binding_digest,
                    operation_at,
                )
                .map_err(storage_persistence)?;
                if committed.state != ProviderRecoveryState::FailedClosed {
                    return Err(LedgerError::ScopeConflict);
                }
            }
            VerificationStatus::Inconclusive => {}
        }
        let _ = execution_started_at;
        transaction.commit().map_err(persistence)
    }
}

impl ReceiptReconciliationInfrastructure for ProjectStore {
    fn recover_staged_receipt(
        &mut self,
        effect: &Effect,
    ) -> Result<Option<DurableReceiptReconciliation>, LedgerError> {
        let transaction = self.connection.transaction().map_err(persistence)?;
        let Some(record) = load_idempotency(&transaction, effect)? else {
            transaction.commit().map_err(persistence)?;
            return Ok(None);
        };
        if record.status != "receipt_recorded" {
            transaction.commit().map_err(persistence)?;
            return Ok(None);
        }
        if record.receipt_json.is_none()
            || record.verification_json.is_some()
            || record.uncertain_reason.is_some()
        {
            return Err(LedgerError::ScopeConflict);
        }
        let Some(reconciliation_head) = load_reconciliation_head(&transaction, effect)? else {
            transaction.commit().map_err(persistence)?;
            return Ok(None);
        };
        if reconciliation_head.status != "receipt_found" {
            transaction.commit().map_err(persistence)?;
            return Ok(None);
        }
        let Some(recovery_head) =
            load_provider_recovery_in_transaction(&transaction, &effect.project_id, &effect.id)
                .map_err(storage_persistence)?
        else {
            transaction.commit().map_err(persistence)?;
            return Ok(None);
        };
        let (receipt, execution_started_at) =
            decode_durable_receipt(&transaction, effect, &record)?;
        let completion = persisted_receipt_completion(
            &transaction,
            effect,
            &record,
            &receipt,
            execution_started_at,
        )?;
        validate_staged_recovery_head(
            effect,
            &recovery_head,
            &receipt,
            reconciliation_head
                .evidence_digest
                .as_deref()
                .ok_or(LedgerError::ScopeConflict)?,
            reconciliation_head.updated_at,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(Some(DurableReceiptReconciliation {
            receipt,
            execution_started_at,
            completion,
        }))
    }

    #[allow(clippy::too_many_lines)]
    fn record_staged_receipt(
        &mut self,
        effect: &Effect,
        lease: &ReconciliationLease,
        staged: &StagedReceiptFound,
        operation_at: DateTime<Utc>,
    ) -> Result<DurableReceiptReconciliation, LedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(persistence)?;
        let reconciliation_head =
            load_reconciliation_head(&transaction, effect)?.ok_or(LedgerError::LeaseLost)?;
        require_current_reconciliation_lease(&reconciliation_head, lease, operation_at)?;
        let execution_started_at = initial_execution_started_at(&transaction, effect)?;
        staged.validate_for(effect, execution_started_at)?;
        if operation_at < staged.observed_at() {
            return Err(LedgerError::ScopeConflict);
        }

        let current_mission = normalized::load_mission_normalized(
            &transaction,
            &effect.project_id,
            &effect.mission_id,
        )
        .map_err(storage_persistence)?
        .ok_or(LedgerError::ScopeConflict)?;
        let current_effect = current_mission
            .effects
            .iter()
            .find(|candidate| candidate.id == effect.id)
            .ok_or(LedgerError::ScopeConflict)?;
        if current_mission.revision != staged.recovery().mission_revision()
            || current_effect != effect
            || current_effect.status != hartevo_domain_kernel::EffectStatus::VerificationRequired
        {
            return Err(LedgerError::ScopeConflict);
        }
        let connection = authorization::load_connection_in_transaction(
            &transaction,
            &effect.project_id,
            &staged.recovery().connection().id,
        )
        .map_err(storage_persistence)?;
        if connection.snapshot() != *staged.recovery().connection()
            || !connection.permits_scopes(&effect.required_scopes, operation_at)
        {
            return Err(LedgerError::ScopeConflict);
        }
        let recovery_head =
            load_provider_recovery_in_transaction(&transaction, &effect.project_id, &effect.id)
                .map_err(storage_persistence)?
                .ok_or(LedgerError::ScopeConflict)?;
        validate_staged_recovery_fence(effect, &recovery_head, staged)?;

        let observation = staged.observation();
        finish_reconciliation_rows(
            &transaction,
            effect,
            &reconciliation_head,
            "receipt_found",
            "",
            &observation,
            None,
            operation_at,
        )?;
        let receipt_json = serde_json::to_string(staged.receipt()).map_err(persistence)?;
        let updated = transaction
            .execute(
                "UPDATE effect_idempotency
                 SET status = 'receipt_recorded', receipt_json = ?4,
                     verification_json = NULL, uncertain_reason = NULL, updated_at = ?5
                 WHERE project_id = ?1 AND effect_id = ?2
                   AND approval_digest = ?3 AND status = 'uncertain'
                   AND verification_json IS NULL",
                params![
                    effect.project_id.as_str(),
                    effect.id.as_str(),
                    effect.approval_digest(),
                    receipt_json,
                    operation_at.to_rfc3339(),
                ],
            )
            .map_err(persistence)?;
        if updated != 1 {
            return Err(LedgerError::ScopeConflict);
        }
        let committed_recovery = record_provider_recovery_receipt_in_transaction(
            &transaction,
            &effect.project_id,
            &effect.id,
            staged.recovery().recovery_revision(),
            staged.recovery().recovery_binding_digest(),
            staged.recovery().readback_storage_ref().to_owned(),
            staged.recovery().readback_content_digest().to_owned(),
            staged.evidence_digest().to_owned(),
            operation_at,
        )
        .map_err(storage_persistence)?;
        validate_staged_recovery_head(
            effect,
            &committed_recovery,
            staged.receipt(),
            staged.evidence_digest(),
            operation_at,
        )?;
        transaction.commit().map_err(persistence)?;
        Ok(DurableReceiptReconciliation {
            receipt: staged.receipt().clone(),
            execution_started_at,
            completion: PersistedCompletionPoint::reconciliation_head_receipt_found(operation_at),
        })
    }
}

fn validate_staged_recovery_fence(
    effect: &Effect,
    head: &ProviderRecoveryHead,
    staged: &StagedReceiptFound,
) -> Result<(), LedgerError> {
    let fence = staged.recovery();
    let binding = &head.binding;
    let approval = effect.approval.as_ref().ok_or(LedgerError::ScopeConflict)?;
    if !matches!(
        head.state,
        ProviderRecoveryState::InFlight | ProviderRecoveryState::Uncertain
    ) || head.revision != fence.recovery_revision()
        || binding.binding_digest != fence.recovery_binding_digest()
        || head.capsule.content_digest != fence.recovery_capsule_content_digest()
        || head.capsule.key_version != fence.recovery_capsule_key_version()
        || head.capsule.object_revision != fence.recovery_capsule_object_revision()
        || binding.tenant_id != effect.tenant_id
        || binding.project_id != effect.project_id
        || binding.mission_id != effect.mission_id
        || binding.effect_id != effect.id
        || binding.approval_scope_digest != effect.approval_digest()
        || binding.broker_authorization_digest != approval.permission_digest
        || binding.provider_id != effect.provider
        || binding.capability_id != effect.capability
        || binding.credential_revision != fence.connection().revision
        || effect.account_id.as_ref() != Some(&fence.connection().account_id)
        || head.readback_storage_ref.is_some()
        || head.receipt_evidence_digest.is_some()
        || head.verification_evidence_digest.is_some()
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_staged_recovery_head(
    effect: &Effect,
    head: &ProviderRecoveryHead,
    receipt: &Receipt,
    evidence_digest: &str,
    operation_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let binding = &head.binding;
    let approval = effect.approval.as_ref().ok_or(LedgerError::ScopeConflict)?;
    let expected_storage_ref = format!("cas://{evidence_digest}");
    if head.state != ProviderRecoveryState::ReceiptObserved
        || head.updated_at != operation_at
        || head.readback_storage_ref.as_deref() != Some(expected_storage_ref.as_str())
        || head.readback_content_digest.as_deref() != Some(evidence_digest)
        || head.receipt_evidence_digest.as_deref() != Some(evidence_digest)
        || head.verification_evidence_digest.is_some()
        || receipt.response_digest != evidence_digest
        || binding.tenant_id != effect.tenant_id
        || binding.project_id != effect.project_id
        || binding.mission_id != effect.mission_id
        || binding.effect_id != effect.id
        || binding.approval_scope_digest != effect.approval_digest()
        || binding.broker_authorization_digest != approval.permission_digest
        || binding.provider_id != effect.provider
        || binding.capability_id != effect.capability
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn storage_persistence(error: impl std::fmt::Display) -> LedgerError {
    LedgerError::Persistence(error.to_string())
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
struct LatestVerificationAttempt {
    status: String,
    request_digest: String,
    lease_expires_at: DateTime<Utc>,
    receipt_json: Option<String>,
    verification_json: Option<String>,
    failure_class: Option<String>,
    updated_at: DateTime<Utc>,
}

fn latest_verification_attempt(
    transaction: &Transaction<'_>,
    effect: &Effect,
) -> Result<Option<LatestVerificationAttempt>, LedgerError> {
    transaction
        .query_row(
            "SELECT status, request_digest, lease_expires_at, receipt_json,
                    verification_json, failure_class, updated_at
             FROM execution_attempts
             WHERE project_id = ?1 AND effect_id = ?2
               AND id LIKE 'verification-attempt:%'
             ORDER BY generation DESC LIMIT 1",
            params![effect.project_id.as_str(), effect.id.as_str()],
            |row| {
                Ok(LatestVerificationAttempt {
                    status: row.get(0)?,
                    request_digest: row.get(1)?,
                    lease_expires_at: parse_time(&row.get::<_, String>(2)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    receipt_json: row.get(3)?,
                    verification_json: row.get(4)?,
                    failure_class: row.get(5)?,
                    updated_at: parse_time(&row.get::<_, String>(6)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                })
            },
        )
        .optional()
        .map_err(persistence)
}

fn ensure_verification_attempt_bindings(
    transaction: &Transaction<'_>,
    effect: &Effect,
    binding_digest: &str,
) -> Result<(), LedgerError> {
    let conflicting = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM execution_attempts
                 WHERE project_id = ?1 AND effect_id = ?2
                   AND id LIKE 'verification-attempt:%'
                   AND request_digest <> ?3
             )",
            params![
                effect.project_id.as_str(),
                effect.id.as_str(),
                binding_digest
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(persistence)?;
    if conflicting != 0 {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_verification_attempt(
    transaction: &Transaction<'_>,
    effect: &Effect,
    receipt: &Receipt,
    owner: &str,
    attempt_no: u64,
    generation: u64,
    lease_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    binding_digest: &str,
) -> Result<VerificationLease, LedgerError> {
    let attempt_id = ExecutionAttemptId::from_stable(format!(
        "verification-attempt:{}:{attempt_no}:{generation}",
        effect.id
    ));
    let receipt_json = serde_json::to_string(receipt).map_err(persistence)?;
    transaction
        .execute(
            "INSERT INTO execution_attempts
               (id, tenant_id, project_id, mission_id, effect_id, attempt_no, generation,
                status, lease_owner, lease_expires_at, request_digest, receipt_json,
                created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'verifying', ?8, ?9, ?10, ?11, ?12, ?12)",
            params![
                attempt_id.as_str(),
                effect.tenant_id.as_str(),
                effect.project_id.as_str(),
                effect.mission_id.as_str(),
                effect.id.as_str(),
                to_sql_u64(attempt_no)?,
                to_sql_u64(generation)?,
                owner,
                lease_expires_at.to_rfc3339(),
                binding_digest,
                receipt_json,
                now.to_rfc3339(),
            ],
        )
        .map_err(persistence)?;
    Ok(VerificationLease {
        attempt_id,
        owner: owner.into(),
        generation,
        attempt_no: u32::try_from(attempt_no)
            .map_err(|_| LedgerError::Persistence("verification attempt number overflow".into()))?,
        binding_digest: binding_digest.to_owned(),
        expires_at: lease_expires_at,
    })
}

fn require_current_verification_lease(
    transaction: &Transaction<'_>,
    effect: &Effect,
    lease: &VerificationLease,
    binding: &ReceiptVerificationClaimBinding,
    receipt_json: &str,
    operation_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let row = transaction
        .query_row(
            "SELECT lease_owner, generation, attempt_no, lease_expires_at, status,
                    request_digest, receipt_json, verification_json, failure_class
             FROM execution_attempts
             WHERE id = ?1 AND project_id = ?2 AND effect_id = ?3
               AND generation = (
                 SELECT MAX(current.generation) FROM execution_attempts current
                 WHERE current.project_id = ?2 AND current.effect_id = ?3
                   AND current.id LIKE 'verification-attempt:%'
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
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(persistence)?;
    let Some((
        owner,
        generation,
        attempt_no,
        expires_at,
        status,
        request_digest,
        stored_receipt_json,
        stored_verification_json,
        failure_class,
    )) = row
    else {
        return Err(LedgerError::LeaseLost);
    };
    let expires_at = parse_time(&expires_at)?;
    if owner != lease.owner
        || u64::try_from(generation).ok() != Some(lease.generation)
        || u32::try_from(attempt_no).ok() != Some(lease.attempt_no)
        || expires_at != lease.expires_at
        || expires_at <= operation_at
        || status != "verifying"
        || request_digest != binding.digest()
        || stored_receipt_json.as_deref() != Some(receipt_json)
        || stored_verification_json.is_some()
        || failure_class.is_some()
    {
        return Err(LedgerError::LeaseLost);
    }
    Ok(())
}

fn validate_verification_prestate(
    effect: &Effect,
    record: &IdempotencyRecord,
    recovery_head: &ProviderRecoveryHead,
    receipt: &Receipt,
) -> Result<(), LedgerError> {
    let approval = effect.approval.as_ref().ok_or(LedgerError::ScopeConflict)?;
    let expected_storage_ref = format!("cas://{}", receipt.response_digest);
    let binding = &recovery_head.binding;
    if binding.tenant_id != effect.tenant_id
        || binding.project_id != effect.project_id
        || binding.mission_id != effect.mission_id
        || binding.effect_id != effect.id
        || binding.approval_scope_digest != effect.approval_digest()
        || binding.broker_authorization_digest != approval.permission_digest
        || binding.provider_id != effect.provider
        || binding.capability_id != effect.capability
        || recovery_head.readback_storage_ref.as_deref() != Some(expected_storage_ref.as_str())
        || recovery_head.readback_content_digest.as_deref()
            != Some(receipt.response_digest.as_str())
        || recovery_head.receipt_evidence_digest.as_deref()
            != Some(receipt.response_digest.as_str())
        || receipt.provider != effect.provider
        || receipt.external_id.trim().is_empty()
        || receipt.request_digest != effect.approval_digest()
        || !is_sha256(&receipt.response_digest)
        || record.receipt_json.is_none()
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_durable_verification_status_shape(
    record: &IdempotencyRecord,
    verification: &Verification,
) -> Result<(), LedgerError> {
    let expected_failure = match (record.status.as_str(), &verification.status) {
        ("verified", VerificationStatus::Confirmed) => None,
        ("failed", VerificationStatus::Rejected) => Some("verification_rejected"),
        ("verification_required", VerificationStatus::Inconclusive) => {
            Some("verification_inconclusive")
        }
        _ => return Err(LedgerError::ScopeConflict),
    };
    if record.uncertain_reason.as_deref() != expected_failure {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_verification_connection(
    transaction: &Transaction<'_>,
    effect: &Effect,
    recovery_head: &ProviderRecoveryHead,
    at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    let connection_id = effect
        .connection_id
        .as_ref()
        .ok_or(LedgerError::ScopeConflict)?;
    let account_id = effect
        .account_id
        .as_ref()
        .ok_or(LedgerError::ScopeConflict)?;
    let connection = authorization::load_connection_in_transaction(
        transaction,
        &effect.project_id,
        connection_id,
    )
    .map_err(storage_persistence)?;
    let snapshot = connection.snapshot();
    if snapshot.tenant_id != effect.tenant_id
        || snapshot.project_id != effect.project_id
        || snapshot.provider != effect.provider
        || snapshot.account_id != *account_id
        || connection.revision() != recovery_head.binding.credential_revision
        || !connection.permits_scopes(&effect.required_scopes, at)
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_current_verification_mission(
    transaction: &Transaction<'_>,
    effect: &Effect,
    expected_mission_revision: u64,
    record: &IdempotencyRecord,
    receipt: &Receipt,
    durable_verification: Option<&Verification>,
) -> Result<(), LedgerError> {
    if expected_mission_revision == 0 {
        return Err(LedgerError::ScopeConflict);
    }
    let current_mission =
        normalized::load_mission_normalized(transaction, &effect.project_id, &effect.mission_id)
            .map_err(storage_persistence)?
            .ok_or(LedgerError::ScopeConflict)?;
    let current_effect = current_mission
        .effects
        .iter()
        .find(|candidate| candidate.id == effect.id)
        .ok_or(LedgerError::ScopeConflict)?;
    if current_mission.revision != expected_mission_revision || current_effect != effect {
        return Err(LedgerError::ScopeConflict);
    }
    let projected_status = match record.status.as_str() {
        "verified" => hartevo_domain_kernel::EffectStatus::Verified,
        "failed" => hartevo_domain_kernel::EffectStatus::Failed,
        "verification_required" => hartevo_domain_kernel::EffectStatus::VerificationRequired,
        "receipt_recorded" => hartevo_domain_kernel::EffectStatus::ReceiptRecorded,
        _ => return Err(LedgerError::ScopeConflict),
    };
    if current_effect.receipt.as_ref() != Some(receipt) {
        return Err(LedgerError::ScopeConflict);
    }
    match record.status.as_str() {
        "receipt_recorded" => {
            if record.verification_json.is_some()
                || record.uncertain_reason.is_some()
                || current_effect.status != projected_status
                || current_effect.verification.is_some()
                || durable_verification.is_some()
            {
                return Err(LedgerError::ScopeConflict);
            }
        }
        "verified" | "failed" | "verification_required" => {
            let Some(durable_verification) = durable_verification else {
                return Err(LedgerError::ScopeConflict);
            };
            // During the crash window between the SQL commit and Mission
            // projection the Domain shape is still the exact receipt-only
            // N15 state. After projection it must carry the matching status
            // and the exact durable Verification object.
            let pre_projection = current_effect.status
                == hartevo_domain_kernel::EffectStatus::ReceiptRecorded
                && current_effect.verification.is_none();
            let projected = current_effect.status == projected_status
                && current_effect.verification.as_ref() == Some(durable_verification);
            if !pre_projection && !projected {
                return Err(LedgerError::ScopeConflict);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
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
    let reconciliation_head = load_reconciliation_head(transaction, request.effect)?;
    validate_claim_head_classification(existing.as_ref(), reconciliation_head.as_ref())?;
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

fn validate_claim_head_classification(
    record: Option<&IdempotencyRecord>,
    head: Option<&ReconciliationHead>,
) -> Result<(), LedgerError> {
    let valid = match (record, head) {
        (None, None) => true,
        (Some(record), None) => matches!(
            record.status.as_str(),
            "executing"
                | "failed"
                | "uncertain"
                | "receipt_recorded"
                | "verified"
                | "verification_required"
        ),
        (Some(IdempotencyRecord { status, .. }), Some(head)) if status == "uncertain" => {
            matches!(head.status.as_str(), "leased" | "retry_wait")
        }
        (Some(record), Some(head)) if head.status == "receipt_found" => {
            match record.status.as_str() {
                "receipt_recorded" => {
                    record.receipt_json.is_some() && record.verification_json.is_none()
                }
                "verified" | "verification_required" | "failed" => {
                    record.receipt_json.is_some() && record.verification_json.is_some()
                }
                _ => false,
            }
        }
        _ => false,
    };
    if !valid {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
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
            durable_verification_claim(transaction, request.effect, record)
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
    if load_reconciliation_head(transaction, effect)?.is_some() {
        return Err(LedgerError::ScopeConflict);
    }
    let execution_started_at = initial_execution_started_at(transaction, effect)?;
    if record.updated_at < execution_started_at {
        return Err(LedgerError::ScopeConflict);
    }
    let reason = record
        .uncertain_reason
        .as_ref()
        .filter(|reason| !reason.trim().is_empty())
        .cloned()
        .ok_or(LedgerError::ScopeConflict)?;
    Ok(LedgerClaim::RecoverableProviderRejected {
        reason,
        observed_at: None,
        execution_started_at,
        completion: PersistedCompletionPoint::effect_idempotency_provider_rejected(
            record.updated_at,
        ),
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
    let completion =
        persisted_receipt_completion(transaction, effect, record, &receipt, execution_started_at)?;
    let (attempt_no, generation) = next_attempt(transaction, effect)?;
    Ok(LedgerClaim::RecoverableReceipt {
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
        receipt,
        execution_started_at,
        completion,
    })
}

fn durable_verification_claim(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
) -> Result<LedgerClaim, LedgerError> {
    let (receipt, verification, execution_started_at) =
        decode_durable_verification(transaction, effect, record)?;
    let (receipt_completion, completion) = persisted_verification_completions(
        transaction,
        effect,
        record,
        &receipt,
        &verification,
        execution_started_at,
    )?;
    Ok(LedgerClaim::RecoverableVerification {
        receipt,
        verification,
        execution_started_at,
        receipt_completion,
        completion,
    })
}

fn persisted_receipt_completion(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
    receipt: &Receipt,
    execution_started_at: DateTime<Utc>,
) -> Result<PersistedCompletionPoint, LedgerError> {
    if record.updated_at < execution_started_at || record.updated_at < receipt.accepted_at {
        return Err(LedgerError::ScopeConflict);
    }
    let Some(head) = load_reconciliation_head(transaction, effect)? else {
        return Ok(
            PersistedCompletionPoint::effect_idempotency_provider_receipt(record.updated_at),
        );
    };
    validate_receipt_found_head(effect, &head, receipt, execution_started_at)?;
    if record.updated_at != head.updated_at {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(PersistedCompletionPoint::reconciliation_head_receipt_found(
        head.updated_at,
    ))
}

fn persisted_verification_completions(
    transaction: &Transaction<'_>,
    effect: &Effect,
    record: &IdempotencyRecord,
    receipt: &Receipt,
    verification: &Verification,
    execution_started_at: DateTime<Utc>,
) -> Result<(Option<PersistedCompletionPoint>, PersistedCompletionPoint), LedgerError> {
    if record.updated_at < execution_started_at
        || record.updated_at < receipt.accepted_at
        || record.updated_at < verification.observed_at
    {
        return Err(LedgerError::ScopeConflict);
    }
    let receipt_completion = match load_reconciliation_head(transaction, effect)? {
        None => None,
        Some(head) => {
            validate_receipt_found_head(effect, &head, receipt, execution_started_at)?;
            if head.updated_at > record.updated_at {
                return Err(LedgerError::ScopeConflict);
            }
            Some(PersistedCompletionPoint::reconciliation_head_receipt_found(
                head.updated_at,
            ))
        }
    };
    Ok((
        receipt_completion,
        PersistedCompletionPoint::effect_idempotency_verification(record.updated_at),
    ))
}

fn validate_receipt_found_head(
    effect: &Effect,
    head: &ReconciliationHead,
    receipt: &Receipt,
    execution_started_at: DateTime<Utc>,
) -> Result<(), LedgerError> {
    if head.status != "receipt_found" || head.terminal_reason.is_some() {
        return Err(LedgerError::ScopeConflict);
    }
    let observation = head
        .observation
        .as_ref()
        .ok_or(LedgerError::ScopeConflict)?;
    observation.validate_for(effect, execution_started_at)?;
    let ReconciliationObservation::ReceiptFound {
        receipt: observed_receipt,
        observed_at,
        ..
    } = observation
    else {
        return Err(LedgerError::ScopeConflict);
    };
    if observed_receipt != receipt
        || head.evidence_digest.as_deref() != Some(observation.evidence_digest())
        || head.updated_at < *observed_at
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
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
        || canonical_verifier_id(&verification.verifier).as_deref()
            != Some(verification.verifier.as_str())
        || !verification.independent
        || !is_sha256(&verification.evidence_digest)
        || verification.evidence_digest == receipt.response_digest
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
        return Ok(ReconciliationClaim::Resolved(Box::new(claim)));
    }
    let record = load_idempotency(&transaction, effect)?;
    let Some(record) = record.as_ref() else {
        if load_reconciliation_head(&transaction, effect)?.is_some() {
            return Err(LedgerError::ScopeConflict);
        }
        transaction.commit().map_err(persistence)?;
        return Ok(ReconciliationClaim::NotRequired);
    };
    match record.status.as_str() {
        "verified" | "verification_required" => {
            let claim = durable_verification_claim(&transaction, effect, record)?;
            transaction.commit().map_err(persistence)?;
            return Ok(ReconciliationClaim::Resolved(Box::new(claim)));
        }
        "failed" => {
            let claim = provider_failed_claim(&transaction, effect, record)?;
            transaction.commit().map_err(persistence)?;
            return Ok(ReconciliationClaim::Resolved(Box::new(claim)));
        }
        "receipt_recorded" => {
            let (receipt, execution_started_at) =
                decode_durable_receipt(&transaction, effect, record)?;
            persisted_receipt_completion(
                &transaction,
                effect,
                record,
                &receipt,
                execution_started_at,
            )?;
            transaction.commit().map_err(persistence)?;
            return Ok(ReconciliationClaim::NotRequired);
        }
        "executing" => {
            if load_reconciliation_head(&transaction, effect)?.is_some() {
                return Err(LedgerError::ScopeConflict);
            }
            transaction.commit().map_err(persistence)?;
            return Ok(ReconciliationClaim::NotRequired);
        }
        "uncertain" => {}
        status => {
            return Err(LedgerError::Persistence(format!(
                "invalid reconciliation ledger status {status}"
            )));
        }
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
                Ok(ReconciliationClaim::Resolved(Box::new(
                    reconciliation_dead_letter_claim(
                        head.attempts,
                        &observation,
                        now,
                        execution_started_at,
                    )?,
                )))
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
        "receipt_found" | "provider_rejected" => Err(LedgerError::ScopeConflict),
        "not_executed" | "dead_letter" => {
            let claim =
                load_terminal_reconciliation_claim(transaction, effect)?.ok_or_else(|| {
                    LedgerError::Persistence("missing terminal reconciliation projection".into())
                })?;
            Ok(ReconciliationClaim::Resolved(Box::new(claim)))
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
    let record = load_idempotency(transaction, effect)?.ok_or_else(|| {
        LedgerError::Persistence("terminal reconciliation has no ledger row".into())
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
        ) => {
            validate_not_executed_idempotency(&record, &head)?;
            Ok(Some(LedgerClaim::RecoverableReconciledNotExecuted {
                evidence_digest: evidence_digest.clone(),
                observed_at: *observed_at,
                execution_started_at,
                completion: PersistedCompletionPoint::reconciliation_head_not_executed(
                    head.updated_at,
                ),
            }))
        }
        (
            "provider_rejected",
            ReconciliationObservation::ProviderRejected {
                reason,
                observed_at,
                ..
            },
        ) => {
            validate_reconciled_rejection_idempotency(&record, &head, reason)?;
            Ok(Some(LedgerClaim::RecoverableProviderRejected {
                reason: reason.clone(),
                observed_at: Some(*observed_at),
                execution_started_at,
                completion: PersistedCompletionPoint::reconciliation_head_provider_rejected(
                    head.updated_at,
                ),
            }))
        }
        ("dead_letter", ReconciliationObservation::StillUncertain { reason, .. }) => {
            validate_dead_letter_idempotency(&record, &head, reason)?;
            Ok(Some(reconciliation_dead_letter_claim(
                head.attempts,
                observation,
                head.updated_at,
                execution_started_at,
            )?))
        }
        _ => Err(LedgerError::ScopeConflict),
    }
}

fn validate_reconciled_rejection_idempotency(
    record: &IdempotencyRecord,
    head: &ReconciliationHead,
    reason: &str,
) -> Result<(), LedgerError> {
    if record.status != "failed"
        || record.receipt_json.is_some()
        || record.verification_json.is_some()
        || record.updated_at != head.updated_at
        || record.uncertain_reason.as_deref() != Some(reason)
        || head.terminal_reason.as_deref() != Some(reason)
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_not_executed_idempotency(
    record: &IdempotencyRecord,
    head: &ReconciliationHead,
) -> Result<(), LedgerError> {
    if record.status != "uncertain"
        || record.receipt_json.is_some()
        || record.verification_json.is_some()
        || record.updated_at > head.updated_at
    {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
}

fn validate_dead_letter_idempotency(
    record: &IdempotencyRecord,
    head: &ReconciliationHead,
    reason: &str,
) -> Result<(), LedgerError> {
    validate_not_executed_idempotency(record, head)?;
    if reason.trim().is_empty() || head.terminal_reason.as_deref() != Some(reason) {
        return Err(LedgerError::ScopeConflict);
    }
    Ok(())
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
