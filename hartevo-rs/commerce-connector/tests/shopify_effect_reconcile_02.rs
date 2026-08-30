use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
use hartevo_commerce_connector::shopify_effect::{
    DraftFulfillmentRequest, SHOPIFY_FULFILLMENT_READ_SCOPE, SHOPIFY_FULFILLMENT_WRITE_SCOPE,
    ShopifyApprovalRevision, ShopifyEffectIdempotencyKey, ShopifyFulfillmentLineItem,
    ShopifyFulfillmentOrderGid, ShopifyFulfillmentOrderLineItemGid, ShopifyFulfillmentScope,
    ShopifyOrderGid, ShopifyProviderReceipt, ShopifyReadbackStatus,
    shopify_fulfillment_adapter_identity, shopify_fulfillment_provider_digest,
};
use hartevo_commerce_connector::shopify_effect_reconcile::{
    ShopifyApprovedDraftFulfillment, ShopifyEffectBoundaryReadback, ShopifyEffectBoundaryReceipt,
    ShopifyExactFulfillmentReadback, ShopifyFulfillmentGid, ShopifyFulfillmentOutcomeStatus,
    ShopifyFulfillmentReceiptReadbackService, ShopifyFulfillmentReconciliationState,
    ShopifyFulfillmentReconciliationStore, ShopifyPluginRevision, ShopifyReceiptReadbackError,
    ShopifyTypedEffectBoundary, shopify_sdk_effect_idempotency_key,
};
use hartevo_connector_sdk::{
    ConnectorError, ConnectorScope, EffectExecutionContext, FreshnessWindow, PreparedEffect,
    ProviderCapabilityKey, ProviderProvenanceClass, ReceiptCandidate, ReceiptCandidateStatus,
    ReconciliationObservation, ReconciliationStatus, VerificationObservation, VerificationStatus,
};
use sha2::{Digest, Sha256};

const NOW_YEAR: i32 = 2026;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
struct FakeBoundaryState {
    execute_calls: u32,
    reconcile_calls: u32,
    verify_calls: u32,
    timeout_after_commit: bool,
    timeout_before_commit: bool,
    readback_mismatch: bool,
    scope_drift: bool,
    operations: BTreeMap<String, ShopifyProviderReceipt>,
}

#[derive(Clone, Debug)]
struct FakeShopifyEffectBoundary {
    state: Arc<Mutex<FakeBoundaryState>>,
}

impl FakeShopifyEffectBoundary {
    fn new(state: Arc<Mutex<FakeBoundaryState>>) -> Self {
        Self { state }
    }
}

impl ShopifyTypedEffectBoundary for FakeShopifyEffectBoundary {
    fn execute(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
    ) -> Result<ShopifyEffectBoundaryReceipt, ConnectorError> {
        let mut state = self.state.lock().expect("fake boundary state");
        state.execute_calls += 1;
        let effect_digest = approved.prepared_effect().effect_digest().to_owned();
        let provider_receipt = state
            .operations
            .get(&effect_digest)
            .cloned()
            .unwrap_or_else(|| provider_receipt(approved));
        if state.timeout_before_commit {
            state.timeout_before_commit = false;
            return Err(ConnectorError::ProviderUncertain);
        }
        state
            .operations
            .entry(effect_digest)
            .or_insert_with(|| provider_receipt.clone());
        let receipt = receipt_candidate(approved, &provider_receipt);
        if state.timeout_after_commit {
            state.timeout_after_commit = false;
            return Err(ConnectorError::ProviderUncertain);
        }
        Ok(ShopifyEffectBoundaryReceipt {
            receipt,
            provider_receipt,
        })
    }

    fn reconcile(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        _prior_provider_receipt: Option<&ShopifyProviderReceipt>,
    ) -> Result<ShopifyEffectBoundaryReadback, ConnectorError> {
        let mut state = self.state.lock().expect("fake boundary state");
        state.reconcile_calls += 1;
        let effect_digest = approved.prepared_effect().effect_digest().to_owned();
        let Some(provider_receipt) = state.operations.get(&effect_digest).cloned() else {
            return Ok(ShopifyEffectBoundaryReadback {
                receipt: None,
                reconciliation: ReconciliationObservation::new(
                    effect_digest,
                    approved.prepared_effect().scope().clone(),
                    ReconciliationStatus::NotExecuted,
                    digest("not-executed"),
                    now(),
                    FreshnessWindow::new(
                        now() - Duration::seconds(1),
                        now() + Duration::seconds(30),
                        1,
                    )
                    .expect("freshness"),
                )
                .expect("not-executed reconciliation"),
                exact_readback: None,
            });
        };
        let scope = if state.scope_drift {
            connector_scope("drift-account")
        } else {
            approved.prepared_effect().scope().clone()
        };
        let reconciliation = ReconciliationObservation::new(
            effect_digest,
            scope,
            ReconciliationStatus::ReceiptFound,
            digest("shopify-provider-state"),
            now(),
            FreshnessWindow::new(
                now() - Duration::seconds(1),
                now() + Duration::seconds(30),
                1,
            )
            .expect("freshness"),
        )
        .expect("receipt-found reconciliation");
        let mut exact = exact_readback(approved, provider_receipt.clone());
        if state.readback_mismatch {
            exact.order_gid =
                ShopifyOrderGid::parse("gid://shopify/Order/9999").expect("mismatched order GID");
        }
        Ok(ShopifyEffectBoundaryReadback {
            receipt: Some(receipt_candidate(approved, &provider_receipt)),
            reconciliation,
            exact_readback: Some(exact),
        })
    }

    fn verify(
        &mut self,
        approved: &ShopifyApprovedDraftFulfillment,
        readback: &ShopifyEffectBoundaryReadback,
    ) -> Result<VerificationObservation, ConnectorError> {
        let mut state = self.state.lock().expect("fake boundary state");
        state.verify_calls += 1;
        let receipt = readback.receipt.as_ref().expect("receipt for verification");
        assert!(readback.exact_readback.is_some());
        VerificationObservation::new(
            receipt.receipt_digest().to_owned(),
            approved.prepared_effect().scope().clone(),
            VerificationStatus::Confirmed,
            digest("shopify-verification-evidence"),
            now(),
            true,
        )
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 4, 0, 0)
        .single()
        .expect("stable test time")
}

fn connector_scope(account_id: &str) -> ConnectorScope {
    ConnectorScope::new(
        "tenant-1",
        "project-1",
        "shopify",
        account_id,
        [
            SHOPIFY_FULFILLMENT_READ_SCOPE.to_owned(),
            SHOPIFY_FULFILLMENT_WRITE_SCOPE.to_owned(),
        ],
    )
    .expect("Shopify connector scope")
}

fn fulfillment_scope(account_id: &str) -> ShopifyFulfillmentScope {
    ShopifyFulfillmentScope::new(
        connector_scope(account_id),
        ShopDomain::parse("demo.myshopify.com").expect("Shopify shop"),
    )
    .expect("Shopify fulfillment scope")
}

fn draft(scope: ShopifyFulfillmentScope, generation: u64, suffix: &str) -> DraftFulfillmentRequest {
    DraftFulfillmentRequest::new(
        format!("shopify-draft-fulfillment-reconcile-{suffix}"),
        "mission-commerce-69",
        scope,
        ShopifyApiVersion::latest(),
        ShopifyOrderGid::parse("gid://shopify/Order/1001").expect("order GID"),
        ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001")
            .expect("fulfillment order GID"),
        vec![
            ShopifyFulfillmentLineItem::new(
                ShopifyFulfillmentOrderLineItemGid::parse(
                    "gid://shopify/FulfillmentOrderLineItem/5001",
                )
                .expect("line item GID"),
                2,
            )
            .expect("line item"),
        ],
        generation,
        ShopifyApprovalRevision::new(7).expect("approval revision"),
        ShopifyEffectIdempotencyKey::parse(format!("shopify-effect-idem-reconcile-{suffix}"))
            .expect("Shopify idempotency key"),
        now() - Duration::seconds(30),
        now() + Duration::seconds(300),
    )
    .expect("Shopify draft fulfillment request")
}

fn sdk_idempotency_key(draft: &DraftFulfillmentRequest) -> String {
    shopify_sdk_effect_idempotency_key(draft)
}

fn approved(
    scope: ShopifyFulfillmentScope,
    generation: u64,
    plugin_revision: u64,
    suffix: &str,
) -> ShopifyApprovedDraftFulfillment {
    let draft = draft(scope, generation, suffix);
    let adapter = shopify_fulfillment_adapter_identity().expect("Shopify effect adapter");
    let capability = ProviderCapabilityKey::new("shopify", "commerce.fulfillment.draft")
        .expect("Shopify fulfillment capability");
    let prepared_effect = PreparedEffect::new(
        connector_scope(draft.tenant_scope().connector_scope().account_id()),
        capability,
        adapter,
        draft.request_digest().to_owned(),
        sdk_idempotency_key(&draft),
        draft.created_at(),
        draft.expires_at(),
        1,
    )
    .expect("prepared Shopify effect");
    let execution_context = EffectExecutionContext::from_broker(
        prepared_effect.scope().clone(),
        prepared_effect.effect_digest(),
        digest("broker-approved-effect"),
        now() + Duration::seconds(600),
    )
    .expect("test-only broker execution capsule");
    ShopifyApprovedDraftFulfillment::new(
        draft,
        prepared_effect,
        execution_context,
        ShopifyPluginRevision::new(plugin_revision).expect("plugin revision"),
    )
    .expect("approved Shopify draft")
}

fn service(
    state: Arc<Mutex<FakeBoundaryState>>,
    scope: ShopifyFulfillmentScope,
    generation: u64,
    plugin_revision: u64,
    provenance: ProviderProvenanceClass,
) -> ShopifyFulfillmentReceiptReadbackService<FakeShopifyEffectBoundary> {
    let plugin_revision = ShopifyPluginRevision::new(plugin_revision).expect("plugin revision");
    let store = ShopifyFulfillmentReconciliationStore::new(&scope, generation, plugin_revision)
        .expect("reconciliation store");
    ShopifyFulfillmentReceiptReadbackService::new(
        FakeShopifyEffectBoundary::new(state),
        scope,
        ShopifyApiVersion::latest(),
        plugin_revision,
        provenance,
        store,
    )
    .expect("reconciliation service")
}

fn provider_receipt(approved: &ShopifyApprovedDraftFulfillment) -> ShopifyProviderReceipt {
    let draft = approved.draft();
    ShopifyProviderReceipt {
        receipt_id: format!(
            "shopify-provider-receipt-reconcile-{}",
            draft.idempotency_key().as_str()
        ),
        provider_operation_id: format!(
            "shopify-provider-op-reconcile-{}",
            draft.idempotency_key().as_str()
        ),
        request_digest: draft.request_digest().to_owned(),
        idempotency_key: draft.idempotency_key().clone(),
        scope_digest: draft.tenant_scope().digest(),
        shop: draft.tenant_scope().shop().clone(),
        order_gid: draft.order_gid().clone(),
        fulfillment_order_gid: draft.fulfillment_order_gid().clone(),
        line_items: draft.line_items().to_owned(),
        provider_generation: draft.provider_generation(),
        approval_revision: draft.approval_revision(),
        provider_digest: shopify_fulfillment_provider_digest(draft.api_version()),
        observed_at: draft.created_at(),
        evidence_digest: digest("shopify-provider-receipt-evidence"),
        provenance_class: ProviderProvenanceClass::ControlledProvider,
    }
}

fn receipt_candidate(
    approved: &ShopifyApprovedDraftFulfillment,
    provider_receipt: &ShopifyProviderReceipt,
) -> ReceiptCandidate {
    ReceiptCandidate::new(
        approved.prepared_effect(),
        digest("shopify-provider-request-id"),
        ReceiptCandidateStatus::Uncertain,
        digest("shopify-provider-response"),
        provider_receipt.observed_at,
    )
    .expect("typed SDK receipt candidate")
}

fn exact_readback(
    approved: &ShopifyApprovedDraftFulfillment,
    provider_receipt: ShopifyProviderReceipt,
) -> ShopifyExactFulfillmentReadback {
    let draft = approved.draft();
    ShopifyExactFulfillmentReadback::new(
        ShopifyFulfillmentGid::parse("gid://shopify/Fulfillment/3001").expect("fulfillment GID"),
        provider_receipt,
        draft.tenant_scope().digest(),
        draft.tenant_scope().connector_scope().account_id(),
        draft.tenant_scope().shop().clone(),
        draft.order_gid().clone(),
        draft.fulfillment_order_gid().clone(),
        draft.line_items().to_owned(),
        ShopifyReadbackStatus::Fulfilled,
        now(),
        digest("shopify-exact-fulfillment-state"),
        ProviderProvenanceClass::ControlledProvider,
    )
    .expect("exact Shopify readback")
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut digest = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut digest, "{byte:02x}").expect("writing to String cannot fail");
    }
    digest
}

#[test]
fn approved_draft_binds_existing_sdk_effect_capsule_and_plugin_revision() {
    let approved = approved(fulfillment_scope("account-1"), 3, 9, "binding");
    approved
        .validate_at(now())
        .expect("approved effect binding");
    assert_eq!(approved.draft().provider_generation(), 3);
    assert_eq!(approved.draft().approval_revision().value(), 7);
    assert_eq!(approved.plugin_revision().value(), 9);
    assert_eq!(
        approved.sdk_idempotency_key(),
        sdk_idempotency_key(approved.draft())
    );
    assert_eq!(
        approved.prepared_effect().payload_digest(),
        approved.draft().request_digest()
    );
    assert_eq!(
        approved.prepared_effect().effect_digest(),
        approved.execution_context().effect_digest()
    );
    assert_eq!(approved.approval_binding_digest().len(), 64);

    let request_identity = serde_json::to_value(approved.provider_request_identity())
        .expect("provider request identity JSON");
    assert_eq!(request_identity["operation"], "fulfillmentCreate");
    assert_eq!(request_identity["accountId"], "account-1");
    assert!(request_identity["effectDigest"].as_str().is_some());
}

#[test]
fn execute_then_readback_emits_sdk_receipt_verification_and_outcome() {
    let state = Arc::new(Mutex::new(FakeBoundaryState::default()));
    let scope = fulfillment_scope("account-1");
    let approved = approved(scope.clone(), 1, 4, "success");
    let mut service = service(
        state.clone(),
        scope,
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    let result = service
        .submit_approved(&approved, now())
        .expect("receipt/readback outcome");

    assert!(!result.replayed);
    assert!(!result.is_first_party());
    assert!(!result.is_catalog_only());
    assert_eq!(result.operation, "fulfillmentCreate");
    assert_eq!(result.provider_request.account_id, "account-1");
    assert_eq!(
        result.provider_request.order_gid,
        *approved.draft().order_gid()
    );
    assert_eq!(
        result.provider_response.provider_operation_id,
        result.provider_receipt.provider_operation_id
    );
    assert_eq!(
        result.exact_readback.fulfillment_gid.as_str(),
        "gid://shopify/Fulfillment/3001"
    );
    assert_eq!(result.receipt.status(), ReceiptCandidateStatus::Uncertain);
    assert_eq!(
        result.reconciliation.status(),
        ReconciliationStatus::ReceiptFound
    );
    assert_eq!(result.verification.status(), VerificationStatus::Confirmed);
    assert_eq!(
        result.outcome.status,
        ShopifyFulfillmentOutcomeStatus::Confirmed
    );
    assert_eq!(result.outcome.live_validation_status, "BLOCKED_ENV");
    assert_eq!(service.store().records().len(), 1);
    assert_eq!(
        service.store().records()[approved.draft().idempotency_key().as_str()].state,
        ShopifyFulfillmentReconciliationState::Verified
    );

    let state = state.lock().expect("fake boundary state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.reconcile_calls, 1);
    assert_eq!(state.verify_calls, 1);
}

#[test]
fn timeout_after_commit_restarts_by_exact_readback_without_duplicate_execute() {
    let state = Arc::new(Mutex::new(FakeBoundaryState {
        timeout_after_commit: true,
        ..FakeBoundaryState::default()
    }));
    let scope = fulfillment_scope("account-1");
    let approved = approved(scope.clone(), 1, 4, "timeout-after-commit");
    let mut first = service(
        state.clone(),
        scope.clone(),
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    assert_eq!(
        first.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::ExecutionUncertain)
    );
    assert_eq!(
        first.store().records()[approved.draft().idempotency_key().as_str()].state,
        ShopifyFulfillmentReconciliationState::Uncertain
    );
    let checkpoint = serde_json::to_vec(first.store()).expect("durable reconciliation checkpoint");
    let recovered_store: ShopifyFulfillmentReconciliationStore =
        serde_json::from_slice(&checkpoint).expect("reopen reconciliation checkpoint");
    let mut recovered = ShopifyFulfillmentReceiptReadbackService::new(
        FakeShopifyEffectBoundary::new(state.clone()),
        scope,
        ShopifyApiVersion::latest(),
        ShopifyPluginRevision::new(4).expect("plugin revision"),
        ProviderProvenanceClass::ControlledProvider,
        recovered_store,
    )
    .expect("recovered reconciliation service");

    let result = recovered
        .submit_approved(&approved, now())
        .expect("recovered exact readback");
    assert!(result.replayed);
    assert_eq!(
        result.reconciliation.status(),
        ReconciliationStatus::ReceiptFound
    );
    let replay = recovered
        .submit_approved(&approved, now())
        .expect("durable verified replay");
    assert!(replay.replayed);

    let state = state.lock().expect("fake boundary state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.reconcile_calls, 1);
    assert_eq!(state.verify_calls, 1);
}

#[test]
fn not_executed_is_terminal_and_never_replays_same_typed_effect() {
    let state = Arc::new(Mutex::new(FakeBoundaryState {
        timeout_before_commit: true,
        ..FakeBoundaryState::default()
    }));
    let scope = fulfillment_scope("account-1");
    let approved = approved(scope.clone(), 1, 4, "timeout-before-commit");
    let mut retry_service = service(
        state.clone(),
        scope,
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    assert_eq!(
        retry_service.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::ExecutionUncertain)
    );
    assert_eq!(
        retry_service.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::NotExecutedTerminal {
            evidence_digest: digest("not-executed"),
        })
    );
    assert_eq!(
        retry_service.store().records()[approved.draft().idempotency_key().as_str()].state,
        ShopifyFulfillmentReconciliationState::NotExecuted
    );
    assert_eq!(
        retry_service.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::NotExecutedTerminal {
            evidence_digest: digest("not-executed"),
        })
    );
    let state = state.lock().expect("fake boundary state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.operations.len(), 0);
    assert_eq!(state.reconcile_calls, 1);
    assert_eq!(state.verify_calls, 0);
}

#[test]
fn scope_drift_and_readback_mismatch_fail_closed_and_never_retry_write() {
    let state = Arc::new(Mutex::new(FakeBoundaryState::default()));
    let service_scope = fulfillment_scope("account-1");
    let drifted_approved = approved(fulfillment_scope("account-2"), 1, 4, "scope-drift");
    let mut scope_service = service(
        state.clone(),
        service_scope,
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    assert_eq!(
        scope_service.submit_approved(&drifted_approved, now()),
        Err(ShopifyReceiptReadbackError::ScopeDrift)
    );
    assert!(state.lock().expect("fake boundary state").execute_calls == 0);

    let mismatch_state = Arc::new(Mutex::new(FakeBoundaryState {
        readback_mismatch: true,
        ..FakeBoundaryState::default()
    }));
    let scope = fulfillment_scope("account-1");
    let approved = approved(scope.clone(), 1, 4, "readback-mismatch");
    let mut mismatch_service = service(
        mismatch_state.clone(),
        scope,
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    assert_eq!(
        mismatch_service.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::ReadbackMismatch)
    );
    assert_eq!(
        mismatch_service.store().records()[approved.draft().idempotency_key().as_str()].state,
        ShopifyFulfillmentReconciliationState::FailedClosed
    );
    assert_eq!(
        mismatch_service.submit_approved(&approved, now()),
        Err(ShopifyReceiptReadbackError::PreviouslyFailedClosed)
    );
    let mismatch_state = mismatch_state.lock().expect("fake boundary state");
    assert_eq!(mismatch_state.execute_calls, 1);
    assert_eq!(mismatch_state.verify_calls, 0);
}

#[test]
fn revoke_and_production_provenance_fail_closed_without_boundary_dispatch() {
    let state = Arc::new(Mutex::new(FakeBoundaryState::default()));
    let scope = fulfillment_scope("account-1");
    let revoke_approved = approved(scope.clone(), 1, 4, "revoke");
    let mut revoke_service = service(
        state.clone(),
        scope,
        1,
        4,
        ProviderProvenanceClass::ControlledProvider,
    );
    revoke_service.revoke(now());
    assert_eq!(
        revoke_service.submit_approved(&revoke_approved, now()),
        Err(ShopifyReceiptReadbackError::ConsumerNotMounted)
    );

    let production_state = Arc::new(Mutex::new(FakeBoundaryState::default()));
    let production_scope = fulfillment_scope("account-1");
    let production_approved = approved(production_scope.clone(), 1, 4, "production-blocked");
    let mut production = service(
        production_state.clone(),
        production_scope,
        1,
        4,
        ProviderProvenanceClass::ProductionProvider,
    );
    assert_eq!(
        production.submit_approved(&production_approved, now()),
        Err(ShopifyReceiptReadbackError::BlockedEnv)
    );
    let production_state = production_state.lock().expect("fake boundary state");
    assert_eq!(production_state.execute_calls, 0);
    assert_eq!(production_state.reconcile_calls, 0);
    assert_eq!(production_state.verify_calls, 0);
}
