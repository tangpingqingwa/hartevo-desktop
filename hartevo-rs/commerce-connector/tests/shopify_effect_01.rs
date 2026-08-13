use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::shopify::{ShopDomain, ShopifyApiVersion};
use hartevo_commerce_connector::shopify_effect::{
    DraftFulfillmentRequest, FULFILLMENT_CREATE_MUTATION, FULFILLMENT_READBACK_QUERY,
    SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS, SHOPIFY_FULFILLMENT_READ_SCOPE,
    SHOPIFY_FULFILLMENT_WRITE_SCOPE, ShopifyApprovalRevision, ShopifyEffectIdempotencyKey,
    ShopifyEffectLifecycle, ShopifyFulfillmentEffectError, ShopifyFulfillmentEffectService,
    ShopifyFulfillmentEffectStore, ShopifyFulfillmentLineItem, ShopifyFulfillmentOrderGid,
    ShopifyFulfillmentOrderLineItemGid, ShopifyFulfillmentProvider,
    ShopifyFulfillmentProviderError, ShopifyFulfillmentRecordState, ShopifyFulfillmentScope,
    ShopifyOrderGid, ShopifyProbeStatus, ShopifyProviderReceipt, ShopifyReadbackLookup,
    ShopifyReadbackObservation, ShopifyReadbackStatus, ShopifyScopeProbe, ShopifyScopeProbeRequest,
    shopify_fulfillment_adapter_identity, shopify_fulfillment_provider_digest,
};
use hartevo_connector_sdk::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const NOW_YEAR: i32 = 2026;

#[derive(Clone, Debug, Default)]
struct FakeState {
    probe_calls: u32,
    execute_calls: u32,
    readback_calls: u32,
    timeout_after_commit: bool,
    missing_write_scope: bool,
    wrong_generation: bool,
    operations: BTreeMap<String, ShopifyProviderReceipt>,
}

#[derive(Clone, Debug)]
struct FakeShopifyFulfillmentProvider {
    state: Arc<Mutex<FakeState>>,
}

impl FakeShopifyFulfillmentProvider {
    fn new(state: Arc<Mutex<FakeState>>) -> Self {
        Self { state }
    }
}

impl ShopifyFulfillmentProvider for FakeShopifyFulfillmentProvider {
    fn probe_scope(
        &mut self,
        request: &ShopifyScopeProbeRequest,
    ) -> Result<ShopifyScopeProbe, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.probe_calls += 1;
        let mut granted_scopes = request.required_scopes.clone();
        if state.missing_write_scope {
            granted_scopes.remove(SHOPIFY_FULFILLMENT_WRITE_SCOPE);
        }
        let provider_generation = if state.wrong_generation {
            request.provider_generation + 1
        } else {
            request.provider_generation
        };
        Ok(ShopifyScopeProbe {
            status: ShopifyProbeStatus::Reachable,
            scope_digest: request.scope.digest(),
            shop: request.scope.shop().clone(),
            provider_digest: request.provider_digest.clone(),
            provider_generation,
            granted_scopes,
            observed_at: request.at,
            expires_at: request.at + Duration::seconds(30),
            evidence_digest: digest("shopify-probe-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        })
    }

    fn execute_draft_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
    ) -> Result<ShopifyProviderReceipt, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.execute_calls += 1;
        let receipt = ShopifyProviderReceipt {
            receipt_id: format!(
                "shopify-provider-receipt-{}",
                request.idempotency_key().as_str()
            ),
            provider_operation_id: format!(
                "shopify-provider-op-{}",
                request.idempotency_key().as_str()
            ),
            request_digest: request.request_digest().to_owned(),
            idempotency_key: request.idempotency_key().clone(),
            scope_digest: request.tenant_scope().digest(),
            shop: request.tenant_scope().shop().clone(),
            order_gid: request.order_gid().clone(),
            fulfillment_order_gid: request.fulfillment_order_gid().clone(),
            line_items: request.line_items().to_owned(),
            provider_generation: request.provider_generation(),
            approval_revision: request.approval_revision(),
            provider_digest: shopify_fulfillment_provider_digest(request.api_version()),
            observed_at: request.created_at(),
            evidence_digest: digest("shopify-provider-receipt-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        };
        state.operations.insert(
            request.idempotency_key().as_str().to_owned(),
            receipt.clone(),
        );
        if state.timeout_after_commit {
            state.timeout_after_commit = false;
            return Err(ShopifyFulfillmentProviderError::Timeout);
        }
        Ok(receipt)
    }

    fn readback_fulfillment(
        &mut self,
        request: &DraftFulfillmentRequest,
        lookup: &ShopifyReadbackLookup,
    ) -> Result<Option<ShopifyReadbackObservation>, ShopifyFulfillmentProviderError> {
        let mut state = self.state.lock().expect("fake provider state");
        state.readback_calls += 1;
        assert_eq!(lookup.idempotency_key, *request.idempotency_key());
        assert_eq!(lookup.request_digest, request.request_digest());
        let Some(provider_receipt) = state
            .operations
            .get(request.idempotency_key().as_str())
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(ShopifyReadbackObservation {
            provider_receipt,
            status: ShopifyReadbackStatus::Fulfilled,
            observed_at: request.created_at(),
            evidence_digest: digest("shopify-readback-evidence"),
            provenance_class: ProviderProvenanceClass::ControlledProvider,
        }))
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 3, 0, 0)
        .single()
        .expect("stable test time")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-1",
        "project-1",
        "shopify",
        "account-1",
        [
            SHOPIFY_FULFILLMENT_READ_SCOPE.to_owned(),
            SHOPIFY_FULFILLMENT_WRITE_SCOPE.to_owned(),
        ],
    )
    .expect("Shopify connector scope")
}

fn fulfillment_scope() -> ShopifyFulfillmentScope {
    ShopifyFulfillmentScope::new(
        scope(),
        ShopDomain::parse("demo.myshopify.com").expect("Shopify shop"),
    )
    .expect("Shopify fulfillment scope")
}

fn auth_binding(
    generation: u64,
) -> hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding {
    let scope = scope();
    let issued_at = now() - Duration::seconds(30);
    let secret = SecretReference::new(
        format!("secret-ref-shopify-{generation}"),
        scope,
        generation,
    )
    .expect("opaque secret reference");
    let adapter = shopify_fulfillment_adapter_identity().expect("Shopify effect adapter");
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        adapter.clone(),
        format!("lease-shopify-{generation}"),
        generation,
        issued_at,
        now() + Duration::seconds(300),
    )
    .expect("credential lease");
    let session = ConnectorAuth::begin_auth_session(
        &secret,
        &lease,
        format!("auth-session-shopify-{generation}"),
        generation,
        issued_at,
        now() + Duration::seconds(240),
    )
    .expect("auth session");
    hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding::new(
        secret, lease, session, adapter,
    )
    .expect("Shopify auth binding")
}

fn request(
    generation: u64,
    approval_revision: u64,
    idempotency_suffix: &str,
) -> DraftFulfillmentRequest {
    let line_item = ShopifyFulfillmentLineItem::new(
        ShopifyFulfillmentOrderLineItemGid::parse("gid://shopify/FulfillmentOrderLineItem/5001")
            .expect("line item GID"),
        2,
    )
    .expect("line item");
    DraftFulfillmentRequest::new(
        format!("shopify-draft-fulfillment-{idempotency_suffix}"),
        "mission-commerce-69",
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        ShopifyOrderGid::parse("gid://shopify/Order/1001").expect("order GID"),
        ShopifyFulfillmentOrderGid::parse("gid://shopify/FulfillmentOrder/2001")
            .expect("fulfillment order GID"),
        vec![line_item],
        generation,
        ShopifyApprovalRevision::new(approval_revision).expect("approval revision"),
        ShopifyEffectIdempotencyKey::parse(format!("shopify-effect-idem-{idempotency_suffix}"))
            .expect("idempotency key"),
        now() - Duration::seconds(30),
        now() + Duration::seconds(300),
    )
    .expect("draft fulfillment request")
}

fn service(
    state: Arc<Mutex<FakeState>>,
    generation: u64,
    provenance_class: ProviderProvenanceClass,
    auth: Option<hartevo_commerce_connector::shopify_effect::ShopifyFulfillmentAuthBinding>,
) -> ShopifyFulfillmentEffectService<FakeShopifyFulfillmentProvider> {
    ShopifyFulfillmentEffectService::new(
        FakeShopifyFulfillmentProvider::new(state),
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        provenance_class,
        ShopifyFulfillmentEffectStore::new(generation).expect("effect store"),
        auth,
    )
    .expect("Shopify effect service")
}

fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut output = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

#[test]
fn draft_binds_mission_shop_order_items_generation_approval_and_idempotency() {
    assert!(FULFILLMENT_CREATE_MUTATION.contains("fulfillmentCreate"));
    assert!(FULFILLMENT_READBACK_QUERY.contains("Fulfillment"));

    let draft = request(1, 7, "binding");
    let encoded = serde_json::to_value(&draft).expect("draft JSON");
    let decoded: DraftFulfillmentRequest = serde_json::from_value(encoded).expect("draft decode");
    assert_eq!(decoded, draft);
    assert_eq!(draft.mission_id(), "mission-commerce-69");
    assert_eq!(draft.tenant_scope().shop().as_str(), "demo.myshopify.com");
    assert_eq!(draft.provider_generation(), 1);
    assert_eq!(draft.approval_revision().value(), 7);
    assert_eq!(draft.line_items().len(), 1);
    assert_eq!(draft.request_digest().len(), 64);

    let json: Value = serde_json::to_value(&draft).expect("draft JSON");
    assert!(json.get("requestDigest").is_some());
    assert!(json.get("idempotencyKey").is_some());
}

#[test]
fn controlled_provider_probes_before_execute_and_returns_receipt_with_readback() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut service = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    let result = service
        .submit_draft_at(&request(1, 7, "success"), now())
        .expect("controlled fulfillment result");

    assert!(result.is_verified());
    assert!(!result.is_first_party());
    assert_eq!(
        result.live_validation_status,
        SHOPIFY_FULFILLMENT_LIVE_VALIDATION_STATUS
    );
    assert_eq!(result.provider_generation, 1);
    assert_eq!(result.approval_revision.value(), 7);
    assert!(!result.provider_receipt.receipt_id.is_empty());
    assert!(result.readback.verified);
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.probe_calls, 1);
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn timeout_after_commit_restarts_by_readback_without_a_second_execute() {
    let state = Arc::new(Mutex::new(FakeState {
        timeout_after_commit: true,
        ..FakeState::default()
    }));
    let draft = request(1, 7, "timeout");
    let mut first = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        first.submit_draft_at(&draft, now()),
        Err(ShopifyFulfillmentEffectError::ExecutionUncertain)
    );
    assert_eq!(
        first.store().records()[draft.idempotency_key().as_str()].state,
        ShopifyFulfillmentRecordState::Uncertain
    );
    let durable_store = serde_json::to_vec(first.store()).expect("durable effect checkpoint");
    let recovered_store: ShopifyFulfillmentEffectStore =
        serde_json::from_slice(&durable_store).expect("reopen effect checkpoint");

    let mut recovered = ShopifyFulfillmentEffectService::new(
        FakeShopifyFulfillmentProvider::new(state.clone()),
        fulfillment_scope(),
        ShopifyApiVersion::latest(),
        ProviderProvenanceClass::ControlledProvider,
        recovered_store,
        Some(auth_binding(1)),
    )
    .expect("recovered Shopify service");
    let result = recovered
        .submit_draft_at(&draft, now())
        .expect("readback after restart");
    assert!(result.replayed);
    assert!(result.is_verified());

    let state_snapshot = state.lock().expect("fake provider state");
    assert_eq!(state_snapshot.execute_calls, 1);
    assert_eq!(state_snapshot.probe_calls, 2);
    assert_eq!(state_snapshot.readback_calls, 1);
    drop(state_snapshot);

    let replay = recovered
        .submit_draft_at(&draft, now())
        .expect("durable verified replay");
    assert!(replay.replayed);
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.probe_calls, 2);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn idempotency_conflict_never_reuses_a_key_for_different_approval_revision() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut service = service(
        state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    service
        .submit_draft_at(&request(1, 7, "conflict"), now())
        .expect("initial fulfillment");
    assert_eq!(
        service.submit_draft_at(&request(1, 8, "conflict"), now()),
        Err(ShopifyFulfillmentEffectError::IdempotencyConflict)
    );
    let state = state.lock().expect("fake provider state");
    assert_eq!(state.execute_calls, 1);
    assert_eq!(state.readback_calls, 1);
}

#[test]
fn probe_scope_and_production_environment_fail_closed_before_execute() {
    let missing_scope_state = Arc::new(Mutex::new(FakeState {
        missing_write_scope: true,
        ..FakeState::default()
    }));
    let mut missing_scope = service(
        missing_scope_state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        missing_scope.submit_draft_at(&request(1, 7, "missing-scope"), now()),
        Err(ShopifyFulfillmentEffectError::ProbeMissingScope)
    );
    let missing_scope_state = missing_scope_state.lock().expect("fake provider state");
    assert_eq!(missing_scope_state.execute_calls, 0);

    let production_state = Arc::new(Mutex::new(FakeState::default()));
    let mut production = service(
        production_state.clone(),
        1,
        ProviderProvenanceClass::ProductionProvider,
        Some(auth_binding(1)),
    );
    assert_eq!(
        production.submit_draft_at(&request(1, 7, "blocked-env"), now()),
        Err(ShopifyFulfillmentEffectError::BlockedEnv)
    );
    let production_state = production_state.lock().expect("fake provider state");
    assert_eq!(production_state.probe_calls, 0);
    assert_eq!(production_state.execute_calls, 0);

    let no_auth_state = Arc::new(Mutex::new(FakeState::default()));
    let mut no_auth = service(
        no_auth_state.clone(),
        1,
        ProviderProvenanceClass::ControlledProvider,
        None,
    );
    assert_eq!(
        no_auth.submit_draft_at(&request(1, 7, "no-auth"), now()),
        Err(ShopifyFulfillmentEffectError::BlockedEnv)
    );
}

#[test]
fn rotation_revoke_and_unmount_invalidate_old_generation_and_durable_records() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut effect_service = service(
        state,
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    effect_service
        .submit_draft_at(&request(1, 7, "lifecycle"), now())
        .expect("initial fulfillment");
    assert_eq!(effect_service.store().records().len(), 1);

    effect_service
        .rotate_auth(auth_binding(2))
        .expect("credential rotation");
    assert!(effect_service.store().records().is_empty());
    assert_eq!(
        effect_service.submit_draft_at(&request(1, 7, "lifecycle"), now()),
        Err(ShopifyFulfillmentEffectError::GenerationMismatch)
    );

    effect_service
        .submit_draft_at(&request(2, 8, "lifecycle-new-generation"), now())
        .expect("new generation fulfillment");
    let revoked = effect_service.revoke(now());
    assert_eq!(revoked.lifecycle, ShopifyEffectLifecycle::Revoked);
    assert!(effect_service.store().records().is_empty());
    assert_eq!(
        effect_service.submit_draft_at(&request(2, 8, "after-revoke"), now()),
        Err(ShopifyFulfillmentEffectError::ConsumerNotMounted)
    );

    let state = Arc::new(Mutex::new(FakeState::default()));
    let mut unmounted = service(
        state,
        1,
        ProviderProvenanceClass::ControlledProvider,
        Some(auth_binding(1)),
    );
    let unmounted_receipt = unmounted.unmount(now());
    assert_eq!(
        unmounted_receipt.lifecycle,
        ShopifyEffectLifecycle::Unmounted
    );
    assert_eq!(
        unmounted.submit_draft_at(&request(1, 7, "after-unmount"), now()),
        Err(ShopifyFulfillmentEffectError::ConsumerNotMounted)
    );
}
