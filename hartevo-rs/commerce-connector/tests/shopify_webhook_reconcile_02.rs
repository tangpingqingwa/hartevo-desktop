use std::collections::{BTreeMap, VecDeque};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::shopify::{
    ConnectorAuth, ConnectorScope, ProviderProvenanceClass, SecretReference, ShopDomain,
    ShopifyAdminTransport, ShopifyApiVersion, ShopifyAuthBinding, ShopifyCursorStore,
    ShopifyCursorStream, ShopifyError, ShopifyGraphqlRequest, ShopifyGraphqlResponse,
    ShopifyReconciliationSource, ShopifyReconciliationStatus, ShopifyTenantScope,
    ShopifyTransportError, ShopifyWebhookCheckpoint, ShopifyWebhookCommitOutcome,
    ShopifyWebhookHeaders, shopify_cursor_adapter_identity,
    verify_cursor_webhook_delivery_for_generation,
};
use ring::hmac;
use serde_json::json;

#[derive(Debug)]
struct FakeShopifyTransport {
    responses: VecDeque<ShopifyGraphqlResponse>,
}

impl FakeShopifyTransport {
    fn new(responses: impl IntoIterator<Item = ShopifyGraphqlResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
        }
    }
}

impl ShopifyAdminTransport for FakeShopifyTransport {
    fn execute(
        &mut self,
        _request: ShopifyGraphqlRequest,
    ) -> Result<ShopifyGraphqlResponse, ShopifyTransportError> {
        self.responses
            .pop_front()
            .ok_or_else(|| ShopifyTransportError::Failed("fixture response exhausted".into()))
    }
}

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 1, 0, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-shopify-reconcile-2",
        "project-commerce-reconcile-2",
        "shopify",
        "shop-account-reconcile-2",
        vec!["read_orders".into(), "read_products".into()],
    )
    .expect("connector scope")
}

fn tenant_scope() -> ShopifyTenantScope {
    ShopifyTenantScope::new(
        scope(),
        ShopDomain::parse("reconcile-shop.myshopify.com").expect("shop domain"),
    )
    .expect("tenant scope")
}

fn auth_binding(revision: u64) -> ShopifyAuthBinding {
    let scope = scope();
    let secret = SecretReference::new("secret-ref-shopify-reconcile-test", scope.clone(), revision)
        .expect("secret reference");
    let adapter = shopify_cursor_adapter_identity().expect("cursor adapter");
    let issued_at = at();
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        adapter,
        format!("credential-lease-shopify-reconcile-{revision}"),
        revision,
        issued_at,
        issued_at + Duration::minutes(5),
    )
    .expect("credential lease");
    let session = ConnectorAuth::begin_auth_session(
        &secret,
        &lease,
        format!("auth-session-shopify-reconcile-{revision}"),
        revision,
        issued_at,
        issued_at + Duration::minutes(5),
    )
    .expect("auth session");
    ShopifyAuthBinding::new(secret, lease, session).expect("Shopify auth binding")
}

fn consumer(
    transport: FakeShopifyTransport,
    store: ShopifyCursorStore,
    revision: u64,
) -> hartevo_commerce_connector::shopify::ShopifyDurableCursorConsumer<FakeShopifyTransport> {
    hartevo_commerce_connector::shopify::ShopifyDurableCursorConsumer::new(
        transport,
        tenant_scope(),
        ShopifyApiVersion::parse("2026-07").expect("API version"),
        auth_binding(revision),
        ProviderProvenanceClass::ControlledProvider,
        store,
    )
    .expect("cursor consumer")
}

fn order_page(
    id: &str,
    updated_at: &str,
    has_next_page: bool,
    end_cursor: Option<&str>,
) -> ShopifyGraphqlResponse {
    ShopifyGraphqlResponse {
        status: 200,
        body: json!({
            "data": {
                "orders": {
                    "edges": [{
                        "cursor": end_cursor.unwrap_or("fixture-order-edge"),
                        "node": {"id": id, "updatedAt": updated_at}
                    }],
                    "pageInfo": {"hasNextPage": has_next_page, "endCursor": end_cursor}
                }
            },
            "extensions": {
                "cost": {
                    "requestedQueryCost": 10,
                    "actualQueryCost": 8,
                    "throttleStatus": {
                        "maximumAvailable": 1000,
                        "currentlyAvailable": 992,
                        "restoreRate": 50.0
                    }
                }
            }
        }),
        headers: BTreeMap::new(),
    }
}

fn webhook(
    sequence: u64,
    delivery_id: &str,
    generation: u64,
    order_id: &str,
    updated_at: &str,
) -> ShopifyWebhookCheckpoint {
    let raw_body = format!(
        r#"{{"admin_graphql_api_id":"gid://shopify/Order/{order_id}","updated_at":"{updated_at}"}}"#
    );
    let client_secret = b"fixture-shopify-reconcile-secret";
    let key = hmac::Key::new(hmac::HMAC_SHA256, client_secret);
    let signature = BASE64.encode(hmac::sign(&key, raw_body.as_bytes()).as_ref());
    let headers = ShopifyWebhookHeaders::new(
        signature,
        delivery_id,
        "orders/updated",
        ShopDomain::parse("reconcile-shop.myshopify.com").expect("shop domain"),
        ShopifyApiVersion::parse("2026-07").expect("API version"),
    )
    .expect("webhook headers");
    verify_cursor_webhook_delivery_for_generation(
        raw_body.as_bytes(),
        headers,
        client_secret,
        &tenant_scope(),
        ShopifyCursorStream::Orders,
        "mission-reconcile-orders",
        sequence,
        Some(format!("event-reconcile-{sequence}")),
        at(),
        at() + Duration::seconds(1),
        generation,
    )
    .expect("verified webhook")
}

#[test]
fn sequence_gap_triggers_bounded_poll_and_exact_receipt_is_idempotent() {
    let target_updated_at = "2026-08-14T01:00:00Z";
    let mut consumer = consumer(
        FakeShopifyTransport::new([order_page(
            "gid://shopify/Order/42",
            target_updated_at,
            false,
            None,
        )]),
        ShopifyCursorStore::new(),
        1,
    );
    let delivery = webhook(2, "delivery-reconcile-2", 1, "42", target_updated_at);
    let receipt = consumer
        .reconcile_webhook_delivery(delivery.clone(), 2, at())
        .expect("bounded gap fill");
    assert_eq!(receipt.source, ShopifyReconciliationSource::GapFill);
    assert_eq!(receipt.status, ShopifyReconciliationStatus::Exact);
    assert!(receipt.is_exact());
    assert_eq!(receipt.poll_pages, 1);
    assert_eq!(
        receipt
            .gap
            .as_ref()
            .expect("sequence gap")
            .first_missing_sequence,
        1
    );
    assert_eq!(receipt.generation, 1);
    assert!(!receipt.is_first_party());
    assert_eq!(consumer.store().checkpoints()[0].page_sequence(), 1);
    assert_eq!(
        consumer.store().checkpoints()[0]
            .webhook_checkpoints()
            .len(),
        1
    );

    let duplicate = consumer
        .reconcile_webhook_delivery(delivery, 2, at())
        .expect("duplicate delivery");
    assert_eq!(duplicate.source, ShopifyReconciliationSource::Webhook);
    assert_eq!(duplicate.status, ShopifyReconciliationStatus::Duplicate);
    assert_eq!(
        duplicate.duplicate_of.as_deref(),
        Some(receipt.receipt_id.as_str())
    );
    assert_eq!(
        consumer.store().checkpoints()[0]
            .reconciliation_receipts()
            .iter()
            .filter(|candidate| candidate.status == ShopifyReconciliationStatus::Exact)
            .count(),
        1
    );
}

#[test]
fn out_of_order_late_and_duplicate_deliveries_have_no_duplicate_checkpoint() {
    let mut consumer = consumer(
        FakeShopifyTransport::new([order_page(
            "gid://shopify/Order/99",
            "2026-08-14T01:00:00Z",
            true,
            Some("cursor-after-seed"),
        )]),
        ShopifyCursorStore::new(),
        1,
    );
    consumer
        .read_next(
            "mission-reconcile-orders",
            ShopifyCursorStream::Orders,
            2,
            at(),
        )
        .expect("seed cursor");

    let second = webhook(2, "delivery-reconcile-2", 1, "42", "2026-08-14T01:00:00Z");
    let first = webhook(1, "delivery-reconcile-1", 1, "41", "2026-08-14T00:59:00Z");
    assert_eq!(
        consumer.ingest_webhook(second.clone()),
        Ok(ShopifyWebhookCommitOutcome::Committed)
    );
    assert_eq!(
        consumer.ingest_webhook(first.clone()),
        Ok(ShopifyWebhookCommitOutcome::Committed)
    );
    assert_eq!(
        consumer.ingest_webhook(first),
        Ok(ShopifyWebhookCommitOutcome::AlreadyCommitted)
    );
    let checkpoint = consumer
        .store()
        .checkpoint("mission-reconcile-orders", ShopifyCursorStream::Orders)
        .expect("checkpoint");
    assert_eq!(
        checkpoint
            .webhook_checkpoints()
            .iter()
            .map(|delivery| delivery.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(checkpoint.webhook_checkpoints()[0].generation, 1);
    assert_eq!(
        checkpoint.webhook_checkpoints()[0]
            .poll_cursor_binding
            .page_sequence,
        0
    );
}

#[test]
fn bounded_gap_poll_resumes_after_store_crash_and_reopen() {
    let gap_delivery = webhook(2, "delivery-reconcile-gap", 1, "42", "2026-08-14T01:00:00Z");
    let mut first_run = consumer(
        FakeShopifyTransport::new([
            order_page(
                "gid://shopify/Order/10",
                "2026-08-14T00:10:00Z",
                true,
                Some("c1"),
            ),
            order_page(
                "gid://shopify/Order/11",
                "2026-08-14T00:20:00Z",
                true,
                Some("c2"),
            ),
            order_page(
                "gid://shopify/Order/12",
                "2026-08-14T00:30:00Z",
                true,
                Some("c3"),
            ),
        ]),
        ShopifyCursorStore::new(),
        1,
    );
    let pending = first_run
        .reconcile_webhook_delivery(gap_delivery.clone(), 2, at())
        .expect("bounded gap poll");
    assert_eq!(pending.status, ShopifyReconciliationStatus::GapPending);
    assert_eq!(pending.poll_pages, 3);
    assert_eq!(
        first_run
            .store()
            .checkpoint("mission-reconcile-orders", ShopifyCursorStream::Orders)
            .expect("checkpoint")
            .page_sequence(),
        3
    );

    let reopened_store: ShopifyCursorStore =
        serde_json::from_str(&serde_json::to_string(first_run.store()).expect("store JSON"))
            .expect("reopened store");
    let mut reopened = consumer(
        FakeShopifyTransport::new([order_page(
            "gid://shopify/Order/42",
            "2026-08-14T01:00:00Z",
            false,
            None,
        )]),
        reopened_store,
        1,
    );
    let exact = reopened
        .reconcile_webhook_delivery(gap_delivery, 2, at() + Duration::minutes(1))
        .expect("resume gap poll");
    assert_eq!(exact.status, ShopifyReconciliationStatus::Exact);
    assert_eq!(exact.source, ShopifyReconciliationSource::GapFill);
    assert_eq!(exact.poll_pages, 1);
    assert_eq!(
        reopened
            .store()
            .checkpoint("mission-reconcile-orders", ShopifyCursorStream::Orders)
            .expect("checkpoint")
            .page_sequence(),
        4
    );
}

#[test]
fn rotation_invalidates_old_generation_webhooks_and_poll_results() {
    let page = order_page(
        "gid://shopify/Order/99",
        "2026-08-14T01:00:00Z",
        true,
        Some("cursor-after-rotation"),
    );
    let mut consumer = consumer(
        FakeShopifyTransport::new([page.clone(), page]),
        ShopifyCursorStore::new(),
        1,
    );
    let old_envelope = consumer
        .read_next(
            "mission-reconcile-orders",
            ShopifyCursorStream::Orders,
            2,
            at(),
        )
        .expect("old generation poll");
    let old_webhook = webhook(
        1,
        "delivery-old-generation",
        1,
        "42",
        "2026-08-14T01:00:00Z",
    );
    assert_eq!(
        consumer.ingest_webhook(old_webhook.clone()),
        Ok(ShopifyWebhookCommitOutcome::Committed)
    );
    consumer
        .rotate_auth(auth_binding(2))
        .expect("rotate generation");
    assert!(matches!(
        consumer.ingest_webhook(old_webhook),
        Err(ShopifyError::WebhookGenerationMismatch)
    ));
    assert!(matches!(
        consumer.commit(&old_envelope),
        Err(ShopifyError::CheckpointConflict | ShopifyError::CheckpointGenerationMismatch)
    ));
    let new_envelope = consumer
        .read_next(
            "mission-reconcile-orders",
            ShopifyCursorStream::Orders,
            2,
            at(),
        )
        .expect("new generation poll");
    assert_eq!(new_envelope.generation, 2);
    assert_ne!(new_envelope.result_id, old_envelope.result_id);
    assert!(
        consumer
            .store()
            .checkpoint("mission-reconcile-orders", ShopifyCursorStream::Orders)
            .expect("checkpoint")
            .webhook_checkpoints()
            .is_empty()
    );
}

#[test]
fn receipt_is_typed_and_serializable_without_first_party_claim() {
    let mut consumer = consumer(
        FakeShopifyTransport::new([order_page(
            "gid://shopify/Order/42",
            "2026-08-14T01:00:00Z",
            false,
            None,
        )]),
        ShopifyCursorStore::new(),
        1,
    );
    let receipt = consumer
        .reconcile_webhook_delivery(
            webhook(2, "delivery-typed-receipt", 1, "42", "2026-08-14T01:00:00Z"),
            2,
            at(),
        )
        .expect("typed receipt");
    let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
    let decoded: hartevo_commerce_connector::shopify::ShopifyReconciliationReceipt =
        serde_json::from_str(&encoded).expect("receipt round trip");
    assert_eq!(decoded, receipt);
    assert!(!decoded.is_first_party());
    assert_eq!(decoded.live_validation_status, "BLOCKED_ENV");
    assert_eq!(decoded.poll_cursor_binding.generation, 1);
}
