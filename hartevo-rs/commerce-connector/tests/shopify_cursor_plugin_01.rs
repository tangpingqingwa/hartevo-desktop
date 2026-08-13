use std::collections::{BTreeMap, VecDeque};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::shopify::{
    AuthSession, ConnectorAuth, ConnectorScope, CredentialLease, ProviderProvenanceClass,
    SecretReference, ShopDomain, ShopifyAdminTransport, ShopifyApiVersion, ShopifyAuthBinding,
    ShopifyCommitOutcome, ShopifyCursorCheckpoint, ShopifyCursorStore, ShopifyCursorStoreLifecycle,
    ShopifyCursorStream, ShopifyError, ShopifyGraphqlRequest, ShopifyGraphqlResponse,
    ShopifyPollReconcile, ShopifyTenantScope, ShopifyTransportError, ShopifyTypedItems,
    ShopifyUnmountReceipt, ShopifyWebhookCheckpoint, ShopifyWebhookCommitOutcome,
    ShopifyWebhookHeaders, shopify_cursor_adapter_identity, verify_cursor_webhook_delivery,
};
use hartevo_connector_sdk::ProviderAdapterIdentity;
use hartevo_connector_sdk::ProviderCapabilityKey;
use ring::hmac;
use serde_json::{Value, json};

#[derive(Debug)]
struct FakeShopifyTransport {
    responses: VecDeque<ShopifyGraphqlResponse>,
    requests: Vec<ShopifyGraphqlRequest>,
}

impl FakeShopifyTransport {
    fn new(responses: impl IntoIterator<Item = ShopifyGraphqlResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl ShopifyAdminTransport for FakeShopifyTransport {
    fn execute(
        &mut self,
        request: ShopifyGraphqlRequest,
    ) -> Result<ShopifyGraphqlResponse, ShopifyTransportError> {
        self.requests.push(request);
        self.responses
            .pop_front()
            .ok_or_else(|| ShopifyTransportError::Failed("fixture response exhausted".into()))
    }
}

fn at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 0, 0, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope() -> ConnectorScope {
    ConnectorScope::new(
        "tenant-shopify-1",
        "project-commerce-1",
        "shopify",
        "shop-account-1",
        vec!["read_orders".into(), "read_products".into()],
    )
    .expect("connector scope")
}

fn tenant_scope() -> ShopifyTenantScope {
    ShopifyTenantScope::new(
        scope(),
        ShopDomain::parse("demo-shop.myshopify.com").expect("shop domain"),
    )
    .expect("tenant scope")
}

fn auth_binding(revision: u64) -> ShopifyAuthBinding {
    let scope = scope();
    let secret = SecretReference::new("secret-ref-shopify-cursor-test", scope.clone(), revision)
        .expect("secret reference");
    let adapter = shopify_cursor_adapter_identity().expect("cursor adapter");
    let issued_at = at();
    let lease = ConnectorAuth::issue_credential_lease(
        &secret,
        adapter,
        format!("credential-lease-shopify-{revision}"),
        revision,
        issued_at,
        issued_at + Duration::minutes(5),
    )
    .expect("credential lease");
    let session = ConnectorAuth::begin_auth_session(
        &secret,
        &lease,
        format!("auth-session-shopify-{revision}"),
        revision,
        issued_at,
        issued_at + Duration::minutes(5),
    )
    .expect("auth session");
    ShopifyAuthBinding::new(secret, lease, session).expect("Shopify auth binding")
}

fn graphql_response(data: impl Into<Value>) -> ShopifyGraphqlResponse {
    let data = data.into();
    ShopifyGraphqlResponse {
        status: 200,
        body: json!({
            "data": data,
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

fn product_page(
    id: &str,
    updated_at: &str,
    has_next_page: bool,
    end_cursor: Option<&str>,
) -> ShopifyGraphqlResponse {
    graphql_response(json!({
        "products": {
            "edges": [{
                "cursor": end_cursor.unwrap_or("cursor-product-1"),
                "node": {
                    "id": id,
                    "title": "Fixture product",
                    "updatedAt": updated_at,
                    "variants": {
                        "nodes": [{"id": "gid://shopify/ProductVariant/1", "sku": "SKU-1"}],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }
                }
            }],
            "pageInfo": {"hasNextPage": has_next_page, "endCursor": end_cursor}
        }
    }))
}

fn order_page(id: &str, updated_at: &str) -> ShopifyGraphqlResponse {
    graphql_response(json!({
        "orders": {
            "edges": [{
                "cursor": "cursor-order-1",
                "node": {"id": id, "updatedAt": updated_at}
            }],
            "pageInfo": {"hasNextPage": false, "endCursor": null}
        }
    }))
}

fn consumer(
    transport: FakeShopifyTransport,
    provenance: ProviderProvenanceClass,
    store: ShopifyCursorStore,
) -> hartevo_commerce_connector::shopify::ShopifyDurableCursorConsumer<FakeShopifyTransport> {
    hartevo_commerce_connector::shopify::ShopifyDurableCursorConsumer::new(
        transport,
        tenant_scope(),
        ShopifyApiVersion::parse("2026-07").expect("API version"),
        auth_binding(1),
        provenance,
        store,
    )
    .expect("cursor consumer")
}

fn webhook_for_order(updated_at: &str, delivery_id: &str) -> ShopifyWebhookCheckpoint {
    let raw_body = format!(
        r#"{{"admin_graphql_api_id":"gid://shopify/Order/42","updated_at":"{updated_at}"}}"#
    );
    let client_secret = b"fixture-shopify-client-secret";
    let key = hmac::Key::new(hmac::HMAC_SHA256, client_secret);
    let signature = BASE64.encode(hmac::sign(&key, raw_body.as_bytes()).as_ref());
    let headers = ShopifyWebhookHeaders::new(
        signature,
        delivery_id,
        "orders/updated",
        ShopDomain::parse("demo-shop.myshopify.com").expect("shop domain"),
        ShopifyApiVersion::parse("2026-07").expect("API version"),
    )
    .expect("webhook headers");
    verify_cursor_webhook_delivery(
        raw_body.as_bytes(),
        headers,
        client_secret,
        &tenant_scope(),
        ShopifyCursorStream::Orders,
        "mission-orders",
        1,
        Some("event-orders-1".into()),
        at(),
        at() + Duration::seconds(1),
    )
    .expect("verified webhook checkpoint")
}

#[test]
fn crash_reopen_commits_the_same_page_once() {
    let first_page = product_page(
        "gid://shopify/Product/1",
        "2026-08-14T00:00:00Z",
        true,
        Some("cursor-product-1"),
    );
    let second_page = product_page(
        "gid://shopify/Product/2",
        "2026-08-14T00:01:00Z",
        false,
        None,
    );
    let mut original = consumer(
        FakeShopifyTransport::new([first_page.clone()]),
        ProviderProvenanceClass::ControlledProvider,
        ShopifyCursorStore::new(),
    );
    let first = original
        .read_next("mission-products", ShopifyCursorStream::Products, 2, at())
        .expect("first page");
    assert_eq!(first.page_sequence, 1);
    assert_eq!(first.quota_cost.actual_query_cost, 8);
    assert_eq!(first.live_validation_status, "BLOCKED_ENV");
    assert!(!first.is_first_party());
    assert!(matches!(first.typed_items, ShopifyTypedItems::Products(_)));
    assert!(first.sdk_next_cursor().expect("SDK cursor").is_some());

    let reopened_store: ShopifyCursorStore =
        serde_json::from_str(&serde_json::to_string(original.store()).expect("store JSON"))
            .expect("reopened cursor store");
    let mut reopened = consumer(
        FakeShopifyTransport::new([first_page, second_page]),
        ProviderProvenanceClass::ControlledProvider,
        reopened_store,
    );
    let reopened_first = reopened
        .read_next("mission-products", ShopifyCursorStream::Products, 2, at())
        .expect("reopened first page");
    assert_eq!(reopened_first.result_id, first.result_id);
    assert_eq!(
        reopened.commit(&reopened_first),
        Ok(ShopifyCommitOutcome::Committed)
    );
    assert_eq!(
        reopened.commit(&reopened_first),
        Ok(ShopifyCommitOutcome::AlreadyCommitted)
    );

    let second = reopened
        .read_next("mission-products", ShopifyCursorStream::Products, 2, at())
        .expect("second page");
    assert_eq!(second.page_sequence, 2);
    assert_eq!(
        reopened.commit(&second),
        Ok(ShopifyCommitOutcome::Committed)
    );
    assert!(
        reopened
            .store()
            .checkpoint("mission-products", ShopifyCursorStream::Products)
            .expect("checkpoint")
            .is_complete()
    );
}

#[test]
fn webhook_and_poll_reconcile_exactly_without_losing_webhook_state() {
    let mut consumer = consumer(
        FakeShopifyTransport::new([order_page("gid://shopify/Order/42", "2026-08-14T00:00:00Z")]),
        ProviderProvenanceClass::ControlledProvider,
        ShopifyCursorStore::new(),
    );
    let envelope = consumer
        .read_next("mission-orders", ShopifyCursorStream::Orders, 2, at())
        .expect("orders page");
    let webhook = webhook_for_order("2026-08-14T00:00:00Z", "delivery-orders-1");
    assert_eq!(
        consumer.ingest_webhook(webhook.clone()),
        Ok(ShopifyWebhookCommitOutcome::Committed)
    );
    assert_eq!(
        consumer.reconcile_webhook(&envelope, &webhook),
        Ok(ShopifyPollReconcile::Exact {
            delivery_id: "delivery-orders-1".into(),
            resource_id: "gid://shopify/Order/42".into(),
        })
    );
    assert_eq!(
        consumer.commit(&envelope),
        Ok(ShopifyCommitOutcome::Committed)
    );
    assert_eq!(
        consumer.ingest_webhook(webhook),
        Ok(ShopifyWebhookCommitOutcome::AlreadyCommitted)
    );

    let mismatch = webhook_for_order("2026-08-14T00:01:00Z", "delivery-orders-2");
    assert_eq!(
        envelope.reconcile_webhook(&mismatch),
        Ok(ShopifyPollReconcile::NotObserved)
    );
}

#[test]
fn rotation_revoke_and_unmount_reclaim_cursor_state() {
    let mut revoked_consumer = consumer(
        FakeShopifyTransport::new([product_page(
            "gid://shopify/Product/1",
            "2026-08-14T00:00:00Z",
            true,
            Some("cursor-product-1"),
        )]),
        ProviderProvenanceClass::ControlledProvider,
        ShopifyCursorStore::new(),
    );
    revoked_consumer
        .read_next("mission-products", ShopifyCursorStream::Products, 2, at())
        .expect("cursor page");
    revoked_consumer
        .rotate_auth(auth_binding(2))
        .expect("monotonic credential rotation");
    assert_eq!(
        revoked_consumer
            .auth()
            .expect("rotated auth")
            .secret_reference()
            .credential_revision(),
        2
    );

    let revoked = revoked_consumer.revoke();
    assert_eq!(
        revoked,
        ShopifyUnmountReceipt {
            cleared_checkpoints: 1,
            lifecycle: ShopifyCursorStoreLifecycle::Revoked,
        }
    );
    assert!(revoked_consumer.store().checkpoints().is_empty());
    assert!(matches!(
        revoked_consumer.read_next("mission-products", ShopifyCursorStream::Products, 2, at()),
        Err(ShopifyError::AuthenticationUnavailable)
    ));

    let mut fresh = consumer(
        FakeShopifyTransport::new([product_page(
            "gid://shopify/Product/1",
            "2026-08-14T00:00:00Z",
            false,
            None,
        )]),
        ProviderProvenanceClass::ControlledProvider,
        ShopifyCursorStore::new(),
    );
    fresh
        .read_next("mission-products", ShopifyCursorStream::Products, 2, at())
        .expect("fresh cursor page");
    let unmounted = fresh.unmount();
    assert_eq!(unmounted.cleared_checkpoints, 1);
    assert_eq!(unmounted.lifecycle, ShopifyCursorStoreLifecycle::Unmounted);
    assert!(fresh.store().checkpoints().is_empty());
}

#[test]
fn production_provenance_is_blocked_before_transport_execution() {
    let mut consumer = consumer(
        FakeShopifyTransport::new([]),
        ProviderProvenanceClass::ProductionProvider,
        ShopifyCursorStore::new(),
    );
    assert!(matches!(
        consumer.read_next("mission-products", ShopifyCursorStream::Products, 2, at()),
        Err(ShopifyError::BlockedEnv)
    ));
}

#[test]
fn scope_and_sdk_wiring_are_provider_specific() {
    let tenant = tenant_scope();
    assert_eq!(tenant.tenant_id(), "tenant-shopify-1");
    assert_eq!(tenant.shop().as_str(), "demo-shop.myshopify.com");
    assert_eq!(
        shopify_cursor_adapter_identity()
            .expect("adapter")
            .adapter_id(),
        "commerce.shopify.cursor.readonly"
    );
    let capability =
        hartevo_commerce_connector::shopify::shopify_cursor_capability(ShopifyCursorStream::Orders)
            .expect("capability");
    assert_eq!(capability.provider_id(), "shopify");
    assert_eq!(
        capability.capability_id(),
        "commerce.orders.incremental_read"
    );
    let checkpoint = ShopifyCursorCheckpoint::new(
        "mission-products",
        &tenant,
        ShopifyApiVersion::parse("2026-07").expect("API version"),
        ShopifyCursorStream::Products,
        2,
    )
    .expect("checkpoint");
    assert_eq!(checkpoint.page_sequence(), 0);
    assert!(
        checkpoint
            .sdk_cursor(tenant.scope())
            .expect("SDK cursor")
            .is_none()
    );
}

#[allow(dead_code)]
fn _sdk_types_are_referenced(
    _identity: ProviderAdapterIdentity,
    _capability: ProviderCapabilityKey,
    _session: AuthSession,
    _lease: CredentialLease,
    _secret: SecretReference,
) {
}
