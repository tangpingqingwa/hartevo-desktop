use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use hartevo_commerce_connector::shopify::{
    BULK_OPERATION_QUERY, SHOP_IDENTITY_QUERY, SHOPIFY_LATEST_API_VERSION,
    SHOPIFY_LIVE_VALIDATION_STATUS, SHOPIFY_READ_EVIDENCE_LEVEL, ShopDomain, ShopifyApiVersion,
    ShopifyAuthState, ShopifyAuthStatus, ShopifyBlockedEnvReason, ShopifyCredentialReference,
    ShopifyError, ShopifyGraphqlRequest, ShopifyGraphqlResponse,
};
use serde_json::json;

fn fixture_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 13, 0, 0, 0)
        .single()
        .expect("fixture time")
}

fn identity_request() -> ShopifyGraphqlRequest {
    ShopifyGraphqlRequest::new(
        ShopDomain::parse("demo.myshopify.com").expect("shop"),
        ShopifyApiVersion::latest(),
        "ShopifyShopIdentity",
        SHOP_IDENTITY_QUERY,
        json!({}),
    )
    .expect("request")
}

#[test]
fn auth_state_is_disconnected_or_blocked_without_claiming_connected_access() {
    let observed_at = fixture_time();
    let disconnected = ShopifyAuthState::disconnected(observed_at);
    assert_eq!(disconnected.status(), ShopifyAuthStatus::Disconnected);
    assert!(!disconnected.can_issue_live_read());
    assert!(!disconnected.grants_connected_authority());

    let blocked = ShopifyAuthState::no_credentials(observed_at);
    assert_eq!(blocked.status(), ShopifyAuthStatus::BlockedEnv);
    assert!(matches!(
        blocked,
        ShopifyAuthState::BlockedEnv {
            reason: ShopifyBlockedEnvReason::CredentialsUnavailable,
            ..
        }
    ));
    assert_eq!(SHOPIFY_LIVE_VALIDATION_STATUS, "BLOCKED_ENV");

    let credential = ShopifyCredentialReference::parse("keychain://shopify/commerce04")
        .expect("opaque reference");
    let reference_only = ShopifyAuthState::credential_reference_only(observed_at, credential);
    assert_eq!(
        reference_only.status(),
        ShopifyAuthStatus::CredentialReferenceOnly
    );
    assert_eq!(
        reference_only.credential().expect("reference").as_str(),
        "keychain://shopify/commerce04"
    );
    assert!(!reference_only.can_issue_live_read());
    assert!(!reference_only.grants_connected_authority());
}

#[test]
fn graphql_response_provenance_binds_shop_operation_and_body_digest() {
    let request = identity_request();
    let response = ShopifyGraphqlResponse {
        status: 200,
        body: json!({"data":{"shop":{"id":"gid://shopify/Shop/123"}}}),
        headers: BTreeMap::from([(String::from("x-request-id"), String::from("request-04"))]),
    };
    let provenance = response
        .first_party_provenance(&request, fixture_time())
        .expect("provenance");
    assert_eq!(provenance.provider_id, "shopify");
    assert_eq!(provenance.evidence_level, SHOPIFY_READ_EVIDENCE_LEVEL);
    assert_eq!(provenance.shop.as_str(), "demo.myshopify.com");
    assert_eq!(provenance.api_version.as_str(), SHOPIFY_LATEST_API_VERSION);
    assert_eq!(provenance.operation_name, "ShopifyShopIdentity");
    assert_eq!(provenance.request_id.as_deref(), Some("request-04"));
    assert_eq!(provenance.response_digest.len(), 64);
    assert!(!provenance.grants_connected_authority());

    let mut tampered = provenance;
    tampered.provider_id = "sorftime".into();
    assert_eq!(
        tampered.validate(),
        Err(ShopifyError::InvalidReadProvenance)
    );
}

#[test]
fn bulk_poll_uses_current_async_read_query() {
    assert!(BULK_OPERATION_QUERY.contains("bulkOperation(id: $id)"));
    assert!(!BULK_OPERATION_QUERY.contains("node(id: $id)"));
}
