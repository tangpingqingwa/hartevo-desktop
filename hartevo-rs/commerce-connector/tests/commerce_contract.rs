use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{TimeZone, Utc};
use hartevo_commerce_connector::amazon::{
    AmazonAccountIdentity, AmazonAccountScope, AmazonLwaTransport, AmazonMarketplace,
    AmazonNotificationLifecycle, AmazonNotificationLifecycleState, AmazonOperation, AmazonRegion,
    AmazonReport, AmazonReportLifecycle, AmazonReportLifecycleState, AmazonReportStatus,
    AmazonRole, AmazonSpApiRequest, AmazonSpApiResponse, AmazonTransportError,
    LwaAccessTokenObservation, LwaCredentialReference, LwaRefreshRequest, list_reports_request,
    parse_reports_page, refresh_lwa,
};
use hartevo_commerce_connector::shopify::{
    PRODUCTS_PAGE_QUERY, SHOP_IDENTITY_QUERY, ShopDomain, ShopifyAdminTransport, ShopifyApiVersion,
    ShopifyBulkStatus, ShopifyGraphqlRequest, ShopifyGraphqlResponse, ShopifyScopeSet,
    ShopifyTransportError, poll_bulk_operation, read_products_paginated, read_shop_identity,
    start_bulk_product_read, verify_webhook_delivery,
};
use hartevo_commerce_connector::sorftime::{
    SORFTIME_API_HOST, SorftimeAccountId, SorftimeApiRequest, SorftimeCliRequest, SorftimeDataset,
    SorftimeMarket, SorftimeResponse, SorftimeTransport, SorftimeTransportError,
    SorftimeTransportKind, query_estimate_api, query_estimate_cli,
};
use hartevo_commerce_connector::world::{MarketplaceWorldError, marketplace_world};
use hartevo_commerce_connector::{Asin, CanonicalSku, MarketId, ReadOnlyAuthority};
use hartevo_domain_kernel::CurrencyCode;
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

#[derive(Debug)]
struct FakeLwaTransport {
    requests: Vec<LwaRefreshRequest>,
}

impl AmazonLwaTransport for FakeLwaTransport {
    fn refresh(
        &mut self,
        request: LwaRefreshRequest,
    ) -> Result<LwaAccessTokenObservation, AmazonTransportError> {
        self.requests.push(request);
        let issued_at = Utc
            .with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
            .single()
            .expect("fixture time");
        LwaAccessTokenObservation::from_raw_token(b"fixture-lwa-token", issued_at, 3_600)
            .map_err(|error| AmazonTransportError::Failed(error.to_string()))
    }
}

#[derive(Debug)]
struct FakeSorftimeTransport {
    api_requests: Vec<SorftimeApiRequest>,
    cli_requests: Vec<SorftimeCliRequest>,
    response: SorftimeResponse,
}

impl SorftimeTransport for FakeSorftimeTransport {
    fn execute_api(
        &mut self,
        request: SorftimeApiRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        self.api_requests.push(request);
        Ok(self.response.clone())
    }

    fn execute_cli(
        &mut self,
        request: SorftimeCliRequest,
    ) -> Result<SorftimeResponse, SorftimeTransportError> {
        self.cli_requests.push(request);
        Ok(self.response.clone())
    }
}

fn graphql_response(data: Value) -> ShopifyGraphqlResponse {
    let mut body = serde_json::Map::new();
    body.insert("data".into(), data);
    ShopifyGraphqlResponse {
        status: 200,
        body: Value::Object(body),
        headers: BTreeMap::new(),
    }
}

fn fixture_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
        .single()
        .expect("fixture time")
}

fn amazon_scope() -> AmazonAccountScope {
    AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
        AmazonMarketplace::us(),
        BTreeSet::from([
            AmazonRole::inventory(),
            AmazonRole::notifications(),
            AmazonRole::reports(),
        ]),
    )
    .expect("Amazon scope")
}

fn access_token() -> LwaAccessTokenObservation {
    LwaAccessTokenObservation::from_raw_token(b"fixture-token", fixture_time(), 3_600)
        .expect("access token")
}

#[test]
fn shopify_identity_scopes_and_cursor_pagination_are_exact() {
    let shop = ShopDomain::parse("Demo-Shop.myshopify.com").expect("shop");
    let requested =
        ShopifyScopeSet::new(vec!["read_products".into(), "read_orders".into()]).expect("scopes");
    let identity_response = graphql_response(json!({
        "shop": {
            "id": "gid://shopify/Shop/123",
            "name": "Demo Shop",
            "myshopifyDomain": "demo-shop.myshopify.com"
        },
        "currentAppInstallation": {
            "accessScopes": [
                {"handle": "read_orders"},
                {"handle": "read_products"}
            ]
        }
    }));
    let page_one = graphql_response(json!({
        "products": {
            "edges": [{
                "cursor": "cursor-1",
                "node": {
                    "id": "gid://shopify/Product/1",
                    "title": "Filter",
                    "variants": {
                        "nodes": [{"id": "gid://shopify/ProductVariant/1", "sku": "SKU-1"}],
                        "pageInfo": {"hasNextPage": false, "endCursor": null}
                    }
                }
            }],
            "pageInfo": {"hasNextPage": true, "endCursor": "cursor-1"}
        }
    }));
    let page_two = graphql_response(json!({
        "products": {
            "edges": [],
            "pageInfo": {"hasNextPage": false, "endCursor": null}
        }
    }));
    let mut transport = FakeShopifyTransport::new([identity_response, page_one, page_two]);
    let read = read_shop_identity(
        &mut transport,
        &shop,
        &ShopifyApiVersion::latest(),
        requested,
    )
    .expect("identity");
    assert_eq!(read.identity.domain, shop);
    assert!(read.scopes.is_satisfied());
    assert_eq!(transport.requests[0].query, SHOP_IDENTITY_QUERY);
    let products = read_products_paginated(&mut transport, &shop, &ShopifyApiVersion::latest(), 50)
        .expect("products");
    assert_eq!(products.len(), 1);
    assert_eq!(
        products[0].variant_skus[0],
        CanonicalSku::parse("SKU-1").expect("SKU")
    );
    assert_eq!(transport.requests[1].query, PRODUCTS_PAGE_QUERY);
    assert_eq!(transport.requests[2].variables["after"], "cursor-1");
}

#[test]
fn shopify_bulk_read_and_webhook_signature_are_read_only_seams() {
    let shop = ShopDomain::parse("demo.myshopify.com").expect("shop");
    let start = graphql_response(json!({
        "bulkOperationRunQuery": {
            "bulkOperation": {
                "id": "gid://shopify/BulkOperation/1",
                "status": "CREATED"
            },
            "userErrors": []
        }
    }));
    let poll = graphql_response(json!({
        "bulkOperation": {
            "id": "gid://shopify/BulkOperation/1",
            "status": "COMPLETED",
            "errorCode": null,
            "url": "https://storage.shopify.com/result.ndjson",
            "objectCount": 1,
            "completedAt": "2026-08-01T00:02:00Z"
        }
    }));
    let mut transport = FakeShopifyTransport::new([start, poll]);
    let operation =
        start_bulk_product_read(&mut transport, shop.clone(), ShopifyApiVersion::latest())
            .expect("bulk start");
    assert_eq!(operation.status, ShopifyBulkStatus::Created);
    let completed = poll_bulk_operation(
        &mut transport,
        shop.clone(),
        ShopifyApiVersion::latest(),
        operation.id,
    )
    .expect("bulk poll");
    assert!(completed.status.is_terminal());
    assert_eq!(completed.object_count, Some(1));

    let body = br#"{"id":"fixture"}"#;
    let secret = b"shopify-fixture-secret";
    let signature = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), body).as_ref(),
    );
    let headers = hartevo_commerce_connector::shopify::ShopifyWebhookHeaders::new(
        signature,
        "webhook-1",
        "orders/create",
        ShopDomain::parse("demo.myshopify.com").expect("shop"),
        ShopifyApiVersion::latest(),
    )
    .expect("headers");
    let verified = verify_webhook_delivery(body, headers, secret).expect("webhook");
    assert_eq!(verified.dedupe_key(), "webhook-1");
    assert!(verified.ensure_shop(&shop).is_ok());
    assert!(
        verified
            .ensure_shop(&ShopDomain::parse("other.myshopify.com").expect("shop"))
            .is_err()
    );
    assert!(!ReadOnlyAuthority::provider_execution());
}

#[test]
fn amazon_lwa_scope_paths_rate_headers_and_async_lifecycles_are_typed() {
    let credential =
        LwaCredentialReference::new("client-id", "secret-reference", "refresh-reference")
            .expect("credential reference");
    let mut lwa = FakeLwaTransport {
        requests: Vec::new(),
    };
    let token = refresh_lwa(&mut lwa, credential).expect("LWA refresh");
    assert_eq!(lwa.requests[0].grant_type, "refresh_token");
    assert_eq!(
        lwa.requests[0].endpoint,
        "https://api.amazon.com/auth/o2/token"
    );

    let request = list_reports_request(amazon_scope(), token.clone(), None).expect("reports");
    assert_eq!(request.operation, AmazonOperation::ReportsList);
    assert_eq!(
        request.endpoint().expect("endpoint").as_str(),
        "https://sellingpartnerapi-na.amazon.com/reports/2021-06-30/reports"
    );
    let response = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::from([
            ("X-Amzn-RequestId".into(), "request-1".into()),
            ("x-amzn-RateLimit-Limit".into(), "0.0222".into()),
        ]),
        body: json!({}),
    };
    let metadata = response.metadata().expect("metadata");
    assert_eq!(metadata.request_id.as_deref(), Some("request-1"));
    assert_eq!(metadata.rate_limit.expect("rate").raw, "0.0222");

    let report_page = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::new(),
        body: json!({
            "reports": [{
                "reportId": "report-2",
                "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                "processingStatus": "DONE",
                "createdTime": "2026-08-01T00:00:00Z",
                "processingEndTime": "2026-08-01T00:01:00Z",
                "reportDocumentId": "doc-2"
            }],
            "nextToken": "next-1"
        }),
    };
    let reports = parse_reports_page(&report_page).expect("typed reports page");
    assert_eq!(reports.reports[0].report_id, "report-2");
    assert_eq!(reports.reports[0].document_id.as_deref(), Some("doc-2"));
    assert_eq!(reports.next_token.as_deref(), Some("next-1"));

    let vendor = AmazonAccountIdentity::vendor("VENDOR01").expect("vendor");
    assert_eq!(vendor.account_id(), "VENDOR01");
    assert_eq!(AmazonMarketplace::uk().region, AmazonRegion::Europe);
    assert_eq!(AmazonMarketplace::japan().region, AmazonRegion::FarEast);

    let queued = AmazonReport::new(
        "report-1",
        "GET_MERCHANT_LISTINGS_ALL_DATA",
        AmazonReportStatus::InQueue,
        None,
        fixture_time(),
        None,
    )
    .expect("report");
    let lifecycle = AmazonReportLifecycle::from_report(&queued);
    let in_progress = lifecycle
        .advance(AmazonReportLifecycleState::InProgress, None)
        .expect("in progress");
    assert!(
        in_progress
            .advance(AmazonReportLifecycleState::Succeeded, Some("doc-1".into()))
            .is_ok()
    );
    assert!(
        lifecycle
            .advance(AmazonReportLifecycleState::Succeeded, None)
            .is_err()
    );

    let notification =
        AmazonNotificationLifecycle::requested("ANY_OFFER_CHANGED").expect("notification");
    let notification = notification
        .advance(AmazonNotificationLifecycleState::DestinationReady, None)
        .expect("destination");
    let notification = notification
        .advance(AmazonNotificationLifecycleState::SubscriptionActive, None)
        .expect("subscription");
    assert!(
        notification
            .advance(
                AmazonNotificationLifecycleState::DeliveryObserved,
                Some("delivery-1".into()),
            )
            .is_ok()
    );
}

#[test]
fn sorftime_api_and_cli_keep_estimates_and_cost_provenance_separate() {
    let market = SorftimeMarket::new(
        MarketId::parse("ATVPDKIKX0DER").expect("market"),
        "en-US",
        CurrencyCode::parse("USD").expect("currency"),
    )
    .expect("market");
    let account = SorftimeAccountId::parse("sorftime-fixture-account").expect("account");
    let api_request = SorftimeApiRequest::new(
        "https://open.sorftime.com/api",
        account.clone(),
        market.clone(),
        SorftimeDataset::ProductTrend,
        "request-api-1",
        json!({"asin":"B0C0MERC01"}),
    )
    .expect("API request");
    let cli_request = SorftimeCliRequest::new(
        account,
        market,
        SorftimeDataset::ProductTrend,
        "request-cli-1",
        json!({"asin":"B0C0MERC01"}),
    )
    .expect("CLI request");
    let response = SorftimeResponse {
        status: 200,
        request_id: "response-1".into(),
        body: json!({
            "asin":"B0C0MERC01",
            "estimatedUnits":420,
            "estimatedRevenueMinor":42000,
            "currency":"USD"
        }),
        cost_units: 3,
        cost_currency: None,
        cost_source: "fixture-price-list/v1".into(),
    };
    let mut transport = FakeSorftimeTransport {
        api_requests: Vec::new(),
        cli_requests: Vec::new(),
        response,
    };
    let estimate =
        query_estimate_api(&mut transport, api_request, fixture_time()).expect("API estimate");
    assert_eq!(estimate.provenance.provider_id, "sorftime");
    assert_eq!(estimate.provenance.transport, SorftimeTransportKind::Api);
    assert_eq!(estimate.provenance.request_cost.units, 3);
    assert_eq!(
        estimate.target_asin,
        Some(Asin::parse("B0C0MERC01").expect("ASIN"))
    );
    let cli_estimate =
        query_estimate_cli(&mut transport, cli_request, fixture_time()).expect("CLI estimate");
    assert_eq!(
        cli_estimate.provenance.transport,
        SorftimeTransportKind::Cli
    );
    assert_eq!(transport.api_requests.len(), 1);
    assert_eq!(transport.cli_requests.len(), 1);
    assert_eq!(
        transport.api_requests[0].endpoint,
        format!("https://{SORFTIME_API_HOST}/api")
    );
    assert!(estimate.is_estimate_only() && cli_estimate.is_estimate_only());
}

#[test]
fn deterministic_world_is_replayable_and_rejects_authority_drift() {
    let first = marketplace_world().expect("world");
    let second = marketplace_world().expect("world");
    assert_eq!(
        first.content_digest().expect("digest"),
        second.content_digest().expect("digest")
    );
    assert_eq!(first.initial_state_digest, second.initial_state_digest);
    assert_eq!(first.first_party.facts.len(), 4);
    assert_eq!(first.estimate_only.estimates.len(), 1);
    assert!(!first.external_network_allowed);
    assert!(!ReadOnlyAuthority::connected());

    let mut drifted = first;
    drifted.estimate_only.provider_id = "amazon-sp-api".into();
    assert_eq!(
        drifted.validate(),
        Err(MarketplaceWorldError::EstimateAuthorityConflict)
    );
}

#[test]
fn canonical_ids_are_strict_and_not_free_form_json() {
    assert_eq!(
        Asin::parse("b0c0merc01").expect("ASIN").as_str(),
        "B0C0MERC01"
    );
    assert!(Asin::parse("not-an-asin").is_err());
    assert!(CanonicalSku::parse(" SKU ").is_err());
    assert!(
        AmazonSpApiRequest {
            scope: amazon_scope(),
            operation: AmazonOperation::ReportsList,
            method: "GET".into(),
            path: "/reports/2021-06-30/reports".into(),
            query: BTreeMap::new(),
            access_token: access_token(),
        }
        .endpoint()
        .is_ok()
    );
}
