use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_commerce_connector::amazon::{
    AmazonAccountIdentity, AmazonAccountScope, AmazonLwaAuthState, AmazonNotificationCursor,
    AmazonOperation, AmazonReport, AmazonReportStatus, AmazonRole, LwaAccessTokenObservation,
};
use hartevo_commerce_connector::amazon_insight::{
    AMAZON_INSIGHT_CAPABILITY_ID, AMAZON_INSIGHT_LIVE_VALIDATION_STATUS,
    AMAZON_REPORT_CREATION_POLICY, AmazonDocumentCursor, AmazonFreshnessEvidence,
    AmazonInsightClassification, AmazonInsightCursor, AmazonInsightDurableStore,
    AmazonInsightError, AmazonInsightProviderError, AmazonInsightReadRequest, AmazonInsightSource,
    AmazonNotificationEvent, AmazonNotificationFeed, AmazonNotificationPage,
    AmazonNotificationPageRequest, AmazonNotificationType, AmazonPreauthorizedReportJob,
    AmazonProviderGeneration, AmazonQuotaCostEvidence, AmazonReportDocumentId,
    AmazonReportDocumentPage, AmazonReportDocumentPageRequest, AmazonReportStatusPage,
    AmazonReportStatusRequest, AmazonSpApiInsightAdapter, CommerceInsightReadService,
    amazon_scope_digest, live_probe_enabled, notification_cursor_sp_api_request,
    report_document_sp_api_request, report_status_sp_api_request,
};
use hartevo_connector_sdk::{ConnectorScope, ProviderProvenanceClass, SecretReference};

const NOW_YEAR: i32 = 2026;

#[derive(Clone, Debug)]
struct FakeAmazonState {
    report_status_calls: u32,
    report_document_calls: u32,
    notification_calls: u32,
    report_status: AmazonReportStatusPage,
    report_pages: BTreeMap<String, AmazonReportDocumentPage>,
    notification_pages: BTreeMap<String, AmazonNotificationPage>,
    rate_limit_document_once: bool,
    expired_document_url: bool,
}

#[derive(Clone, Debug)]
struct FakeAmazonSpApiAdapter {
    state: Arc<Mutex<FakeAmazonState>>,
}

impl FakeAmazonSpApiAdapter {
    fn new(state: Arc<Mutex<FakeAmazonState>>) -> Self {
        Self { state }
    }
}

impl AmazonSpApiInsightAdapter for FakeAmazonSpApiAdapter {
    fn read_report_status(
        &mut self,
        _request: AmazonReportStatusRequest,
    ) -> Result<AmazonReportStatusPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.report_status_calls += 1;
        Ok(state.report_status.clone())
    }

    fn read_report_document_page(
        &mut self,
        request: AmazonReportDocumentPageRequest,
    ) -> Result<AmazonReportDocumentPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.report_document_calls += 1;
        if state.rate_limit_document_once {
            state.rate_limit_document_once = false;
            return Err(AmazonInsightProviderError::RateLimited {
                retry_after_seconds: 10,
                quota: quota(AmazonOperation::ReportsDocument, "rate-limited"),
            });
        }
        let key = request
            .requested_cursor
            .as_ref()
            .map_or_else(|| "<start>".to_owned(), |cursor| cursor.as_str().to_owned());
        let mut page = state
            .report_pages
            .get(&key)
            .cloned()
            .expect("configured report page");
        if state.expired_document_url {
            page.document_url_expires_at = request.at - Duration::seconds(1);
        }
        Ok(page)
    }

    fn read_notification_page(
        &mut self,
        request: AmazonNotificationPageRequest,
    ) -> Result<AmazonNotificationPage, AmazonInsightProviderError> {
        let mut state = self.state.lock().expect("fake Amazon state");
        state.notification_calls += 1;
        let key = request
            .requested_cursor
            .as_ref()
            .map_or_else(|| "<start>".to_owned(), |cursor| cursor.as_str().to_owned());
        Ok(state
            .notification_pages
            .get(&key)
            .cloned()
            .expect("configured notification page"))
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW_YEAR, 8, 14, 5, 0, 0)
        .single()
        .expect("stable test time")
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn connector_scope(account_id: &str) -> ConnectorScope {
    ConnectorScope::new(
        "tenant-amazon",
        "project-commerce",
        "amazon-sp-api",
        account_id,
        ["reports.read".to_owned(), "notifications.read".to_owned()],
    )
    .expect("Amazon ConnectorScope")
}

fn seller_scope() -> AmazonAccountScope {
    AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::reports(), AmazonRole::notifications()]),
    )
    .expect("Amazon account scope")
}

fn secret(scope: &AmazonAccountScope) -> SecretReference {
    SecretReference::new(
        "secret-ref-amazon-insight-1",
        connector_scope(scope.account.account_id()),
        7,
    )
    .expect("opaque Amazon SecretReference")
}

fn generation() -> AmazonProviderGeneration {
    AmazonProviderGeneration::new(7).expect("provider generation")
}

fn auth_state() -> AmazonLwaAuthState {
    let token = LwaAccessTokenObservation::from_raw_token(
        b"controlled-token-only",
        now() - Duration::seconds(10),
        600,
    )
    .expect("token observation");
    AmazonLwaAuthState::token_observed(token)
}

fn report_job(scope: &AmazonAccountScope) -> AmazonPreauthorizedReportJob {
    AmazonPreauthorizedReportJob::new(
        scope,
        generation(),
        "report-1",
        "GET_MERCHANT_LISTINGS_ALL_DATA",
        digest("external-preauthorized-report-job"),
        now() - Duration::seconds(30),
    )
    .expect("pre-authorized report job")
}

fn report_request(scope: &AmazonAccountScope) -> AmazonInsightReadRequest {
    AmazonInsightReadRequest::new(
        "mission-research-report-1",
        scope.clone(),
        generation(),
        AmazonInsightSource::Report {
            job: report_job(scope),
        },
        now() - Duration::seconds(20),
        now() + Duration::seconds(300),
        100,
    )
    .expect("report research request")
}

fn notification_request(scope: AmazonAccountScope) -> AmazonInsightReadRequest {
    AmazonInsightReadRequest::new(
        "mission-research-notifications-1",
        scope,
        generation(),
        AmazonInsightSource::Notifications {
            feed: AmazonNotificationFeed::new("ORDER_CHANGE", "1.0", "subscription-1")
                .expect("notification feed"),
        },
        now() - Duration::seconds(20),
        now() + Duration::seconds(300),
        100,
    )
    .expect("notification research request")
}

fn quota(operation: AmazonOperation, request_id: &str) -> AmazonQuotaCostEvidence {
    AmazonQuotaCostEvidence::new(
        operation,
        Some(
            hartevo_commerce_connector::amazon::AmazonRateLimit::parse("0.0167")
                .expect("rate limit"),
        ),
        None,
        1,
        Some(request_id.to_owned()),
    )
    .expect("quota evidence")
}

fn freshness(revision: u64) -> AmazonFreshnessEvidence {
    AmazonFreshnessEvidence::new(
        now() - Duration::seconds(1),
        now() + Duration::seconds(60),
        revision,
    )
    .expect("freshness evidence")
}

fn report_status_page() -> AmazonReportStatusPage {
    AmazonReportStatusPage {
        report: AmazonReport::new(
            "report-1",
            "GET_MERCHANT_LISTINGS_ALL_DATA",
            AmazonReportStatus::Done,
            Some("DOC-1".to_owned()),
            now() - Duration::seconds(20),
            Some(now() - Duration::seconds(10)),
        )
        .expect("done report"),
        quota: quota(AmazonOperation::ReportsGet, "status-1"),
        freshness: freshness(1),
    }
}

fn report_page(
    requested_cursor: Option<AmazonDocumentCursor>,
    page_sequence: u64,
    next_cursor: Option<AmazonDocumentCursor>,
    record_id: &str,
) -> AmazonReportDocumentPage {
    AmazonReportDocumentPage {
        document_id: AmazonReportDocumentId::parse("DOC-1").expect("document id"),
        document_url_digest: digest("presigned-document-url"),
        document_url_expires_at: now() + Duration::seconds(300),
        requested_cursor,
        page_sequence,
        next_cursor,
        records: vec![
            hartevo_commerce_connector::amazon_insight::AmazonInsightRecord::new(
                record_id,
                digest(record_id),
                now(),
            )
            .expect("report record"),
        ],
        observed_at: now(),
        quota: quota(AmazonOperation::ReportsDocument, "document-1"),
        freshness: freshness(page_sequence),
    }
}

fn report_state() -> Arc<Mutex<FakeAmazonState>> {
    Arc::new(Mutex::new(FakeAmazonState {
        report_status_calls: 0,
        report_document_calls: 0,
        notification_calls: 0,
        report_status: report_status_page(),
        report_pages: BTreeMap::from([
            (
                "<start>".to_owned(),
                report_page(
                    None,
                    1,
                    Some(AmazonDocumentCursor::parse("document-cursor-2").expect("cursor")),
                    "row-1",
                ),
            ),
            (
                "document-cursor-2".to_owned(),
                report_page(
                    Some(AmazonDocumentCursor::parse("document-cursor-2").expect("cursor")),
                    2,
                    None,
                    "row-2",
                ),
            ),
        ]),
        notification_pages: BTreeMap::new(),
        rate_limit_document_once: false,
        expired_document_url: false,
    }))
}

fn notification_state() -> Arc<Mutex<FakeAmazonState>> {
    let notification_type = AmazonNotificationType::parse("ORDER_CHANGE").expect("type");
    let event_type = notification_type.clone();
    let event = move |delivery_id: &str, sequence: u64| {
        AmazonNotificationEvent::new(
            delivery_id,
            sequence,
            event_type.clone(),
            now(),
            digest(delivery_id),
        )
        .expect("notification event")
    };
    Arc::new(Mutex::new(FakeAmazonState {
        report_status_calls: 0,
        report_document_calls: 0,
        notification_calls: 0,
        report_status: report_status_page(),
        report_pages: BTreeMap::new(),
        notification_pages: BTreeMap::from([
            (
                "<start>".to_owned(),
                AmazonNotificationPage {
                    notification_type: notification_type.clone(),
                    requested_cursor: None,
                    page_sequence: 1,
                    next_cursor: Some(
                        AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
                    ),
                    events: vec![event("delivery-1", 1), event("delivery-2", 2)],
                    observed_at: now(),
                    quota: quota(AmazonOperation::NotificationsSubscriptionsList, "notif-1"),
                    freshness: freshness(1),
                },
            ),
            (
                "notification-cursor-2".to_owned(),
                AmazonNotificationPage {
                    notification_type: notification_type.clone(),
                    requested_cursor: Some(
                        AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
                    ),
                    page_sequence: 2,
                    next_cursor: None,
                    events: vec![event("delivery-2", 2), event("delivery-3", 3)],
                    observed_at: now(),
                    quota: quota(AmazonOperation::NotificationsSubscriptionsList, "notif-2"),
                    freshness: freshness(2),
                },
            ),
        ]),
        rate_limit_document_once: false,
        expired_document_url: false,
    }))
}

fn service(
    state: Arc<Mutex<FakeAmazonState>>,
    scope: AmazonAccountScope,
    auth: AmazonLwaAuthState,
    store: AmazonInsightDurableStore,
    secret_reference: SecretReference,
) -> CommerceInsightReadService<FakeAmazonSpApiAdapter> {
    CommerceInsightReadService::new(
        FakeAmazonSpApiAdapter::new(state),
        secret_reference,
        scope,
        generation(),
        auth,
        ProviderProvenanceClass::ControlledProvider,
        store,
    )
    .expect("Amazon insight service")
}

fn new_store(
    scope: &AmazonAccountScope,
    secret_reference: &SecretReference,
) -> AmazonInsightDurableStore {
    AmazonInsightDurableStore::new(scope, secret_reference, generation()).expect("durable store")
}

#[test]
fn report_and_notification_request_helpers_are_get_only_and_no_create_policy() {
    let scope = seller_scope();
    let token = match auth_state() {
        AmazonLwaAuthState::TokenObserved { token, .. } => token,
        AmazonLwaAuthState::Disconnected { .. } | AmazonLwaAuthState::BlockedEnv { .. } => {
            panic!("token observation")
        }
    };
    let job = report_job(&scope);
    let status_request = AmazonReportStatusRequest {
        scope: scope.clone(),
        job,
        access_token: token.clone(),
        provider_generation: generation(),
        at: now(),
    };
    let status_http = report_status_sp_api_request(&status_request).expect("status GET");
    assert_eq!(status_http.method, "GET");
    assert_eq!(status_http.path, "/reports/2021-06-30/reports/report-1");

    let document_http = report_document_sp_api_request(&AmazonReportDocumentPageRequest {
        scope: scope.clone(),
        document_id: AmazonReportDocumentId::parse("DOC-1").expect("document"),
        access_token: token.clone(),
        provider_generation: generation(),
        requested_cursor: None,
        page_size: 100,
        at: now(),
    })
    .expect("document GET");
    assert_eq!(document_http.method, "GET");
    assert_eq!(document_http.path, "/reports/2021-06-30/documents/DOC-1");

    let notification_http = notification_cursor_sp_api_request(&AmazonNotificationPageRequest {
        scope,
        feed: AmazonNotificationFeed::new("ORDER_CHANGE", "1.0", "subscription-1").expect("feed"),
        access_token: token,
        provider_generation: generation(),
        requested_cursor: Some(
            AmazonNotificationCursor::parse("notification-cursor-2").expect("cursor"),
        ),
        page_size: 100,
        at: now(),
    })
    .expect("notification GET");
    assert_eq!(notification_http.method, "GET");
    assert_eq!(notification_http.path, "/notifications/v1/subscriptions");
    assert_eq!(
        notification_http.query.get("nextToken"),
        Some(&"notification-cursor-2".to_owned())
    );
    assert_eq!(
        AMAZON_REPORT_CREATION_POLICY,
        "PREAUTHORIZED_REPORT_JOB_ONLY"
    );
}

#[test]
fn report_status_document_cursor_is_durable_and_restart_has_zero_duplicate_rows() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    let store = new_store(&scope, &secret_reference);
    let mut first_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        store,
        secret_reference.clone(),
    );

    let first = first_service
        .read(&request, now())
        .expect("first report page");
    assert_eq!(first.page_sequence, 1);
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].item_id, "row-1");
    assert_eq!(
        first.classification,
        AmazonInsightClassification::ReportRecord
    );
    assert_eq!(
        first.source,
        hartevo_commerce_connector::amazon_insight::AmazonInsightSourceKind::Report
    );
    assert_eq!(first.scope_digest, amazon_scope_digest(&scope));
    assert_eq!(
        first.report_type.as_ref().expect("report type").as_str(),
        "GET_MERCHANT_LISTINGS_ALL_DATA"
    );
    assert!(first.processing_job_digest.is_some());
    assert!(first.document_id.is_some());
    assert!(!first.content_digest.is_empty());
    assert!(!first.result_digest.is_empty());
    assert_eq!(first.quota.cost_units, 1);
    assert!(first.freshness.valid_until > now());
    assert!(!first.is_connected());
    assert!(!first.is_first_party());
    assert!(first.is_mission_adoptable());
    assert_eq!(
        first.live_validation_status,
        AMAZON_INSIGHT_LIVE_VALIDATION_STATUS
    );

    let checkpoint_bytes =
        serde_json::to_vec(first_service.store()).expect("durable checkpoint JSON");
    let checkpoint_json = String::from_utf8(checkpoint_bytes.clone()).expect("checkpoint UTF-8");
    assert!(!checkpoint_json.contains("controlled-token-only"));
    let restored_store: AmazonInsightDurableStore =
        serde_json::from_slice(&checkpoint_bytes).expect("restored checkpoint");
    let mut restarted = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        restored_store,
        secret_reference,
    );
    let second = restarted
        .read(&request, now() + Duration::seconds(1))
        .expect("second report page after restart");
    assert_eq!(second.page_sequence, 2);
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].item_id, "row-2");
    assert_ne!(first.items[0].item_id, second.items[0].item_id);
    assert!(matches!(
        second.next_cursor,
        AmazonInsightCursor::Report(None)
    ));
    assert!(matches!(
        restarted.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));
    let state = state.lock().expect("fake state");
    assert_eq!(state.report_status_calls, 1);
    assert_eq!(state.report_document_calls, 2);
}

#[test]
fn notifications_resume_cursor_and_dedupe_duplicate_delivery_without_duplicate_result_items() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let state = notification_state();
    let mut notification_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );

    let first = notification_service
        .read(&request, now())
        .expect("first notification page");
    assert_eq!(first.items.len(), 2);
    assert_eq!(
        first.classification,
        AmazonInsightClassification::NotificationEvent
    );
    let second = notification_service
        .read(&request, now() + Duration::seconds(1))
        .expect("second notification page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].item_id, "delivery-3");
    assert!(matches!(
        second.next_cursor,
        AmazonInsightCursor::Notifications(None)
    ));
    assert!(matches!(
        notification_service.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::ResearchComplete)
    ));
    assert_eq!(
        notification_service.store().checkpoints()[&request.research_id]
            .seen_delivery_identities
            .len(),
        3
    );
    let state = state.lock().expect("fake state");
    assert_eq!(state.notification_calls, 2);
}

#[test]
fn cursor_rollback_and_out_of_order_notification_fail_closed() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let state = notification_state();
    {
        let mut fake = state.lock().expect("fake state");
        let page = fake
            .notification_pages
            .get_mut("notification-cursor-2")
            .expect("second page");
        page.next_cursor = Some(
            AmazonNotificationCursor::parse("notification-cursor-2").expect("rollback cursor"),
        );
        page.events = vec![
            AmazonNotificationEvent::new(
                "delivery-3",
                3,
                AmazonNotificationType::parse("ORDER_CHANGE").expect("type"),
                now(),
                digest("delivery-3"),
            )
            .expect("event"),
        ];
    }
    let mut rollback_service = service(
        state,
        scope,
        auth_state(),
        new_store(&seller_scope(), &secret_reference),
        secret_reference,
    );
    rollback_service.read(&request, now()).expect("first page");
    assert!(matches!(
        rollback_service.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::CursorRollback)
    ));
    assert!(matches!(
        rollback_service.read(&request, now() + Duration::seconds(2)),
        Err(AmazonInsightError::PreviouslyFailedClosed)
    ));

    let out_of_order_state = notification_state();
    {
        let mut fake = out_of_order_state.lock().expect("fake state");
        let page = fake
            .notification_pages
            .get_mut("notification-cursor-2")
            .expect("second page");
        page.next_cursor = None;
        page.events = vec![
            AmazonNotificationEvent::new(
                "delivery-old",
                1,
                AmazonNotificationType::parse("ORDER_CHANGE").expect("type"),
                now(),
                digest("delivery-old"),
            )
            .expect("event"),
        ];
    }
    let scope = seller_scope();
    let secret_reference = secret(&scope);
    let mut out_of_order = service(
        out_of_order_state,
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    out_of_order.read(&request, now()).expect("first page");
    assert!(matches!(
        out_of_order.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::OutOfOrderNotification)
    ));
}

#[test]
fn retry_after_is_durable_and_expired_document_url_fails_closed() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    state.lock().expect("fake state").rate_limit_document_once = true;
    let mut retry_service = service(
        state.clone(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference.clone(),
    );
    assert!(matches!(
        retry_service.read(&request, now()),
        Err(AmazonInsightError::RetryAfter { .. })
    ));
    assert!(matches!(
        retry_service.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::RetryAfterNotElapsed { .. })
    ));
    let recovered = retry_service
        .read(&request, now() + Duration::seconds(11))
        .expect("retry after elapsed");
    assert_eq!(recovered.page_sequence, 1);

    let expired_state = report_state();
    expired_state
        .lock()
        .expect("fake state")
        .expired_document_url = true;
    let mut expired = service(
        expired_state,
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    assert!(matches!(
        expired.read(&request, now()),
        Err(AmazonInsightError::DocumentUrlExpired)
    ));
    assert!(matches!(
        expired.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::PreviouslyFailedClosed)
    ));
}

#[test]
fn scope_drift_revoke_and_no_credentials_are_fail_closed_without_connected_authority() {
    let scope = seller_scope();
    let request = report_request(&scope);
    let secret_reference = secret(&scope);
    let state = report_state();
    let mut no_credentials = service(
        state.clone(),
        scope.clone(),
        AmazonLwaAuthState::no_credentials(now()),
        new_store(&scope, &secret_reference),
        secret_reference.clone(),
    );
    assert!(!no_credentials.is_connected());
    assert!(matches!(
        no_credentials.read(&request, now()),
        Err(AmazonInsightError::BlockedEnv)
    ));
    assert_eq!(state.lock().expect("fake state").report_status_calls, 0);

    let drifted_scope = AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER02").expect("seller"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::reports()]),
    )
    .expect("drift scope");
    let drifted_job = AmazonPreauthorizedReportJob::new(
        &seller_scope(),
        generation(),
        "report-1",
        "GET_MERCHANT_LISTINGS_ALL_DATA",
        digest("external-preauthorized-report-job"),
        now() - Duration::seconds(30),
    )
    .expect("job");
    assert!(matches!(
        AmazonInsightReadRequest::new(
            "mission-research-report-drift",
            drifted_scope,
            generation(),
            AmazonInsightSource::Report { job: drifted_job },
            now() - Duration::seconds(10),
            now() + Duration::seconds(100),
            100,
        ),
        Err(AmazonInsightError::ScopeDrift)
    ));

    let scope = seller_scope();
    let secret_reference = secret(&scope);
    let mut revoked = service(
        report_state(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    revoked.revoke(now()).expect("revoke");
    assert!(matches!(
        revoked.read(&request, now() + Duration::seconds(1)),
        Err(AmazonInsightError::ConsumerNotMounted)
    ));
    assert!(revoked.store().checkpoints().is_empty());
}

#[test]
#[ignore = "requires HARTEVO_AMAZON_SP_API_LIVE=1, real LWA credentials, and an external read adapter"]
fn env_gated_live_probe_is_explicit() {
    assert!(live_probe_enabled());
}

#[test]
fn mission_capability_is_read_only_and_source_is_amazon_sp_api() {
    let scope = seller_scope();
    let request = notification_request(scope.clone());
    let secret_reference = secret(&scope);
    let service = service(
        notification_state(),
        scope.clone(),
        auth_state(),
        new_store(&scope, &secret_reference),
        secret_reference,
    );
    let capability = service.capability(&request);
    assert_eq!(capability.capability_id, AMAZON_INSIGHT_CAPABILITY_ID);
    assert_eq!(capability.provider_id, "amazon-sp-api");
    assert!(capability.read_only);
    assert!(!capability.connected);
    assert_eq!(capability.scope_digest, amazon_scope_digest(&scope));
}

#[test]
fn scope_digest_keeps_seller_vendor_marketplace_region_and_generation_exact() {
    let seller = seller_scope();
    let vendor = AmazonAccountScope::new(
        AmazonAccountIdentity::vendor("VENDOR01").expect("vendor"),
        hartevo_commerce_connector::amazon::AmazonMarketplace::uk(),
        BTreeSet::from([AmazonRole::reports()]),
    )
    .expect("vendor scope");
    assert_eq!(
        vendor.marketplace.region,
        hartevo_commerce_connector::amazon::AmazonRegion::Europe
    );
    assert_ne!(amazon_scope_digest(&seller), amazon_scope_digest(&vendor));
    assert!(
        AmazonInsightDurableStore::new(
            &seller,
            &SecretReference::new(
                "secret-ref-amazon-insight-generation-mismatch",
                connector_scope(seller.account.account_id()),
                8,
            )
            .expect("generation mismatch secret"),
            generation(),
        )
        .is_err()
    );
}
