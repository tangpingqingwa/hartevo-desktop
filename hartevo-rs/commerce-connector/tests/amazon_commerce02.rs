use std::collections::{BTreeMap, BTreeSet};

use chrono::{Duration, TimeZone, Utc};
use hartevo_commerce_connector::ReadOnlyAuthority;
use hartevo_commerce_connector::amazon::{
    AMAZON_LIVE_VALIDATION_STATUS, AMAZON_PROVIDER_ID, AMAZON_READ_EVIDENCE_LEVEL,
    AmazonAccountIdentity, AmazonAccountScope, AmazonBlockedEnvReason, AmazonError,
    AmazonFirstPartySource, AmazonLwaAuthState, AmazonLwaAuthStatus, AmazonMarketplace,
    AmazonNotificationCursor, AmazonOperation, AmazonReportStatus, AmazonRole, AmazonSpApiRequest,
    AmazonSpApiResponse, AmazonThrottleError, LwaAccessTokenObservation, get_report_request,
    list_notification_subscriptions_request, list_reports_request,
    parse_notification_subscriptions_page_read, parse_report_read, parse_reports_page_read,
};
use serde_json::json;

fn fixture_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0)
        .single()
        .expect("fixture time")
}

fn scope() -> AmazonAccountScope {
    AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
        AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::notifications(), AmazonRole::reports()]),
    )
    .expect("scope")
}

fn token() -> LwaAccessTokenObservation {
    LwaAccessTokenObservation::from_raw_token(b"commerce-02-fixture-token", fixture_time(), 3_600)
        .expect("token")
}

#[test]
fn lwa_state_is_honest_without_credentials_and_never_connected_authority() {
    let disconnected = AmazonLwaAuthState::disconnected(fixture_time());
    assert_eq!(disconnected.status(), AmazonLwaAuthStatus::Disconnected);
    assert!(!disconnected.can_issue_read_at(fixture_time()));

    let blocked = AmazonLwaAuthState::blocked_env(
        fixture_time(),
        AmazonBlockedEnvReason::CredentialsUnavailable,
    );
    assert_eq!(blocked.status(), AmazonLwaAuthStatus::BlockedEnv);
    assert_eq!(AMAZON_LIVE_VALIDATION_STATUS, "BLOCKED_ENV");
    assert!(!blocked.can_issue_read_at(fixture_time()));

    let observed = AmazonLwaAuthState::token_observed(token());
    assert_eq!(observed.status(), AmazonLwaAuthStatus::TokenObserved);
    assert!(observed.can_issue_read_at(fixture_time() + Duration::seconds(1)));
    assert!(!observed.grants_connected_authority());
    assert!(!ReadOnlyAuthority::connected());
}

#[test]
fn reports_keep_first_party_provenance() {
    let scope = scope();
    let access_token = token();
    let reports_request =
        list_reports_request(scope.clone(), access_token.clone(), None).expect("reports request");
    let reports_response = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::from([
            ("x-amzn-RequestId".into(), "request-reports-1".into()),
            ("x-amzn-RateLimit-Limit".into(), "0.5".into()),
        ]),
        body: json!({
            "reports": [{
                "reportId": "report-02",
                "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                "processingStatus": "IN_PROGRESS",
                "createdTime": "2026-08-01T00:00:00Z"
            }],
            "nextToken": "reports-cursor-02"
        }),
    };
    let reports = parse_reports_page_read(&reports_request, &reports_response, fixture_time())
        .expect("reports read");
    assert_eq!(reports.value.reports.len(), 1);
    assert_eq!(
        reports.value.next_token.as_deref(),
        Some("reports-cursor-02")
    );
    assert_eq!(reports.provenance.provider_id, AMAZON_PROVIDER_ID);
    assert_eq!(
        reports.provenance.source,
        AmazonFirstPartySource::SellingPartnerApi
    );
    assert_eq!(
        reports.provenance.evidence_level,
        AMAZON_READ_EVIDENCE_LEVEL
    );
    assert_eq!(
        reports.provenance.request_id.as_deref(),
        Some("request-reports-1")
    );
    assert!(reports.provenance.is_first_party());
}

#[test]
fn notifications_keep_first_party_provenance_and_cursor() {
    let scope = scope();
    let access_token = token();
    let notification_request = list_notification_subscriptions_request(
        scope.clone(),
        access_token.clone(),
        "ANY_OFFER_CHANGED",
        Some("1.0".into()),
        30,
        None,
    )
    .expect("notification request");
    assert_eq!(
        notification_request.operation,
        AmazonOperation::NotificationsSubscriptionsList
    );
    assert_eq!(
        notification_request.query.get("notificationTypes"),
        Some(&"ANY_OFFER_CHANGED".to_owned())
    );
    assert_eq!(
        notification_request.query.get("pageSize"),
        Some(&"30".to_owned())
    );
    let notification_response = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::from([("x-amzn-RequestId".into(), "request-notify-1".into())]),
        body: json!({
            "payload": {
                "subscriptions": [{
                    "subscriptionId": "subscription-02",
                    "payloadVersion": "1.0",
                    "destinationId": "destination-02"
                }],
                "nextToken": "notify-cursor-02"
            }
        }),
    };
    let notifications = parse_notification_subscriptions_page_read(
        &notification_request,
        &notification_response,
        fixture_time(),
    )
    .expect("notification read");
    assert_eq!(notifications.value.subscriptions.len(), 1);
    assert_eq!(
        notifications
            .value
            .next_cursor
            .as_ref()
            .map(AmazonNotificationCursor::as_str),
        Some("notify-cursor-02")
    );
    assert_eq!(
        notifications.provenance.operation,
        notification_request.operation
    );

    let cursor = AmazonNotificationCursor::parse("notify-cursor-02").expect("cursor");
    let next_request = list_notification_subscriptions_request(
        scope,
        access_token,
        "ANY_OFFER_CHANGED",
        Some("1.0".into()),
        30,
        Some(cursor),
    )
    .expect("next notification request");
    assert_eq!(
        next_request.query.get("nextToken"),
        Some(&"notify-cursor-02".to_owned())
    );
}

#[test]
fn report_payload_and_operation_throttle_are_read_only_and_fail_closed() {
    let scope = scope();
    let access_token = token();
    let report_request = get_report_request(scope.clone(), access_token.clone(), "report-02")
        .expect("report request");
    let report_response = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::new(),
        body: json!({
            "payload": {
                "reportId": "report-02",
                "reportType": "GET_MERCHANT_LISTINGS_ALL_DATA",
                "processingStatus": "DONE",
                "createdTime": "2026-08-01T00:00:00Z",
                "processingEndTime": "2026-08-01T00:01:00Z",
                "reportDocumentId": "document-02"
            }
        }),
    };
    let report =
        parse_report_read(&report_request, &report_response, fixture_time()).expect("report read");
    assert_eq!(report.value.status, AmazonReportStatus::Done);
    assert_eq!(report.value.document_id.as_deref(), Some("document-02"));

    let rate_response = AmazonSpApiResponse {
        status: 200,
        headers: BTreeMap::from([("x-amzn-RateLimit-Limit".into(), "0.5".into())]),
        body: json!({}),
    };
    let mut throttle = hartevo_commerce_connector::amazon::AmazonOperationThrottle::from_response(
        AmazonOperation::ReportsGet,
        &rate_response,
        fixture_time(),
    )
    .expect("throttle");
    throttle.admit(fixture_time()).expect("first permit");
    let throttled = throttle
        .admit(fixture_time())
        .expect_err("second call throttled");
    assert!(matches!(
        throttled,
        AmazonThrottleError::ThrottledUntil {
            operation: AmazonOperation::ReportsGet,
            ..
        }
    ));
    let next = throttle
        .next_available_at
        .clone()
        .expect("next availability")
        .as_datetime();
    throttle.admit(next).expect("permit after interval");

    let write_request = AmazonSpApiRequest {
        scope: scope.clone(),
        operation: AmazonOperation::ReportsGet,
        method: "POST".into(),
        path: "/reports/2021-06-30/reports/report-02".into(),
        query: BTreeMap::new(),
        access_token: access_token.clone(),
    };
    assert!(matches!(
        write_request.endpoint(),
        Err(AmazonError::ReadOnlyMethod(method)) if method == "POST"
    ));

    let missing_role = AmazonAccountScope::new(
        AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
        AmazonMarketplace::us(),
        BTreeSet::from([AmazonRole::inventory()]),
    )
    .expect("scope");
    let reports_without_role = list_reports_request(missing_role, access_token, None)
        .expect("request builder retains typed shape");
    assert!(matches!(
        reports_without_role.endpoint(),
        Err(AmazonError::MissingOperationRole {
            operation: AmazonOperation::ReportsList,
            role
        }) if role == "Reports"
    ));
}
