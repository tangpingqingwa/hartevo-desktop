use serde_json::json;

use crate::{
    BlockedEnvTransport, CLARITY_DATA_EXPORT_PATH, CLARITY_MAX_RESPONSE_BYTES,
    CLARITY_MAX_RESPONSE_ROWS, CLARITY_UX_RESULT_BLOCKED_ENV, ClarityDataExportGetRequest,
    ClarityDataExportProvider, ClarityDataExportTransport, ClarityHttpResponse, ClarityProvider,
    ClarityProviderEvidence, ClarityTransportError, ClarityUxResultRequest, ClarityUxResultService,
    ClarityUxScope, ConsentScope, Digest, Dimension, DimensionSet, FixtureClarityTransport, Metric,
    MetricSet, MissionClarityUxConsumer, MissionResultState, MissionScope, PrivacyPolicy,
    ProjectScope, ProviderErrorKind, ProviderProvenance, RecordingClarityTransport, ResultStatus,
    Revision, SecretReference, TimeWindow, Timestamp, WorkProductScope,
};

const TEST_AT: i64 = 1_762_000_000;

fn fixture_body() -> String {
    json!([
        {
            "metricName": "Traffic",
            "information": [
                {
                    "totalSessionCount": "100",
                    "totalBotSessionCount": "4",
                    "OS": "Android",
                    "Browser": "Chrome",
                    "Campaign": "launch-secret",
                    "URL": "https://example.test/private?user=42",
                    "PageTitle": "Private customer title",
                    "customId": "customer-42",
                    "sessionId": "session-42"
                },
                {
                    "totalSessionCount": "40",
                    "OS": "Other",
                    "Browser": "Edge"
                }
            ]
        },
        {
            "metricName": "Scroll Depth",
            "information": [
                {
                    "scrollDepthPercentage": 75.5,
                    "OS": "Android",
                    "Browser": "Chrome"
                }
            ]
        }
    ])
    .to_string()
}

fn fixture_scope() -> ClarityUxScope {
    let project = ProjectScope::new(
        "clarity-project",
        "site-01",
        "checkout-web",
        "deploy-2026-08-14",
        "https://example.test/products?campaign=private",
    )
    .expect("project scope");
    let metrics = MetricSet::new([Metric::Traffic, Metric::ScrollDepth]).expect("metrics");
    let dimensions = DimensionSet::new([Dimension::Os, Dimension::Browser, Dimension::Campaign])
        .expect("dimensions");
    ClarityUxScope::new(
        project,
        TimeWindow::new(2).expect("window"),
        metrics,
        dimensions,
        MissionScope::new("mission-ux", 7).expect("mission"),
        WorkProductScope::new("work-product-ux", 3).expect("work product"),
        ConsentScope::aggregate_ux("consent-grant-ux", 2).expect("consent"),
        PrivacyPolicy::strict_v1(),
    )
    .expect("scope")
}

type RecordedProvider = ClarityDataExportProvider<RecordingClarityTransport>;
type RecordedService = ClarityUxResultService<RecordedProvider>;

fn recorded_service(
    responses: impl IntoIterator<Item = Result<ClarityHttpResponse, ClarityTransportError>>,
) -> (ClarityUxScope, RecordedService) {
    let scope = fixture_scope();
    let secret = SecretReference::new("keyring-clarity-export", &scope, 4).expect("secret");
    let mut transport = RecordingClarityTransport::new();
    for response in responses {
        transport.push_response(response);
    }
    let provider =
        ClarityDataExportProvider::new(transport, ProviderProvenance::Recording).expect("provider");
    let service = ClarityUxResultService::new(scope.clone(), secret, provider).expect("service");
    (scope, service)
}

fn ok_response() -> Result<ClarityHttpResponse, ClarityTransportError> {
    Ok(ClarityHttpResponse::ok(fixture_body()))
}

fn error_response(status: u16) -> Result<ClarityHttpResponse, ClarityTransportError> {
    Ok(ClarityHttpResponse::new(
        status,
        r#"{"url":"https://private.example","sessionId":"raw-session"}"#,
    ))
}

fn request(scope: &ClarityUxScope) -> ClarityUxResultRequest {
    ClarityUxResultRequest::new(scope, Timestamp::new(TEST_AT).expect("timestamp"))
}

#[test]
fn exact_bounds_and_allowlisted_get_seam_are_enforced() {
    assert!(TimeWindow::new(0).is_err());
    assert!(TimeWindow::new(4).is_err());
    assert!(
        DimensionSet::new([
            Dimension::Browser,
            Dimension::Device,
            Dimension::Os,
            Dimension::Source,
        ])
        .is_err()
    );
    assert!(DimensionSet::new([Dimension::Browser, Dimension::Browser]).is_err());
    assert!(ProjectScope::new("p", "s", "a", "d", "http://example.test").is_err());

    let scope = fixture_scope();
    let get_request =
        ClarityDataExportGetRequest::new(&scope, Timestamp::new(TEST_AT).expect("timestamp"))
            .expect("get request");
    let path = get_request.path_and_query().expect("path");
    assert!(path.starts_with("https://www.clarity.ms/"));
    assert!(path.contains(CLARITY_DATA_EXPORT_PATH));
    assert!(path.contains("numOfDays=2"));
    assert!(path.contains("dimension1=OS"));
    assert!(path.contains("dimension2=Browser"));
    assert!(path.contains("dimension3=Campaign"));
    assert!(!path.contains("metric"));
    assert!(!path.contains("query="));
}

#[test]
fn complete_proposal_is_deterministic_and_privacy_preserving() {
    let (scope, mut service) = recorded_service([ok_response(), ok_response()]);
    let first = service.propose(&request(&scope)).expect("proposal");
    let second = service.propose(&request(&scope)).expect("same proposal");
    assert_eq!(first, second);
    assert_eq!(first.status(), ResultStatus::Complete);
    assert!(first.evidence.redactions.raw_api_body_dropped);
    assert!(first.evidence.redactions.url_values > 0);
    assert!(first.evidence.redactions.campaign_values > 0);
    assert!(first.evidence.redactions.page_title_values > 0);
    assert!(first.evidence.redactions.custom_identifier_values > 0);
    assert!(first.evidence.redactions.session_values > 0);
    assert!(!first.native_provider);
    assert!(!first.connected);
    assert!(!first.outcome_authority);
    assert_eq!(first.receipt(), second.receipt());

    let serialized = serde_json::to_string(&first).expect("proposal JSON");
    for forbidden in [
        "https://example.test/private?user=42",
        "launch-secret",
        "Private customer title",
        "customer-42",
        "session-42",
        "raw-session",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    assert!(serialized.contains("redacted"));
}

#[test]
fn raw_secret_reference_never_serializes_or_debug_prints_the_locator() {
    let scope = fixture_scope();
    let secret = SecretReference::new("keyring-clarity-export", &scope, 4).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("keyring-clarity-export"));
    assert!(!debug.contains("Bearer"));
    assert!(serde_json::to_string(&scope.digest()).is_ok());
}

#[test]
fn http_error_families_are_typed_without_body_leakage() {
    let (scope, mut service) = recorded_service([
        error_response(401),
        error_response(403),
        error_response(400),
        error_response(429),
    ]);
    let statuses = [
        (ResultStatus::AccessLost, ProviderErrorKind::Unauthorized),
        (ResultStatus::AccessLost, ProviderErrorKind::Forbidden),
        (ResultStatus::ProviderUnknown, ProviderErrorKind::BadRequest),
        (ResultStatus::RateLimited, ProviderErrorKind::RateLimited),
    ];
    for (status, error) in statuses {
        let proposal = service.propose(&request(&scope)).expect("typed status");
        assert_eq!(proposal.status, status);
        assert_eq!(proposal.evidence.error, Some(error));
        let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
        assert!(!serialized.contains("private.example"));
        assert!(!serialized.contains("raw-session"));
    }

    let (scope, mut service) = recorded_service([Err(ClarityTransportError::Expired)]);
    let proposal = service.propose(&request(&scope)).expect("expired state");
    assert_eq!(proposal.status, ResultStatus::Expired);
    assert_eq!(proposal.evidence.error, Some(ProviderErrorKind::Expired));
}

#[test]
fn quota_exhaustion_is_rate_limited_before_the_transport_call() {
    let (scope, mut service) = recorded_service((0..10).map(|_| ok_response()));
    for _ in 0..10 {
        assert_eq!(
            service
                .propose(&request(&scope))
                .expect("within quota")
                .status(),
            ResultStatus::Complete
        );
    }
    let proposal = service.propose(&request(&scope)).expect("quota state");
    assert_eq!(proposal.status, ResultStatus::RateLimited);
    assert_eq!(
        proposal.evidence.error,
        Some(ProviderErrorKind::QuotaExhausted)
    );
    assert_eq!(service.provider().transport().call_count(), 10);
}

#[test]
fn pagination_and_truncation_fail_closed() {
    let paginated = r#"[{"metricName":"Traffic","information":[],"nextPageToken":"secret"}]"#;
    let (scope, mut service) = recorded_service([Ok(ClarityHttpResponse::ok(paginated))]);
    let proposal = service.propose(&request(&scope)).expect("pagination state");
    assert_eq!(proposal.status, ResultStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.error,
        Some(ProviderErrorKind::NonPaginatedViolation)
    );
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("secret")
    );

    let rows = (0..=usize::from(CLARITY_MAX_RESPONSE_ROWS))
        .map(|_| json!({"totalSessionCount": 1, "OS": "Android"}))
        .collect::<Vec<_>>();
    let body = json!([{"metricName":"Traffic","information":rows}]).to_string();
    let (scope, mut service) = recorded_service([Ok(ClarityHttpResponse::ok(body))]);
    let proposal = service.propose(&request(&scope)).expect("truncation state");
    assert_eq!(proposal.status, ResultStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.error,
        Some(ProviderErrorKind::TruncatedResponse)
    );
}

#[test]
fn response_byte_bound_is_enforced_without_retaining_the_body() {
    let body = "x".repeat(CLARITY_MAX_RESPONSE_BYTES + 1);
    let (scope, mut service) = recorded_service([Ok(ClarityHttpResponse::ok(body))]);
    let proposal = service.propose(&request(&scope)).expect("bounded state");
    assert_eq!(proposal.status, ResultStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.error,
        Some(ProviderErrorKind::ResponseTooLarge)
    );
    assert!(proposal.evidence.redactions.raw_api_body_dropped);
}

#[test]
fn blocked_environment_is_explicitly_non_connected() {
    let scope = fixture_scope();
    let secret = SecretReference::new("keyring-clarity-export", &scope, 4).expect("secret");
    let provider =
        ClarityDataExportProvider::new(BlockedEnvTransport, ProviderProvenance::BlockedEnv)
            .expect("provider");
    let mut service =
        ClarityUxResultService::new(scope.clone(), secret, provider).expect("service");
    let proposal = service.propose(&request(&scope)).expect("blocked state");
    assert_eq!(proposal.status, ResultStatus::ProviderUnknown);
    assert_eq!(proposal.evidence.error, Some(ProviderErrorKind::BlockedEnv));
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::BlockedEnv);
    assert_eq!(CLARITY_UX_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!proposal.connected);
    assert!(!proposal.native_provider);
    assert!(!proposal.receipt().durable_native_receipt);
}

#[test]
fn loopback_and_fixture_transports_remain_non_native() {
    let scope = fixture_scope();
    let secret = SecretReference::new("keyring-clarity-export", &scope, 4).expect("secret");
    let mut loopback = crate::LoopbackClarityTransport::new(fixture_body());
    let request =
        ClarityDataExportGetRequest::new(&scope, Timestamp::new(TEST_AT).expect("timestamp"))
            .expect("request");
    let response = loopback.get(&request).expect("loopback response");
    assert_eq!(response.status(), 200);
    assert_eq!(loopback.requests().len(), 1);
    let fixture: FixtureClarityTransport = RecordingClarityTransport::new();
    let provider = ClarityDataExportProvider::new(fixture, ProviderProvenance::Fixture)
        .expect("fixture provider");
    assert!(!provider.definition().native);
    assert_eq!(secret.scope_digest(), &scope.digest());
}

#[test]
fn stale_mission_revision_scope_drift_and_revocation_fail_closed() {
    let (scope, mut service) = recorded_service([ok_response(), ok_response()]);
    let stale = request(&scope).with_mission_revision(Revision::new(8).expect("revision"));
    assert!(matches!(
        service.propose(&stale),
        Err(crate::ClarityUxResultServiceError::RequestOutOfScope)
    ));

    let mut consumer = MissionClarityUxConsumer::new(scope.clone());
    let proposal = service.propose(&request(&scope)).expect("proposal");
    let result = consumer.consume(proposal.clone()).expect("consume");
    assert_eq!(result.state, MissionResultState::Complete);
    assert!(result.receipt.read_only);
    assert!(!result.adopted_work_product);
    assert_eq!(
        consumer.consume(proposal),
        Err(crate::ConsumerError::Replay)
    );

    let mut tampered = service.propose(&request(&scope)).expect("proposal");
    tampered.proposal_digest = Digest::from_text("tampered-proposal");
    let mut consumer = MissionClarityUxConsumer::new(scope.clone());
    assert_eq!(
        consumer.consume(tampered),
        Err(crate::ConsumerError::Tampered)
    );

    let revocation = service.revoke_registration().expect("revoke registration");
    assert!(revocation.reversible);
    assert!(matches!(
        service.propose(&request(&scope)),
        Err(crate::ClarityUxResultServiceError::RegistrationRevoked)
    ));

    let (scope, mut service) = recorded_service([ok_response()]);
    service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        service.propose(&request(&scope)),
        Err(crate::ClarityUxResultServiceError::SecretRevoked)
    ));
}

#[test]
fn scope_and_privacy_policy_digests_fence_drift() {
    let scope = fixture_scope();
    let other_project = ProjectScope::new(
        "other-project",
        "site-01",
        "checkout-web",
        "deploy-2026-08-14",
        "https://example.test/products?campaign=private",
    )
    .expect("other project");
    let other_scope = ClarityUxScope::new(
        other_project,
        scope.time_window(),
        scope.metrics().clone(),
        scope.dimensions().clone(),
        scope.mission().clone(),
        scope.work_product().clone(),
        scope.consent().clone(),
        scope.privacy_policy().clone(),
    )
    .expect("other scope");
    let secret = SecretReference::new("keyring-clarity-export", &scope, 4).expect("secret");
    let provider = ClarityDataExportProvider::new(
        RecordingClarityTransport::new(),
        ProviderProvenance::Recording,
    )
    .expect("provider");
    assert!(ClarityUxResultService::new(other_scope, secret, provider).is_err());

    let mut policy: serde_json::Value =
        serde_json::to_value(PrivacyPolicy::strict_v1()).expect("policy JSON");
    policy["redactUrl"] = json!(false);
    let tampered = serde_json::from_value::<PrivacyPolicy>(policy).expect("tampered policy");
    assert!(
        ClarityUxScope::new(
            scope.project().clone(),
            scope.time_window(),
            scope.metrics().clone(),
            scope.dimensions().clone(),
            scope.mission().clone(),
            scope.work_product().clone(),
            scope.consent().clone(),
            tampered,
        )
        .is_err()
    );
}

#[test]
fn provider_evidence_digest_detects_tampering() {
    let (scope, mut service) = recorded_service([ok_response()]);
    let proposal = service.propose(&request(&scope)).expect("proposal");
    let get_request =
        ClarityDataExportGetRequest::new(&scope, Timestamp::new(TEST_AT).expect("timestamp"))
            .expect("request");
    let mut evidence: ClarityProviderEvidence = proposal.evidence.clone();
    evidence.rows = evidence.rows.saturating_add(1);
    assert!(!evidence.validate(&get_request, &crate::ClarityProviderDefinition::new()));
}
