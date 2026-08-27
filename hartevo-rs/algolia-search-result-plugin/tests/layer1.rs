use hartevo_algolia_search_result_plugin as algolia;
use serde_json::json;

fn scope(metric: algolia::AlgoliaSearchQualityMetric) -> algolia::AlgoliaSearchQualityScope {
    let spec = algolia::AlgoliaSearchQualityScopeSpec::new(
        algolia::AlgoliaRegion::Us,
        algolia::AlgoliaApplicationId::new("APP123").expect("application"),
        algolia::AlgoliaIndexName::new("products").expect("index"),
        algolia::Revision::new(7).expect("index revision"),
        algolia::AnalyticsWindow::new("2026-08-01", "2026-08-02", 3).expect("window"),
        metric,
        vec![algolia::AnalyticsTag::new("device:mobile phone").expect("tag")],
        algolia::ProjectBinding::new("project-1", 4).expect("project"),
        algolia::MissionBinding::new("mission-1", 5).expect("mission"),
        algolia::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        algolia::ConsentScope::new("consent-reference-1", 2).expect("consent"),
        algolia::AlgoliaAnalyticsAcl::analytics(8).expect("ACL"),
    );
    algolia::AlgoliaSearchQualityScope::new(spec).expect("scope")
}

fn secret() -> algolia::SecretReference {
    algolia::SecretReference::new("host-keyring-handle", 9).expect("secret reference")
}

fn service_with_response(
    metric: algolia::AlgoliaSearchQualityMetric,
    response: algolia::AlgoliaAnalyticsResponse,
) -> algolia::AlgoliaSearchQualityService<algolia::FixtureAlgoliaAnalyticsTransport> {
    let provider = algolia::AlgoliaAnalyticsProvider::new(
        scope(metric),
        secret(),
        algolia::FixtureAlgoliaAnalyticsTransport::new(response),
    )
    .expect("provider");
    algolia::AlgoliaSearchQualityService::new(provider).expect("service")
}

#[test]
fn aggregate_read_is_digest_fenced_and_redacted() {
    let payload = json!({
        "count": 100,
        "noResultCount": 12,
        "rate": 0.12,
        "dates": [
            {"date": "2026-08-02", "count": 50, "noResultCount": 5, "rate": 0.1, "search": "private query"},
            {"date": "2026-08-01", "count": 50, "noResultCount": 7, "rate": 0.14, "objectID": "record-123", "eventData": {"userToken": "user-1"}}
        ],
        "search": "private query",
        "userToken": "user-1",
        "ip": "192.0.2.1"
    });
    let response = algolia::AlgoliaAnalyticsResponse::json(200, &payload);
    let mut service =
        service_with_response(algolia::AlgoliaSearchQualityMetric::NoResultRate, response);
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(proposal.state(), algolia::AlgoliaEvidenceState::Complete);
    assert_eq!(
        proposal.recommendation.disposition,
        algolia::RecommendationDisposition::ReviewContentCoverage
    );
    assert!(proposal.recommendation.non_mutating);
    assert!(proposal.recommendation.provider_reported_only);
    assert!(!proposal.recommendation.claims_content_quality);
    assert!(!proposal.recommendation.claims_relevance_causality);
    assert!(!proposal.recommendation.claims_purchase_intent);
    assert!(!proposal.recommendation.claims_business_success);
    assert!(!proposal.native && !proposal.connected && !proposal.adopts_outcome);

    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("host-keyring-handle"));
    assert!(!serialized.contains("device:mobile phone"));
    assert!(!serialized.contains("private query"));
    assert!(!serialized.contains("user-1"));
    assert!(!serialized.contains("192.0.2.1"));
    assert!(!serialized.contains("record-123"));
    assert!(!serialized.contains("eventData"));

    let second = service.compile_proposal().expect("deterministic proposal");
    assert_eq!(proposal.evidence.digest(), second.evidence.digest());
    assert_eq!(proposal.digest(), second.digest());

    let reordered = algolia::AlgoliaAnalyticsResponse::json(
        200,
        &json!({
            "dates": [
                {"rate": 0.14, "noResultCount": 7, "count": 50, "date": "2026-08-01"},
                {"rate": 0.1, "noResultCount": 5, "count": 50, "date": "2026-08-02"}
            ],
            "rate": 0.12,
            "noResultCount": 12,
            "count": 100
        }),
    );
    let mut reordered_service =
        service_with_response(algolia::AlgoliaSearchQualityMetric::NoResultRate, reordered);
    let reordered_proposal = reordered_service
        .compile_proposal()
        .expect("reordered proposal");
    assert_eq!(
        proposal.evidence.digest(),
        reordered_proposal.evidence.digest()
    );
    assert_eq!(proposal.digest(), reordered_proposal.digest());
}

#[test]
fn all_allowlisted_metrics_use_get_paths_and_digest_only_tags() {
    let cases = [
        (
            algolia::AlgoliaSearchQualityMetric::SearchCount,
            algolia::AlgoliaAnalyticsPayload::search_count(
                40,
                vec![algolia::AlgoliaAnalyticsDay::search_count("2026-08-01", 40)],
            ),
            "/2/searches/count",
        ),
        (
            algolia::AlgoliaSearchQualityMetric::NoResultRate,
            algolia::AlgoliaAnalyticsPayload::no_result_rate(40, 4, Some(0.1), Vec::new()),
            "/2/searches/noResultRate",
        ),
        (
            algolia::AlgoliaSearchQualityMetric::ClickThroughRate,
            algolia::AlgoliaAnalyticsPayload::click_through_rate(40, 20, Some(0.5), Vec::new()),
            "/2/clicks/clickThroughRate",
        ),
        (
            algolia::AlgoliaSearchQualityMetric::ConversionRate,
            algolia::AlgoliaAnalyticsPayload::conversion_rate(40, 8, Some(0.2), Vec::new()),
            "/2/conversions/conversionRate",
        ),
    ];
    for (metric, payload, path) in cases {
        let response = algolia::AlgoliaAnalyticsResponse::json(200, &payload);
        let provider = algolia::AlgoliaAnalyticsProvider::new(
            scope(metric),
            secret(),
            algolia::RecordingAlgoliaAnalyticsTransport::new(response),
        )
        .expect("provider");
        let mut service = algolia::AlgoliaSearchQualityService::new(provider).expect("service");
        let _ = service.read().expect("read");
        let request = &service.provider().transport().requests()[0];
        assert_eq!(request.method, algolia::AlgoliaHttpMethod::Get);
        assert_eq!(request.host, "https://analytics.us.algolia.com");
        assert_eq!(request.path, path);
        assert_eq!(request.tag_digests.len(), 1);
        assert_eq!(request.tag_digests[0].len(), 64);
        assert!(request.is_allowlisted());
        assert!(
            !serde_json::to_string(request)
                .expect("request serializes")
                .contains("device:mobile phone")
        );
    }
}

#[test]
fn status_matrix_is_normalized_without_native_claims() {
    let cases = [
        (402, algolia::AlgoliaEvidenceState::PlanUnavailable),
        (403, algolia::AlgoliaEvidenceState::AccessLost),
        (404, algolia::AlgoliaEvidenceState::AccessLost),
        (429, algolia::AlgoliaEvidenceState::RateLimited),
        (500, algolia::AlgoliaEvidenceState::ProviderUnknown),
        (400, algolia::AlgoliaEvidenceState::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let response = algolia::AlgoliaAnalyticsResponse::json(
            status,
            &json!({
                "message": "raw provider diagnostic",
                "query": "private query"
            }),
        );
        let mut service =
            service_with_response(algolia::AlgoliaSearchQualityMetric::SearchCount, response);
        let evidence = service.read().expect("status becomes typed evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.native && !evidence.connected);
        assert!(evidence.aggregate.is_none());
        let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
        assert!(!serialized.contains("raw provider diagnostic"));
        assert!(!serialized.contains("private query"));
    }
}

#[test]
fn blocked_env_is_access_lost_and_never_connected() {
    let provider = algolia::AlgoliaAnalyticsProvider::new(
        scope(algolia::AlgoliaSearchQualityMetric::SearchCount),
        secret(),
        algolia::BlockedEnvAlgoliaAnalyticsTransport,
    )
    .expect("provider");
    let mut service = algolia::AlgoliaSearchQualityService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, algolia::AlgoliaEvidenceState::AccessLost);
    assert_eq!(
        evidence.classification,
        algolia::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        algolia::TransportProvenance::BlockedEnv
    );
    assert!(!evidence.native && !evidence.connected);
}

#[test]
fn registration_is_reversible_revocable_and_rotates_digest() {
    let response = algolia::AlgoliaAnalyticsResponse::json(
        200,
        &algolia::AlgoliaAnalyticsPayload::search_count(10, Vec::new()),
    );
    let mut service =
        service_with_response(algolia::AlgoliaSearchQualityMetric::SearchCount, response);
    let original = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    let revocation = service.provider_mut().revoke().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, original);
    assert_ne!(revocation.registration_digest, original);
    assert!(matches!(
        service.read(),
        Err(algolia::AlgoliaSearchQualityServiceError::RegistrationRevoked)
    ));
    service.provider_mut().restore().expect("restore");
    assert_ne!(service.registration().registration_digest, original);
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(
            algolia::AlgoliaSearchQualityServiceError::RegistrationRevoked
                | algolia::AlgoliaSearchQualityServiceError::EvidenceMismatch
        )
    ));
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.registration_digest, original);
}

#[test]
fn mission_consumer_rejects_replay_and_keeps_outcome_authority_false() {
    let response = algolia::AlgoliaAnalyticsResponse::json(
        200,
        &algolia::AlgoliaAnalyticsPayload::search_count(
            10,
            vec![algolia::AlgoliaAnalyticsDay::search_count("2026-08-01", 10)],
        ),
    );
    let provider = algolia::AlgoliaAnalyticsProvider::new(
        scope(algolia::AlgoliaSearchQualityMetric::SearchCount),
        secret(),
        algolia::FixtureAlgoliaAnalyticsTransport::new(response),
    )
    .expect("provider");
    let mut consumer = algolia::MissionAlgoliaSearchConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        algolia::MissionAlgoliaSearchResultState::DecisionReady
    );
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected && !result.adopts_outcome);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(algolia::MissionAlgoliaSearchConsumerError::ReplayDetected)
    ));
}

#[test]
fn bounds_and_rate_receipts_fail_closed() {
    assert!(algolia::AnalyticsWindow::new("2026-01-01", "2026-02-01", 1).is_err());
    assert!(algolia::AnalyticsTag::new(" ").is_err());
    assert!(algolia::AlgoliaAnalyticsAcl::new([], 1).is_err());
    assert!(algolia::AlgoliaRateLimitReceipt::new(101, None, None, false).is_err());
    let oversized = algolia::AlgoliaAnalyticsResponse::new(
        200,
        vec![b'x'; algolia::MAX_RESPONSE_BYTES + 1],
        algolia::AlgoliaRateLimitReceipt::default(),
    );
    let mut service =
        service_with_response(algolia::AlgoliaSearchQualityMetric::SearchCount, oversized);
    let evidence = service.read().expect("oversized response becomes evidence");
    assert_eq!(
        evidence.state,
        algolia::AlgoliaEvidenceState::ProviderUnknown
    );
}
