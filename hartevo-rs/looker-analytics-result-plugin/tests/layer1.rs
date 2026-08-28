use hartevo_looker_analytics_result_plugin as looker;
use serde_json::{Value, json};

fn scope() -> looker::LookerAnalyticsScope {
    let spec = looker::LookerAnalyticsScopeSpec::new(
        looker::Instance::new("https://analytics.example.com").expect("instance"),
        Some(looker::FolderId::new("folder-1").expect("folder")),
        Some(looker::DashboardId::new("dashboard-1").expect("dashboard")),
        Some(looker::LookId::new("look-1").expect("look")),
        Some(looker::QueryId::new("query-1").expect("query")),
        looker::ModelName::new("analytics").expect("model"),
        looker::ExploreName::new("orders").expect("explore"),
        looker::DateWindow::new("2026-08-01", "2026-08-07").expect("date window"),
        looker::ProjectBinding::new("project-1", 4).expect("project"),
        looker::MissionBinding::new("mission-1", 5).expect("mission"),
        looker::WorkProductBinding::new("work-product-1", 6).expect("work product"),
        looker::LookerPermissionSnapshot::read_only(8).expect("permissions"),
        looker::ConsentScope::new("consent-reference-1", 9).expect("consent"),
        7,
    )
    .expect("scope spec");
    looker::LookerAnalyticsScope::new(spec).expect("scope")
}

fn secret() -> looker::SecretReference {
    looker::SecretReference::new("client-secret-reference", 3).expect("secret reference")
}

fn search_scope() -> looker::LookerAnalyticsScope {
    let mut value = serde_json::to_value(scope().spec()).expect("scope value");
    value["dashboard"] = Value::Null;
    value["look"] = Value::Null;
    value["query"] = Value::Null;
    let spec: looker::LookerAnalyticsScopeSpec =
        serde_json::from_value(value).expect("search scope spec");
    looker::LookerAnalyticsScope::new(spec).expect("search scope")
}

fn dashboard_payload(revision: u64) -> Value {
    json!({
        "id": "dashboard-1",
        "title": "Private revenue dashboard",
        "description": "private dashboard description must not escape",
        "folder_id": "folder-1",
        "user_id": "private-user-1",
        "revision": revision,
        "dashboard_elements": [
            {"id": "element-1", "query": {"sql": "SELECT secret FROM warehouse"}},
            {"id": "element-2", "body_text": "private tile text"}
        ]
    })
}

fn service_with_response(
    response: looker::LookerResponse,
) -> looker::LookerAnalyticsResultService<looker::FixtureLookerTransport> {
    let provider = looker::LookerProvider::new(
        scope(),
        secret(),
        looker::FixtureLookerTransport::new(response),
    )
    .expect("provider");
    looker::LookerAnalyticsResultService::new(provider).expect("service")
}

#[test]
fn dashboard_metadata_is_bounded_redacted_and_digest_fenced() {
    let mut service =
        service_with_response(looker::LookerResponse::json(200, &dashboard_payload(7)));
    let key = looker::IdempotencyKey::new("dashboard-read-1").expect("key");
    let request = looker::LookerAnalyticsRequest::dashboard(service.scope(), &key)
        .expect("dashboard request");
    let proposal = service.propose(&request).expect("proposal");

    assert_eq!(proposal.state(), looker::LookerEvidenceState::Complete);
    assert_eq!(
        proposal
            .evidence()
            .aggregate()
            .expect("aggregate")
            .item_count,
        1
    );
    assert_eq!(
        proposal.evidence().aggregate().expect("aggregate").items[0].field_count,
        2
    );
    assert!(proposal.evidence().redactions.is_complete());
    assert!(!proposal.evidence().native_provider);
    assert!(!proposal.evidence().connected);
    assert!(!proposal.evidence().first_party);
    assert!(!proposal.evidence().causal_claim);
    assert!(!proposal.evidence().outcome_authority);

    let encoded = serde_json::to_string(&proposal).expect("proposal serializes");
    for forbidden in [
        "client-secret-reference",
        "Private revenue dashboard",
        "private dashboard description",
        "private-user-1",
        "SELECT secret FROM warehouse",
        "private tile text",
    ] {
        assert!(!encoded.contains(forbidden), "leaked {forbidden}");
    }
    assert!(!format!("{service:?}").contains("client-secret-reference"));
    assert!(!format!("{:?}", service.provider().transport()).contains("client-secret-reference"));

    let replay = service.propose(&request).expect("idempotent replay");
    assert!(replay.replayed);
    assert_eq!(replay.proposal_digest, proposal.proposal_digest);
    assert_eq!(
        replay.evidence.evidence_digest,
        proposal.evidence.evidence_digest
    );
}

#[test]
fn search_is_get_only_and_carries_only_query_digest() {
    let payload = json!({
        "items": [
            {"id": "dashboard-1", "title": "Revenue", "folder_id": "folder-1"},
            {"id": "dashboard-2", "title": "Forecast", "folder_id": "folder-1"}
        ],
        "total": 2,
        "next_page_token": "opaque-look-pagination-token"
    });
    let provider = looker::LookerProvider::new(
        search_scope(),
        secret(),
        looker::RecordingLookerTransport::new(looker::LookerResponse::json(200, &payload)),
    )
    .expect("provider");
    let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
    let key = looker::IdempotencyKey::new("search-read-1").expect("key");
    let request = looker::LookerAnalyticsRequest::search_dashboards(
        service.scope(),
        "private customer search",
        &key,
    )
    .expect("search request");
    let page_token =
        looker::OpaquePageToken::new("opaque-look-pagination-token").expect("page token");
    let request = request.with_page_token(&page_token);
    let proposal = service.propose(&request).expect("search proposal");
    assert_eq!(
        proposal.evidence.aggregate().expect("aggregate").item_count,
        2
    );
    assert_eq!(
        proposal
            .evidence
            .aggregate()
            .expect("aggregate")
            .next_page_token_digest
            .as_ref(),
        Some(page_token.digest())
    );
    let recorded = &service.provider().transport().requests()[0];
    assert_eq!(recorded.method, looker::LookerHttpMethod::Get);
    assert_eq!(recorded.path, "/dashboards/search");
    assert!(recorded.search_digest.is_some());
    assert_eq!(
        recorded.page_token_digest.as_ref(),
        Some(page_token.digest())
    );
    assert!(
        !serde_json::to_string(recorded)
            .expect("request serializes")
            .contains("private customer search")
    );
    assert!(
        !serde_json::to_string(recorded)
            .expect("request serializes")
            .contains("opaque-look-pagination-token")
    );
    assert!(recorded.is_allowlisted());

    let forbidden = looker::LookerProviderRequest {
        method: looker::LookerHttpMethod::Get,
        host: "https://analytics.example.com".to_owned(),
        path: "/queries/query-1/run/json".to_owned(),
        operation: looker::LookerOperation::QueryMetadata,
        scope_digest: service.scope().scope_digest().clone(),
        revision_digest: service.scope().revision_digest().clone(),
        target_id_digest: Some(looker::QueryId::new("query-1").expect("query").digest()),
        search_digest: None,
        page_token_digest: None,
        idempotency_key_digest: key.digest().clone(),
        page_size: 1,
    };
    assert!(!forbidden.is_allowlisted());
}

#[test]
fn provider_paths_cover_metadata_reads_without_mutation() {
    let payload = json!({"id": "dashboard-1", "title": "Dashboard", "revision": 7});
    let provider = looker::LookerProvider::new(
        scope(),
        secret(),
        looker::RecordingLookerTransport::new(looker::LookerResponse::json(200, &payload)),
    )
    .expect("provider");
    let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
    let key = looker::IdempotencyKey::new("path-read-1").expect("key");
    let request =
        looker::LookerAnalyticsRequest::dashboard(service.scope(), &key).expect("request");
    service.read_request(&request).expect("read");
    let recorded = &service.provider().transport().requests()[0];
    assert_eq!(recorded.path, "/dashboards/dashboard-1");
    assert_eq!(
        recorded.operation,
        looker::LookerOperation::DashboardMetadata
    );
    assert!(!recorded.path.contains("update"));
    assert!(!recorded.path.contains("delete"));
    assert!(!recorded.path.contains("run"));
}

#[test]
fn all_scoped_metadata_operations_are_bounded_get_reads() {
    type RequestFactory = fn(
        &looker::LookerAnalyticsScope,
        &looker::IdempotencyKey,
    ) -> Result<looker::LookerAnalyticsRequest, looker::ModelError>;
    let cases: [(&str, RequestFactory, Value, &str); 6] = [
        (
            "look",
            looker::LookerAnalyticsRequest::look,
            json!({"id": "look-1", "title": "Orders", "folder_id": "folder-1", "revision": 7}),
            "/looks/look-1",
        ),
        (
            "folder",
            looker::LookerAnalyticsRequest::folder,
            json!({"id": "folder-1", "name": "Shared", "child_count": 2, "revision": 7}),
            "/folders/folder-1",
        ),
        (
            "query",
            looker::LookerAnalyticsRequest::query,
            json!({"id": "query-1", "model": "analytics", "view": "orders", "fields": ["orders.id"], "filters": {"private": "secret"}, "revision": 7}),
            "/queries/query-1",
        ),
        (
            "model",
            looker::LookerAnalyticsRequest::model,
            json!({"name": "analytics", "explores": ["orders"], "revision": 7}),
            "/lookml_models/analytics",
        ),
        (
            "explore",
            looker::LookerAnalyticsRequest::explore,
            json!({"name": "orders", "model": "analytics", "fields": ["orders.id", "orders.created_date"], "revision": 7}),
            "/lookml_models/analytics/explores/orders",
        ),
        (
            "aggregate",
            looker::LookerAnalyticsRequest::aggregate_metadata,
            json!({"items": [{"id": "content-1", "name": "Dashboard metadata"}], "total": 1}),
            "/content/search",
        ),
    ];
    for (label, make_request, payload, expected_path) in cases {
        let provider = looker::LookerProvider::new(
            scope(),
            secret(),
            looker::RecordingLookerTransport::new(looker::LookerResponse::json(200, &payload)),
        )
        .expect("provider");
        let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
        let key = looker::IdempotencyKey::new(format!("operation-{label}")).expect("key");
        let request = make_request(service.scope(), &key).expect("request");
        let evidence = service.read_request(&request).expect("evidence");
        assert!(matches!(
            evidence.state,
            looker::LookerEvidenceState::Complete | looker::LookerEvidenceState::Empty
        ));
        let recorded = &service.provider().transport().requests()[0];
        assert_eq!(recorded.path, expected_path);
        assert_eq!(recorded.method, looker::LookerHttpMethod::Get);
        assert!(recorded.is_allowlisted());
        assert!(!recorded.path.contains("run"));
    }

    let provider = looker::LookerProvider::new(
        scope(),
        secret(),
        looker::RecordingLookerTransport::new(looker::LookerResponse::json(
            200,
            &json!({"items": [{"id": "look-1", "folder_id": "folder-1", "revision": 7}]}),
        )),
    )
    .expect("provider");
    let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
    let request = looker::LookerAnalyticsRequest::search(
        service.scope(),
        looker::LookerSearchKind::Looks,
        "orders",
        &looker::IdempotencyKey::new("search-look").expect("key"),
    )
    .expect("search request");
    service.read_request(&request).expect("search evidence");
    assert_eq!(
        service.provider().transport().requests()[0].path,
        "/looks/search"
    );
}

#[test]
fn wrong_resource_revision_is_rejected_as_provider_tamper() {
    let mut service =
        service_with_response(looker::LookerResponse::json(200, &dashboard_payload(8)));
    let key = looker::IdempotencyKey::new("revision-read-1").expect("key");
    let request =
        looker::LookerAnalyticsRequest::dashboard(service.scope(), &key).expect("request");
    assert!(matches!(
        service.read_request(&request),
        Err(looker::LookerAnalyticsResultServiceError::EvidenceTampered)
    ));
}

#[test]
fn response_scope_drift_is_rejected_without_returning_raw_body() {
    let mut service = service_with_response(looker::LookerResponse::json(
        200,
        &json!({"id": "dashboard-outside-scope", "revision": 7}),
    ));
    let key = looker::IdempotencyKey::new("scope-read-1").expect("key");
    let request =
        looker::LookerAnalyticsRequest::dashboard(service.scope(), &key).expect("request");
    let error = service.read_request(&request).expect_err("scope drift");
    assert!(matches!(
        error,
        looker::LookerAnalyticsResultServiceError::EvidenceTampered
    ));
    assert!(!error.to_string().contains("dashboard-outside-scope"));
}

#[test]
fn partial_and_rate_limited_states_are_typed() {
    let mut empty_service = service_with_response(looker::LookerResponse::json(
        200,
        &json!({"items": [], "total": 0}),
    ));
    assert_eq!(
        empty_service.read().expect("empty evidence").state,
        looker::LookerEvidenceState::Empty
    );

    let partial = json!({
        "partial": true,
        "items": [{"id": "dashboard-1", "title": "Revenue", "revision": 7}],
        "total": 3
    });
    let mut partial_service = service_with_response(looker::LookerResponse::json(200, &partial));
    let partial_evidence = partial_service.read().expect("partial evidence");
    assert_eq!(partial_evidence.state, looker::LookerEvidenceState::Partial);
    assert_eq!(
        partial_evidence.classification,
        looker::EvidenceClassification::Partial
    );

    let mut partial_status_service = service_with_response(looker::LookerResponse::json(
        206,
        &json!({"id": "dashboard-1", "revision": 7}),
    ));
    assert_eq!(
        partial_status_service
            .read()
            .expect("partial status evidence")
            .state,
        looker::LookerEvidenceState::Partial
    );

    let exhausted =
        looker::LookerRateLimitReceipt::new(60, Some(0), Some(60), true).expect("rate receipt");
    let mut rate_service = service_with_response(looker::LookerResponse::json_with_rate_limit(
        200,
        &json!({"id": "dashboard-1", "revision": 7}),
        exhausted,
    ));
    let rate_evidence = rate_service.read().expect("rate-limited evidence");
    assert_eq!(
        rate_evidence.state,
        looker::LookerEvidenceState::RateLimited
    );
    assert_eq!(
        rate_evidence.classification,
        looker::EvidenceClassification::RateLimited
    );
    assert!(rate_evidence.aggregate.is_none());
}

#[test]
fn blocked_env_is_access_loss_and_all_test_provenance_is_non_native() {
    let provider =
        looker::LookerProvider::new(scope(), secret(), looker::BlockedEnvLookerTransport)
            .expect("provider");
    let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.state, looker::LookerEvidenceState::AccessLost);
    assert_eq!(
        evidence.classification,
        looker::EvidenceClassification::BlockedEnv
    );
    assert_eq!(
        evidence.provenance,
        looker::LookerTransportProvenance::BlockedEnv
    );
    assert!(!evidence.connected && !evidence.native_provider && !evidence.first_party);

    for provenance in [
        looker::LookerTransportProvenance::Fixture,
        looker::LookerTransportProvenance::Recording,
        looker::LookerTransportProvenance::Fake,
        looker::LookerTransportProvenance::Loopback,
        looker::LookerTransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn registration_and_secret_revocation_are_reversible_and_digest_bound() {
    let mut service =
        service_with_response(looker::LookerResponse::json(200, &dashboard_payload(7)));
    let original_registration = service.registration().registration_digest.clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_registration_digest, original_registration);
    assert_ne!(revoked.registration_digest, original_registration);
    assert!(matches!(
        service.read(),
        Err(looker::LookerAnalyticsResultServiceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert_ne!(
        service.registration().registration_digest,
        original_registration
    );
    service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        service.read(),
        Err(looker::LookerAnalyticsResultServiceError::SecretRevoked)
    ));
}

#[test]
fn mission_consumer_rejects_replay_and_tampering_without_adoption() {
    let mut service =
        service_with_response(looker::LookerResponse::json(200, &dashboard_payload(7)));
    let scope = service.scope().clone();
    let registration = service.registration().clone();
    let key = looker::IdempotencyKey::new("consumer-read-1").expect("key");
    let request = looker::LookerAnalyticsRequest::dashboard(&scope, &key).expect("request");
    let proposal = service.propose(&request).expect("proposal");
    let mut consumer =
        looker::MissionLookerAnalyticsConsumer::new_bound(scope, registration).expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("result");
    assert_eq!(
        result.state,
        looker::MissionLookerAnalyticsResultState::DecisionReady
    );
    assert!(result.review_only);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adopted);
    assert!(matches!(
        consumer.consume(proposal.clone()),
        Err(looker::MissionLookerAnalyticsConsumerError::ReplayDetected)
    ));

    let mut tampered = proposal;
    tampered.evidence.native_provider = true;
    assert!(matches!(
        consumer.consume(tampered),
        Err(looker::MissionLookerAnalyticsConsumerError::Tampered)
    ));
}

#[test]
fn idempotency_conflict_and_request_scope_drift_fail_closed() {
    let mut service =
        service_with_response(looker::LookerResponse::json(200, &dashboard_payload(7)));
    let key = looker::IdempotencyKey::new("same-key").expect("key");
    let first = looker::LookerAnalyticsRequest::dashboard(service.scope(), &key).expect("request");
    service.propose(&first).expect("first");
    let second =
        looker::LookerAnalyticsRequest::search_dashboards(service.scope(), "different query", &key)
            .expect("second request");
    assert!(matches!(
        service.propose(&second),
        Err(looker::LookerAnalyticsResultServiceError::IdempotencyConflict)
    ));

    let other_scope = {
        let mut value = serde_json::to_value(service.scope().spec()).expect("scope value");
        value["dashboard"] = json!("dashboard-2");
        let spec: looker::LookerAnalyticsScopeSpec =
            serde_json::from_value(value).expect("other spec");
        looker::LookerAnalyticsScope::new(spec).expect("other scope")
    };
    let other_request = looker::LookerAnalyticsRequest::dashboard(
        &other_scope,
        &looker::IdempotencyKey::new("other-key").expect("other key"),
    )
    .expect("other request");
    assert!(matches!(
        service.propose(&other_request),
        Err(looker::LookerAnalyticsResultServiceError::ScopeMismatch)
    ));
}

#[test]
fn transport_errors_never_expose_payload_or_secret_material() {
    let mut fake = looker::FakeLookerTransport::default();
    fake.push_error(looker::LookerTransportError::Partial);
    let provider = looker::LookerProvider::new(scope(), secret(), fake).expect("provider");
    let mut service = looker::LookerAnalyticsResultService::new(provider).expect("service");
    let evidence = service.read().expect("partial transport evidence");
    assert_eq!(evidence.state, looker::LookerEvidenceState::Partial);
    let encoded = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!encoded.contains("client-secret-reference"));
    assert!(!encoded.contains("Partial"));
}
