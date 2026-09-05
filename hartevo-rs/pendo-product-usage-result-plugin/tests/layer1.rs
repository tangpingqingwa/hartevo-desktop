use hartevo_pendo_product_usage_result_plugin as pendo;
use serde_json::json;

const NOW: i64 = 1_762_000_000;

fn scope(target: pendo::TargetReference) -> pendo::PendoProductUsageScope {
    pendo::PendoProductUsageScope::new(
        pendo::SubscriptionId::new("subscription-01").expect("subscription"),
        pendo::ApplicationId::new("application-01").expect("application"),
        pendo::AccountScope::new("account-private").expect("account"),
        pendo::VisitorKind::All,
        target,
        pendo::SegmentScope::all(),
        pendo::TimeWindow::for_days(NOW, 7).expect("window"),
        pendo::ProjectBinding::new("project-pendo", 1).expect("project"),
        pendo::MissionBinding::new("mission-pendo", 2).expect("mission"),
        pendo::WorkProductBinding::new("work-product-pendo", 3).expect("work product"),
        pendo::ConsentScope::new("consent-pendo", 4).expect("consent"),
    )
    .expect("scope")
}

fn page_scope() -> pendo::PendoProductUsageScope {
    scope(pendo::TargetReference::page("page-private").expect("page"))
}

fn aggregate_body() -> String {
    json!({
        "asOf": NOW,
        "rows": [
            {"bucket": "day-1", "metric": "page_views", "value": 12},
            {"bucket": "day-2", "metric": "page_views", "value": 18}
        ]
    })
    .to_string()
}

fn request(scope: &pendo::PendoProductUsageScope) -> pendo::PendoUsageRequest {
    pendo::PendoUsageRequest::aggregate(
        scope,
        pendo::AdoptionMetric::PageViews,
        pendo::Timestamp::new(NOW).expect("timestamp"),
    )
    .expect("request")
}

fn recorded_service(
    responses: impl IntoIterator<Item = Result<pendo::PendoHttpResponse, pendo::PendoTransportError>>,
) -> (
    pendo::PendoProductUsageScope,
    pendo::PendoProductUsageResultService<pendo::RecordingPendoTransport>,
) {
    let scope = page_scope();
    let secret =
        pendo::SecretReference::new("keyring://pendo-integration-key", &scope, 1).expect("secret");
    let mut transport = pendo::RecordingPendoTransport::new();
    for response in responses {
        transport.push_response(response);
    }
    let provider = pendo::PendoProvider::new(transport, pendo::ProviderProvenance::Recording)
        .expect("provider");
    let service = pendo::PendoProductUsageResultService::new(scope.clone(), secret, provider)
        .expect("service");
    (scope, service)
}

fn ok_body() -> Result<pendo::PendoHttpResponse, pendo::PendoTransportError> {
    Ok(pendo::PendoHttpResponse::ok(aggregate_body()))
}

#[test]
fn contract_is_machine_readable_and_authority_is_negative() {
    pendo::validate_contract().expect("contract validation");
    let document: serde_json::Value =
        serde_json::from_str(pendo::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON)
            .expect("contract JSON");
    assert_eq!(document["layer"], 1);
    assert_eq!(
        document["service"]["id"],
        pendo::PENDO_PRODUCT_USAGE_RESULT_SERVICE_ID
    );
    assert_eq!(
        document["provider"]["id"],
        pendo::PENDO_PRODUCT_USAGE_RESULT_PROVIDER_ID
    );
    assert_eq!(document["allowlist"]["writes"], json!([]));
    assert_eq!(document["provider"]["allowlistedWrites"], json!([]));
    assert!(!pendo::Layer1Authority::connected());
    assert!(!pendo::Layer1Authority::native_provider());
    assert!(!pendo::Layer1Authority::first_party());
    assert!(!pendo::Layer1Authority::durable_provider_receipt());
    assert!(!pendo::Layer1Authority::independent_readback());
    assert!(!pendo::Layer1Authority::adopted_work_product());
    assert!(!pendo::Layer1Authority::adopted_outcome());
    assert!(!pendo::Layer1Authority::causal_claims());
    assert!(!pendo::Layer1Authority::external_writes());
}

#[test]
fn scope_is_exact_and_secret_reference_is_opaque() {
    let scope = page_scope();
    let serialized_scope = serde_json::to_string(&scope).expect("scope JSON");
    for forbidden in [
        "account-private",
        "page-private",
        "keyring://pendo-integration-key",
    ] {
        assert!(!serialized_scope.contains(forbidden), "leaked {forbidden}");
    }
    assert_eq!(scope.target().kind(), pendo::TargetKind::Page);
    assert_eq!(scope.visitor_kind(), pendo::VisitorKind::All);
    assert!(scope.segment().is_all());

    let secret =
        pendo::SecretReference::new("keyring://pendo-integration-key", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("keyring://pendo-integration-key"));
    assert!(serde_json::to_string(&secret).is_err());
    assert!(serde_json::from_str::<pendo::SecretReference>("null").is_err());
}

#[test]
fn requests_are_digest_bound_and_use_only_allowlisted_read_seams() {
    let scope = page_scope();
    let secret = pendo::SecretReference::new("keyring-pendo", &scope, 1).expect("secret");
    let aggregate = request(&scope);
    let aggregate_request = pendo::PendoReadRequest::new(&scope, &aggregate, secret.digest())
        .expect("aggregate request");
    assert_eq!(aggregate_request.method, pendo::PendoHttpMethod::Post);
    assert_eq!(aggregate_request.path, pendo::PENDO_AGGREGATION_PATH);
    assert!(aggregate_request.body_digest.is_some());
    assert!(aggregate_request.is_allowlisted());
    assert!(
        !serde_json::to_string(&aggregate_request)
            .expect("request JSON")
            .contains("keyring-pendo")
    );

    let metadata = pendo::PendoUsageRequest::report_metadata(
        &scope,
        pendo::Timestamp::new(NOW).expect("timestamp"),
    )
    .expect("metadata request");
    let metadata_request = pendo::PendoReadRequest::new(&scope, &metadata, secret.digest())
        .expect("metadata read request");
    assert_eq!(metadata_request.method, pendo::PendoHttpMethod::Get);
    assert_eq!(metadata_request.path, "/api/v1/page");
    assert!(metadata_request.body_digest.is_none());
    assert!(metadata_request.is_allowlisted());
}

#[test]
fn aggregate_proposal_is_deterministic_and_record_verify_are_bounded() {
    let (scope, mut service) = recorded_service([ok_body(), ok_body()]);
    let first = service.propose(&request(&scope)).expect("first proposal");
    let second = service.propose(&request(&scope)).expect("second proposal");
    assert_eq!(first, second);
    assert_eq!(first.evidence.state, pendo::EvidenceState::Present);
    assert_eq!(
        first.evidence.aggregate.as_ref().expect("aggregate").total,
        30
    );
    assert!(first.evidence.redactions.raw_response_body_dropped);
    assert!(first.evidence.is_bounded_non_native());
    assert_eq!(first.evidence.read_receipt.method, "POST");
    assert_eq!(
        first.evidence.read_receipt.path,
        pendo::PENDO_AGGREGATION_PATH
    );
    assert!(!first.evidence.read_receipt.body_retained);
    assert!(!first.connected);
    assert!(!first.native_provider);
    assert!(!first.first_party);
    assert!(!first.causal_claim);

    let serialized = serde_json::to_string(&first).expect("proposal JSON");
    for forbidden in [
        "page-private",
        "account-private",
        "keyring-pendo",
        "visitorId",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }

    let verification = service.verify_proposal(&first).expect("verification");
    assert!(verification.verified);
    assert!(verification.tamper_evident);
    assert!(!verification.independent_native_readback);
    let observation = service.record_observation(&first).expect("observation");
    assert!(observation.recorded);
    assert!(!observation.durable);
    assert!(!observation.native);
    assert!(!observation.connected);
    assert!(!observation.independent_readback);

    let mut consumer = pendo::MissionPendoUsageConsumer::new(scope);
    let result = consumer.consume(first.clone()).expect("consumer result");
    assert_eq!(result.state, pendo::MissionPendoUsageResultState::Present);
    assert!(!result.adopted_work_product);
    assert!(!result.outcome_authority);
    assert!(!result.causal_claim);
    assert_eq!(consumer.consumed_count(), 1);
    assert_eq!(
        consumer.consume(first),
        Err(pendo::MissionPendoUsageConsumerError::Replay)
    );
}

#[test]
fn metadata_read_hashes_labels_and_stays_non_native() {
    let scope = scope(pendo::TargetReference::feature("feature-private").expect("feature"));
    let secret = pendo::SecretReference::new("keyring-pendo", &scope, 1).expect("secret");
    let body = json!({
        "id": "feature-private",
        "name": "Billing private label",
        "appId": "application-private",
        "kind": "feature",
        "version": "v7",
        "updatedAt": NOW
    })
    .to_string();
    let mut transport = pendo::RecordingPendoTransport::new();
    transport.push_response(Ok(pendo::PendoHttpResponse::ok(body)));
    let provider = pendo::PendoProvider::new(transport, pendo::ProviderProvenance::Recording)
        .expect("provider");
    let mut service = pendo::PendoProductUsageResultService::new(scope.clone(), secret, provider)
        .expect("service");
    let evidence = service
        .read_report_metadata(pendo::Timestamp::new(NOW).expect("timestamp"))
        .expect("metadata evidence");
    assert_eq!(evidence.state, pendo::EvidenceState::Present);
    let metadata = evidence.metadata.clone().expect("metadata");
    assert_eq!(metadata.target, pendo::TargetKind::Feature);
    assert!(metadata.label_digest.is_some());
    assert_eq!(metadata.field_count, 6);
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    for forbidden in [
        "feature-private",
        "Billing private label",
        "application-private",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn visitor_pii_and_event_rows_fail_closed_without_body_leakage() {
    let body = json!({
        "rows": [{
            "bucket": "day-1",
            "value": 4,
            "visitorId": "visitor-private",
            "email": "person@example.test",
            "eventPayload": {"secret": "raw-event"}
        }]
    })
    .to_string();
    let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::ok(body))]);
    let proposal = service
        .propose(&request(&scope))
        .expect("bounded failure proposal");
    assert_eq!(
        proposal.evidence.state,
        pendo::EvidenceState::ProviderUnknown
    );
    assert_eq!(
        proposal.evidence.error,
        Some(pendo::ProviderErrorKind::PrivacyViolation)
    );
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in ["visitor-private", "person@example.test", "raw-event"] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
}

#[test]
fn response_and_row_bounds_fail_closed() {
    let oversized = "x".repeat(pendo::MAX_RESPONSE_BYTES + 1);
    let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::ok(oversized))]);
    let evidence = service.read(&request(&scope)).expect("oversized evidence");
    assert_eq!(evidence.state, pendo::EvidenceState::ProviderUnknown);
    assert_eq!(
        evidence.error,
        Some(pendo::ProviderErrorKind::ResponseTooLarge)
    );
    assert!(evidence.redactions.raw_response_body_dropped);

    let rows = (0..=pendo::MAX_ROWS)
        .map(|index| json!({"bucket": format!("day-{index}"), "value": 1}))
        .collect::<Vec<_>>();
    let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::ok(
        json!({"rows": rows}).to_string(),
    ))]);
    let evidence = service.read(&request(&scope)).expect("row-bound evidence");
    assert_eq!(evidence.state, pendo::EvidenceState::ProviderUnknown);
    assert_eq!(evidence.error, Some(pendo::ProviderErrorKind::TooManyRows));
}

#[test]
fn stale_partial_and_http_statuses_are_typed() {
    let stale_body = json!({
        "asOf": NOW - pendo::MAX_STALENESS_SECONDS - 1,
        "rows": [{"bucket": "day-1", "value": 1}]
    })
    .to_string();
    let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::ok(stale_body))]);
    assert_eq!(
        service
            .read(&request(&scope))
            .expect("stale evidence")
            .state,
        pendo::EvidenceState::Stale
    );

    let partial_body = json!({
        "partial": true,
        "rows": [{"bucket": "day-1", "value": 1}]
    })
    .to_string();
    let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::ok(partial_body))]);
    assert_eq!(
        service
            .read(&request(&scope))
            .expect("partial evidence")
            .state,
        pendo::EvidenceState::Partial
    );

    for (status, expected_state, expected_error) in [
        (
            401,
            pendo::EvidenceState::AccessLost,
            pendo::ProviderErrorKind::Unauthorized,
        ),
        (
            403,
            pendo::EvidenceState::AccessLost,
            pendo::ProviderErrorKind::Forbidden,
        ),
        (
            429,
            pendo::EvidenceState::RateLimited,
            pendo::ProviderErrorKind::RateLimited,
        ),
        (
            500,
            pendo::EvidenceState::ProviderUnknown,
            pendo::ProviderErrorKind::MalformedResponse,
        ),
    ] {
        let (scope, mut service) = recorded_service([Ok(pendo::PendoHttpResponse::new(
            status,
            r#"{"email":"private@example.test"}"#,
        ))]);
        let evidence = service.read(&request(&scope)).expect("typed HTTP evidence");
        assert_eq!(evidence.state, expected_state);
        assert_eq!(evidence.error, Some(expected_error));
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence JSON")
                .contains("private@example.test")
        );
    }
}

#[test]
fn blocked_environment_and_loopback_never_claim_native_or_connected() {
    let scope = page_scope();
    let secret = pendo::SecretReference::new("keyring-pendo", &scope, 1).expect("secret");
    let provider = pendo::PendoProvider::new(
        pendo::BlockedEnvPendoTransport,
        pendo::ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = pendo::PendoProductUsageResultService::new(scope.clone(), secret, provider)
        .expect("service");
    let evidence = service.read(&request(&scope)).expect("blocked evidence");
    assert_eq!(evidence.state, pendo::EvidenceState::AccessLost);
    assert_eq!(
        evidence.classification,
        pendo::EvidenceClassification::BlockedEnv
    );
    assert_eq!(evidence.provenance, pendo::ProviderProvenance::BlockedEnv);
    assert_eq!(pendo::PENDO_PRODUCT_USAGE_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!evidence.connected);
    assert!(!evidence.native_provider);
    assert!(!evidence.first_party);

    let request =
        pendo::PendoReadRequest::new(&scope, &request(&scope), pendo::sha256_digest(b"secret"))
            .expect("request");
    let mut loopback = pendo::LoopbackPendoTransport::new(aggregate_body());
    let response = pendo::PendoTransport::read(&mut loopback, &request).expect("loopback");
    assert_eq!(response.status_code(), 200);
    assert_eq!(loopback.requests().len(), 1);
}

#[test]
fn registration_and_secret_revocation_are_reversible_and_scope_bound() {
    let (current_scope, mut service) = recorded_service([ok_body(), ok_body(), ok_body()]);
    let first = service.propose(&request(&current_scope)).expect("proposal");
    let first_registration = service.registration().registration_digest().clone();
    assert_eq!(
        service.registration().permission_digest(),
        &pendo::PendoPermission::layer1_read_only().digest()
    );
    assert!(!service.registration().query_digest().is_empty());
    let revocation = service.revoke_registration().expect("revoke");
    assert!(revocation.reversible);
    assert_eq!(revocation.state, pendo::RegistrationState::Revoked);
    assert_ne!(revocation.previous_digest, revocation.next_digest);
    assert_ne!(
        first_registration,
        service.registration().registration_digest().clone()
    );
    assert!(matches!(
        service.verify_proposal(&first),
        Err(pendo::PendoProductUsageServiceError::RegistrationRevoked)
    ));
    service
        .restore_registration()
        .expect("restore registration");
    let second = service
        .propose(&request(&current_scope))
        .expect("restored proposal");
    assert_ne!(first.registration_digest, second.registration_digest);

    service.revoke_secret().expect("revoke secret");
    assert!(matches!(
        service.propose(&request(&current_scope)),
        Err(pendo::PendoProductUsageServiceError::SecretRevoked)
    ));
    service.restore_secret().expect("restore secret");
    assert!(service.propose(&request(&current_scope)).is_ok());

    let other_scope = scope(pendo::TargetReference::page("other-page").expect("other page"));
    assert!(pendo::SecretReference::new("keyring-pendo", &other_scope, 1).is_ok());
    assert_ne!(other_scope.digest(), service.scope().digest());
}

#[test]
fn scope_drift_tamper_replay_and_quota_are_fenced() {
    let (scope, mut service) = recorded_service((0..10).map(|_| ok_body()));
    let stale_request = request(&scope).with_mission_revision(pendo::Revision::new(99).unwrap());
    assert!(matches!(
        service.read(&stale_request),
        Err(pendo::PendoProductUsageServiceError::RequestOutOfScope)
    ));

    let proposal = service.propose(&request(&scope)).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.connected = true;
    assert!(matches!(
        service.verify_proposal(&tampered),
        Err(pendo::PendoProductUsageServiceError::EvidenceMismatch)
    ));

    for _ in 0..9 {
        assert!(service.propose(&request(&scope)).is_ok());
    }
    let limited = service.read(&request(&scope)).expect("quota evidence");
    assert_eq!(limited.state, pendo::EvidenceState::RateLimited);
    assert_eq!(limited.error, Some(pendo::ProviderErrorKind::RateLimited));
    assert_eq!(service.provider().transport().call_count(), 10);
}
