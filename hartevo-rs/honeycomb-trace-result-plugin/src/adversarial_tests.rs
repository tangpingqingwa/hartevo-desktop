use super::*;

struct Fixture {
    scope: HoneycombTraceScope,
    secret: SecretReference,
    query_id: QueryId,
    query_result_id: QueryResultId,
    snapshot: QueryResultSnapshot,
}

fn fixture() -> Fixture {
    let dataset = DatasetId::new("checkout-traces").expect("dataset");
    let window = TimeWindow::new(1_700_000_000, 1_700_003_600).expect("window");
    let query = HoneycombQuery::new(
        dataset.clone(),
        window.clone(),
        vec![
            Calculation::Count,
            Calculation::Rate,
            Calculation::p99(ApprovedField::DurationMs),
            Calculation::ErrorRate,
        ],
        vec![ApprovedField::ServiceName, ApprovedField::Environment],
        vec![QueryFilter::exists(ApprovedField::Error)],
        100,
    )
    .expect("query");
    let marker = DeploymentMarker::new(
        DeploymentId::new("marker-2026-08-15").expect("marker"),
        DeploymentId::new("deploy-2026-08-15").expect("deployment"),
        Revision::new(3).expect("deployment revision"),
        1_700_001_800,
    )
    .expect("marker");
    let scope = HoneycombTraceScope::new(
        HoneycombRegion::Us,
        TeamId::new("team-platform").expect("team"),
        EnvironmentId::new("production").expect("environment"),
        dataset,
        query,
        marker,
        window,
        Mission::new(
            MissionId::new("mission-reliability").expect("mission"),
            Revision::new(11).expect("mission revision"),
        ),
        Project::new(
            ProjectId::new("project-checkout").expect("project"),
            Revision::new(4).expect("project revision"),
        ),
        WorkProduct::new(
            WorkProductId::new("work-product-trace-evidence").expect("work product"),
            Revision::new(8).expect("work product revision"),
        ),
        ConsentScope::aggregate_trace_read_only("reliability decision evidence").expect("consent"),
        PermissionScope::least_privilege(),
    )
    .expect("scope");
    let secret = SecretReference::new("opaque-honeycomb-config-key", &scope, 2).expect("secret");
    let query_id = QueryId::new("query-aggregate-1").expect("query id");
    let query_result_id = QueryResultId::new("query-result-1").expect("query result id");
    let point = AggregatePoint::new(
        1_700_000_000,
        vec![
            DimensionValue::text("checkout"),
            DimensionValue::text("production"),
        ],
        vec![
            AggregateValue::Count(42),
            AggregateValue::RateMilliPerSecond(12),
            AggregateValue::LatencyMillis {
                percentile: Percentile::P99,
                value: 240,
            },
            AggregateValue::ErrorRateBasisPoints(125),
        ],
    )
    .expect("point");
    let series = AggregateSeries::new(vec![point]).expect("series");
    let snapshot = QueryResultSnapshot::new(
        &scope,
        query_id.clone(),
        query_result_id.clone(),
        QueryResultState::Complete,
        vec![series],
        None,
        1_700_003_601,
        Digest::from_text("recorded-query-result-response"),
    )
    .expect("snapshot");
    Fixture {
        scope,
        secret,
        query_id,
        query_result_id,
        snapshot,
    }
}

fn service_with(
    fixture: &Fixture,
    transport: RecordingHoneycombTransport,
) -> HoneycombTraceResultService<RecordingHoneycombTransport> {
    let provider = HoneycombQueryProvider::new(
        transport,
        fixture.scope.region,
        ProviderProvenance::Recording,
    )
    .expect("provider");
    HoneycombTraceResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        RetryPolicy::default(),
    )
    .expect("service")
}

#[test]
fn contract_scope_and_registration_are_version_and_digest_bound() {
    validate_contract().expect("contract");
    let fixture = fixture();
    fixture.scope.validate().expect("scope");
    let provider =
        HoneycombProviderDefinition::layer1(fixture.scope.region, ProviderProvenance::Recording)
            .expect("provider");
    let registration =
        HoneycombRegistration::new(&fixture.scope, provider.provider_digest).expect("registration");
    registration
        .validate(&fixture.scope)
        .expect("registration validates");
    assert_eq!(
        registration.schema_version,
        HONEYCOMB_TRACE_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        registration.contract_version,
        HONEYCOMB_TRACE_RESULT_CONTRACT_VERSION
    );
    assert_eq!(
        registration.provider_id.as_str(),
        HONEYCOMB_TRACE_RESULT_PROVIDER_ID
    );
    assert_eq!(
        registration.permission_digest,
        *fixture.scope.permission_digest()
    );
    assert_eq!(registration.query_digest, *fixture.scope.query_digest());
    assert_ne!(registration.registration_digest, Digest::from_text("other"));
    let mut revoked = registration;
    let revocation = revoked.revoke().expect("revocation");
    assert_eq!(revoked.state, RegistrationState::Revoked);
    assert!(revoked.revoke().is_err());
    assert_eq!(revocation.registration_digest, revoked.registration_digest);
}

#[test]
fn opaque_secret_and_redacted_aggregate_evidence_never_retain_raw_values() {
    let fixture = fixture();
    let secret_debug = format!("{:?}", fixture.secret);
    assert!(!secret_debug.contains("opaque-honeycomb-config-key"));
    let serialized = serde_json::to_string(&fixture.snapshot).expect("snapshot JSON");
    assert!(serialized.contains("checkout-traces"));
    assert!(!serialized.contains("\"checkout\""));
    assert!(!serialized.contains("ui"));
    assert!(!serialized.contains("trace.id"));
    assert!(!serialized.contains("log"));
    assert_eq!(fixture.snapshot.validate_digest(), Ok(()));
}

#[test]
fn query_ast_is_typed_allowlisted_and_bounded() {
    let fixture = fixture();
    assert_eq!(
        ApprovedField::parse("service.name"),
        Ok(ApprovedField::ServiceName)
    );
    assert!(ApprovedField::parse("trace.id").is_err());
    assert!(ApprovedField::parse("user.email").is_err());
    assert!(ApprovedField::parse("log.message").is_err());
    assert!(TimeWindow::new(1_700_000_000, 1_700_000_000 + MAX_QUERY_RANGE_SECONDS + 1).is_err());
    assert!(
        HoneycombQuery::new(
            fixture.scope.dataset.clone(),
            fixture.scope.time_window.clone(),
            vec![Calculation::Count],
            vec![
                ApprovedField::ServiceName,
                ApprovedField::Environment,
                ApprovedField::StatusCode,
                ApprovedField::Error,
                ApprovedField::SpanKind,
            ],
            Vec::new(),
            10,
        )
        .is_err()
    );
    assert!(
        HoneycombQuery::new(
            fixture.scope.dataset.clone(),
            fixture.scope.time_window.clone(),
            vec![Calculation::Count],
            Vec::new(),
            Vec::new(),
            0,
        )
        .is_err()
    );
    assert!(
        HoneycombQuery::new(
            fixture.scope.dataset.clone(),
            fixture.scope.time_window.clone(),
            vec![Calculation::p99(ApprovedField::StatusCode)],
            Vec::new(),
            Vec::new(),
            10,
        )
        .is_err()
    );
    assert!(
        QueryFilter::new(
            ApprovedField::Error,
            FilterOperator::Exists,
            Some(FilterValue::text("must-not-be-retained")),
        )
        .is_err()
    );
    assert!(
        !format!("{:?}", FilterValue::text("private-user-value")).contains("private-user-value")
    );
}

#[test]
fn permissions_region_and_api_version_fail_closed() {
    assert!(PermissionScope::new([HoneycombPermission::RunQueries]).is_err());
    assert!(
        HoneycombProviderDefinition::new(
            HoneycombRegion::Us,
            HoneycombApiVersion::V1,
            [HoneycombPermission::RunQueries],
            ProviderProvenance::Recording,
            HONEYCOMB_TRACE_RESULT_PROVIDER_VERSION,
        )
        .is_err()
    );
    assert!(
        HoneycombProviderDefinition::new(
            HoneycombRegion::Us,
            HoneycombApiVersion::V2,
            [
                HoneycombPermission::RunQueries,
                HoneycombPermission::ManageQueries
            ],
            ProviderProvenance::Recording,
            HONEYCOMB_TRACE_RESULT_PROVIDER_VERSION,
        )
        .is_err()
    );
    let fixture = fixture();
    let wrong_region_provider = HoneycombQueryProvider::new(
        RecordingHoneycombTransport::default(),
        HoneycombRegion::Eu1,
        ProviderProvenance::Recording,
    )
    .expect("provider definition");
    assert!(
        HoneycombTraceResultService::new(
            fixture.scope,
            fixture.secret,
            wrong_region_provider,
            RetryPolicy::default(),
        )
        .is_err()
    );
}

#[test]
fn typed_query_and_query_result_creation_are_non_native_and_region_bound() {
    let fixture = fixture();
    let query_request = QueryCreateRequest::from_scope(&fixture.scope);
    assert_eq!(query_request.path, "/1/queries/checkout-traces");
    assert_eq!(query_request.content_type, "application/json");
    assert!(!query_request.native_execution);
    let query_response = QueryCreateResponse::recorded(
        &query_request,
        fixture.query_id.clone(),
        Digest::from_text("query-response"),
    );
    let result_request =
        QueryResultCreateRequest::from_scope(&fixture.scope, fixture.query_id.clone());
    let result_response = QueryResultCreateResponse::recorded(
        &result_request,
        fixture.query_result_id.clone(),
        QueryResultState::Queued,
        Digest::from_text("result-response"),
    );
    let mut transport = RecordingHoneycombTransport::default();
    transport.push_query_response(Ok(query_response));
    transport.push_query_result_response(Ok(result_response));
    let mut service = service_with(&fixture, transport);
    assert_eq!(
        service.create_query().expect("query creation").query_id,
        fixture.query_id
    );
    assert_eq!(
        service
            .create_query_result(fixture.query_id.clone())
            .expect("query result creation")
            .query_result_id,
        fixture.query_result_id
    );
    let get_request = QueryResultGetRequest::from_scope(
        &fixture.scope,
        fixture.query_id,
        fixture.query_result_id,
    );
    assert_eq!(
        get_request.path,
        "/1/query_results/checkout-traces/query-result-1"
    );
    assert!(!get_request.native_readback);
}

#[test]
fn recording_complete_result_produces_deterministic_proposal_receipt_and_mission_projection() {
    let fixture = fixture();
    let mut transport = RecordingHoneycombTransport::default();
    transport.push_get_response(Ok(fixture.snapshot.clone()));
    let mut service = service_with(&fixture, transport);
    let proposal = service
        .reconcile(fixture.query_id.clone(), fixture.query_result_id.clone())
        .expect("proposal");
    assert_eq!(proposal.projection, QueryResultState::Complete);
    assert!(!proposal.authority.connected());
    assert!(!proposal.authority.native());
    assert!(!proposal.authority.durable_receipt());
    assert!(!proposal.authority.outcome());
    assert!(!proposal.authority.work_product_adoption());
    proposal.validate_digest().expect("proposal digest");
    let receipt_a = service.record_receipt(&proposal).expect("receipt");
    let receipt_b = service.record_receipt(&proposal).expect("receipt replay");
    assert_eq!(receipt_a, receipt_b);
    assert!(!receipt_a.durable);
    assert!(!receipt_a.connected);
    let consumer =
        MissionHoneycombTraceConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let mission_result = consumer.consume(proposal).expect("mission result");
    assert_eq!(mission_result.state, MissionResultState::PendingDecision);
    assert_eq!(
        mission_result.adoption,
        AdoptionAvailability::NotAdoptedLayer2
    );
    assert_eq!(mission_result.mission_id, fixture.scope.mission.id);
    assert_eq!(mission_result.project_id, fixture.scope.project.id);
    assert_eq!(
        mission_result.work_product_id,
        fixture.scope.work_product.id
    );
}

#[test]
fn projections_distinguish_queued_running_partial_empty_rate_limited_access_lost_and_unknown() {
    for state in [
        QueryResultState::Queued,
        QueryResultState::Running,
        QueryResultState::Partial,
        QueryResultState::Empty,
    ] {
        let fixture = fixture();
        let snapshot = QueryResultSnapshot::new(
            &fixture.scope,
            fixture.query_id.clone(),
            fixture.query_result_id.clone(),
            state,
            if state == QueryResultState::Empty {
                Vec::new()
            } else {
                fixture.snapshot.series.clone()
            },
            None,
            1_700_003_601,
            Digest::from_text(format!("{state:?}-response")),
        )
        .expect("state snapshot");
        let mut transport = RecordingHoneycombTransport::default();
        transport.push_get_response(Ok(snapshot));
        let mut service = service_with(&fixture, transport);
        let proposal = service
            .reconcile(fixture.query_id.clone(), fixture.query_result_id.clone())
            .expect("state proposal");
        assert_eq!(proposal.projection, state);
    }

    for (status, expected) in [
        (401, QueryResultState::AccessLost),
        (403, QueryResultState::AccessLost),
        (400, QueryResultState::ProviderUnknown),
        (404, QueryResultState::ProviderUnknown),
        (415, QueryResultState::ProviderUnknown),
    ] {
        let fixture = fixture();
        let mut transport = RecordingHoneycombTransport::default();
        transport.push_get_response(Err(TransportError::from_status(status, "redacted error")));
        let mut service = service_with(&fixture, transport);
        let proposal = service
            .reconcile(fixture.query_id.clone(), fixture.query_result_id.clone())
            .expect("error projection");
        assert_eq!(proposal.projection, expected);
        assert_eq!(
            proposal.evidence.snapshot.error_kind,
            Some(match status {
                401 => ProviderErrorKind::Unauthenticated,
                403 => ProviderErrorKind::PermissionDenied,
                400 => ProviderErrorKind::BadRequest,
                404 => ProviderErrorKind::NotFound,
                _ => ProviderErrorKind::UnsupportedMediaType,
            })
        );
    }
}

#[test]
fn rate_limit_retries_with_capped_safe_backoff_and_exposes_exhaustion() {
    let first_fixture = fixture();
    let mut transport = RecordingHoneycombTransport::default();
    transport.push_get_response(Err(TransportError::new(
        ProviderErrorKind::RateLimited,
        Some(429),
        Some(10_000),
        "rate limit diagnostic",
    )));
    transport.push_get_response(Err(TransportError::from_status(
        429,
        "rate limit diagnostic 2",
    )));
    transport.push_get_response(Ok(first_fixture.snapshot.clone()));
    let mut service = service_with(&first_fixture, transport);
    let proposal = service
        .reconcile(
            first_fixture.query_id.clone(),
            first_fixture.query_result_id.clone(),
        )
        .expect("retried result");
    assert_eq!(proposal.projection, QueryResultState::Complete);
    assert_eq!(proposal.evidence.retries.len(), 2);
    assert_eq!(proposal.evidence.retries[0].delay_seconds, 60);
    assert_eq!(proposal.evidence.retries[1].delay_seconds, 2);

    let fixture = fixture();
    let mut transport = RecordingHoneycombTransport::default();
    for _ in 0..3 {
        transport.push_get_response(Err(TransportError::from_status(429, "exhausted")));
    }
    let mut service = service_with(&fixture, transport);
    let proposal = service
        .reconcile(fixture.query_id, fixture.query_result_id)
        .expect("rate-limited projection");
    assert_eq!(proposal.projection, QueryResultState::RateLimited);
    assert_eq!(proposal.evidence.retries.len(), 2);
}

#[test]
fn tampering_replay_and_revocation_fail_closed() {
    let first_fixture = fixture();
    let mut transport = RecordingHoneycombTransport::default();
    let mut tampered = first_fixture.snapshot.clone();
    tampered.query_digest = Digest::from_text("different-query");
    transport.push_get_response(Ok(tampered));
    let mut service = service_with(&first_fixture, transport);
    assert_eq!(
        service
            .reconcile(
                first_fixture.query_id.clone(),
                first_fixture.query_result_id.clone(),
            )
            .expect_err("tampered evidence"),
        HoneycombServiceError::TamperedEvidence
    );

    let fixture = fixture();
    let mut transport = RecordingHoneycombTransport::default();
    transport.push_get_response(Ok(fixture.snapshot.clone()));
    let mut service = service_with(&fixture, transport);
    let proposal = service
        .reconcile(fixture.query_id.clone(), fixture.query_result_id.clone())
        .expect("proposal");
    let mut replayed = proposal.clone();
    replayed.proposal_digest = Digest::from_text("replayed-tampered-proposal");
    assert_eq!(
        service
            .record_receipt(&replayed)
            .expect_err("replay tamper"),
        HoneycombServiceError::TamperedEvidence
    );

    let registration = service.registration().clone();
    let consumer =
        MissionHoneycombTraceConsumer::new(fixture.scope.clone(), &registration).expect("consumer");
    let mut revoked_consumer = consumer;
    revoked_consumer.revoke().expect("consumer revoke");
    assert_eq!(
        revoked_consumer
            .consume(proposal)
            .expect_err("revoked consumer"),
        ConsumerError::Revoked
    );
    service.revoke_registration().expect("service revoke");
    assert_eq!(
        service.propose_query().expect_err("revoked service"),
        HoneycombServiceError::RegistrationRevoked
    );
}

#[test]
fn fixture_loopback_and_blocked_env_transports_remain_non_native() {
    let fixture = fixture();
    let query_request = QueryCreateRequest::from_scope(&fixture.scope);
    let query_response = QueryCreateResponse::recorded(
        &query_request,
        fixture.query_id.clone(),
        Digest::from_text("fixture-query"),
    );
    let mut fixture_transport = FixtureHoneycombTransport::default();
    fixture_transport.push_query_response(Ok(query_response));
    let provider = HoneycombQueryProvider::new(
        fixture_transport,
        fixture.scope.region,
        ProviderProvenance::Fixture,
    )
    .expect("fixture provider");
    assert!(!provider.definition().native);
    assert!(!provider.definition().connected);

    let loopback_transport = LoopbackHoneycombTransport::new(
        fixture.query_id.clone(),
        fixture.query_result_id.clone(),
        fixture.snapshot.clone(),
    );
    let loopback_provider = HoneycombQueryProvider::new(
        loopback_transport,
        fixture.scope.region,
        ProviderProvenance::Loopback,
    )
    .expect("loopback provider");
    let mut loopback_service = HoneycombTraceResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        loopback_provider,
        RetryPolicy::default(),
    )
    .expect("loopback service");
    assert_eq!(
        loopback_service
            .create_query()
            .expect("loopback query")
            .query_id,
        fixture.query_id
    );
    let proposal = loopback_service
        .reconcile(fixture.query_id.clone(), fixture.query_result_id.clone())
        .expect("loopback result");
    assert_eq!(proposal.projection, QueryResultState::Complete);

    let blocked_provider = HoneycombQueryProvider::new(
        BlockedEnvHoneycombTransport,
        fixture.scope.region,
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut blocked_service = HoneycombTraceResultService::new(
        fixture.scope.clone(),
        fixture.secret,
        blocked_provider,
        RetryPolicy::default(),
    )
    .expect("blocked service");
    let error = blocked_service.create_query().expect_err("blocked query");
    assert!(matches!(
        error,
        HoneycombServiceError::Provider {
            kind: ProviderErrorKind::BlockedEnv,
            ..
        }
    ));
}
