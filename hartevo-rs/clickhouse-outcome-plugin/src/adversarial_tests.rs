use super::*;

#[derive(Clone)]
struct Fixture {
    scope: ClickHouseScope,
    secret: SecretReference,
    bounds: ResultBounds,
    query: ParameterizedSelect,
    proposal: ClickHouseQueryProposal,
    schema: QuerySchema,
    row: BoundedRow,
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn fixture_with_bounds(bounds: ResultBounds) -> Fixture {
    let scope = ClickHouseScope::new(
        "https://clickhouse.example:8443",
        "analytics-cluster",
        "analytics",
        "events",
        "events-schema",
        3,
        "project-1",
        "mission-1",
        "work-product-1",
        7,
        digest("permission-1"),
        digest("consent-1"),
    )
    .expect("scope");
    let secret = SecretReference::service_token("opaque-service-token-ref", &scope, 4)
        .expect("secret reference");
    let query = ParameterizedSelect::compile(
        &scope,
        format!(
            "SELECT id, event_id FROM analytics.events WHERE tenant_id = {{tenant:UInt64}} ORDER BY id, event_id LIMIT {}",
            bounds.max_rows().min(2)
        ),
        [QueryParameter::from_public_value(
            "tenant",
            QueryParameterType::UInt64,
            "7",
        )
        .expect("typed parameter")],
        bounds,
    )
    .expect("query");
    let proposal = ClickHouseQueryProposal::compile(
        &scope,
        &secret,
        QueryProposalRequest::new(
            query.clone(),
            bounds,
            QueryMode::BoundedReadProposal,
            scope.work_product_revision(),
        ),
    )
    .expect("proposal");
    let schema = QuerySchema::with_revision(
        scope.schema_revision(),
        vec![
            QuerySchemaField::new("id", CellType::UInt64, false).expect("id field"),
            QuerySchemaField::new("event_id", CellType::UInt64, false).expect("event field"),
        ],
    )
    .expect("schema");
    let row = BoundedRow::new(vec![
        RedactedCell::from_public_value(CellType::UInt64, "1").expect("id cell"),
        RedactedCell::from_public_value(CellType::UInt64, "2").expect("event cell"),
    ])
    .expect("row");
    Fixture {
        scope,
        secret,
        bounds,
        query,
        proposal,
        schema,
        row,
    }
}

fn fixture() -> Fixture {
    fixture_with_bounds(ResultBounds::new(10, 4_096).expect("bounds"))
}

fn response(
    fixture: &Fixture,
    query_id: &str,
    status: QueryStatus,
    schema: Option<QuerySchema>,
    rows: Vec<BoundedRow>,
) -> ClickHouseQueryResponse {
    let statistics = QueryStatistics::new(
        20,
        2_000,
        rows.len() as u64,
        rows.iter().map(BoundedRow::encoded_bytes).sum(),
        1_000,
        4_096,
    );
    ClickHouseQueryResponse::new(
        QueryId::new(query_id).expect("query id"),
        status,
        schema,
        rows,
        vec![QueryProgress::new(20, 2_000, Some(20), 900)],
        statistics.clone(),
        QuerySummary::new(&statistics),
        Vec::new(),
        fixture.proposal.query_digest().clone(),
        fixture.proposal.config_digest().clone(),
        fixture.scope.fence(),
        fixture.secret.credential_revision(),
    )
}

type TestProvider = ClickHouseProviderAdapter<RecordingClickHouseTransport>;

fn service_with_response(
    fixture: &Fixture,
    response: Result<ClickHouseQueryResponse, TransportError>,
    retry_policy: RetryPolicy,
) -> ClickHouseOutcomeService<TestProvider> {
    let mut transport = RecordingClickHouseTransport::default();
    transport.push_response(response);
    let provider = ClickHouseProviderAdapter::new(transport, "1.0.0").expect("provider");
    ClickHouseOutcomeService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        retry_policy,
    )
    .expect("service")
}

fn request(fixture: &Fixture) -> QueryProposalRequest {
    QueryProposalRequest::new(
        fixture.query.clone(),
        fixture.bounds,
        QueryMode::BoundedReadProposal,
        fixture.scope.work_product_revision(),
    )
}

#[test]
fn typed_scope_secret_query_and_complete_evidence_are_bound() {
    let fixture = fixture();
    let mut service = service_with_response(
        &fixture,
        Ok(response(
            &fixture,
            "query-1",
            QueryStatus::Complete,
            Some(fixture.schema.clone()),
            vec![fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    let proposal = service.propose(request(&fixture)).expect("proposal");
    assert_eq!(proposal.status(), ResultStatus::Complete);
    assert_eq!(
        proposal.evidence.query_id.as_ref().map(QueryId::as_str),
        Some("query-1")
    );
    assert_eq!(proposal.evidence.rows.len(), 1);
    assert_eq!(
        proposal.evidence.digests.query_digest,
        *fixture.proposal.query_digest()
    );
    assert_eq!(
        proposal.evidence.digests.registration_digest,
        service.registration().registration_digest.clone()
    );
    proposal.validate_digests().expect("evidence digests");
    assert!(!format!("{proposal:?}").contains("SELECT"));
    assert!(!format!("{:?}", fixture.secret).contains("opaque-service-token-ref"));
    assert!(!proposal.authority().connected());
    assert!(!proposal.authority().native());
    assert!(!proposal.authority().first_party());
    assert!(!proposal.is_adopted());

    let mut consumer =
        MissionClickHouseOutcomeConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let result = consumer.consume_once(proposal).expect("Mission projection");
    assert_eq!(result.project_id, *fixture.scope.project_id());
    assert_eq!(result.mission_id, *fixture.scope.mission_id());
    assert_eq!(result.state, MissionResultState::PendingDecision);
    assert!(!result.authority.truth());
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
}

#[test]
fn parameter_types_ast_allowlist_and_stable_tie_breaker_fail_closed() {
    let fixture = fixture();
    assert!(
        QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "nope").is_err()
    );
    assert!(QueryParameter::from_public_value("ratio", QueryParameterType::Float32, "1.5").is_ok());
    assert!(
        QueryParameter::from_public_value("ratio", QueryParameterType::Float32, "1e100").is_err()
    );
    assert!(matches!(
        ParameterizedSelect::compile(
            &fixture.scope,
            "SELECT id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id LIMIT 1",
            [
                QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "7")
                    .expect("parameter")
            ],
            fixture.bounds,
        ),
        Err(QueryCompileError::StableOrderingRequired)
    ));
    assert!(matches!(
        ParameterizedSelect::compile(
            &fixture.scope,
            "SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:Int64} ORDER BY id, event_id LIMIT 1",
            [
                QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "7")
                    .expect("parameter")
            ],
            fixture.bounds,
        ),
        Err(QueryCompileError::ParameterTypeMismatch)
    ));
    for sql in [
        "INSERT INTO analytics.events VALUES ({tenant:UInt64})",
        "SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id",
        "SELECT id, event_id FROM analytics.other WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT 1",
        "SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT {limit:UInt64}",
        "SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT 1; SELECT 1",
        "SELECT id, event_id FROM analytics.events -- hidden\n WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT 1",
    ] {
        assert!(
            ParameterizedSelect::compile(
                &fixture.scope,
                sql,
                [
                    QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "7")
                        .expect("parameter")
                ],
                fixture.bounds,
            )
            .is_err()
        );
    }
    let explain = ParameterizedSelect::compile(
        &fixture.scope,
        "EXPLAIN SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT 1",
        [QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "7").expect("parameter")],
        fixture.bounds,
    )
    .expect("explain select");
    assert_eq!(explain.kind(), ClickHouseQueryKind::ExplainSelect);
}

#[test]
fn truncation_schema_drift_tamper_and_replay_are_typed() {
    let mut truncated = fixture_with_bounds(ResultBounds::new(1, 4_096).expect("bounds"));
    truncated.query = ParameterizedSelect::compile(
        &truncated.scope,
        "SELECT id, event_id FROM analytics.events WHERE tenant_id = {tenant:UInt64} ORDER BY id, event_id LIMIT 1",
        [QueryParameter::from_public_value("tenant", QueryParameterType::UInt64, "7").expect("parameter")],
        truncated.bounds,
    )
    .expect("bounded query");
    truncated.proposal =
        ClickHouseQueryProposal::compile(&truncated.scope, &truncated.secret, request(&truncated))
            .expect("proposal");
    let mut service = service_with_response(
        &truncated,
        Ok(response(
            &truncated,
            "query-truncated",
            QueryStatus::Complete,
            Some(truncated.schema.clone()),
            vec![truncated.row.clone(), truncated.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    let proposal = service
        .propose(request(&truncated))
        .expect("truncated proposal");
    assert_eq!(proposal.status(), ResultStatus::Truncated);
    assert!(proposal.evidence.row_bound_exceeded);

    let fixture = fixture();
    let drift_schema = QuerySchema::with_revision(
        Revision::new(2).expect("revision"),
        fixture.schema.fields.clone(),
    )
    .expect("drift schema");
    let mut service = service_with_response(
        &fixture,
        Ok(response(
            &fixture,
            "query-schema-drift",
            QueryStatus::Complete,
            Some(drift_schema),
            vec![fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    assert_eq!(
        service
            .propose(request(&fixture))
            .expect_err("schema drift"),
        ClickHouseServiceError::SchemaDrift
    );

    let mut tampered_response = response(
        &fixture,
        "query-tampered",
        QueryStatus::Complete,
        Some(fixture.schema.clone()),
        vec![fixture.row.clone()],
    );
    tampered_response.response_digest = digest("tampered-response");
    let mut service = service_with_response(
        &fixture,
        Ok(tampered_response),
        RetryPolicy::new(1).expect("retry policy"),
    );
    assert_eq!(
        service.propose(request(&fixture)).expect_err("tamper"),
        ClickHouseServiceError::TamperedEvidence
    );

    let mut service = service_with_response(
        &fixture,
        Ok(response(
            &fixture,
            "query-replay",
            QueryStatus::Complete,
            Some(fixture.schema.clone()),
            vec![fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(response(
            &fixture,
            "query-replay",
            QueryStatus::Complete,
            Some(fixture.schema.clone()),
            vec![fixture.row.clone()],
        )));
    let _ = service.propose(request(&fixture)).expect("first proposal");
    assert_eq!(
        service.propose(request(&fixture)).expect_err("replay"),
        ClickHouseServiceError::DuplicateOrReplay
    );
}

#[test]
fn byte_truncation_and_cell_type_drift_fail_closed() {
    let byte_fixture = fixture_with_bounds(ResultBounds::new(10, 32).expect("small bytes"));
    let mut byte_service = service_with_response(
        &byte_fixture,
        Ok(response(
            &byte_fixture,
            "query-byte-truncated",
            QueryStatus::Complete,
            Some(byte_fixture.schema.clone()),
            vec![byte_fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    let byte_proposal = byte_service
        .propose(request(&byte_fixture))
        .expect("byte-truncated proposal");
    assert_eq!(byte_proposal.status(), ResultStatus::Truncated);
    assert!(byte_proposal.evidence.byte_bound_exceeded);
    byte_proposal.validate_digests().expect("byte evidence");

    let fixture = fixture();
    let mismatched_schema = QuerySchema::with_revision(
        fixture.scope.schema_revision(),
        vec![
            QuerySchemaField::new("id", CellType::String, false).expect("id field"),
            QuerySchemaField::new("event_id", CellType::UInt64, false).expect("event field"),
        ],
    )
    .expect("mismatched schema");
    let mut service = service_with_response(
        &fixture,
        Ok(response(
            &fixture,
            "query-cell-type-drift",
            QueryStatus::Complete,
            Some(mismatched_schema),
            vec![fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    assert_eq!(
        service
            .propose(request(&fixture))
            .expect_err("cell type drift"),
        ClickHouseServiceError::InvalidResponseShape
    );
}

#[test]
fn http_errors_timeout_cancelled_and_blocked_env_never_claim_native() {
    let cases = [
        (TransportError::bad_request(), ResultStatus::FinalError),
        (TransportError::unauthenticated(), ResultStatus::AccessLost),
        (TransportError::access_denied(), ResultStatus::AccessLost),
        (TransportError::not_found(), ResultStatus::ProviderUnknown),
        (
            TransportError::rate_limited(),
            ResultStatus::ProviderUnknown,
        ),
        (
            TransportError::server_failure(),
            ResultStatus::ProviderUnknown,
        ),
        (TransportError::timeout(), ResultStatus::ProviderUnknown),
        (TransportError::cancelled(), ResultStatus::Cancelled),
    ];
    for (error, status) in cases {
        let fixture = fixture();
        let mut service = service_with_response(
            &fixture,
            Err(error),
            RetryPolicy::new(1).expect("retry policy"),
        );
        let proposal = service
            .propose(request(&fixture))
            .expect("typed provider error");
        assert_eq!(proposal.status(), status);
        assert!(!proposal.authority().native());
        assert!(!proposal.authority().connected());
    }

    let fixture = fixture();
    let provider = ClickHouseProviderAdapter::new(BlockedEnvTransport, "1.0.0").expect("provider");
    let mut service = ClickHouseOutcomeService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        RetryPolicy::new(1).expect("retry policy"),
    )
    .expect("blocked service");
    let proposal = service
        .propose(request(&fixture))
        .expect("blocked projection");
    assert_eq!(proposal.status(), ResultStatus::ProviderUnknown);
    assert!(proposal.evidence.provider_errors[0].blocked_env);
    assert_eq!(
        service.provider().provenance(),
        ProviderProvenance::BlockedEnv
    );
}

#[test]
fn revocation_stale_mission_and_secret_fences_close_the_boundary() {
    let fixture = fixture();
    let mut service = service_with_response(
        &fixture,
        Ok(response(
            &fixture,
            "query-revocation",
            QueryStatus::Complete,
            Some(fixture.schema.clone()),
            vec![fixture.row.clone()],
        )),
        RetryPolicy::new(1).expect("retry policy"),
    );
    let proposal = service.propose(request(&fixture)).expect("proposal");
    let mut consumer =
        MissionClickHouseOutcomeConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let wrong_mission = MissionId::new("mission-stale").expect("mission");
    assert_eq!(
        consumer
            .consume_for(
                &wrong_mission,
                fixture.scope.project_id(),
                fixture.scope.work_product_revision(),
                proposal.clone(),
            )
            .expect_err("stale Mission"),
        ConsumerError::FenceMismatch
    );
    let replay = proposal.clone();
    let _ = consumer.consume_once(proposal).expect("first delivery");
    assert_eq!(
        consumer
            .consume_once(replay)
            .expect_err("replayed proposal"),
        ConsumerError::DuplicateReplay
    );

    let mut revoked = service_with_response(
        &fixture,
        Err(TransportError::blocked_env()),
        RetryPolicy::new(1).expect("retry policy"),
    );
    revoked
        .revoke_registration()
        .expect("registration revocation");
    assert_eq!(
        revoked
            .propose(request(&fixture))
            .expect_err("revoked registration"),
        ClickHouseServiceError::RegistrationRevoked
    );

    let mut secret_revoked = service_with_response(
        &fixture,
        Err(TransportError::blocked_env()),
        RetryPolicy::new(1).expect("retry policy"),
    );
    secret_revoked.revoke_secret().expect("secret revocation");
    assert_eq!(
        secret_revoked
            .propose(request(&fixture))
            .expect_err("revoked secret"),
        ClickHouseServiceError::SecretRevoked
    );
}
