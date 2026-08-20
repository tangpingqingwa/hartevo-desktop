use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_athena_query_result_plugin::{
    AthenaExecutionState, AthenaQueryResultStatus, AwsAccountId, AwsAthenaEvidenceRequest,
    AwsAthenaProvider, AwsAthenaQueryResultScope, AwsAthenaQueryResultService,
    AwsAthenaTransportError, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, CatalogName, ColumnShape, ColumnType, ConsentScope, DatabaseName, Digest,
    FixtureTransport, GetQueryExecutionRequest, GetQueryExecutionResponse, GetQueryResultsRequest,
    GetQueryResultsResponse, MissionId, MissionIdentity, OpaquePageToken, ParameterizedAthenaQuery,
    PermissionSnapshot, ProjectId, ProjectIdentity, QueryExecutionId, QueryExecutionMetadata,
    QueryParameter, QueryParameterType, QueryResultsProjection, RecordingTransport, ResultBounds,
    RowShape, SecretReference, TableName, TransportProvenance, WorkProductId, WorkProductIdentity,
    WorkgroupName,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "sigv4-keyring-ref-athena-819";
const RAW_QUERY: &str =
    "SELECT * FROM awsdatacatalog.analytics.events WHERE event_id = :event LIMIT 10";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn bounds() -> ResultBounds {
    ResultBounds::new(10, 1_024 * 1_024, 4, 10).expect("bounds")
}

fn scope() -> AwsAthenaQueryResultScope {
    let permission = PermissionSnapshot::for_layer_one(1);
    AwsAthenaQueryResultScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_athena_query_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        WorkgroupName::new("analytics-workgroup").expect("workgroup"),
        CatalogName::new("awsdatacatalog").expect("catalog"),
        DatabaseName::new("analytics").expect("database"),
        [TableName::new("events").expect("table")],
        MissionIdentity::new(MissionId::new("mission-819").expect("mission"), 7)
            .expect("mission identity"),
        ProjectIdentity::new(ProjectId::new("project-819").expect("project"), 11)
            .expect("project identity"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-819").expect("work product"),
            13,
        )
        .expect("work product identity"),
        permission.digest(),
    )
    .expect("scope")
}

fn query(scope: &AwsAthenaQueryResultScope) -> ParameterizedAthenaQuery {
    ParameterizedAthenaQuery::compile(
        scope,
        RAW_QUERY,
        [
            QueryParameter::from_public_value("event", QueryParameterType::String, b"event-1")
                .expect("parameter"),
        ],
        bounds(),
    )
    .expect("query")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-819", 1, now() + Duration::days(7)).expect("consent")
}

fn fixture_service() -> AwsAthenaQueryResultService<FixtureTransport> {
    let scope = scope();
    let provider = AwsAthenaProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    AwsAthenaQueryResultService::new(scope, secret, consent(), provider, now()).expect("service")
}

fn recording_service() -> AwsAthenaQueryResultService<RecordingTransport> {
    let scope = scope();
    let provider = AwsAthenaProvider::new(RecordingTransport::default()).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    AwsAthenaQueryResultService::new(scope, secret, consent(), provider, now()).expect("service")
}

fn execution_response(
    service: &AwsAthenaQueryResultService<RecordingTransport>,
    request: &AwsAthenaEvidenceRequest,
    state: AthenaExecutionState,
    expired: bool,
) -> GetQueryExecutionResponse {
    let provider_request = GetQueryExecutionRequest::new(
        service.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
    )
    .expect("execution request");
    let metadata = QueryExecutionMetadata::new(
        service.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
        state,
        Some(2_048),
        Some(100),
        Some("s3://fixture.invalid/opaque-output"),
        None::<&str>,
        expired,
    )
    .expect("metadata");
    GetQueryExecutionResponse::new(
        &provider_request,
        metadata,
        768,
        TransportProvenance::Recording,
    )
    .expect("execution response")
}

fn projection(row_count: usize) -> QueryResultsProjection {
    let columns = vec![
        ColumnShape::new(1, "event_id", ColumnType::String, false).expect("column"),
        ColumnShape::new(2, "event_type", ColumnType::String, true).expect("column"),
    ];
    let rows = (0..row_count)
        .map(|index| {
            RowShape::from_public_values(
                vec![ColumnType::String, ColumnType::String],
                [format!("event-{index}"), "shape-only".to_owned()],
            )
            .expect("row")
        })
        .collect();
    QueryResultsProjection::new(columns, rows).expect("projection")
}

fn push_execution(
    service: &mut AwsAthenaQueryResultService<RecordingTransport>,
    request: &AwsAthenaEvidenceRequest,
    state: AthenaExecutionState,
) {
    let response = execution_response(service, request, state, false);
    service
        .provider_mut()
        .transport_mut()
        .push_execution_response(Ok(response));
}

#[test]
fn contract_is_versioned_and_layer_one_honest() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(
        hartevo_aws_athena_query_result_plugin::contract_digest(),
        CONTRACT_DIGEST
    );
    assert_eq!(document["service"]["readOnly"], true);
    assert_eq!(document["service"]["startsQueries"], false);
    assert_eq!(document["provider"]["connectedEvidence"], false);
    assert_eq!(document["provider"]["nativeEvidence"], false);
    assert_eq!(document["provider"]["firstPartyEvidence"], false);
    assert_eq!(document["consumer"]["adoptsWorkProduct"], false);
}

#[test]
fn query_compiler_rejects_injection_and_out_of_scope_reads() {
    let scope = scope();
    let parameter = QueryParameter::from_public_value("event", QueryParameterType::String, b"x")
        .expect("parameter");
    let valid = ParameterizedAthenaQuery::compile(
        &scope,
        "EXPLAIN SELECT event_id FROM awsdatacatalog.analytics.events WHERE event_id = @event LIMIT 10",
        [parameter.clone()],
        bounds(),
    )
    .expect("explain select");
    assert!(valid.is_explain());
    assert_eq!(valid.parameter_names().collect::<Vec<_>>(), vec!["event"]);
    assert!(!format!("{valid:?}").contains("EXPLAIN SELECT"));

    for (sql, expected) in [
        (
            "SELECT * FROM awsdatacatalog.analytics.events WHERE event_id = :event; DROP TABLE awsdatacatalog.analytics.events",
            hartevo_aws_athena_query_result_plugin::QueryCompileError::MultiStatement,
        ),
        (
            "DELETE FROM awsdatacatalog.analytics.events WHERE event_id = :event LIMIT 1",
            hartevo_aws_athena_query_result_plugin::QueryCompileError::ForbiddenOperation { operation: "DML" },
        ),
        (
            "SELECT * FROM awsdatacatalog.analytics.events WHERE event_id = :event -- secret LIMIT 1",
            hartevo_aws_athena_query_result_plugin::QueryCompileError::Comment,
        ),
        (
            "SELECT * FROM awsdatacatalog.analytics.events WHERE event_id = :event LIMIT :limit",
            hartevo_aws_athena_query_result_plugin::QueryCompileError::ParameterizedLimitUnsupported,
        ),
    ] {
        let result = ParameterizedAthenaQuery::compile(&scope, sql, [parameter.clone()], bounds());
        assert_eq!(result.expect_err("rejected query"), expected);
    }
    let out_of_scope = ParameterizedAthenaQuery::compile(
        &scope,
        "SELECT * FROM awsdatacatalog.analytics.other WHERE event_id = :event LIMIT 1",
        [parameter],
        bounds(),
    );
    assert!(matches!(
        out_of_scope,
        Err(hartevo_aws_athena_query_result_plugin::QueryCompileError::TableOutOfScope)
    ));
    let aliased_cross_scope = ParameterizedAthenaQuery::compile(
        &scope,
        "SELECT e.event_id FROM awsdatacatalog.analytics.events AS e, awsdatacatalog.analytics.other AS o WHERE e.event_id = :event LIMIT 1",
        [
            QueryParameter::from_public_value("event", QueryParameterType::String, b"x")
                .expect("parameter"),
        ],
        bounds(),
    );
    assert!(matches!(
        aliased_cross_scope,
        Err(hartevo_aws_athena_query_result_plugin::QueryCompileError::UnsupportedTableExpression)
    ));
}

#[test]
fn fixture_proposal_is_bounded_redacted_and_mission_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.status(), AthenaQueryResultStatus::Succeeded);
    assert_eq!(proposal.pages, 1);
    assert!(proposal.pages_complete);
    assert!(proposal.results.is_some());
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    proposal.validate_integrity().expect("proposal integrity");
    assert!(service.verify(&proposal).valid);

    let serialized_registration =
        serde_json::to_string(service.registration()).expect("registration");
    let serialized_proposal = serde_json::to_string(&proposal).expect("proposal");
    let debug = format!("{service:?}{proposal:?}");
    for raw in [
        RAW_SECRET,
        RAW_QUERY,
        "s3://fixture.invalid/opaque-output",
        "event-1",
    ] {
        assert!(!serialized_registration.contains(raw));
        assert!(!serialized_proposal.contains(raw));
        assert!(!debug.contains(raw));
    }

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.can_be_adopted());
    result
        .validate_integrity()
        .expect("Mission result integrity");
    let recorded = consumer
        .record(&proposal, "mission-record-819")
        .expect("record");
    assert!(!recorded.replayed);
    recorded.validate_integrity().expect("record integrity");
    let replay = consumer
        .record(&proposal, "mission-record-819")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn execution_statuses_and_transport_failures_are_typed() {
    for (execution_state, expected) in [
        (
            AthenaExecutionState::Queued,
            AthenaQueryResultStatus::Queued,
        ),
        (
            AthenaExecutionState::Running,
            AthenaQueryResultStatus::Running,
        ),
        (
            AthenaExecutionState::Succeeded,
            AthenaQueryResultStatus::Succeeded,
        ),
        (
            AthenaExecutionState::Failed,
            AthenaQueryResultStatus::Failed,
        ),
        (
            AthenaExecutionState::Cancelled,
            AthenaQueryResultStatus::Cancelled,
        ),
        (
            AthenaExecutionState::Unknown,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
    ] {
        let mut service = recording_service();
        let request = service
            .request(
                query(service.scope()),
                QueryExecutionId::new("execution-status").expect("id"),
                bounds(),
                false,
                now(),
            )
            .expect("request");
        push_execution(&mut service, &request, execution_state);
        let proposal = service.propose(request).expect("proposal");
        assert_eq!(proposal.status(), expected);
    }

    let mut expired = recording_service();
    let request = expired
        .request(
            query(expired.scope()),
            QueryExecutionId::new("execution-expired").expect("id"),
            bounds(),
            false,
            now(),
        )
        .expect("request");
    let provider_request = GetQueryExecutionRequest::new(
        expired.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
    )
    .expect("provider request");
    let metadata = QueryExecutionMetadata::new(
        expired.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
        AthenaExecutionState::Succeeded,
        None,
        None,
        None::<&str>,
        None::<&str>,
        true,
    )
    .expect("expired metadata");
    expired
        .provider_mut()
        .transport_mut()
        .push_execution_response(Ok(GetQueryExecutionResponse::new(
            &provider_request,
            metadata,
            100,
            TransportProvenance::Recording,
        )
        .expect("expired response")));
    assert_eq!(
        expired.propose(request).expect("expired proposal").status(),
        AthenaQueryResultStatus::Expired
    );

    for (failure, expected) in [
        (
            AwsAthenaTransportError::Unauthorized,
            AthenaQueryResultStatus::AccessLost,
        ),
        (
            AwsAthenaTransportError::Forbidden,
            AthenaQueryResultStatus::AccessLost,
        ),
        (
            AwsAthenaTransportError::AccessLost,
            AthenaQueryResultStatus::AccessLost,
        ),
        (
            AwsAthenaTransportError::BadRequest,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::NotFound,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::Conflict,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::RateLimited {
                retry_after_seconds: Some(2),
            },
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::ServerError { status: 503 },
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::Timeout,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
        (
            AwsAthenaTransportError::Partial,
            AthenaQueryResultStatus::Partial,
        ),
        (
            AwsAthenaTransportError::Expired,
            AthenaQueryResultStatus::Expired,
        ),
        (
            AwsAthenaTransportError::InvalidResponse,
            AthenaQueryResultStatus::Tampered,
        ),
        (
            AwsAthenaTransportError::Tampered,
            AthenaQueryResultStatus::Tampered,
        ),
        (
            AwsAthenaTransportError::PaginationLoop,
            AthenaQueryResultStatus::Tampered,
        ),
        (
            AwsAthenaTransportError::Unknown,
            AthenaQueryResultStatus::ProviderUnknown,
        ),
    ] {
        let mut service = recording_service();
        let request = service
            .request(
                query(service.scope()),
                QueryExecutionId::new("execution-error").expect("id"),
                bounds(),
                false,
                now(),
            )
            .expect("request");
        service
            .provider_mut()
            .transport_mut()
            .push_execution_response(Err(failure));
        let proposal = service.propose(request).expect("typed failure proposal");
        assert_eq!(proposal.status(), expected);
        assert!(proposal.failure.is_some());
    }

    let mut blocked = AwsAthenaQueryResultService::new(
        scope(),
        SecretReference::sigv4(RAW_SECRET, &scope(), 1).expect("secret"),
        consent(),
        AwsAthenaProvider::new(BlockedEnvTransport).expect("blocked provider"),
        now(),
    )
    .expect("blocked service");
    let proposal = blocked
        .propose(blocked.default_request(now()).expect("blocked request"))
        .expect("blocked proposal");
    assert_eq!(proposal.status(), AthenaQueryResultStatus::ProviderUnknown);
    assert_eq!(
        proposal.failure.expect("blocked failure").category,
        "blocked_env"
    );
    assert!(!blocked.provider().provenance().is_connected());
}

#[test]
fn pagination_is_opaque_bound_and_truncation_is_partial() {
    let mut service = recording_service();
    let request = service
        .request(
            query(service.scope()),
            QueryExecutionId::new("execution-pages").expect("id"),
            bounds(),
            true,
            now(),
        )
        .expect("request");
    push_execution(&mut service, &request, AthenaExecutionState::Succeeded);
    let first = GetQueryResultsRequest::new(
        service.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
        request.bounds(),
        None,
    )
    .expect("first page request");
    let token_one =
        OpaquePageToken::new("opaque-page-one", first.binding_digest().clone(), 2).expect("token");
    let first_response = GetQueryResultsResponse::new(
        &first,
        projection(1),
        Some(token_one.clone()),
        false,
        false,
        200,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second = GetQueryResultsRequest::new(
        service.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
        request.bounds(),
        Some(token_one.clone()),
    )
    .expect("second page request");
    let second_response = GetQueryResultsResponse::new(
        &second,
        projection(1),
        None,
        true,
        false,
        200,
        TransportProvenance::Recording,
    )
    .expect("second page");
    service
        .provider_mut()
        .transport_mut()
        .push_results_response(Ok(first_response));
    service
        .provider_mut()
        .transport_mut()
        .push_results_response(Ok(second_response));
    let proposal = service.propose(request).expect("paged proposal");
    assert_eq!(proposal.status(), AthenaQueryResultStatus::Succeeded);
    assert_eq!(proposal.pages, 2);
    assert_eq!(proposal.results.expect("results").row_count, 2);

    let mut truncated = recording_service();
    let small_bounds = ResultBounds::new(1, 1_024 * 1_024, 4, 10).expect("small bounds");
    let request = truncated
        .request(
            query(truncated.scope()),
            QueryExecutionId::new("execution-truncate").expect("id"),
            small_bounds,
            true,
            now(),
        )
        .expect("request");
    push_execution(&mut truncated, &request, AthenaExecutionState::Succeeded);
    let results_request = GetQueryResultsRequest::new(
        truncated.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
        small_bounds,
        None,
    )
    .expect("results request");
    truncated
        .provider_mut()
        .transport_mut()
        .push_results_response(Ok(GetQueryResultsResponse::new(
            &results_request,
            projection(2),
            None,
            true,
            false,
            200,
            TransportProvenance::Recording,
        )
        .expect("truncation response")));
    let proposal = truncated.propose(request).expect("partial proposal");
    assert_eq!(proposal.status(), AthenaQueryResultStatus::Partial);
    assert!(proposal.truncated);
    assert_eq!(proposal.results.expect("partial shape").row_count, 1);
}

#[test]
fn tamper_replay_stale_mission_and_revocation_fail_closed() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    let stale = AwsAthenaEvidenceRequest::new(
        service.scope(),
        request.query().clone(),
        request.execution_id().clone(),
        request.bounds(),
        request.include_results(),
        request.expected_provider_digest().clone(),
        request.expected_registration_digest().clone(),
        hartevo_aws_athena_query_result_plugin::Revision::new(999).expect("revision"),
        now(),
    );
    assert!(matches!(
        stale,
        Err(hartevo_aws_athena_query_result_plugin::AwsAthenaQueryResultError::MissionStale)
    ));

    let proposal = service.propose(request).expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let mut tampered = proposal.clone();
    tampered.state = AthenaQueryResultStatus::Tampered;
    assert!(consumer.consume(&tampered).is_err());
    consumer.record(&proposal, "replay-key").expect("record");
    let mut other_service = fixture_service();
    let other_request = other_service
        .request(
            other_service.default_query().expect("other query"),
            QueryExecutionId::new("other-execution").expect("other execution"),
            bounds(),
            true,
            now(),
        )
        .expect("other request");
    let other_proposal = other_service
        .propose(other_request)
        .expect("other proposal");
    assert!(matches!(
        consumer.record(&other_proposal, "replay-key"),
        Err(hartevo_aws_athena_query_result_plugin::ConsumerError::ReplayConflict)
    ));
    assert_eq!(consumer.record_count(), 1);

    let mut revoked = fixture_service();
    revoked.revoke().expect("revoke");
    let request = revoked.default_request(now()).expect("revoked request");
    assert!(matches!(
        revoked.propose(request),
        Err(
            hartevo_aws_athena_query_result_plugin::AwsAthenaQueryResultError::RegistrationInactive
        )
    ));
    revoked.restore_registration().expect("restore");
    assert!(revoked.consumer().is_ok());
    revoked.revoke_secret_reference().expect("secret revoke");
    assert!(revoked.consumer().is_err());
    assert!(matches!(
        revoked.propose(revoked.default_request(now()).expect("request")),
        Err(
            hartevo_aws_athena_query_result_plugin::AwsAthenaQueryResultError::InvalidRegistration
                | hartevo_aws_athena_query_result_plugin::AwsAthenaQueryResultError::SecretRevoked,
        )
    ));
}

#[test]
fn response_tamper_and_page_token_scope_mismatch_are_rejected() {
    let mut service = recording_service();
    let request = service
        .request(
            query(service.scope()),
            QueryExecutionId::new("execution-tamper").expect("id"),
            bounds(),
            false,
            now(),
        )
        .expect("request");
    let execution_request = GetQueryExecutionRequest::new(
        service.scope(),
        request.query_digest().clone(),
        request.execution_id().clone(),
    )
    .expect("execution request");
    let valid = execution_response(&service, &request, AthenaExecutionState::Succeeded, false)
        .with_declared_digest(Digest::from_text("tampered"));
    service
        .provider_mut()
        .transport_mut()
        .push_execution_response(Ok(valid));
    let proposal = service.propose(request).expect("tamper proposal");
    assert_eq!(proposal.status(), AthenaQueryResultStatus::Tampered);
    assert_eq!(
        proposal.failure.expect("failure").category,
        "invalid_response"
    );
    assert_ne!(
        execution_request.request_digest(),
        &Digest::from_text("raw-secret")
    );

    let first = GetQueryResultsRequest::new(
        service.scope(),
        Digest::from_text("query-a"),
        QueryExecutionId::new("execution-a").expect("id"),
        bounds(),
        None,
    )
    .expect("page request");
    let other_binding = Digest::from_text("other-binding");
    let token = OpaquePageToken::new("opaque", other_binding, 2).expect("opaque token");
    assert!(
        GetQueryResultsRequest::new(
            service.scope(),
            Digest::from_text("query-a"),
            QueryExecutionId::new("execution-a").expect("id"),
            bounds(),
            Some(token),
        )
        .is_err()
    );
    assert!(first.recorded_request().page_token_digest.is_none());
}

#[test]
fn all_supported_provenances_are_honest() {
    assert!(!TransportProvenance::Fixture.is_connected());
    assert!(!TransportProvenance::Recording.is_native());
    assert!(!TransportProvenance::Loopback.is_first_party());
    assert!(!TransportProvenance::BlockedEnv.is_connected());
}
