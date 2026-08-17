use chrono::{TimeZone, Utc};
use hartevo_aws_neptune_graph_result_plugin::{
    AwsAccountId, AwsNeptuneGraphResultContract, AwsNeptuneGraphResultService,
    AwsNeptuneGraphScope, AwsNeptuneProvider, AwsNeptuneTransportError, BlockedEnvTransport,
    CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, Digest, EVIDENCE_LEVEL,
    ExecuteOpenCypherQueryRequest, ExecuteOpenCypherQueryResponse, FixtureTransport,
    GraphNamespace, GraphRowProjection, MissionIdentity, NeptuneClusterId, NeptuneEvidenceState,
    NodeProjection, OpaqueCursor, OpenCypherQuery, PLUGIN_ID, PROVIDER_ID, PermissionSnapshot,
    ProjectIdentity, QueryCompileError, QueryLimits, QueryParameter, QueryParameterType,
    RecordingTransport, SERVICE_ID, SecretReference, TransportProvenance, VpcEndpoint,
    WorkProductIdentity, contract_digest,
};
use serde_json::Value;

const RAW_SECRET: &str = "fixture-sigv4-secret-material";
const RAW_NODE: &str = "node-raw-identifier-17";
const RAW_QUERY: &str = "MATCH (n:Person {id: $id}) RETURN n LIMIT 2";

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_787_000_000, 0)
        .single()
        .expect("fixture timestamp")
}

fn limits() -> QueryLimits {
    QueryLimits::new(4, 4_096, 1_000, 4).expect("limits")
}

fn query_with_limits(limits: QueryLimits) -> OpenCypherQuery {
    OpenCypherQuery::compile(
        RAW_QUERY,
        [
            QueryParameter::from_public_value("id", QueryParameterType::String, "person-17")
                .expect("parameter"),
        ],
        limits,
    )
    .expect("bounded query")
}

fn scope_for(query: &OpenCypherQuery) -> AwsNeptuneGraphScope {
    AwsNeptuneGraphScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_neptune_graph_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        VpcEndpoint::new("https://vpce-123456.neptune.us-east-1.amazonaws.com").expect("endpoint"),
        NeptuneClusterId::new("cluster-17").expect("cluster"),
        GraphNamespace::new("mission-graph").expect("graph"),
        query.template_digest().clone(),
        query.parameter_digest().clone(),
        MissionIdentity::new("mission-17", 7).expect("mission"),
        ProjectIdentity::new("project-17", 11).expect("project"),
        WorkProductIdentity::new("work-product-17", 13).expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> (
    AwsNeptuneGraphResultService<FixtureTransport>,
    OpenCypherQuery,
    AwsNeptuneGraphScope,
) {
    let query = query_with_limits(limits());
    let scope = scope_for(&query);
    let provider = AwsNeptuneProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 3).expect("secret");
    let service = AwsNeptuneGraphResultService::new(
        scope.clone(),
        secret,
        PermissionSnapshot::for_layer_one(2),
        provider,
        limits(),
    )
    .expect("service");
    (service, query, scope)
}

#[test]
fn contract_registration_and_secret_boundary_are_pinned() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest(), CONTRACT_DIGEST);
    AwsNeptuneGraphResultContract::baseline().expect("validated contract");

    let (service, query, scope) = fixture_service();
    let registration = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!(
        "{service:?}{:?}{:?}{:?}",
        service.secret_reference(),
        query,
        scope
    );
    assert!(registration.contains("secretReferenceDigest"));
    assert!(!registration.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_QUERY));
    assert!(service.registration().validate().is_ok());
    assert_eq!(
        AwsNeptuneGraphResultService::<FixtureTransport>::describe_capabilities().service_id,
        SERVICE_ID
    );
    assert_eq!(
        AwsNeptuneGraphResultService::<FixtureTransport>::describe_capabilities().provider_id,
        PROVIDER_ID
    );
    assert!(!AwsNeptuneGraphResultService::<FixtureTransport>::describe_capabilities().connected);
    assert!(!AwsNeptuneGraphResultService::<FixtureTransport>::describe_capabilities().native);
}

#[test]
fn ast_allowlist_rejects_writes_loads_variable_traversals_and_unbounded_output() {
    let bounds = limits();
    let parameter = || {
        QueryParameter::from_public_value("id", QueryParameterType::String, "person-17")
            .expect("parameter")
    };
    let compile = |query: &str| OpenCypherQuery::compile(query, [parameter()], bounds);

    assert!(matches!(
        compile("DELETE n"),
        Err(QueryCompileError::ForbiddenOperation { .. })
    ));
    assert!(matches!(
        compile("MATCH (n:Person {id: $id}) SET n.x = 1 RETURN n LIMIT 1"),
        Err(QueryCompileError::ForbiddenOperation { .. })
    ));
    assert!(matches!(
        compile("LOAD CSV FROM 's3://bucket/input.csv' AS row RETURN row LIMIT 1"),
        Err(QueryCompileError::S3Read)
    ));
    assert!(matches!(
        compile("MATCH (a:Person {id: $id})-[r:KNOWS*]->(b:Person) RETURN a,r,b LIMIT 1"),
        Err(QueryCompileError::VariableLengthTraversal)
    ));
    assert!(matches!(
        compile("MATCH (n:Person {id: $id}) RETURN n"),
        Err(QueryCompileError::UnboundedOutput)
    ));
    assert!(matches!(
        compile("MATCH (n:Person {id: $id}) RETURN n LIMIT $id"),
        Err(QueryCompileError::ParameterizedLimitUnsupported)
    ));
    assert!(matches!(
        compile("MATCH (n:Person {id: $id}) RETURN * LIMIT 1"),
        Err(QueryCompileError::ArbitraryQueryText)
    ));
    assert!(matches!(
        compile(
            "MATCH (n:Person {id: $id}) RETURN n LIMIT 1; MATCH (m:Person {id: $id}) RETURN m LIMIT 1"
        ),
        Err(QueryCompileError::MultiStatement)
    ));

    let relationship = OpenCypherQuery::compile(
        "MATCH (a:Person {id: $id})-[r:KNOWS]->(b:Person) RETURN a,r,b LIMIT 2",
        [parameter()],
        bounds,
    )
    .expect("fixed relationship query");
    assert!(relationship.ast().is_relationship_query());
}

#[test]
fn fixture_proposal_is_bounded_redacted_and_mission_review_only() {
    let (mut service, query, scope) = fixture_service();
    let proposal = service.propose(query.clone()).expect("proposal");
    assert_eq!(proposal.state, NeptuneEvidenceState::Present);
    assert_eq!(proposal.row_count, 1);
    assert_eq!(proposal.node_count, 2);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [RAW_SECRET, RAW_QUERY, RAW_NODE, "Person", "person-17"] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let row = NodeProjection::from_public(
        RAW_NODE.as_bytes(),
        ["Person"],
        vec![("ssn".to_owned(), b"very-private".to_vec())],
    )
    .expect("node projection");
    let row_debug = format!("{row:?}");
    let row_json = serde_json::to_string(&row).expect("row JSON");
    assert!(!row_debug.contains(RAW_NODE));
    assert!(!row_json.contains(RAW_NODE));
    assert!(!row_json.contains("very-private"));
    assert_eq!(proposal.scope_digest, scope.digest());

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let receipt = consumer
        .record(&proposal, "mission-17/idempotency")
        .expect("record");
    assert!(!receipt.replayed);
    assert!(receipt.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "mission-17/idempotency")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn pagination_limits_and_replay_tamper_fences_fail_closed() {
    let one_row_limits = QueryLimits::new(1, 4_096, 1_000, 4).expect("limits");
    let query = OpenCypherQuery::compile(
        "MATCH (n:Person {id: $id}) RETURN n LIMIT 1",
        [
            QueryParameter::from_public_value("id", QueryParameterType::String, "person-17")
                .expect("parameter"),
        ],
        one_row_limits,
    )
    .expect("one-row query");
    let scope = scope_for(&query);
    let request = ExecuteOpenCypherQueryRequest::new(&scope, query.clone()).expect("request");
    let row = GraphRowProjection::fixture(query.query_digest(), false).expect("row");
    let cursor = OpaqueCursor::for_request("opaque-page-2", &request, 2).expect("cursor");
    let first = ExecuteOpenCypherQueryResponse::new(
        &request,
        vec![row.clone()],
        Some(cursor.clone()),
        256,
        1,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second_request = request.with_cursor(cursor).expect("second request");
    let second = ExecuteOpenCypherQueryResponse::new(
        &second_request,
        vec![row],
        None,
        256,
        1,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(first));
    transport.push_response(Ok(second));
    let provider = AwsNeptuneProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let mut service = AwsNeptuneGraphResultService::new(
        scope,
        secret,
        PermissionSnapshot::for_layer_one(1),
        provider,
        QueryLimits::layer_one(),
    )
    .expect("service");
    let proposal = service.propose(query).expect("partial proposal");
    assert_eq!(proposal.state, NeptuneEvidenceState::Partial);
    assert_eq!(
        proposal.partial_reason,
        Some(hartevo_aws_neptune_graph_result_plugin::PartialReason::RowLimit)
    );
    assert_eq!(proposal.row_count, 1);
    assert!(proposal.validate_integrity().is_ok());

    let (query, scope) = {
        let query = query_with_limits(limits());
        let scope = scope_for(&query);
        (query, scope)
    };
    let request = ExecuteOpenCypherQueryRequest::new(&scope, query.clone()).expect("request");
    let row = GraphRowProjection::fixture(query.query_digest(), false).expect("row");
    let tampered = ExecuteOpenCypherQueryResponse::new(
        &request,
        vec![row],
        None,
        256,
        1,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_result_digest(Digest::from_text("tampered"));
    let mut transport = RecordingTransport::default();
    transport.push_response(Ok(tampered));
    let provider = AwsNeptuneProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let mut service = AwsNeptuneGraphResultService::new(
        scope,
        secret,
        PermissionSnapshot::for_layer_one(1),
        provider,
        limits(),
    )
    .expect("service");
    let proposal = service.propose(query).expect("tampered proposal");
    assert_eq!(proposal.state, NeptuneEvidenceState::Tampered);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn blocked_environment_and_provider_statuses_never_claim_native_evidence() {
    let query = query_with_limits(limits());
    let scope = scope_for(&query);
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let provider = AwsNeptuneProvider::new(BlockedEnvTransport).expect("blocked provider");
    let mut service = AwsNeptuneGraphResultService::new_layer_one(scope.clone(), secret, provider)
        .expect("service");
    let proposal = service.propose(query.clone()).expect("blocked proposal");
    assert_eq!(proposal.state, NeptuneEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);

    let cases = [
        (
            AwsNeptuneTransportError::BadRequest,
            NeptuneEvidenceState::BadRequest,
        ),
        (
            AwsNeptuneTransportError::Unauthorized,
            NeptuneEvidenceState::AccessLost,
        ),
        (
            AwsNeptuneTransportError::Forbidden,
            NeptuneEvidenceState::AccessLost,
        ),
        (
            AwsNeptuneTransportError::NotFound,
            NeptuneEvidenceState::AccessLost,
        ),
        (
            AwsNeptuneTransportError::Conflict,
            NeptuneEvidenceState::Conflict,
        ),
        (
            AwsNeptuneTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
            NeptuneEvidenceState::Throttled,
        ),
        (
            AwsNeptuneTransportError::Server { status_code: 503 },
            NeptuneEvidenceState::ServerError,
        ),
        (
            AwsNeptuneTransportError::Timeout,
            NeptuneEvidenceState::Timeout,
        ),
        (
            AwsNeptuneTransportError::Unknown,
            NeptuneEvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let query = query_with_limits(limits());
        let scope = scope_for(&query);
        let mut transport = RecordingTransport::default();
        transport.push_response(Err(error));
        let provider = AwsNeptuneProvider::new(transport).expect("recording provider");
        let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
        let mut service =
            AwsNeptuneGraphResultService::new_layer_one(scope, secret, provider).expect("service");
        let proposal = service.propose(query).expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.connected && !proposal.native && !proposal.first_party);
        assert!(proposal.validate_integrity().is_ok());
    }
}

#[test]
fn registration_revocation_and_reversal_close_the_consumer() {
    let (mut service, query, _scope) = fixture_service();
    let mut consumer = service.consumer().expect("consumer");
    let proposal = service.propose(query.clone()).expect("proposal");
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(service.propose(query.clone()).is_err());
    assert!(consumer.consume(&proposal).is_err());
    service.restore_registration().expect("restore");
    assert!(service.is_active());
    assert!(consumer.consume(&proposal).is_err());
    service.reverse_registration().expect("reverse");
    assert!(!service.is_active());
    service
        .restore_registration()
        .expect("restore after reverse");
    assert!(service.registration().validate().is_ok());
    assert!(consumer.revoke().is_ok());
    assert!(consumer.consume(&proposal).is_err());
}
