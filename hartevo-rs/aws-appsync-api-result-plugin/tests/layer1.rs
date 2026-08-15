use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_appsync_api_result_plugin::{
    ApiArn, ApiId, ApiLifecycleState, ApiSummary, AppSyncApiType, AppSyncEvidenceState,
    AwsAccountId, AwsAppSyncApiResultService, AwsAppSyncApiScope, AwsAppSyncOperation,
    AwsAppSyncProvider, AwsRegion, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA, CONTRACT_VERSION, Cursor, Digest, FixtureTransport, GetApiRequest,
    ListGraphqlApisRequest, ListGraphqlApisResponse, MissionIdentity, PLUGIN_ID, PROVIDER_ID,
    ProjectIdentity, RecordingTransport, SERVICE_ID, SecretReference, TransportProvenance,
    WorkProductIdentity,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_API_ID: &str = "api811fixture";
const RAW_API_ARN: &str = "arn:aws:appsync:us-east-1:123456789012:apis/api811fixture";
const RAW_SECRET: &str = "opaque-appsync-fixture-secret";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsAppSyncApiScope {
    AwsAppSyncApiScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        hartevo_aws_appsync_api_result_plugin::ApiIdentity::new(
            ApiId::new(RAW_API_ID).expect("api id"),
            ApiArn::new(RAW_API_ARN).expect("api arn"),
        )
        .expect("api identity"),
        AppSyncApiType::Graphql,
        MissionIdentity::new("mission-811", 7).expect("mission"),
        ProjectIdentity::new("project-811", 11).expect("project"),
        WorkProductIdentity::new("work-product-811", 13).expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> AwsAppSyncApiResultService<FixtureTransport> {
    let scope = scope();
    let provider = AwsAppSyncProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_appsync_api_result_plugin::ConsentScope::for_layer_one(
        "consent-811",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    AwsAppSyncApiResultService::new(scope, secret, consent, provider, now()).expect("service")
}

#[test]
fn contract_and_registration_are_digest_bound_and_secret_redacted() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(
        hartevo_aws_appsync_api_result_plugin::contract_digest(),
        CONTRACT_DIGEST
    );

    let service = fixture_service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 5);
    assert_eq!(service.describe_capabilities().provider_id, PROVIDER_ID);
    assert_eq!(service.describe_capabilities().service_id, SERVICE_ID);
    assert!(!service.describe_capabilities().arbitrary_graphql);
    assert!(!service.describe_capabilities().mutation_authority);
}

#[test]
fn fixture_proposal_is_bounded_digest_only_and_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::Available);
    assert!(proposal.list_complete);
    assert!(proposal.associations_complete);
    assert_eq!(proposal.list_pages, 1);
    assert_eq!(proposal.data_source_pages, 1);
    assert_eq!(proposal.resolver_pages, 1);
    assert!(proposal.api.is_some());
    assert!(proposal.schema.is_some());
    assert!(proposal.associations.is_some());
    assert_eq!(proposal.request_receipts.len(), 5);
    assert_eq!(proposal.cost_receipts.len(), 5);
    assert!(
        proposal
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(
        proposal
            .cost_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.availability_claim);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_API_ID,
        RAW_API_ARN,
        RAW_SECRET,
        "https://fixture.appsync-api.example/graphql",
        "fixture-schema-hash",
        "fixture-data-source-primary",
        "Query.get",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "idempotency-811")
        .expect("record");
    assert!(!recorded.replayed);
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-811")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_unknown_and_never_native() {
    let scope = scope();
    let provider = AwsAppSyncProvider::new(BlockedEnvTransport).expect("provider");
    let secret = SecretReference::api_key(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_appsync_api_result_plugin::ConsentScope::for_layer_one(
        "consent-811",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsAppSyncApiResultService::new(scope, secret, consent, provider, now()).expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_revoke_emits_revoked_projection_and_restore_is_reversible() {
    let mut service = fixture_service();
    service.revoke().expect("revoke");
    let request = service.default_request(now()).expect("revoked request");
    let proposal = service.propose(request).expect("revoked proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::Revoked);
    assert!(!proposal.can_be_adopted());
    assert!(service.consumer().is_err());
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    assert!(service.consumer().is_ok());
}

#[test]
fn schema_revision_fence_is_fail_closed_as_stale() {
    let scope = scope()
        .with_revision_fence(
            hartevo_aws_appsync_api_result_plugin::RevisionFence::new(
                Some(Digest::from_text("expected-schema-revision")),
                None,
                None,
                None,
                None,
                None,
            )
            .expect("fence"),
        )
        .expect("fenced scope");
    let provider =
        AwsAppSyncProvider::new(FixtureTransport::for_scope(&scope, now())).expect("provider");
    let secret = SecretReference::oidc(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_appsync_api_result_plugin::ConsentScope::for_layer_one(
        "consent-811",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsAppSyncApiResultService::new(scope, secret, consent, provider, now()).expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("stale proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::Stale);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "revision_drift"
    );
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn tampered_response_is_rejected_before_projection() {
    let scope = scope();
    let request = ListGraphqlApisRequest::first(&scope, 25).expect("request");
    let summary = ApiSummary::new(
        scope.api().clone(),
        AppSyncApiType::Graphql,
        ApiLifecycleState::Active,
        true,
        now(),
        "fixture-revision",
    )
    .expect("summary");
    let response = ListGraphqlApisResponse::new(
        &request,
        vec![summary],
        None,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered-response"));
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(response));
    let provider = AwsAppSyncProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_appsync_api_result_plugin::ConsentScope::for_layer_one(
        "consent-811",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsAppSyncApiResultService::new(scope, secret, consent, provider, now()).expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::Tampered);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "tampered"
    );
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn repeated_opaque_next_token_is_rejected() {
    let scope = scope();
    let first_request = ListGraphqlApisRequest::first(&scope, 25).expect("first request");
    let first_cursor = Cursor::new("marker-a", &scope, AwsAppSyncOperation::ListGraphqlApis, 2)
        .expect("first cursor");
    let first_response = ListGraphqlApisResponse::new(
        &first_request,
        Vec::new(),
        Some(first_cursor.clone()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_request =
        ListGraphqlApisRequest::new(&scope, 25, Some(first_cursor)).expect("second request");
    let second_cursor = Cursor::new("marker-b", &scope, AwsAppSyncOperation::ListGraphqlApis, 3)
        .expect("second cursor");
    let second_response = ListGraphqlApisResponse::new(
        &second_request,
        Vec::new(),
        Some(second_cursor.clone()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("second response");
    let third_request =
        ListGraphqlApisRequest::new(&scope, 25, Some(second_cursor)).expect("third request");
    let repeated_cursor = Cursor::new("marker-a", &scope, AwsAppSyncOperation::ListGraphqlApis, 4)
        .expect("repeated cursor");
    let third_response = ListGraphqlApisResponse::new(
        &third_request,
        Vec::new(),
        Some(repeated_cursor),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("third response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first_response));
    transport.push_list_response(Ok(second_response));
    transport.push_list_response(Ok(third_response));
    let provider = AwsAppSyncProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_appsync_api_result_plugin::ConsentScope::for_layer_one(
        "consent-811",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsAppSyncApiResultService::new(scope, secret, consent, provider, now()).expect("service");
    let proposal = service
        .propose(service.request(25, 4, now()).expect("request"))
        .expect("loop proposal");
    assert_eq!(proposal.state, AppSyncEvidenceState::Tampered);
    assert_eq!(proposal.list_pages, 3);
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn all_layer_one_transports_are_non_native_and_non_connected() {
    assert!(!TransportProvenance::Recording.is_native());
    assert!(!TransportProvenance::Fixture.is_connected());
    assert!(!TransportProvenance::Loopback.is_first_party());
    assert!(!TransportProvenance::BlockedEnv.is_native());
}

#[allow(dead_code)]
fn _get_request_is_read_only() {
    let _ = GetApiRequest::for_scope(&scope()).expect("get request");
}
