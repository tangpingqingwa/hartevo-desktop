use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_cloudfront_distribution_result_plugin::{
    AwsAccountId, AwsCloudFrontDistributionScope, AwsCloudFrontDistributionService,
    AwsCloudFrontProvider, AwsCloudFrontTransportError, AwsRegion, BlockedEnvTransport,
    CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, CloudFrontEvidenceState,
    Cursor, DeploymentIdentity, Digest, DistributionArn, DistributionId, DistributionIdentity,
    DistributionStatus, EVIDENCE_LEVEL, FixtureTransport, GetDistributionRequest,
    GetDistributionResponse, ListDistributionsRequest, ListDistributionsResponse, MissionIdentity,
    PLUGIN_ID, PROVIDER_ID, ProjectIdentity, RecordingTransport, SERVICE_ID, SecretReference,
    TransportProvenance, contract_digest,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_DISTRIBUTION_ID: &str = "EDIST123456789";
const RAW_DISTRIBUTION_ARN: &str = "arn:aws:cloudfront::123456789012:distribution/EDIST123456789";
const RAW_DOMAIN: &str = "d123.example.com";
const RAW_SECRET: &str = "opaque-sigv4-fixture-secret";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsCloudFrontDistributionScope {
    AwsCloudFrontDistributionScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("global").expect("region"),
        DistributionIdentity::new(
            DistributionId::new(RAW_DISTRIBUTION_ID).expect("distribution id"),
            DistributionArn::new(RAW_DISTRIBUTION_ARN).expect("distribution arn"),
            hartevo_aws_cloudfront_distribution_result_plugin::DomainName::new(RAW_DOMAIN)
                .expect("domain"),
        )
        .expect("distribution identity"),
        MissionIdentity::new("mission-620", 7).expect("mission"),
        ProjectIdentity::new("project-620", 11).expect("project"),
        DeploymentIdentity::new("deployment-620", 13).expect("deployment"),
    )
    .expect("scope")
}

fn fixture_service()
-> hartevo_aws_cloudfront_distribution_result_plugin::AwsCloudFrontDistributionService<
    FixtureTransport,
> {
    let scope = scope();
    let provider = AwsCloudFrontProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now()).expect("service")
}

#[test]
fn contract_and_registration_are_digest_bound_and_secret_redacted() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest(), CONTRACT_DIGEST);

    let service = fixture_service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert_eq!(service.describe_capabilities().provider_id, PROVIDER_ID);
    assert_eq!(service.describe_capabilities().service_id, SERVICE_ID);
}

#[test]
fn fixture_proposal_is_bounded_digest_only_and_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::Ready);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.distribution.is_some());
    let projection = proposal.distribution.as_ref().expect("projection");
    assert_eq!(projection.alias_count, 2);
    assert_eq!(projection.origin_count, 1);
    assert!(projection.waf.associated);
    assert_eq!(proposal.request_receipts.len(), 3);
    assert_eq!(proposal.cost_receipts.len(), 3);
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
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_DISTRIBUTION_ID,
        RAW_DISTRIBUTION_ARN,
        RAW_DOMAIN,
        RAW_SECRET,
        "fixture-etag",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "idempotency-620")
        .expect("record");
    assert!(!recorded.replayed);
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-620")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_unknown_and_never_native() {
    let scope = scope();
    let provider = AwsCloudFrontProvider::new(BlockedEnvTransport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_revoke_closes_service_and_consumer() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    service.revoke().expect("revoke");
    assert!(!service.registration().is_active());
    assert!(service.propose(request).is_err());
    assert!(service.consumer().is_err());
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
}

#[test]
fn transport_status_is_fail_closed_with_redacted_receipt() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Err(AwsCloudFrontTransportError::RateLimited {
        retry_after_seconds: Some(3),
    }));
    let provider = AwsCloudFrontProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("throttled proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::Throttled);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").status_code,
        Some(429)
    );
    assert_eq!(proposal.request_receipts.len(), 1);
    assert!(proposal.request_receipts[0].redacted);
}

#[test]
fn etag_drift_is_fail_closed_after_list_and_get() {
    let scope = scope();
    let list_request = ListDistributionsRequest::first(&scope, 100).expect("list request");
    let list_summary = hartevo_aws_cloudfront_distribution_result_plugin::DistributionSummary::new(
        scope.distribution().clone(),
        DistributionStatus::Deployed,
        true,
        now(),
        "etag-list",
    )
    .expect("list summary");
    let list_response = ListDistributionsResponse::new(
        &list_request,
        vec![list_summary],
        None,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let get_request = GetDistributionRequest::for_scope(&scope).expect("get request");
    let get_summary = hartevo_aws_cloudfront_distribution_result_plugin::DistributionSummary::new(
        scope.distribution().clone(),
        DistributionStatus::Deployed,
        true,
        now(),
        "etag-get",
    )
    .expect("get summary");
    let get_response = GetDistributionResponse::new(
        &get_request,
        get_summary,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("get response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_get_response(Ok(get_response));
    let provider = AwsCloudFrontProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("drift proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::ConfigDrift);
    assert_eq!(proposal.request_receipts.len(), 2);
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn tampered_response_is_rejected_before_projection() {
    let scope = scope();
    let list_request = ListDistributionsRequest::first(&scope, 100).expect("list request");
    let list_response = ListDistributionsResponse::new(
        &list_request,
        Vec::new(),
        None,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("list response")
    .with_declared_digest(Digest::from_text("tampered-response"));
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    let provider = AwsCloudFrontProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::Tampered);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "tampered"
    );
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn repeated_opaque_marker_is_rejected_as_pagination_loop() {
    let scope = scope();
    let first_request = ListDistributionsRequest::first(&scope, 100).expect("first request");
    let first_cursor = Cursor::new("marker-a", &scope, 2).expect("first cursor");
    let first_response = ListDistributionsResponse::new(
        &first_request,
        Vec::new(),
        Some(first_cursor.clone()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_request =
        ListDistributionsRequest::new(&scope, 100, Some(first_cursor)).expect("second request");
    let second_cursor = Cursor::new("marker-b", &scope, 3).expect("second cursor");
    let second_response = ListDistributionsResponse::new(
        &second_request,
        Vec::new(),
        Some(second_cursor.clone()),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("second response");
    let third_request =
        ListDistributionsRequest::new(&scope, 100, Some(second_cursor)).expect("third request");
    let third_response = ListDistributionsResponse::new(
        &third_request,
        Vec::new(),
        Some(Cursor::new("marker-a", &scope, 4).expect("repeated cursor")),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("third response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first_response));
    transport.push_list_response(Ok(second_response));
    transport.push_list_response(Ok(third_response));
    let provider = AwsCloudFrontProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_cloudfront_distribution_result_plugin::ConsentScope::for_layer_one(
        "consent-620",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsCloudFrontDistributionService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.request(100, 4, now()).expect("request"))
        .expect("loop proposal");
    assert_eq!(proposal.state, CloudFrontEvidenceState::PaginationLoop);
    assert_eq!(proposal.list_pages, 3);
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn loopback_and_recording_provenance_are_non_native() {
    assert_eq!(TransportProvenance::Recording.as_str(), "recording");
    assert!(!TransportProvenance::Recording.is_native());
    assert!(!TransportProvenance::Fixture.is_connected());
    assert!(!TransportProvenance::Loopback.is_first_party());
    assert!(!TransportProvenance::BlockedEnv.is_native());
}
