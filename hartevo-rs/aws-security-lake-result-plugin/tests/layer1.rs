use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_security_lake_result_plugin::{
    AwsAccountId, AwsRegion, AwsSecurityLakeProvider, AwsSecurityLakeScope, AwsSecurityLakeService,
    DataLakeArn, DataLakeExceptionProjection, DataLakeIdentity, DataLakeProjection,
    DataLakeSourceProjection, DeploymentIdentity, EvidenceState, FixtureTransport,
    GetDataLakeSourcesRequest, GetDataLakeSourcesResponse, LakeStatus,
    ListDataLakeExceptionsRequest, ListDataLakeExceptionsResponse, ListDataLakesRequest,
    ListDataLakesResponse, ListLogSourcesRequest, ListLogSourcesResponse, LogSourceProjection,
    MissionAwsSecurityLakeConsumer, MissionIdentity, OpaquePageToken, OrganizationId,
    ProjectIdentity, SecretReference, SourceName, SourceState, TransportProvenance,
    WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsSecurityLakeScope {
    let region = AwsRegion::new("us-east-1").expect("region");
    AwsSecurityLakeScope::new(
        OrganizationId::new("o-exampleorg").expect("organization"),
        AwsAccountId::new("123456789012").expect("account"),
        vec![region.clone()],
        vec![
            DataLakeIdentity::new(
                region,
                Some(
                    DataLakeArn::new(
                        "arn:aws:securitylake:us-east-1:123456789012:data-lake/default",
                    )
                    .expect("lake arn"),
                ),
            )
            .expect("lake"),
        ],
        vec![SourceName::new("CloudTrail").expect("source")],
        14,
        DeploymentIdentity::new("deployment-646", 3).expect("deployment"),
        MissionIdentity::new("mission-646", 7).expect("mission"),
        ProjectIdentity::new("project-646", 11).expect("project"),
        WorkProductIdentity::new("work-product-646", 13).expect("work product"),
    )
    .expect("scope")
}

fn lake_projection(scope: &AwsSecurityLakeScope) -> DataLakeProjection {
    let lake = scope.lakes().first().expect("lake");
    DataLakeProjection::new(
        lake.region().clone(),
        lake.arn().cloned().expect("lake arn"),
        LakeStatus::Completed,
        Some("kms-reference-never-retained"),
        Some(365),
        None,
    )
    .expect("lake projection")
}

fn service_with_all_complete_pages()
-> hartevo_aws_security_lake_result_plugin::AwsSecurityLakeService<FixtureTransport> {
    let scope = scope();
    let lake = lake_projection(&scope);
    let list_lakes_request = ListDataLakesRequest::for_scope(&scope).expect("list lakes request");
    let list_lakes_page = ListDataLakesResponse::new(
        &list_lakes_request,
        vec![lake],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("list lakes page");

    let log_source_request = ListLogSourcesRequest::for_scope(&scope).expect("log source request");
    let log_source = LogSourceProjection::new(
        scope.account().clone(),
        scope.regions()[0].clone(),
        scope.sources()[0].clone(),
        "AWS::CloudTrail",
        SourceState::Enabled,
        9,
        ["Management"],
    )
    .expect("log source projection");
    let log_source_page = ListLogSourcesResponse::new(
        &log_source_request,
        vec![log_source],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("log source page");

    let snapshot_request = GetDataLakeSourcesRequest::for_scope(&scope).expect("snapshot request");
    let snapshot_source = DataLakeSourceProjection::new(
        scope.lakes()[0].clone(),
        scope.account().clone(),
        scope.sources()[0].clone(),
        ["Management"],
        SourceState::Enabled,
        "COLLECTING",
    )
    .expect("snapshot projection");
    let snapshot_page = GetDataLakeSourcesResponse::new(
        &snapshot_request,
        vec![snapshot_source],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("snapshot page");

    let exceptions_request =
        ListDataLakeExceptionsRequest::for_scope(&scope).expect("exceptions request");
    let retention = scope.retention_fence(now()).expect("retention fence");
    let exception = DataLakeExceptionProjection::new(
        scope.regions()[0].clone(),
        "SOURCE_PERMISSION",
        "review role permissions",
        now() - Duration::hours(1),
        &retention,
    )
    .expect("exception projection");
    let exceptions_page = ListDataLakeExceptionsResponse::new(
        &exceptions_request,
        vec![exception],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("exceptions page");

    let mut transport = FixtureTransport::new();
    transport.push_list_data_lakes_response(Ok(list_lakes_page));
    transport.push_list_log_sources_response(Ok(log_source_page));
    transport.push_get_data_lake_sources_response(Ok(snapshot_page));
    transport.push_list_data_lake_exceptions_response(Ok(exceptions_page));
    let provider = AwsSecurityLakeProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4("opaque-sigv4-secret", &scope, 2).expect("secret");
    let consent = hartevo_aws_security_lake_result_plugin::ConsentScope::for_layer_one(
        "consent-646",
        4,
        now() + Duration::days(1),
    )
    .expect("consent");
    AwsSecurityLakeService::new(scope, secret, consent, provider, now()).expect("service")
}

#[test]
fn registration_and_secret_are_digest_bound_without_raw_handles() {
    let service = service_with_all_complete_pages();
    let registration = serde_json::to_string(service.registration()).expect("registration JSON");
    let secret = serde_json::to_string(service.secret_reference()).expect("secret JSON");
    let debug = format!("{:?}", service.secret_reference());
    assert!(registration.contains("secretReferenceDigest"));
    assert!(!registration.contains("opaque-sigv4-secret"));
    assert_eq!(secret, "{\"opaque\":true}");
    assert!(!debug.contains("opaque-sigv4-secret"));
    assert!(service.registration().validate().is_ok());
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(
        service
            .describe_capabilities()
            .operations
            .contains(&"ListDataLakeExceptions".to_owned())
    );
}

#[test]
fn all_allowlisted_reads_project_digest_only_evidence_and_record_below_kernel() {
    let mut service = service_with_all_complete_pages();
    let mut consumer = MissionAwsSecurityLakeConsumer::new(
        service.scope().clone(),
        service.registration().clone(),
    )
    .expect("consumer");

    let proposals = [
        service.read_list_data_lakes().expect("list lakes"),
        service.read_list_log_sources().expect("list sources"),
        service
            .read_get_data_lake_sources()
            .expect("snapshot sources"),
        service
            .read_list_data_lake_exceptions()
            .expect("exceptions"),
    ];
    for (index, proposal) in proposals.iter().enumerate() {
        assert_eq!(proposal.state, EvidenceState::Complete);
        assert!(proposal.evidence.complete);
        assert!(proposal.evidence.validate_integrity().is_ok());
        let result = consumer.consume(proposal).expect("Mission result");
        assert!(result.accepted);
        assert!(result.review_only);
        assert!(!result.connected);
        assert!(!result.native);
        assert!(!result.outcome_adopted);
        let recorded = consumer
            .record(proposal, format!("idempotency-{index}"))
            .expect("recording");
        assert!(recorded.validate_integrity().is_ok());
        assert!(!recorded.native);
        let serialized = serde_json::to_string(&result).expect("result JSON");
        assert!(!serialized.contains("opaque-sigv4-secret"));
        assert!(!serialized.contains("review role permissions"));
    }
    assert_eq!(consumer.record_count(), 4);
}

#[test]
fn pagination_is_opaque_and_bound_to_the_filter() {
    let scope = scope();
    let request = ListLogSourcesRequest::for_scope(&scope).expect("request");
    let source = LogSourceProjection::new(
        scope.account().clone(),
        scope.regions()[0].clone(),
        scope.sources()[0].clone(),
        "AWS::CloudTrail",
        SourceState::Enabled,
        10,
        ["Management"],
    )
    .expect("source");
    let raw_token = OpaquePageToken::new("raw-provider-next-token").expect("token");
    let first = ListLogSourcesResponse::new(
        &request,
        vec![source.clone()],
        Some(raw_token),
        512,
        TransportProvenance::Fixture,
    )
    .expect("first page");
    let next = first.next_token().expect("next token").clone();
    let next_request = ListLogSourcesRequest::new(&scope, request.filter().clone(), Some(next))
        .expect("next request");
    let second = ListLogSourcesResponse::new(
        &next_request,
        vec![source],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("second page");
    assert!(
        serde_json::to_string(&first)
            .expect("page JSON")
            .contains("tokenDigest")
    );
    assert!(
        !serde_json::to_string(&first)
            .expect("page JSON")
            .contains("raw-provider-next-token")
    );
    assert_eq!(first.next_token().expect("next").page_number(), 2);
    assert!(second.next_token().is_none());

    let mut transport = FixtureTransport::new();
    transport.push_list_log_sources_response(Ok(first));
    transport.push_list_log_sources_response(Ok(second));
    let provider = AwsSecurityLakeProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4("opaque", &scope, 1).expect("secret");
    let consent = hartevo_aws_security_lake_result_plugin::ConsentScope::for_layer_one(
        "consent",
        1,
        now() + Duration::days(1),
    )
    .expect("consent");
    let mut service =
        AwsSecurityLakeService::new(scope, secret, consent, provider, now()).expect("service");
    let proposal = service.read_list_log_sources().expect("read");
    assert_eq!(proposal.state, EvidenceState::Complete);
    assert_eq!(proposal.evidence.pagination.pages_observed, 2);
    assert_eq!(proposal.evidence.pagination.cursor_digests.len(), 1);
}

#[test]
fn retention_gap_and_blocked_environment_fail_closed_without_native_claims() {
    let scoped = scope();
    let retention = scoped.retention_fence(now()).expect("retention");
    let request = ListDataLakeExceptionsRequest::for_scope(&scoped).expect("request");
    let old_exception = DataLakeExceptionProjection::new(
        scoped.regions()[0].clone(),
        "STALE",
        "old remediation",
        now() - Duration::days(15),
        &retention,
    )
    .expect("old exception projection");
    let page = ListDataLakeExceptionsResponse::new(
        &request,
        vec![old_exception],
        None,
        512,
        TransportProvenance::Fixture,
    )
    .expect("page");
    let mut transport = FixtureTransport::new();
    transport.push_list_data_lake_exceptions_response(Ok(page));
    let provider = AwsSecurityLakeProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4("opaque", &scoped, 1).expect("secret");
    let consent = hartevo_aws_security_lake_result_plugin::ConsentScope::for_layer_one(
        "consent",
        1,
        now() + Duration::days(1),
    )
    .expect("consent");
    let mut service = AwsSecurityLakeService::new(scoped.clone(), secret, consent, provider, now())
        .expect("service");
    let proposal = service
        .read_list_data_lake_exceptions()
        .expect("proposal despite fail-closed state");
    assert_eq!(proposal.state, EvidenceState::RetentionGap);
    let consumer = MissionAwsSecurityLakeConsumer::new(scoped, service.registration().clone())
        .expect("consumer");
    assert!(consumer.consume(&proposal).is_err());

    let blocked_provider = AwsSecurityLakeProvider::default();
    let blocked_scope = scope();
    let blocked_secret = SecretReference::sigv4("opaque", &blocked_scope, 1).expect("secret");
    let blocked_consent = hartevo_aws_security_lake_result_plugin::ConsentScope::for_layer_one(
        "consent",
        1,
        now() + Duration::days(1),
    )
    .expect("consent");
    let mut blocked_service = AwsSecurityLakeService::new(
        blocked_scope,
        blocked_secret,
        blocked_consent,
        blocked_provider,
        now(),
    )
    .expect("blocked service");
    let blocked = blocked_service
        .read_list_data_lakes()
        .expect("blocked proposal");
    assert_eq!(blocked.state, EvidenceState::ProviderUnknown);
    assert!(!blocked.connected);
    assert!(!blocked.native);
    assert_eq!(blocked.provenance, TransportProvenance::BlockedEnv);
}
