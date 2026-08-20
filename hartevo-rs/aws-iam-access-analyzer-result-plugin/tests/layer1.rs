use hartevo_aws_iam_access_analyzer_result_plugin as iam;

use iam::{
    AccessExposure, AnalysisState, AwsIamAccessAnalyzerError, AwsIamAccessAnalyzerRegistration,
    AwsIamAccessAnalyzerService, FilterCriterion, FindingFilters, FindingStatus, FindingSummaryV2,
    FindingType, ListFindingsV2Request, Locale, MissionIamAccessAnalyzerConsumer, OpaqueCursor,
    PageBounds, PermissionSnapshot, PolicyFindingType, PolicyResourceType, ProviderIdentity,
    ProviderProvenance, RecordingTransport, RegistrationId, ResourceArn, ResourceType, Revision,
    SecretReference, SortAttribute, SortCriteria, SortOrder, Timestamp, TransportProvenance,
    ValidatePolicyFinding, ValidatePolicyRequest,
};

fn make_registration() -> AwsIamAccessAnalyzerRegistration {
    let scope = iam::fixture_scope();
    AwsIamAccessAnalyzerRegistration::new(
        RegistrationId::new("registration-510", 1).expect("registration id"),
        scope.clone(),
        SecretReference::for_scope("opaque-sigv4-iam-reference", &scope, 3).expect("secret"),
        PermissionSnapshot::for_layer_one(2).expect("permissions"),
        ProviderIdentity::new(4, "fixture-provider").expect("provider"),
        5,
    )
    .expect("registration")
}

fn bounds() -> PageBounds {
    PageBounds::new(3, 8, 4).expect("bounds")
}

fn findings_request(scope: &iam::AwsIamAccessAnalyzerScope) -> ListFindingsV2Request {
    let filters = FindingFilters::new([iam::FindingFilter::new(
        iam::FindingFilterKey::FindingType,
        FilterCriterion::equals("ExternalAccess").expect("criterion"),
    )
    .expect("finding filter")])
    .expect("filters");
    ListFindingsV2Request::new(
        scope,
        filters,
        Some(SortCriteria::new(SortAttribute::UpdatedAt, SortOrder::Desc)),
        bounds(),
        None,
    )
    .expect("request")
}

fn public_finding() -> FindingSummaryV2 {
    FindingSummaryV2::new(
        "finding-public-1",
        FindingType::ExternalAccess,
        FindingStatus::Active,
        ResourceType::S3Bucket,
        iam::AwsAccountId::new("123456789012").expect("owner"),
        Some(iam::Digest::from_text("arn:aws:s3:::fixture-resource")),
        Timestamp::new(1_700_000_001).expect("analyzed"),
        Timestamp::new(1_700_000_000).expect("created"),
        Timestamp::new(1_700_000_002).expect("updated"),
        0,
        None,
        None,
        AccessExposure::Public,
    )
    .expect("finding")
}

fn policy_request(scope: &iam::AwsIamAccessAnalyzerScope) -> ValidatePolicyRequest {
    ValidatePolicyRequest::new(
        scope,
        r#"{"Version":"2012-10-17","Statement":[]}"#,
        Locale::En,
        bounds(),
        None,
    )
    .expect("policy request")
}

#[test]
fn contract_registration_and_secret_are_opaque_and_non_native() {
    let registration = make_registration();
    let serialized = serde_json::to_string(&registration).expect("safe registration");
    let debug = format!("{registration:?}");
    assert!(!serialized.contains("opaque-sigv4-iam-reference"));
    assert!(!debug.contains("opaque-sigv4-iam-reference"));
    assert!(serialized.contains("referenceDigest"));
    assert_eq!(registration.status(), iam::RegistrationStatus::Active);
    assert_eq!(
        iam::contract_digest().as_str(),
        "0a243b54edac711c289fb02fc530b83d1720f6fd98d51b48ec6db739d4fa4021"
    );
    let capabilities = iam::AwsIamAccessAnalyzerService::new(
        registration,
        RecordingTransport::new(ProviderProvenance::Recording),
    )
    .expect("service")
    .describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.least_privilege_certified);
}

#[test]
fn exact_scope_and_allowlists_reject_drift() {
    let scope = iam::fixture_scope();
    let wrong_analyzer = iam::AnalyzerArn::new(
        "arn:aws:access-analyzer:us-west-2:123456789012:analyzer/fixture-analyzer",
    )
    .expect("well-formed wrong analyzer");
    assert!(
        iam::AwsIamAccessAnalyzerScope::from_input(iam::AwsIamAccessAnalyzerScopeInput {
            account: scope.account.clone(),
            region: scope.region.clone(),
            analyzer: wrong_analyzer,
            analyzer_type: scope.analyzer_type,
            policy_type: scope.policy_type,
            policy_resource_type: scope.policy_resource_type,
            policy_revision: scope.policy_revision,
            resource: scope.resource.clone(),
            mission: scope.mission.clone(),
            project: scope.project.clone(),
            consent: scope.consent.clone(),
        },)
        .is_err()
    );
    assert!(PolicyResourceType::new("AWS::IAM::Role").is_err());
    assert!(ResourceArn::new("arn:aws:s3:::fixture-resource\n").is_err());
    assert!(PageBounds::new(33, 8, 4).is_err());
    assert!(PageBounds::new(2, 8, 101).is_err());
    let wrong_cursor =
        OpaqueCursor::new("cursor", iam::Digest::from_text("different-binding")).expect("cursor");
    assert!(
        ListFindingsV2Request::new(
            &scope,
            FindingFilters::empty(),
            None,
            bounds(),
            Some(wrong_cursor),
        )
        .is_err()
    );
    let bad_json = ValidatePolicyRequest::new(&scope, "[]", Locale::En, bounds(), None);
    assert_eq!(
        bad_json,
        Err(AwsIamAccessAnalyzerError::InvalidPolicyDocument)
    );
}

#[test]
fn list_findings_is_bounded_redacted_and_public_cross_account_internal_unused_are_typed() {
    let registration = make_registration();
    let scope = registration.scope().clone();
    let request = findings_request(&scope);
    let bound_request = request
        .clone()
        .with_permission_digest(registration.permission_snapshot().digest.clone());
    let cross_account = FindingSummaryV2::new(
        "finding-cross-account-2",
        FindingType::ExternalAccess,
        FindingStatus::Archived,
        ResourceType::IamRole,
        iam::AwsAccountId::new("999999999999").expect("owner"),
        Some(iam::Digest::from_text("resource-2")),
        Timestamp::new(1_700_000_001).expect("analyzed"),
        Timestamp::new(1_700_000_000).expect("created"),
        Timestamp::new(1_700_000_002).expect("updated"),
        2,
        Some(iam::Digest::from_text("actions")),
        None,
        AccessExposure::CrossAccount,
    )
    .expect("finding");
    let internal = FindingSummaryV2::new(
        "finding-internal-3",
        FindingType::InternalAccess,
        FindingStatus::Resolved,
        ResourceType::S3Bucket,
        iam::AwsAccountId::new("123456789012").expect("owner"),
        Some(iam::Digest::from_text("resource-3")),
        Timestamp::new(1_700_000_001).expect("analyzed"),
        Timestamp::new(1_700_000_000).expect("created"),
        Timestamp::new(1_700_000_002).expect("updated"),
        0,
        None,
        None,
        AccessExposure::Internal,
    )
    .expect("finding");
    let unused = FindingSummaryV2::new(
        "finding-unused-4",
        FindingType::UnusedPermission,
        FindingStatus::Active,
        ResourceType::IamRole,
        iam::AwsAccountId::new("123456789012").expect("owner"),
        None,
        Timestamp::new(1_700_000_001).expect("analyzed"),
        Timestamp::new(1_700_000_000).expect("created"),
        Timestamp::new(1_700_000_002).expect("updated"),
        0,
        None,
        None,
        AccessExposure::Unused,
    )
    .expect("finding");
    let response = iam::ListFindingsV2Response::for_request(
        &bound_request,
        vec![public_finding(), cross_account, internal, unused],
        None,
        registration.provider(),
        ProviderProvenance::Recording,
    )
    .expect("response");
    let mut transport = RecordingTransport::new(ProviderProvenance::Recording);
    transport.push_findings_response(Ok(response));
    let mut service = AwsIamAccessAnalyzerService::new(registration, transport).expect("service");
    let evidence = service.read_findings_v2(&request).expect("evidence");
    assert_eq!(evidence.state, AnalysisState::Complete);
    assert_eq!(evidence.finding_count, 4);
    assert_eq!(evidence.findings[0].exposure, AccessExposure::Public);
    assert_eq!(evidence.findings[1].exposure, AccessExposure::CrossAccount);
    assert_eq!(evidence.findings[2].exposure, AccessExposure::Internal);
    assert_eq!(evidence.findings[3].exposure, AccessExposure::Unused);
    let rendered = format!("{evidence:?}");
    assert!(!rendered.contains("principal"));
    assert!(!rendered.contains("fixture-policy-body"));
    evidence.validate_integrity().expect("evidence integrity");
}

#[test]
fn cursor_replay_page_budget_and_retry_are_fail_closed() {
    let registration = make_registration();
    let scope = registration.scope().clone();
    let request = findings_request(&scope);
    let bound_request = request
        .clone()
        .with_permission_digest(registration.permission_snapshot().digest.clone());
    let cursor = OpaqueCursor::new(
        "opaque-page-token",
        bound_request.cursor_binding_digest().clone(),
    )
    .expect("cursor");
    let first = iam::ListFindingsV2Response::for_request(
        &bound_request,
        vec![public_finding()],
        Some(cursor.clone()),
        registration.provider(),
        ProviderProvenance::Recording,
    )
    .expect("first response");
    let second_request = bound_request.next_page(cursor).expect("second request");
    let second = iam::ListFindingsV2Response::for_request(
        &second_request,
        vec![],
        None,
        registration.provider(),
        ProviderProvenance::Recording,
    )
    .expect("second response");
    let mut transport = RecordingTransport::new(ProviderProvenance::Recording);
    transport.push_findings_response(Err(iam::AwsIamTransportError::Http(429)));
    transport.push_findings_response(Ok(first));
    transport.push_findings_response(Ok(second));
    let mut service = AwsIamAccessAnalyzerService::new(registration, transport).expect("service");
    let evidence = service
        .read_findings_v2(&request)
        .expect("bounded evidence");
    assert_eq!(evidence.state, AnalysisState::Complete);
    assert_eq!(evidence.retry.attempts, 2);
    assert!(evidence.retry.retried);
    assert_eq!(evidence.retry.backoff_millis, 100);
    assert_eq!(evidence.pages_observed, 2);

    let replay_cursor = OpaqueCursor::new("opaque-page-token", iam::Digest::from_text("different"))
        .expect("replay cursor");
    assert!(bound_request.next_page(replay_cursor).is_err());

    let registration = make_registration();
    let scope = registration.scope().clone();
    let request = ListFindingsV2Request::new(
        &scope,
        FindingFilters::empty(),
        None,
        PageBounds::new(1, 8, 4).expect("one page"),
        None,
    )
    .expect("request")
    .with_permission_digest(registration.permission_snapshot().digest.clone());
    let cursor = OpaqueCursor::new("bounded-cursor", request.cursor_binding_digest().clone())
        .expect("cursor");
    let response = iam::ListFindingsV2Response::for_request(
        &request,
        vec![public_finding()],
        Some(cursor),
        registration.provider(),
        ProviderProvenance::Recording,
    )
    .expect("response");
    let mut transport = RecordingTransport::new(ProviderProvenance::Recording);
    transport.push_findings_response(Ok(response));
    let mut service = AwsIamAccessAnalyzerService::new(registration, transport).expect("service");
    let evidence = service
        .read_findings_v2(&request)
        .expect("partial evidence");
    assert_eq!(
        evidence.state,
        AnalysisState::Partial(iam::PartialReason::PageBudgetExhausted)
    );
}

#[test]
fn validate_policy_redacts_document_and_retains_typed_issue_locations() {
    let registration = make_registration();
    let scope = registration.scope().clone();
    let request = policy_request(&scope);
    let bound_request = request
        .clone()
        .with_permission_digest(registration.permission_snapshot().digest.clone());
    let location =
        iam::PolicyLocation::new("Statement[0].Principal", 2, 3, 10, 2, 18, 25).expect("location");
    let finding = ValidatePolicyFinding::new(
        PolicyFindingType::SecurityWarning,
        "PUBLIC_ACCESS",
        "raw policy details must not survive",
        "https://docs.aws.amazon.com/iam/",
        vec![location],
    )
    .expect("policy finding");
    let response = iam::ValidatePolicyResponse::for_request(
        &bound_request,
        vec![finding],
        None,
        registration.provider(),
        ProviderProvenance::Fake,
    )
    .expect("policy response");
    let mut transport = RecordingTransport::new(ProviderProvenance::Fake);
    transport.push_policy_response(Ok(response));
    let mut service = AwsIamAccessAnalyzerService::new(registration, transport).expect("service");
    let evidence = service
        .read_validate_policy(&request)
        .expect("policy evidence");
    assert_eq!(evidence.state, AnalysisState::Complete);
    assert_eq!(evidence.finding_count, 1);
    assert_eq!(
        evidence.findings[0].finding_type,
        PolicyFindingType::SecurityWarning
    );
    assert!(
        serde_json::to_string(&request)
            .expect("request serialization")
            .contains("policyDigest")
    );
    let serialized = serde_json::to_string(&evidence).expect("evidence serialization");
    assert!(!serialized.contains("raw policy details must not survive"));
    assert!(!serialized.contains("Statement[0].Principal"));
    evidence.validate_integrity().expect("policy integrity");
}

#[test]
fn provider_unknown_blocked_env_tamper_stale_mission_and_revocation_are_explicit() {
    let registration = make_registration();
    let scope = registration.scope().clone();
    let request = findings_request(&scope);
    let mut transport = RecordingTransport::new(ProviderProvenance::Fake);
    transport.push_findings_response(Err(iam::AwsIamTransportError::Http(500)));
    transport.push_findings_response(Err(iam::AwsIamTransportError::Http(500)));
    transport.push_findings_response(Err(iam::AwsIamTransportError::Http(500)));
    let mut service = AwsIamAccessAnalyzerService::new(registration, transport).expect("service");
    let unknown = service
        .observe_findings_v2(&request)
        .expect("unknown evidence");
    assert!(matches!(unknown.state, AnalysisState::ProviderUnknown(_)));
    assert_eq!(
        unknown.provider_error,
        Some(iam::ProviderErrorKind::ServerError)
    );

    let consumer = MissionIamAccessAnalyzerConsumer::from_registration(service.registration())
        .expect("consumer");
    let review = consumer.consume_findings(&unknown);
    assert_eq!(
        review.expect("review").state,
        iam::MissionReviewState::ProviderUnknown
    );

    let mut tampered = unknown.clone();
    tampered.finding_count = 1;
    assert_eq!(
        tampered.validate_integrity(),
        Err(AwsIamAccessAnalyzerError::TamperedEvidence)
    );
    assert_eq!(
        consumer.consume_findings_at_revision(&unknown, Revision::new(99).expect("revision")),
        Err(AwsIamAccessAnalyzerError::StaleMissionRevision)
    );

    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.read_findings_v2(&request),
        Err(AwsIamAccessAnalyzerError::RegistrationRevoked)
    );
    assert_eq!(
        service.restore_registration().expect("restore").status,
        iam::RegistrationStatus::Active
    );
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.read_findings_v2(&request),
        Err(AwsIamAccessAnalyzerError::RegistrationReversed)
    );

    let blocked_registration = make_registration();
    let mut blocked =
        AwsIamAccessAnalyzerService::new(blocked_registration, iam::BlockedEnvTransport)
            .expect("blocked service");
    let blocked_evidence = blocked
        .observe_findings_v2(&request)
        .expect("blocked evidence");
    assert_eq!(blocked_evidence.state, AnalysisState::BlockedEnv);
    assert_eq!(
        blocked.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
    assert!(!blocked.provider().connected());
    assert!(!blocked.provider().native());
    assert!(!blocked.provider().first_party());
}

#[test]
fn http_error_classes_are_normalized_without_response_bodies() {
    let cases = [
        (400, iam::AwsIamProviderError::BadRequest),
        (401, iam::AwsIamProviderError::Unauthorized),
        (403, iam::AwsIamProviderError::Forbidden),
        (404, iam::AwsIamProviderError::NotFound),
        (409, iam::AwsIamProviderError::Conflict),
        (
            429,
            iam::AwsIamProviderError::RateLimited {
                retry_after_seconds: None,
            },
        ),
        (500, iam::AwsIamProviderError::ServerError { status: 500 }),
    ];
    for (status, expected) in cases {
        let registration = make_registration();
        let request = findings_request(registration.scope());
        let mut transport = RecordingTransport::new(ProviderProvenance::Fake);
        transport.push_findings_response(Err(iam::AwsIamTransportError::Http(status)));
        let retry = iam::RetryPolicy::new(1, 0).expect("single attempt");
        let mut service =
            AwsIamAccessAnalyzerService::with_retry_policy(registration, transport, retry)
                .expect("service");
        assert_eq!(
            service.read_findings_v2(&request),
            Err(AwsIamAccessAnalyzerError::Provider(expected))
        );
    }

    let registration = make_registration();
    let request = findings_request(registration.scope());
    let mut transport = RecordingTransport::new(ProviderProvenance::Fake);
    transport.push_findings_response(Err(iam::AwsIamTransportError::Timeout));
    let retry = iam::RetryPolicy::new(1, 0).expect("single attempt");
    let mut service =
        AwsIamAccessAnalyzerService::with_retry_policy(registration, transport, retry)
            .expect("service");
    assert_eq!(
        service.read_findings_v2(&request),
        Err(AwsIamAccessAnalyzerError::Provider(
            iam::AwsIamProviderError::Timeout,
        ))
    );
}
