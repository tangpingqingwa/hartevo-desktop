use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_resilience_hub_result_plugin::{
    ApplicationArn, ApplicationIdentity, ApplicationMetadata, ApplicationMetadataInput,
    ApplicationVersion, ApplicationVersionIdentity, AssessmentArn, AssessmentIdentity,
    AssessmentMetadata, AssessmentMetadataInput, AssessmentStatus, AwsAccountId, AwsRegion,
    AwsResilienceHubProvider, AwsResilienceHubRegistration, AwsResilienceHubScope,
    AwsResilienceHubTransportError, ComplianceStatus, ConsentScope, DescribeAppRequest,
    DescribeAppResponse, DriftStatus, FakeTransport, FixtureTransport, ListAppAssessmentsRequest,
    ListAppAssessmentsResponse, ListAppsRequest, ListAppsResponse, LoopbackTransport,
    MAX_PAGE_SIZE, MissionIdentity, OpaqueCursor, PermissionSnapshot, PostureStatus,
    ProjectIdentity, RecordingTransport, ResilienceEvidenceState, ResiliencyPolicyArn,
    ResiliencyPolicyIdentity, RiskCategory, RpoRtoPosture, SecretReference, TransportProvenance,
    WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_APPLICATION_ARN: &str =
    "arn:aws:resiliencehub:us-east-1:123456789012:app/fixture-application";
const RAW_ASSESSMENT_ARN: &str =
    "arn:aws:resiliencehub:us-east-1:123456789012:assessment/fixture-assessment";
const RAW_POLICY_ARN: &str =
    "arn:aws:resiliencehub:us-east-1:123456789012:resiliency-policy/fixture-policy";
const RAW_RESOURCE_ARN: &str = "arn:aws:ec2:us-east-1:123456789012:instance/private";
const RAW_MESSAGE: &str = "provider-private-resilience-message";
const RAW_RECOMMENDATION: &str = "provider recommendation text";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsResilienceHubScope {
    AwsResilienceHubScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        ApplicationIdentity::new(ApplicationArn::new(RAW_APPLICATION_ARN).expect("application")),
        ApplicationVersionIdentity::new(
            ApplicationVersion::new("release-7").expect("application version"),
        ),
        AssessmentIdentity::new(AssessmentArn::new(RAW_ASSESSMENT_ARN).expect("assessment")),
        ResiliencyPolicyIdentity::new(
            ResiliencyPolicyArn::new(RAW_POLICY_ARN).expect("resiliency policy"),
        ),
        MissionIdentity::new("mission-1", 7).expect("Mission"),
        ProjectIdentity::new("project-1", 11).expect("Project"),
        WorkProductIdentity::new("work-product-1", 13).expect("Work Product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsResilienceHubScope) -> SecretReference {
    SecretReference::sigv4("opaque-sigv4-handle", scope, 1).expect("secret reference")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 4, now() + Duration::days(7)).expect("consent")
}

fn assessment_input(
    status: AssessmentStatus,
    compliance_status: ComplianceStatus,
    drift: DriftStatus,
    expires_at: Option<DateTime<Utc>>,
) -> AssessmentMetadataInput {
    AssessmentMetadataInput {
        status,
        compliance_status,
        resiliency_score: Some(87),
        rpo_rto: RpoRtoPosture::new(
            PostureStatus::Met,
            PostureStatus::AtRisk,
            Some(15),
            Some(120),
        )
        .expect("RPO/RTO posture"),
        drift,
        risk_categories: vec![(RiskCategory::RecoveryTime, 1, now())],
        observed_at: now(),
        assessed_at: Some(now() - Duration::minutes(5)),
        expires_at,
        status_message: Some(RAW_MESSAGE.to_owned()),
        recommendation_text: Some(RAW_RECOMMENDATION.to_owned()),
        resource_arns: vec![RAW_RESOURCE_ARN.to_owned()],
        tags: vec!["sensitive=true".to_owned()],
    }
}

fn app_metadata(scope: &AwsResilienceHubScope) -> ApplicationMetadata {
    ApplicationMetadata::new(
        scope,
        ApplicationMetadataInput {
            application_version: scope.application_version().clone(),
            resiliency_policy: scope.resiliency_policy().clone(),
            drift: DriftStatus::NotDetected,
            observed_at: now(),
            expires_at: Some(now() + Duration::hours(12)),
            status_message: Some(RAW_MESSAGE.to_owned()),
            resource_arns: vec![RAW_RESOURCE_ARN.to_owned()],
            tags: vec!["secret=true".to_owned()],
        },
    )
    .expect("application metadata")
}

fn assessment_metadata(
    scope: &AwsResilienceHubScope,
    status: AssessmentStatus,
    compliance_status: ComplianceStatus,
    drift: DriftStatus,
    expires_at: Option<DateTime<Utc>>,
    assessed_at: Option<DateTime<Utc>>,
) -> AssessmentMetadata {
    let mut input = assessment_input(status, compliance_status, drift, expires_at);
    input.assessed_at = assessed_at;
    AssessmentMetadata::new(scope, input).expect("assessment metadata")
}

fn fixture_service()
-> hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService<FixtureTransport> {
    let scope = scope();
    let provider = AwsResilienceHubProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("fixture service")
}

#[test]
fn contract_scope_registration_and_four_read_seams_are_digest_fenced() {
    let scope = scope();
    let list_apps = ListAppsRequest::new(&scope, 10, None).expect("ListApps request");
    assert!(list_apps.path_and_query().contains("/apps?"));
    assert!(!list_apps.path_and_query().contains("opaque-next-token"));
    let describe_app = DescribeAppRequest::for_scope(&scope).expect("DescribeApp request");
    assert!(describe_app.path_and_query().contains("applicationDigest="));
    let list_assessments =
        ListAppAssessmentsRequest::new(&scope, 10, None).expect("ListAppAssessments request");
    assert!(
        list_assessments
            .path_and_query()
            .contains("/app-assessments?")
    );
    let describe_assessment =
        hartevo_aws_resilience_hub_result_plugin::DescribeAppAssessmentRequest::for_scope(&scope)
            .expect("DescribeAppAssessment request");
    assert!(
        describe_assessment
            .path_and_query()
            .contains("assessmentDigest=")
    );

    let service = fixture_service();
    assert!(service.registration().validate().is_ok());
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("opaque-sigv4-handle"));
    assert!(!debug.contains("opaque-sigv4-handle"));
    assert_eq!(service.describe_capabilities().operations.len(), 4);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().first_party);

    let provider = AwsResilienceHubProvider::default();
    let forbidden_permissions = PermissionSnapshot {
        revision: 1,
        permissions: ["resiliencehub:StartAppAssessment".to_owned()]
            .into_iter()
            .collect(),
    };
    assert!(
        AwsResilienceHubRegistration::new(
            "forbidden-permissions",
            scope.clone(),
            secret(&scope),
            forbidden_permissions,
            consent(),
            provider.definition(),
            1,
        )
        .is_err()
    );

    let other_scope = AwsResilienceHubScope::new(
        AwsAccountId::new("210987654321").expect("other account"),
        scope.region().clone(),
        scope.application().clone(),
        scope.application_version().clone(),
        scope.assessment().clone(),
        scope.resiliency_policy().clone(),
        scope.mission().clone(),
        scope.project().clone(),
        scope.work_product().clone(),
    )
    .expect("other scope");
    assert!(
        AwsResilienceHubRegistration::new(
            "wrong-secret-scope",
            other_scope,
            secret(&scope),
            PermissionSnapshot::for_layer_one(1),
            consent(),
            provider.definition(),
            1,
        )
        .is_err()
    );
}

#[test]
fn fixture_assessment_proposal_projects_only_bounded_redacted_posture() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, ResilienceEvidenceState::Compliant);
    assert!(proposal.list_apps_complete);
    assert!(proposal.list_app_assessments_complete);
    assert_eq!(proposal.list_apps_pages, 1);
    assert_eq!(proposal.list_app_assessments_pages, 1);
    assert_eq!(
        proposal
            .assessment
            .as_ref()
            .expect("assessment")
            .resiliency_score(),
        Some(92)
    );
    assert_eq!(
        proposal
            .assessment
            .as_ref()
            .expect("assessment")
            .rpo_rto()
            .rto,
        PostureStatus::Met
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert_eq!(proposal.evidence.evidence_digest.as_str().len(), 64);
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_APPLICATION_ARN,
        RAW_ASSESSMENT_ARN,
        RAW_POLICY_ARN,
        RAW_RESOURCE_ARN,
        RAW_MESSAGE,
        RAW_RECOMMENDATION,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
    assert!(serialized.contains("resiliencyScore"));
    assert!(serialized.contains("riskCategories"));

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(!result.can_be_adopted());
    assert_eq!(result.state, ResilienceEvidenceState::Compliant);
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_connected_native_or_first_party() {
    let scope = scope();
    let mut fixture = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsResilienceHubProvider::new(FixtureTransport::for_scope(&scope, now())).expect("fixture"),
        now(),
    )
    .expect("fixture service");
    let mut fake = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsResilienceHubProvider::new(FakeTransport::for_scope(&scope, now())).expect("fake"),
        now(),
    )
    .expect("fake service");
    let mut loopback = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsResilienceHubProvider::new(LoopbackTransport::for_scope(&scope, now()))
            .expect("loopback"),
        now(),
    )
    .expect("loopback service");
    let mut blocked = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsResilienceHubProvider::default(),
        now(),
    )
    .expect("blocked service");

    for (proposal, provenance) in [
        (
            fixture
                .propose(fixture.default_request(now()).expect("request"))
                .expect("fixture proposal"),
            TransportProvenance::Fixture,
        ),
        (
            fake.propose(fake.default_request(now()).expect("request"))
                .expect("fake proposal"),
            TransportProvenance::Fake,
        ),
        (
            loopback
                .propose(loopback.default_request(now()).expect("request"))
                .expect("loopback proposal"),
            TransportProvenance::Loopback,
        ),
        (
            blocked
                .propose(blocked.default_request(now()).expect("request"))
                .expect("blocked proposal"),
            TransportProvenance::BlockedEnv,
        ),
    ] {
        assert_eq!(proposal.provenance, provenance);
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.first_party);
        assert!(!proposal.provider_receipt);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn status_expiry_and_drift_are_distinct_fail_closed_states() {
    let cases = [
        (
            AssessmentStatus::InProgress,
            ComplianceStatus::Unknown,
            DriftStatus::NotDetected,
            Some(now() + Duration::hours(1)),
            Some(now() - Duration::minutes(5)),
            ResilienceEvidenceState::InProgress,
        ),
        (
            AssessmentStatus::Succeeded,
            ComplianceStatus::NonCompliant,
            DriftStatus::NotDetected,
            Some(now() + Duration::hours(1)),
            Some(now() - Duration::minutes(5)),
            ResilienceEvidenceState::NonCompliant,
        ),
        (
            AssessmentStatus::Succeeded,
            ComplianceStatus::Compliant,
            DriftStatus::Detected,
            Some(now() + Duration::hours(1)),
            Some(now() - Duration::minutes(5)),
            ResilienceEvidenceState::Drifted,
        ),
        (
            AssessmentStatus::Expired,
            ComplianceStatus::Compliant,
            DriftStatus::NotDetected,
            Some(now() - Duration::hours(1)),
            Some(now() - Duration::minutes(5)),
            ResilienceEvidenceState::Expired,
        ),
        (
            AssessmentStatus::Succeeded,
            ComplianceStatus::Compliant,
            DriftStatus::NotDetected,
            Some(now() + Duration::hours(1)),
            Some(now() - Duration::days(2)),
            ResilienceEvidenceState::Expired,
        ),
        (
            AssessmentStatus::Succeeded,
            ComplianceStatus::Compliant,
            DriftStatus::Unknown,
            Some(now() + Duration::hours(1)),
            Some(now() - Duration::minutes(5)),
            ResilienceEvidenceState::Unknown,
        ),
    ];
    for (status, compliance, drift, expires_at, assessed_at, expected) in cases {
        let scope = scope();
        let app = app_metadata(&scope);
        let assessment =
            assessment_metadata(&scope, status, compliance, drift, expires_at, assessed_at);
        let list_apps =
            ListAppsRequest::new(&scope, MAX_PAGE_SIZE, None).expect("ListApps request");
        let describe_app = DescribeAppRequest::for_scope(&scope).expect("DescribeApp request");
        let list_assessments = ListAppAssessmentsRequest::new(&scope, MAX_PAGE_SIZE, None)
            .expect("ListAppAssessments request");
        let describe_assessment =
            hartevo_aws_resilience_hub_result_plugin::DescribeAppAssessmentRequest::for_scope(
                &scope,
            )
            .expect("DescribeAppAssessment request");
        let mut transport = RecordingTransport::default();
        let list_response = ListAppsResponse::new(
            &list_apps,
            vec![app.clone()],
            None,
            512,
            TransportProvenance::Recording,
        )
        .expect("ListApps response");
        transport.push_list_apps_response(Ok(list_response));
        transport.push_describe_app_response(Ok(DescribeAppResponse::new(
            &describe_app,
            app,
            512,
            TransportProvenance::Recording,
        )
        .expect("DescribeApp response")));
        transport.push_list_app_assessments_response(Ok(ListAppAssessmentsResponse::new(
            &list_assessments,
            vec![assessment.clone()],
            None,
            512,
            TransportProvenance::Recording,
        )
        .expect("ListAppAssessments response")));
        transport.push_describe_app_assessment_response(Ok(
            hartevo_aws_resilience_hub_result_plugin::DescribeAppAssessmentResponse::new(
                &describe_assessment,
                assessment,
                512,
                TransportProvenance::Recording,
            )
            .expect("DescribeAppAssessment response"),
        ));
        let provider = AwsResilienceHubProvider::new(transport).expect("provider");
        let mut service = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            provider,
            now(),
        )
        .expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, expected);
        assert_eq!(
            service.verify(&proposal).review_eligible,
            expected.is_review_complete()
        );
    }
}

#[test]
fn pagination_is_opaque_bounded_and_loop_safe() {
    let scope = scope();
    let app = app_metadata(&scope);
    let first_request = ListAppsRequest::new(&scope, MAX_PAGE_SIZE, None).expect("first request");
    let first_cursor = OpaqueCursor::new(
        "loop-token",
        &scope,
        "ListApps",
        first_request.query_digest(),
        2,
    )
    .expect("first cursor");
    let second_request = ListAppsRequest::new(&scope, MAX_PAGE_SIZE, Some(first_cursor.clone()))
        .expect("second request");
    let repeated_cursor = OpaqueCursor::new(
        "loop-token",
        &scope,
        "ListApps",
        second_request.query_digest(),
        3,
    )
    .expect("repeated cursor");
    let first_response = ListAppsResponse::new(
        &first_request,
        vec![app.clone()],
        Some(first_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_response = ListAppsResponse::new(
        &second_request,
        vec![app],
        Some(repeated_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("second response");
    let mut transport = RecordingTransport::default();
    transport.push_list_apps_response(Ok(first_response));
    transport.push_list_apps_response(Ok(second_response));
    let provider = AwsResilienceHubProvider::new(transport).expect("provider");
    let mut service = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let proposal = service
        .propose(service.request(2, now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, ResilienceEvidenceState::Partial);
    assert!(!proposal.list_apps_complete);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "pagination_loop"
    );
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn transport_statuses_map_to_explicit_non_adoptable_evidence() {
    let cases = [
        (
            AwsResilienceHubTransportError::BadRequest,
            ResilienceEvidenceState::Unknown,
            Some(400),
        ),
        (
            AwsResilienceHubTransportError::Unauthorized,
            ResilienceEvidenceState::AccessLoss,
            Some(401),
        ),
        (
            AwsResilienceHubTransportError::Forbidden,
            ResilienceEvidenceState::AccessLoss,
            Some(403),
        ),
        (
            AwsResilienceHubTransportError::NotFound,
            ResilienceEvidenceState::NotFound,
            Some(404),
        ),
        (
            AwsResilienceHubTransportError::RateLimited {
                retry_after_seconds: Some(10),
            },
            ResilienceEvidenceState::Throttled,
            Some(429),
        ),
        (
            AwsResilienceHubTransportError::ServerError { status: 500 },
            ResilienceEvidenceState::Unknown,
            Some(500),
        ),
        (
            AwsResilienceHubTransportError::Timeout,
            ResilienceEvidenceState::Unknown,
            None,
        ),
        (
            AwsResilienceHubTransportError::AccessLost,
            ResilienceEvidenceState::AccessLoss,
            None,
        ),
    ];
    for (error, expected, status_code) in cases {
        let scope = scope();
        let mut transport = RecordingTransport::default();
        transport.push_list_apps_response(Err(error));
        let provider = AwsResilienceHubProvider::new(transport).expect("provider");
        let mut service = hartevo_aws_resilience_hub_result_plugin::AwsResilienceHubService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            provider,
            now(),
        )
        .expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert_eq!(
            proposal.failure.as_ref().expect("failure").status_code,
            status_code
        );
        assert!(proposal.state.is_non_adoptable());
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!proposal.first_party);
    }
}

#[test]
fn tamper_revocation_replay_and_scope_drift_fail_closed() {
    let mut service = fixture_service();
    let mut proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let original_digest = proposal.proposal_digest.clone();
    proposal.list_apps_complete = false;
    assert!(proposal.validate_integrity().is_err());
    proposal.list_apps_complete = true;
    assert_eq!(proposal.proposal_digest, original_digest);

    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    service.revoke().expect("revoke");
    assert!(
        service
            .propose(service.default_request(now()).expect("request"))
            .is_err()
    );
    assert!(!service.verify(&proposal).review_eligible);
    service.restore_registration().expect("restore");
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());

    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    assert!(consumer.record(&proposal, "recording-key").is_ok());
    assert!(consumer.record(&proposal, "recording-key").is_ok());
    assert!(consumer.record(&proposal, "").is_err());
}

#[test]
fn provider_definition_and_permission_snapshot_are_version_bound_read_only() {
    let provider = AwsResilienceHubProvider::default();
    provider
        .definition()
        .validate()
        .expect("provider definition");
    let permissions = PermissionSnapshot::for_layer_one(3);
    assert!(
        permissions
            .permissions
            .contains("resiliencehub:DescribeAppAssessment")
    );
    assert!(!permissions.permissions.iter().any(|permission| {
        permission.contains("Start")
            || permission.contains("Update")
            || permission.contains("Delete")
    }));
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
}
