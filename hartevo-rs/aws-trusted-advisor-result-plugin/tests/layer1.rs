use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_trusted_advisor_result_plugin::{
    AwsAccountId, AwsRegion, AwsTrustedAdvisorCategory, AwsTrustedAdvisorProvider,
    AwsTrustedAdvisorProviderError, AwsTrustedAdvisorScope, AwsTrustedAdvisorService,
    AwsTrustedAdvisorTransportError, CategorySummary, CheckId, ConsentScope,
    DescribeTrustedAdvisorCheckRefreshStatusesRequest,
    DescribeTrustedAdvisorCheckRefreshStatusesResponse, DescribeTrustedAdvisorCheckResultRequest,
    DescribeTrustedAdvisorCheckResultResponse, DescribeTrustedAdvisorChecksRequest,
    DescribeTrustedAdvisorChecksResponse, Digest, FixtureTransport, FlaggedResourceDigest,
    MAX_FLAGGED_RESOURCES_PER_PAGE, MAX_RESPONSE_BYTES, MissionAwsTrustedAdvisorConsumer,
    MissionAwsTrustedAdvisorResultState, MissionBinding, MissionId, ModelError, PageCursor,
    PermissionSnapshot, ProjectBinding, ProjectId, RecommendationStatus, RecordingTransport,
    RefreshState, Revision, SecretReference, SupportPlan, TransportProvenance,
    TrustedAdvisorCheckDefinition, TrustedAdvisorCheckResult, TrustedAdvisorRefreshStatus,
    WorkProductBinding, WorkProductId,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_ACCOUNT: &str = "123456789012";
const RAW_SECRET: &str = "keyring/aws-support/trusted-advisor";
const RAW_RESOURCE: &str = "arn:aws:ec2:us-east-1:123456789012:instance/i-raw-fixture";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope_with(plan: SupportPlan, max_age: Duration) -> AwsTrustedAdvisorScope {
    let permissions = PermissionSnapshot::trusted_advisor_read(Revision::new(2).expect("revision"))
        .expect("permissions");
    AwsTrustedAdvisorScope::new(
        AwsAccountId::new(RAW_ACCOUNT).expect("account"),
        plan,
        AwsRegion::new("us-east-1").expect("region"),
        CheckId::new("check-layer1").expect("check"),
        AwsTrustedAdvisorCategory::Security,
        ProjectBinding::new(
            ProjectId::new("project-layer1").expect("project"),
            Revision::new(3).expect("revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-layer1").expect("mission"),
            Revision::new(4).expect("revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-layer1").expect("work product"),
            Revision::new(5).expect("revision"),
        ),
        Revision::new(6).expect("work product revision"),
        permissions,
        ConsentScope::for_layer_one("consent-layer1", 7).expect("consent"),
        max_age,
    )
    .expect("scope")
}

fn secret(scope: &AwsTrustedAdvisorScope) -> SecretReference {
    SecretReference::sigv4(
        RAW_SECRET,
        scope,
        Revision::new(8).expect("secret revision"),
    )
    .expect("secret")
}

fn fixture_service(scope: &AwsTrustedAdvisorScope) -> AwsTrustedAdvisorService<FixtureTransport> {
    let provider = AwsTrustedAdvisorProvider::new(FixtureTransport::for_scope(scope, now()))
        .expect("fixture provider");
    AwsTrustedAdvisorService::new(scope.clone(), secret(scope), provider).expect("service")
}

fn result_for(
    scope: &AwsTrustedAdvisorScope,
    status: RecommendationStatus,
    timestamp: DateTime<Utc>,
    next_page: Option<PageCursor>,
    identifier: &str,
) -> TrustedAdvisorCheckResult {
    let summary = CategorySummary::new(scope.category(), status, 1, 4).expect("summary");
    let flagged = vec![
        FlaggedResourceDigest::new(identifier, scope.region().clone()).expect("flagged resource"),
    ];
    TrustedAdvisorCheckResult::new(
        scope,
        status,
        timestamp,
        summary,
        flagged,
        next_page,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("result")
}

fn recording_service(
    scope: &AwsTrustedAdvisorScope,
    refresh_state: RefreshState,
    refresh_at: Option<DateTime<Utc>>,
    result_status: RecommendationStatus,
) -> AwsTrustedAdvisorService<RecordingTransport> {
    let checks_request =
        DescribeTrustedAdvisorChecksRequest::for_scope(scope).expect("checks request");
    let definition = TrustedAdvisorCheckDefinition::new(
        scope,
        digest("trusted-advisor-definition"),
        512,
        TransportProvenance::Recording,
    )
    .expect("definition");
    let checks_response = DescribeTrustedAdvisorChecksResponse::new(
        &checks_request,
        vec![definition],
        512,
        TransportProvenance::Recording,
    )
    .expect("checks response");

    let refresh_request = DescribeTrustedAdvisorCheckRefreshStatusesRequest::for_scope(scope)
        .expect("refresh request");
    let refresh_status = TrustedAdvisorRefreshStatus::new(
        scope,
        refresh_state,
        refresh_at,
        768,
        TransportProvenance::Recording,
    )
    .expect("refresh status");
    let refresh_response = DescribeTrustedAdvisorCheckRefreshStatusesResponse::new(
        &refresh_request,
        refresh_status,
        768,
        TransportProvenance::Recording,
    )
    .expect("refresh response");

    let result_request =
        DescribeTrustedAdvisorCheckResultRequest::for_scope(scope, None).expect("result request");
    let result = result_for(
        scope,
        result_status,
        now() - Duration::minutes(30),
        None,
        RAW_RESOURCE,
    );
    let result_response = DescribeTrustedAdvisorCheckResultResponse::new(
        &result_request,
        result,
        1_024,
        TransportProvenance::Recording,
    )
    .expect("result response");

    let mut transport = RecordingTransport::default();
    transport.push_checks_response(Ok(checks_response));
    transport.push_refresh_response(Ok(refresh_response));
    transport.push_result_response(Ok(result_response));
    let provider = AwsTrustedAdvisorProvider::new(transport).expect("recording provider");
    AwsTrustedAdvisorService::new(scope.clone(), secret(scope), provider).expect("service")
}

#[test]
fn contract_service_provider_and_registration_are_layer_one_bound() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let service = fixture_service(&scope);
    service.definition().validate().expect("service definition");
    service
        .provider()
        .definition()
        .validate()
        .expect("provider definition");
    service.registration().validate().expect("registration");
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let scope_json = serde_json::to_string(&scope).expect("scope JSON");
    let debug = format!("{service:?}");
    for raw in [RAW_ACCOUNT, RAW_SECRET] {
        assert!(
            !registration_json.contains(raw),
            "raw value leaked in registration: {raw}"
        );
        assert!(
            !scope_json.contains(raw),
            "raw value leaked in scope: {raw}"
        );
        assert!(!debug.contains(raw), "raw value leaked in debug: {raw}");
    }
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(registration_json.contains("providerApiRevision"));
    assert!(registration_json.contains("checkIdDigest"));
    assert!(registration_json.contains("categoryDigest"));
    assert!(registration_json.contains("evidencePolicyDigest"));
    assert!(service.definition().read_only);
    assert!(!service.definition().external_writes);
    assert!(!service.definition().native);
    assert_eq!(
        service.provider().provenance(),
        TransportProvenance::Fixture
    );
    assert!(!service.provider().provenance().is_native());
}

#[test]
fn fixture_result_is_fresh_bounded_and_digest_only() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let mut service = fixture_service(&scope);
    let proposal = service.compile_proposal_at(now()).expect("proposal");
    assert_eq!(
        proposal.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::Complete
    );
    assert_eq!(proposal.evidence.status, RecommendationStatus::Warning);
    assert_eq!(proposal.evidence.flagged_resources.len(), 2);
    assert!(proposal.review_eligible());
    assert!(proposal.is_review_only());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.outcome_adopted);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{:?}", proposal.evidence.flagged_resources);
    for raw in [RAW_RESOURCE, RAW_ACCOUNT, RAW_SECRET] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in debug: {raw}");
    }
    for item in &proposal.evidence.flagged_resources {
        assert_eq!(item.resource_digest().as_str().len(), 64);
    }
}

#[test]
fn mission_consumer_records_verifies_and_rejects_replay_without_adoption() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let service = fixture_service(&scope);
    let mut consumer = MissionAwsTrustedAdvisorConsumer::new(service).expect("consumer");
    let proposal = consumer.compile_proposal_at(now()).expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        MissionAwsTrustedAdvisorResultState::RecommendationWarning
    );
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(!result.connected);
    assert!(!result.native);
    let verification = consumer.verify(&proposal).expect("verification");
    assert!(verification.valid);
    let recorded = consumer
        .record(&proposal, "mission-record-1")
        .expect("record");
    assert!(!recorded.replayed);
    let replay = consumer
        .record(&proposal, "mission-record-1")
        .expect("replay");
    assert!(replay.replayed);
    replay.validate_integrity().expect("replay receipt");
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hartevo_aws_trusted_advisor_result_plugin::MissionAwsTrustedAdvisorConsumerError::ReplayDetected)
    ));
}

#[test]
fn unsupported_support_plan_is_explicit_and_does_not_call_transport() {
    let scope = scope_with(SupportPlan::Developer, Duration::hours(24));
    let provider = AwsTrustedAdvisorProvider::new(RecordingTransport::default()).expect("provider");
    let service = AwsTrustedAdvisorService::new(
        scope,
        secret(&scope_with(SupportPlan::Developer, Duration::hours(1))),
        provider,
    );
    assert!(service.is_err(), "secret must be from the exact scope");

    let scope = scope_with(SupportPlan::Developer, Duration::hours(24));
    let provider = AwsTrustedAdvisorProvider::new(RecordingTransport::default()).expect("provider");
    let mut service =
        AwsTrustedAdvisorService::new(scope.clone(), secret(&scope), provider).expect("service");
    let proposal = service.compile_proposal_at(now()).expect("proposal");
    assert_eq!(
        proposal.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::UnsupportedSupportPlan
    );
    assert!(!proposal.review_eligible());
    assert_eq!(proposal.evidence.provenance, TransportProvenance::Recording);
}

#[test]
fn stale_refresh_and_refresh_state_fail_closed_before_result_read() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let mut stale = recording_service(
        &scope,
        RefreshState::Complete,
        Some(now() - Duration::days(2)),
        RecommendationStatus::Ok,
    );
    let stale_proposal = stale.compile_proposal_at(now()).expect("stale proposal");
    assert_eq!(
        stale_proposal.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::RefreshStale
    );
    assert!(!stale_proposal.review_eligible());

    let mut in_progress = recording_service(
        &scope,
        RefreshState::InProgress,
        None,
        RecommendationStatus::Ok,
    );
    let progress = in_progress
        .compile_proposal_at(now())
        .expect("progress proposal");
    assert_eq!(
        progress.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::RefreshInProgress
    );
    assert!(!progress.review_eligible());
}

#[test]
fn result_status_transitions_are_preserved_without_causal_claims() {
    for (status, expected) in [
        (
            RecommendationStatus::Ok,
            MissionAwsTrustedAdvisorResultState::DecisionReady,
        ),
        (
            RecommendationStatus::Warning,
            MissionAwsTrustedAdvisorResultState::RecommendationWarning,
        ),
        (
            RecommendationStatus::Error,
            MissionAwsTrustedAdvisorResultState::RecommendationError,
        ),
        (
            RecommendationStatus::NotAvailable,
            MissionAwsTrustedAdvisorResultState::NeedsMoreEvidence,
        ),
    ] {
        let scope = scope_with(SupportPlan::Business, Duration::hours(24));
        let mut service = recording_service(
            &scope,
            RefreshState::Complete,
            Some(now() - Duration::hours(1)),
            status,
        );
        let proposal = service.compile_proposal_at(now()).expect("proposal");
        assert_eq!(proposal.evidence.status, status);
        let mut consumer = MissionAwsTrustedAdvisorConsumer::new(service).expect("consumer");
        let result = consumer.consume(&proposal).expect("result");
        assert_eq!(result.state, expected);
        assert!(!result.outcome_adopted);
        assert!(!result.work_product_adopted);
    }
}

#[test]
fn pagination_is_bounded_and_opaque() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let checks_request = DescribeTrustedAdvisorChecksRequest::for_scope(&scope).expect("checks");
    let definition = TrustedAdvisorCheckDefinition::new(
        &scope,
        digest("definition"),
        512,
        TransportProvenance::Recording,
    )
    .expect("definition");
    let checks_response = DescribeTrustedAdvisorChecksResponse::new(
        &checks_request,
        vec![definition],
        512,
        TransportProvenance::Recording,
    )
    .expect("checks response");
    let refresh_request =
        DescribeTrustedAdvisorCheckRefreshStatusesRequest::for_scope(&scope).expect("refresh");
    let refresh_response = DescribeTrustedAdvisorCheckRefreshStatusesResponse::new(
        &refresh_request,
        TrustedAdvisorRefreshStatus::new(
            &scope,
            RefreshState::Complete,
            Some(now() - Duration::hours(1)),
            768,
            TransportProvenance::Recording,
        )
        .expect("refresh status"),
        768,
        TransportProvenance::Recording,
    )
    .expect("refresh response");
    let cursor = PageCursor::new("raw-next-token", &scope, 2).expect("cursor");
    let page_one_request =
        DescribeTrustedAdvisorCheckResultRequest::for_scope(&scope, None).expect("page one");
    let page_one = DescribeTrustedAdvisorCheckResultResponse::new(
        &page_one_request,
        result_for(
            &scope,
            RecommendationStatus::Warning,
            now() - Duration::minutes(30),
            Some(cursor.clone()),
            "raw-resource-page-one",
        ),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("page one response");
    let page_two_request =
        DescribeTrustedAdvisorCheckResultRequest::for_scope(&scope, Some(cursor))
            .expect("page two");
    let page_two = DescribeTrustedAdvisorCheckResultResponse::new(
        &page_two_request,
        result_for(
            &scope,
            RecommendationStatus::Warning,
            now() - Duration::minutes(30),
            None,
            "raw-resource-page-two",
        ),
        1_024,
        TransportProvenance::Recording,
    )
    .expect("page two response");
    let mut transport = RecordingTransport::default();
    transport.push_checks_response(Ok(checks_response));
    transport.push_refresh_response(Ok(refresh_response));
    transport.push_result_response(Ok(page_one));
    transport.push_result_response(Ok(page_two));
    let provider = AwsTrustedAdvisorProvider::new(transport).expect("provider");
    let mut service =
        AwsTrustedAdvisorService::new(scope.clone(), secret(&scope), provider).expect("service");
    let proposal = service.compile_proposal_at(now()).expect("proposal");
    assert_eq!(proposal.evidence.pages_read, 2);
    assert_eq!(proposal.evidence.flagged_resources.len(), 2);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("raw-next-token"));
    assert!(!serialized.contains("raw-resource-page-one"));
}

#[test]
fn transport_failures_map_to_explicit_non_adoptable_states() {
    let cases = [
        (
            AwsTrustedAdvisorTransportError::BadRequest,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::ProviderUnknown,
        ),
        (
            AwsTrustedAdvisorTransportError::Unauthorized,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::AccessLost,
        ),
        (
            AwsTrustedAdvisorTransportError::Forbidden,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::AccessLost,
        ),
        (
            AwsTrustedAdvisorTransportError::NotFound,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::CheckNotFound,
        ),
        (
            AwsTrustedAdvisorTransportError::Conflict,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::ProviderUnknown,
        ),
        (
            AwsTrustedAdvisorTransportError::RateLimited {
                retry_after_seconds: Some(30),
            },
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::Throttled,
        ),
        (
            AwsTrustedAdvisorTransportError::ServerError { status: 503 },
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::ProviderUnknown,
        ),
        (
            AwsTrustedAdvisorTransportError::Timeout,
            hartevo_aws_trusted_advisor_result_plugin::EvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope_with(SupportPlan::Business, Duration::hours(24));
        let mut transport = RecordingTransport::default();
        transport.push_checks_response(Err(error));
        let provider = AwsTrustedAdvisorProvider::new(transport).expect("provider");
        let mut service = AwsTrustedAdvisorService::new(scope.clone(), secret(&scope), provider)
            .expect("service");
        let proposal = service
            .compile_proposal_at(now())
            .expect("failure proposal");
        assert_eq!(proposal.state(), expected);
        assert!(!proposal.review_eligible());
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
}

#[test]
fn blocked_env_fixture_and_loopback_are_never_native_or_connected() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    for provenance in [TransportProvenance::Fixture, TransportProvenance::Loopback] {
        assert!(!provenance.is_native());
        assert!(!provenance.is_connected());
        assert!(!provenance.is_first_party());
    }
    let mut blocked = AwsTrustedAdvisorService::new(
        scope.clone(),
        secret(&scope),
        AwsTrustedAdvisorProvider::new(
            hartevo_aws_trusted_advisor_result_plugin::BlockedEnvTransport,
        )
        .expect("blocked provider"),
    )
    .expect("blocked service");
    let proposal = blocked
        .compile_proposal_at(now())
        .expect("blocked proposal");
    assert_eq!(
        proposal.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::ProviderUnknown
    );
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .blocked_env
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
}

#[test]
fn tamper_check_id_scope_and_response_drift_fail_closed() {
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let mut service = fixture_service(&scope);
    let proposal = service.compile_proposal_at(now()).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.status = RecommendationStatus::Error;
    assert!(tampered.validate_integrity(&scope).is_err());

    let alternate = CheckId::new("different-check").expect("alternate check");
    let request = DescribeTrustedAdvisorChecksRequest::for_scope(&scope).expect("checks request");
    let definition = TrustedAdvisorCheckDefinition::for_check(
        &scope,
        alternate,
        scope.category(),
        digest("alternate-definition"),
        512,
        TransportProvenance::Recording,
    )
    .expect("alternate definition");
    let response = DescribeTrustedAdvisorChecksResponse::new(
        &request,
        vec![definition],
        512,
        TransportProvenance::Recording,
    )
    .expect("response");
    let mut transport = RecordingTransport::default();
    transport.push_checks_response(Ok(response));
    let provider = AwsTrustedAdvisorProvider::new(transport).expect("provider");
    let mut drifted =
        AwsTrustedAdvisorService::new(scope.clone(), secret(&scope), provider).expect("service");
    let drifted_proposal = drifted.compile_proposal_at(now()).expect("drift proposal");
    assert_eq!(
        drifted_proposal.state(),
        hartevo_aws_trusted_advisor_result_plugin::EvidenceState::CheckNotFound
    );
}

#[test]
fn bounds_account_region_secret_and_registration_revocation_are_fail_closed() {
    assert_eq!(
        AwsAccountId::new("123").unwrap_err(),
        ModelError::InvalidAccountId
    );
    assert_eq!(
        AwsTrustedAdvisorScope::new(
            AwsAccountId::new(RAW_ACCOUNT).expect("account"),
            SupportPlan::Business,
            AwsRegion::new("eu-west-1").expect("region"),
            CheckId::new("check").expect("check"),
            AwsTrustedAdvisorCategory::Security,
            ProjectBinding::new(
                ProjectId::new("project").expect("project"),
                Revision::new(1).expect("revision")
            ),
            MissionBinding::new(
                MissionId::new("mission").expect("mission"),
                Revision::new(1).expect("revision")
            ),
            WorkProductBinding::new(
                WorkProductId::new("work").expect("work"),
                Revision::new(1).expect("revision")
            ),
            Revision::new(1).expect("revision"),
            PermissionSnapshot::trusted_advisor_read(Revision::new(1).expect("revision"))
                .expect("permissions"),
            ConsentScope::for_layer_one("consent", 1).expect("consent"),
            Duration::hours(1),
        )
        .unwrap_err(),
        ModelError::InvalidSupportEndpointRegion
    );

    let mut resources = Vec::new();
    for index in 0..=MAX_FLAGGED_RESOURCES_PER_PAGE {
        resources.push(
            FlaggedResourceDigest::new(
                format!("arn:aws:ec2:us-east-1:resource-{index}"),
                AwsRegion::new("us-east-1").expect("region"),
            )
            .expect("resource"),
        );
    }
    let scope = scope_with(SupportPlan::Business, Duration::hours(24));
    let too_many = TrustedAdvisorCheckResult::new(
        &scope,
        RecommendationStatus::Warning,
        now(),
        CategorySummary::new(scope.category(), RecommendationStatus::Warning, 65, 65)
            .expect("summary"),
        resources,
        None,
        1_024,
        TransportProvenance::Recording,
    );
    assert_eq!(too_many.unwrap_err(), ModelError::BoundsExceeded);
    assert_eq!(
        TrustedAdvisorCheckDefinition::new(
            &scope,
            digest("definition"),
            MAX_RESPONSE_BYTES + 1,
            TransportProvenance::Recording,
        )
        .unwrap_err(),
        ModelError::BoundsExceeded
    );

    let mut consumer =
        MissionAwsTrustedAdvisorConsumer::new(fixture_service(&scope)).expect("consumer");
    let proposal = consumer.compile_proposal_at(now()).expect("proposal");
    consumer.revoke().expect("revoke");
    assert!(matches!(
        consumer.compile_proposal_at(now()),
        Err(hartevo_aws_trusted_advisor_result_plugin::MissionAwsTrustedAdvisorConsumerError::Revoked)
    ));
    consumer.restore().expect("restore");
    assert!(consumer.compile_proposal_at(now()).is_ok());
    assert!(
        consumer.verify(&proposal).is_err(),
        "old registration digest must not verify after restore"
    );
}

#[test]
fn provider_error_surface_remains_typed() {
    let error = AwsTrustedAdvisorTransportError::RateLimited {
        retry_after_seconds: Some(12),
    };
    let wrapped = AwsTrustedAdvisorProviderError::Transport(error.clone());
    assert_eq!(wrapped.to_string(), "AWS Support returned HTTP 429");
    assert_eq!(error.status_code(), Some(429));
    assert_eq!(error.retry_after_seconds(), Some(12));
}
