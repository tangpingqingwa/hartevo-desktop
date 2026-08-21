use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_compute_optimizer_result_plugin::{
    AwsAccountId, AwsComputeOptimizerProvider, AwsComputeOptimizerScope,
    AwsComputeOptimizerService, AwsComputeOptimizerTransportError, AwsRegion, BlockedEnvTransport,
    ComputeOptimizerRecommendation, ConsentScope, Digest, EvidenceState, FixtureTransport,
    GetEC2InstanceRecommendationsRequest, MAX_RESULT_PAGES, MissionAwsComputeOptimizerConsumer,
    MissionAwsComputeOptimizerResultState, MissionBinding, ModelError, OpaquePageCursor,
    PermissionSnapshot, ProjectBinding, ProjectId, RecommendationId, RecommendationStatus,
    RecommendationWindow, RecordingTransport, ResourceKind, ResourceSelector, Revision,
    SecretReference, TransportProvenance, WorkProductBinding, WorkProductId,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_ACCOUNT: &str = "123456789012";
const RAW_SECRET: &str = "keyring/aws/compute-optimizer";
const RAW_EC2: &str = "i-raw-layer1";
const RAW_ASG: &str = "asg-raw-layer1";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope_with(kind: ResourceKind, max_age: Duration) -> AwsComputeOptimizerScope {
    scope_with_id(
        kind,
        match kind {
            ResourceKind::Ec2Instance => RAW_EC2,
            ResourceKind::AutoScalingGroup => RAW_ASG,
        },
        max_age,
    )
}

fn scope_with_id(
    kind: ResourceKind,
    resource_id: &str,
    max_age: Duration,
) -> AwsComputeOptimizerScope {
    let resource = ResourceSelector::from_raw(kind, resource_id).expect("resource");
    AwsComputeOptimizerScope::new(
        AwsAccountId::new(RAW_ACCOUNT).expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        vec![resource],
        RecommendationWindow::closed(now() - Duration::hours(2), now() - Duration::minutes(1))
            .expect("window"),
        ProjectBinding::new(
            ProjectId::new("project-layer1").expect("project"),
            Revision::new(2).expect("revision"),
        ),
        MissionBinding::new(
            hartevo_aws_compute_optimizer_result_plugin::MissionId::new("mission-layer1")
                .expect("mission"),
            Revision::new(3).expect("revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-layer1").expect("work product"),
            Revision::new(4).expect("revision"),
        ),
        Revision::new(5).expect("work product revision"),
        PermissionSnapshot::compute_optimizer_read(Revision::new(6).expect("permission revision"))
            .expect("permissions"),
        ConsentScope::for_layer_one("consent-layer1", 7).expect("consent"),
        max_age,
    )
    .expect("scope")
}

fn secret(scope: &AwsComputeOptimizerScope) -> SecretReference {
    SecretReference::sigv4(
        RAW_SECRET,
        scope,
        Revision::new(8).expect("secret revision"),
    )
    .expect("secret")
}

fn fixture_service(
    scope: &AwsComputeOptimizerScope,
) -> AwsComputeOptimizerService<FixtureTransport> {
    let provider = AwsComputeOptimizerProvider::new(FixtureTransport::for_scope(scope, now()))
        .expect("provider");
    AwsComputeOptimizerService::new(scope.clone(), secret(scope), provider).expect("service")
}

fn recommendation(
    scope: &AwsComputeOptimizerScope,
    kind: ResourceKind,
    status: RecommendationStatus,
    observed_at: DateTime<Utc>,
) -> ComputeOptimizerRecommendation {
    let resource = scope
        .resources()
        .iter()
        .find(|resource| resource.kind() == kind)
        .expect("resource kind")
        .clone();
    ComputeOptimizerRecommendation::new(
        scope,
        resource,
        RecommendationId::new("recommendation-layer1").expect("recommendation id"),
        status,
        observed_at,
        14,
        Digest::from_text("current-config"),
        Digest::from_text("recommended-config"),
    )
    .expect("recommendation")
}

fn recording_service(
    scope: &AwsComputeOptimizerScope,
    error: Option<AwsComputeOptimizerTransportError>,
    observed_at: DateTime<Utc>,
) -> AwsComputeOptimizerService<RecordingTransport> {
    let kind = scope.resources()[0].kind();
    let request = GetEC2InstanceRecommendationsRequest::for_scope(scope, None).expect("request");
    let response =
        hartevo_aws_compute_optimizer_result_plugin::AwsComputeOptimizerRecommendationPage::new(
            &request,
            vec![recommendation(
                scope,
                kind,
                RecommendationStatus::Overprovisioned,
                observed_at,
            )],
            None,
            2048,
            TransportProvenance::Recording,
        )
        .expect("response");
    let mut transport = RecordingTransport::default();
    transport.push_response(kind, error.map_or(Ok(response), Err));
    let provider = AwsComputeOptimizerProvider::new(transport).expect("provider");
    AwsComputeOptimizerService::new(scope.clone(), secret(scope), provider).expect("service")
}

#[test]
fn contract_registration_and_scope_are_redacted_and_reversible() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let service = fixture_service(&scope);
    service.definition().validate().expect("definition");
    service
        .provider()
        .definition()
        .validate()
        .expect("provider");
    service.registration().validate().expect("registration");
    let scope_json = serde_json::to_string(&scope).expect("scope JSON");
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{service:?}");
    for raw in [RAW_ACCOUNT, RAW_SECRET, RAW_EC2] {
        assert!(!scope_json.contains(raw), "raw scope leak: {raw}");
        assert!(
            !registration_json.contains(raw),
            "raw registration leak: {raw}"
        );
        assert!(!debug.contains(raw), "raw debug leak: {raw}");
    }
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(registration_json.contains("resourceAllowlistDigest"));
    assert!(registration_json.contains("recommendationWindowDigest"));
    assert!(!service.definition().native);
    assert!(!service.definition().connected);
}

#[test]
fn fixture_reads_both_resource_kinds_without_native_claims() {
    let ec2 = ResourceSelector::from_raw(ResourceKind::Ec2Instance, RAW_EC2).expect("ec2");
    let asg = ResourceSelector::from_raw(ResourceKind::AutoScalingGroup, RAW_ASG).expect("asg");
    let scope = AwsComputeOptimizerScope::new(
        AwsAccountId::new(RAW_ACCOUNT).expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        vec![ec2, asg],
        RecommendationWindow::closed(now() - Duration::hours(2), now() - Duration::minutes(1))
            .expect("window"),
        ProjectBinding::new(
            ProjectId::new("project").expect("project"),
            Revision::new(1).unwrap(),
        ),
        MissionBinding::new(
            hartevo_aws_compute_optimizer_result_plugin::MissionId::new("mission").unwrap(),
            Revision::new(1).unwrap(),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work").unwrap(),
            Revision::new(1).unwrap(),
        ),
        Revision::new(1).unwrap(),
        PermissionSnapshot::compute_optimizer_read(Revision::new(1).unwrap()).unwrap(),
        ConsentScope::for_layer_one("consent", 1).unwrap(),
        Duration::hours(2),
    )
    .unwrap();
    let mut service = fixture_service(&scope);
    let proposal = service.compile_proposal_at(now()).expect("proposal");
    assert_eq!(proposal.state(), EvidenceState::Complete);
    assert_eq!(proposal.evidence.recommendations.len(), 2);
    assert_eq!(proposal.evidence.pages_read, 2);
    assert!(proposal.review_eligible());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.savings_guarantee);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [RAW_ACCOUNT, RAW_SECRET, RAW_EC2, RAW_ASG] {
        assert!(!serialized.contains(raw), "raw proposal leak: {raw}");
    }
}

#[test]
fn mission_consumer_records_verifies_and_rejects_replay() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let service = fixture_service(&scope);
    let mut consumer = MissionAwsComputeOptimizerConsumer::new(service).expect("consumer");
    let proposal = consumer.compile_proposal_at(now()).expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        MissionAwsComputeOptimizerResultState::RecommendationOverprovisioned
    );
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
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
    replay.validate_integrity().expect("receipt integrity");
    assert!(matches!(
        consumer.consume(&proposal),
        Err(hartevo_aws_compute_optimizer_result_plugin::MissionAwsComputeOptimizerConsumerError::ReplayDetected)
    ));
}

#[test]
fn freshness_window_and_future_timestamp_fail_closed() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(1));
    let mut stale = recording_service(&scope, None, now() - Duration::hours(3));
    let stale_proposal = stale.compile_proposal_at(now()).expect("stale proposal");
    assert_eq!(stale_proposal.state(), EvidenceState::Stale);
    assert!(!stale_proposal.review_eligible());

    let mut future = recording_service(&scope, None, now() + Duration::minutes(1));
    let future_proposal = future.compile_proposal_at(now()).expect("future proposal");
    assert_eq!(future_proposal.state(), EvidenceState::Stale);
    assert!(!future_proposal.review_eligible());
}

#[test]
fn transport_statuses_map_to_explicit_non_adoptable_states() {
    let cases = [
        (
            AwsComputeOptimizerTransportError::BadRequest,
            EvidenceState::ProviderUnknown,
        ),
        (
            AwsComputeOptimizerTransportError::Unauthorized,
            EvidenceState::AccessLost,
        ),
        (
            AwsComputeOptimizerTransportError::Forbidden,
            EvidenceState::AccessLost,
        ),
        (
            AwsComputeOptimizerTransportError::NotFound,
            EvidenceState::ResourceNotFound,
        ),
        (
            AwsComputeOptimizerTransportError::Conflict,
            EvidenceState::ProviderUnknown,
        ),
        (
            AwsComputeOptimizerTransportError::RateLimited {
                retry_after_seconds: Some(12),
            },
            EvidenceState::Throttled,
        ),
        (
            AwsComputeOptimizerTransportError::ServerError { status: 503 },
            EvidenceState::ProviderUnknown,
        ),
        (
            AwsComputeOptimizerTransportError::Timeout,
            EvidenceState::ProviderUnknown,
        ),
        (
            AwsComputeOptimizerTransportError::AccessLost,
            EvidenceState::AccessLost,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
        let mut service = recording_service(&scope, Some(error), now() - Duration::minutes(30));
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
fn pagination_is_opaque_bound_and_scope_token_bound() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let alternate = scope_with_id(
        ResourceKind::Ec2Instance,
        "i-different-scope",
        Duration::hours(2),
    );
    let cursor = OpaquePageCursor::new("raw-next-token", &scope, ResourceKind::Ec2Instance, 2)
        .expect("cursor");
    let request = GetEC2InstanceRecommendationsRequest::for_scope(&scope, Some(cursor.clone()))
        .expect("bound request");
    assert!(!format!("{request:?}").contains("raw-next-token"));
    let other_cursor =
        OpaquePageCursor::new("raw-other-token", &alternate, ResourceKind::Ec2Instance, 2)
            .expect("other cursor");
    assert!(GetEC2InstanceRecommendationsRequest::for_scope(&scope, Some(other_cursor)).is_err());

    assert!(OpaquePageCursor::new("token", &scope, ResourceKind::Ec2Instance, 1).is_err());
    assert!(
        OpaquePageCursor::new(
            "token",
            &scope,
            ResourceKind::Ec2Instance,
            MAX_RESULT_PAGES + 1
        )
        .is_err()
    );
}

#[test]
fn truncation_and_tamper_fail_closed() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let kind = ResourceKind::Ec2Instance;
    let mut transport = RecordingTransport::default();
    let mut cursor = None;
    for page_number in 1..=MAX_RESULT_PAGES {
        let request = GetEC2InstanceRecommendationsRequest::for_scope(&scope, cursor.clone())
            .expect("request");
        let next = OpaquePageCursor::new(
            format!("token-{page_number}"),
            &scope,
            kind,
            if page_number == MAX_RESULT_PAGES {
                MAX_RESULT_PAGES
            } else {
                page_number + 1
            },
        )
        .expect("next cursor");
        let page_recommendation = ComputeOptimizerRecommendation::from_raw_id(
            &scope,
            scope.resources()[0].clone(),
            format!("recommendation-page-{page_number}"),
            RecommendationStatus::Optimized,
            now() - Duration::minutes(20),
            14,
            format!("current-page-{page_number}"),
            format!("recommended-page-{page_number}"),
        )
        .expect("page recommendation");
        let page = hartevo_aws_compute_optimizer_result_plugin::AwsComputeOptimizerRecommendationPage::new(
            &request,
            vec![page_recommendation],
            Some(next.clone()),
            1024,
            TransportProvenance::Recording,
        )
        .expect("page");
        transport.push_response(kind, Ok(page));
        cursor = Some(next);
    }
    let provider = AwsComputeOptimizerProvider::new(transport).expect("provider");
    let mut service =
        AwsComputeOptimizerService::new(scope.clone(), secret(&scope), provider).unwrap();
    let proposal = service
        .compile_proposal_at(now())
        .expect("partial proposal");
    assert_eq!(proposal.state(), EvidenceState::Partial);

    let request = GetEC2InstanceRecommendationsRequest::for_scope(&scope, None).unwrap();
    let page =
        hartevo_aws_compute_optimizer_result_plugin::AwsComputeOptimizerRecommendationPage::new(
            &request,
            vec![recommendation(
                &scope,
                kind,
                RecommendationStatus::Optimized,
                now() - Duration::minutes(20),
            )],
            None,
            1024,
            TransportProvenance::Recording,
        )
        .unwrap()
        .with_declared_digest(Digest::from_text("tampered-page"));
    let mut tampered_transport = RecordingTransport::default();
    tampered_transport.push_response(kind, Ok(page));
    let provider = AwsComputeOptimizerProvider::new(tampered_transport).unwrap();
    let mut tampered =
        AwsComputeOptimizerService::new(scope.clone(), secret(&scope), provider).unwrap();
    let tampered_proposal = tampered.compile_proposal_at(now()).unwrap();
    assert_eq!(tampered_proposal.state(), EvidenceState::Tampered);
}

#[test]
fn resource_allowlist_and_constructor_bounds_are_enforced() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let unauthorized = ResourceSelector::from_raw(ResourceKind::Ec2Instance, "i-not-allowlisted")
        .expect("resource");
    let err = ComputeOptimizerRecommendation::new(
        &scope,
        unauthorized,
        RecommendationId::new("recommendation").unwrap(),
        RecommendationStatus::Optimized,
        now() - Duration::minutes(20),
        14,
        Digest::from_text("current"),
        Digest::from_text("recommended"),
    )
    .unwrap_err();
    assert_eq!(err, ModelError::ResourceNotAllowlisted);
    assert_eq!(
        AwsAccountId::new("123").unwrap_err(),
        ModelError::InvalidAccountId
    );

    let mut many = Vec::new();
    for index in 0..=128 {
        many.push(
            ResourceSelector::from_raw(ResourceKind::Ec2Instance, format!("i-{index}")).unwrap(),
        );
    }
    assert_eq!(
        AwsComputeOptimizerScope::new(
            AwsAccountId::new(RAW_ACCOUNT).unwrap(),
            AwsRegion::new("us-east-1").unwrap(),
            many,
            RecommendationWindow::closed(now() - Duration::hours(1), now()).unwrap(),
            ProjectBinding::new(ProjectId::new("p").unwrap(), Revision::new(1).unwrap()),
            MissionBinding::new(
                hartevo_aws_compute_optimizer_result_plugin::MissionId::new("m").unwrap(),
                Revision::new(1).unwrap(),
            ),
            WorkProductBinding::new(WorkProductId::new("w").unwrap(), Revision::new(1).unwrap()),
            Revision::new(1).unwrap(),
            PermissionSnapshot::compute_optimizer_read(Revision::new(1).unwrap()).unwrap(),
            ConsentScope::for_layer_one("c", 1).unwrap(),
            Duration::hours(1),
        )
        .unwrap_err(),
        ModelError::BoundsExceeded
    );
}

#[test]
fn blocked_env_and_revocation_never_become_native() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let provider = AwsComputeOptimizerProvider::new(BlockedEnvTransport).expect("provider");
    let mut service =
        AwsComputeOptimizerService::new(scope.clone(), secret(&scope), provider).unwrap();
    let proposal = service
        .compile_proposal_at(now())
        .expect("blocked proposal");
    assert_eq!(proposal.state(), EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(proposal.evidence.failure.as_ref().unwrap().blocked_env);
    assert!(!proposal.connected);
    assert!(!proposal.native);

    let mut consumer = MissionAwsComputeOptimizerConsumer::new(fixture_service(&scope)).unwrap();
    let proposal = consumer.compile_proposal_at(now()).unwrap();
    consumer.revoke().unwrap();
    assert!(matches!(
        consumer.compile_proposal_at(now()),
        Err(hartevo_aws_compute_optimizer_result_plugin::MissionAwsComputeOptimizerConsumerError::Revoked)
    ));
    consumer.restore().unwrap();
    assert!(consumer.compile_proposal_at(now()).is_ok());
    assert!(consumer.verify(&proposal).is_err());
}

#[test]
fn secret_reference_is_opaque_and_revocable() {
    let scope = scope_with(ResourceKind::Ec2Instance, Duration::hours(2));
    let secret = secret(&scope);
    let debug = format!("{secret:?}");
    assert!(!debug.contains(RAW_SECRET));
    let mut revoked = secret;
    revoked.revoke().unwrap();
    assert!(revoked.validate_for_scope(&scope).is_err());
    revoked.restore().unwrap();
    assert!(revoked.validate_for_scope(&scope).is_ok());
}
