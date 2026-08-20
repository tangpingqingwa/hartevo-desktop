use chrono::{Duration, Utc};
use serde_json::json;

use hartevo_aws_elb_target_health_result_plugin::{
    AvailabilityZone, AwsAccountId, AwsElbProvider, AwsElbReadRequest, AwsElbScope,
    AwsElbTargetHealthService, AwsElbTargetHealthServiceError, AwsRegion, BlockedEnvTransport,
    CONTRACT_DIGEST, CONTRACT_JSON, DeploymentBinding, Digest, EvidenceState, FixtureTransport,
    HealthCheckSummary, LoadBalancerArn, LoadBalancerReference, MissionAwsElbConsumer,
    MissionAwsElbDecisionState, MissionBinding, OpaqueMarker, PermissionFence, PermissionId,
    ProjectBinding, ReadBounds, ReadOperation, RecordingTransport, Revision, SecretReference,
    TargetGroupArn, TargetGroupReference, TargetGroupType, TargetHealthObservation,
    TargetHealthReasonClass, TargetHealthState, TransportError, TransportFailure,
    WorkProductBinding, contract_digest,
};

fn fixtures(
    target_allowlist: Option<
        std::collections::BTreeSet<hartevo_aws_elb_target_health_result_plugin::TargetIdDigest>,
    >,
) -> (AwsElbScope, SecretReference, PermissionFence) {
    let deployment = DeploymentBinding::new(
        hartevo_aws_elb_target_health_result_plugin::DeploymentId::new("deployment-628").unwrap(),
        Revision::new(1).unwrap(),
    );
    let mission = MissionBinding::new(
        hartevo_aws_elb_target_health_result_plugin::MissionId::new("mission-628").unwrap(),
        Revision::new(1).unwrap(),
    );
    let project = ProjectBinding::new(
        hartevo_aws_elb_target_health_result_plugin::ProjectId::new("project-628").unwrap(),
        Revision::new(1).unwrap(),
    );
    let work_product = WorkProductBinding::new(
        hartevo_aws_elb_target_health_result_plugin::WorkProductId::new("work-product-628")
            .unwrap(),
        Revision::new(1).unwrap(),
    );
    let account = AwsAccountId::aws("111111111111").unwrap();
    let region = AwsRegion::aws("us-east-1").unwrap();
    let load_balancer = LoadBalancerReference::new(
        LoadBalancerArn::aws(
            "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/fixture/abc",
        )
        .unwrap(),
        Revision::new(1).unwrap(),
    );
    let target_group = TargetGroupReference::new(
        TargetGroupArn::aws(
            "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/fixture/abc",
        )
        .unwrap(),
        Revision::new(1).unwrap(),
        TargetGroupType::Instance,
    );
    let permission = PermissionFence::readonly(
        PermissionId::new("permission-628").unwrap(),
        Revision::new(1).unwrap(),
    )
    .unwrap();
    let secret = SecretReference::for_elb("keyring://opaque/aws-elb/628", &region).unwrap();
    let scope = AwsElbScope::for_secret(
        deployment,
        mission,
        project,
        work_product,
        account,
        region,
        load_balancer,
        target_group,
        target_allowlist,
        &permission,
        &secret,
    )
    .unwrap();
    (scope, secret, permission)
}

fn healthy_service() -> AwsElbTargetHealthService<FixtureTransport> {
    let (scope, secret, permission) = fixtures(None);
    let transport = FixtureTransport::for_scope(&scope, Utc::now()).unwrap();
    AwsElbTargetHealthService::new(
        scope,
        secret,
        permission,
        AwsElbProvider::new(transport).unwrap(),
    )
    .unwrap()
}

#[test]
fn contract_and_opaque_boundaries_are_explicit() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).unwrap();
    assert_eq!(contract["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
    hartevo_aws_elb_target_health_result_plugin::AwsElbTargetHealthContract::baseline().unwrap();

    let (scope, secret, _) = fixtures(None);
    let marker = OpaqueMarker::new("raw-marker-must-not-escape").unwrap();
    assert_eq!(
        serde_json::to_string(&secret).unwrap(),
        r#"{"opaque":true}"#
    );
    assert_eq!(
        serde_json::to_string(&marker).unwrap(),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("keyring://opaque/aws-elb/628"));
    assert!(
        !serde_json::to_string(&scope)
            .unwrap()
            .contains("arn:aws:elasticloadbalancing")
    );
    assert!(
        !serde_json::to_string(&marker)
            .unwrap()
            .contains("raw-marker-must-not-escape")
    );
}

#[test]
fn fixture_vertical_slice_is_healthy_review_only_and_recordable() {
    let mut service = healthy_service();
    let read = service.read().unwrap();
    assert_eq!(read.evidence.state, EvidenceState::Healthy);
    assert!(read.evidence.complete);
    assert_eq!(read.evidence.load_balancers.len(), 1);
    assert_eq!(read.evidence.target_groups.len(), 1);
    assert_eq!(read.evidence.target_health.len(), 1);
    assert_eq!(
        read.evidence.target_health[0].state,
        TargetHealthState::Healthy
    );
    assert!(!read.evidence.authority.connected);
    assert!(!read.evidence.authority.native);
    assert!(!read.evidence.authority.first_party);
    assert!(!read.evidence.can_be_adopted());
    assert!(
        read.evidence
            .validate(service.scope(), service.registration())
            .is_ok()
    );

    let mut proposal_service = healthy_service();
    let proposal = proposal_service.propose(Utc::now()).unwrap();
    let mut consumer = MissionAwsElbConsumer::new(
        proposal_service.scope().clone(),
        proposal_service.registration().clone(),
    )
    .unwrap();
    let result = consumer.consume(proposal.clone()).unwrap();
    assert_eq!(
        result.decision_state,
        MissionAwsElbDecisionState::HealthyReview
    );
    assert!(result.accepted);
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.availability_certification);
    assert!(!result.adopted_outcome);
    assert!(!result.work_product_adoption);
    let recorded = consumer.record(&proposal, "mission-record-628").unwrap();
    assert!(!recorded.connected);
    assert!(!recorded.native);
    assert!(!recorded.first_party);
    assert!(consumer.record(&proposal, "mission-record-628").is_err());

    let receipt = proposal_service.record_at(&proposal, Utc::now()).unwrap();
    assert!(proposal_service.verify(&receipt).unwrap().verified);
    assert!(!proposal_service.verify(&receipt).unwrap().adopted_outcome);
}

#[test]
fn all_deterministic_transports_are_never_connected_native_or_first_party() {
    let (scope, secret, permission) = fixtures(None);
    let now = Utc::now();
    let fixture = FixtureTransport::for_scope(&scope, now).unwrap();
    let mut fixture_service = AwsElbTargetHealthService::new(
        scope.clone(),
        secret.clone(),
        permission.clone(),
        AwsElbProvider::new(fixture).unwrap(),
    )
    .unwrap();
    let fixture_result = fixture_service.read().unwrap();
    assert!(!fixture_result.evidence.authority.connected);
    assert!(!fixture_result.evidence.authority.native);
    assert!(!fixture_result.evidence.authority.first_party);
    assert_eq!(
        fixture_result.evidence.provenance,
        hartevo_aws_elb_target_health_result_plugin::ProviderProvenance::Fixture
    );

    let loopback =
        hartevo_aws_elb_target_health_result_plugin::LoopbackTransport::for_scope(&scope, now)
            .unwrap();
    let mut loopback_service = AwsElbTargetHealthService::new(
        scope.clone(),
        secret.clone(),
        permission.clone(),
        AwsElbProvider::new(loopback).unwrap(),
    )
    .unwrap();
    let loopback_result = loopback_service.read().unwrap();
    assert_eq!(
        loopback_result.evidence.provenance,
        hartevo_aws_elb_target_health_result_plugin::ProviderProvenance::Loopback
    );
    assert!(!loopback_result.evidence.authority.connected);
    assert!(!loopback_result.evidence.authority.native);
    assert!(!loopback_result.evidence.authority.first_party);

    let mut blocked_service = AwsElbTargetHealthService::new(
        scope,
        secret,
        permission,
        AwsElbProvider::new(BlockedEnvTransport).unwrap(),
    )
    .unwrap();
    let blocked = blocked_service.read().unwrap();
    assert_eq!(blocked.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        blocked.evidence.provenance,
        hartevo_aws_elb_target_health_result_plugin::ProviderProvenance::BlockedEnv
    );
    assert!(!blocked.evidence.authority.connected);
    assert!(!blocked.evidence.authority.native);
    assert!(!blocked.evidence.authority.first_party);
}

#[test]
fn health_scope_binds_zone_port_and_check_digest() {
    let (base, secret, permission) = fixtures(None);
    let health_check = HealthCheckSummary::new(
        hartevo_aws_elb_target_health_result_plugin::ElbProtocol::Http,
        Some(80),
        Some("/health"),
        30,
        5,
        3,
        3,
        Some("200"),
    )
    .unwrap();
    let availability_zones =
        std::collections::BTreeSet::from([AvailabilityZone::new("us-east-1a").unwrap()]);
    let scope = AwsElbScope::new_with_health_scope(
        base.deployment.clone(),
        base.mission.clone(),
        base.project.clone(),
        base.work_product.clone(),
        base.account_id.clone(),
        base.region.clone(),
        base.load_balancer.clone(),
        base.target_group.clone(),
        base.target_allowlist.clone(),
        Some(availability_zones),
        Some(80),
        &health_check,
        permission.digest(),
        secret.digest(),
    )
    .unwrap();
    assert_ne!(scope.target_health_digest, base.target_health_digest);
    let transport = FixtureTransport::for_scope(&scope, Utc::now()).unwrap();
    let mut service = AwsElbTargetHealthService::new(
        scope,
        secret,
        permission,
        AwsElbProvider::new(transport).unwrap(),
    )
    .unwrap();
    let result = service.read().unwrap();
    assert_eq!(result.evidence.state, EvidenceState::Healthy);
    assert_eq!(
        result.evidence.scope_target_health_digest,
        service.scope().target_health_digest
    );
    assert_eq!(
        result.evidence.load_balancers[0]
            .availability_zone_digests
            .len(),
        1
    );
    let encoded = serde_json::to_string(&result.evidence).unwrap();
    assert!(!encoded.contains("us-east-1a"));
}

#[test]
fn marker_loop_and_page_budget_fail_closed() {
    let (scope, secret, permission) = fixtures(None);
    let bounds = ReadBounds::default();
    let first_request = AwsElbReadRequest::describe_load_balancers(&scope, bounds, None).unwrap();
    let marker = OpaqueMarker::new("same-marker").unwrap();
    let first = hartevo_aws_elb_target_health_result_plugin::DescribeLoadBalancersPage::new(
        &first_request,
        1,
        Vec::new(),
        Some(marker.clone()),
        128,
    )
    .unwrap();
    let second_request = first_request
        .with_marker(Some(marker.bind(&first_request.request_digest, 1).unwrap()))
        .unwrap();
    let second = hartevo_aws_elb_target_health_result_plugin::DescribeLoadBalancersPage::new(
        &second_request,
        2,
        Vec::new(),
        Some(marker),
        128,
    )
    .unwrap();
    let mut transport = RecordingTransport::default();
    transport.push_load_balancers(Ok(first));
    transport.push_load_balancers(Ok(second));
    let mut service = AwsElbTargetHealthService::new(
        scope,
        secret,
        permission,
        AwsElbProvider::new(transport).unwrap(),
    )
    .unwrap();
    let result = service.read().unwrap();
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_elb_target_health_result_plugin::PartialReason::MarkerLoop)
    );
}

#[test]
fn status_failures_are_typed_and_redacted() {
    let failures = [
        (TransportFailure::BadRequest, EvidenceState::BadRequest),
        (TransportFailure::Unauthorized, EvidenceState::Unauthorized),
        (TransportFailure::Forbidden, EvidenceState::Forbidden),
        (TransportFailure::NotFound, EvidenceState::NotFound),
        (TransportFailure::Conflict, EvidenceState::Conflict),
        (TransportFailure::Throttled, EvidenceState::Throttled),
        (
            TransportFailure::ServerFailure,
            EvidenceState::ServerFailure,
        ),
        (TransportFailure::Timeout, EvidenceState::Timeout),
    ];
    for (failure, expected) in failures {
        let (scope, secret, permission) = fixtures(None);
        let mut transport = RecordingTransport::default();
        transport.push_load_balancers(Err(TransportError::new(failure)));
        let mut service = AwsElbTargetHealthService::new(
            scope,
            secret,
            permission,
            AwsElbProvider::new(transport).unwrap(),
        )
        .unwrap();
        let result = service.read().unwrap();
        assert_eq!(result.evidence.state, expected);
        assert!(result.evidence.state.is_fail_closed());
        assert!(!result.evidence.authority.connected);
        assert!(
            result
                .evidence
                .provider_errors
                .iter()
                .all(|error| !error.raw_error_retained)
        );
    }
}

#[test]
fn initial_health_scope_drift_and_page_tamper_fail_closed() {
    let (scope, secret, permission) = fixtures(None);
    let bounds = ReadBounds::default();
    let lb_request = AwsElbReadRequest::describe_load_balancers(&scope, bounds, None).unwrap();
    let mut lb_page = hartevo_aws_elb_target_health_result_plugin::DescribeLoadBalancersPage::new(
        &lb_request,
        1,
        Vec::new(),
        None,
        128,
    )
    .unwrap();
    lb_page.page_digest = Digest::zero();
    let mut transport = RecordingTransport::default();
    transport.push_load_balancers(Ok(lb_page));
    let mut service = AwsElbTargetHealthService::new(
        scope.clone(),
        secret.clone(),
        permission.clone(),
        AwsElbProvider::new(transport).unwrap(),
    )
    .unwrap();
    let tampered = service.read().unwrap();
    assert_eq!(tampered.evidence.state, EvidenceState::Tampered);

    let transport = FixtureTransport::for_scope(&scope, Utc::now()).unwrap();
    let mut service = AwsElbTargetHealthService::new(
        scope,
        secret,
        permission,
        AwsElbProvider::new(transport).unwrap(),
    )
    .unwrap();
    let proposal = service.propose(Utc::now()).unwrap();
    let consumer =
        MissionAwsElbConsumer::new(service.scope().clone(), service.registration().clone())
            .unwrap();
    let mut initial = proposal.clone();
    initial.evidence.state = EvidenceState::Initial;
    assert!(consumer.consume(initial).is_err());
}

#[test]
fn registration_is_reversible_and_revocable() {
    let mut service = healthy_service();
    service.reverse_registration().unwrap();
    assert!(matches!(
        service.read(),
        Err(AwsElbTargetHealthServiceError::RegistrationReversed)
    ));
    service.restore_registration().unwrap();
    assert!(service.is_active());
    service.revoke_registration().unwrap();
    assert!(matches!(
        service.read(),
        Err(AwsElbTargetHealthServiceError::RegistrationRevoked)
    ));
    assert!(service.restore_registration().is_err());
}

#[test]
fn target_health_and_request_serialization_retain_digests_only() {
    let observation = TargetHealthObservation::new(
        "i-raw-target-id",
        Some(80),
        TargetHealthState::Unhealthy,
        TargetHealthReasonClass::Target,
        Some("raw reason and detail must not escape"),
        Utc::now() - Duration::seconds(1),
    )
    .unwrap();
    let serialized = serde_json::to_string(&observation).unwrap();
    assert!(!serialized.contains("i-raw-target-id"));
    assert!(!serialized.contains("raw reason"));
    assert!(serialized.contains("targetIdDigest"));

    let (scope, _, _) = fixtures(None);
    let request = AwsElbReadRequest::new(
        &scope,
        ReadOperation::DescribeTargetHealth,
        ReadBounds::default(),
        None,
    )
    .unwrap();
    let encoded = serde_json::to_string(&request).unwrap();
    assert!(!encoded.contains("arn:aws:elasticloadbalancing"));
    assert!(!encoded.contains("raw-target-id"));
    assert_eq!(json!(request.marker), json!(null));
}
