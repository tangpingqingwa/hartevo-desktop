use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_route53_health_result_plugin::{
    AwsAccountId, AwsRegion, AwsRoute53HealthContract, AwsRoute53HealthReadRequest,
    AwsRoute53HealthScope, AwsRoute53HealthService, AwsRoute53Provider, DeploymentBinding,
    DeploymentId, Digest, EvidenceState, FixtureTransport, GetHealthCheckRequest,
    GetHealthCheckStatusRequest, HealthCheckBinding, HealthCheckConfiguration, HealthCheckId,
    HealthCheckObservation, HealthCheckSummary, HealthCheckTarget, HealthCheckType,
    ListHealthChecksPage, ListHealthChecksRequest, MissionAwsRoute53Consumer,
    MissionAwsRoute53DecisionState, MissionId, ObservationStatus, OpaqueMarker, PermissionAction,
    PermissionFence, PermissionId, ProjectBinding, ProjectId, ProviderRevision, ReadBounds,
    RecordingTransport, Revision, SecretReference, TransportError, TransportFailure,
    WorkProductBinding, WorkProductId,
};

type Service = AwsRoute53HealthService<RecordingTransport>;

fn at(second: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0)
        .single()
        .expect("fixed timestamp")
        + Duration::seconds(second)
}

fn scope_for(target: HealthCheckTarget) -> AwsRoute53HealthScope {
    let permission = PermissionFence::readonly(
        PermissionId::new("route53-read-permission").expect("permission id"),
        Revision::new(3).expect("permission revision"),
    )
    .expect("permission");
    AwsRoute53HealthScope::new(
        DeploymentBinding::new(
            DeploymentId::new("deployment-616").expect("deployment"),
            Revision::new(11).expect("deployment revision"),
        ),
        hartevo_aws_route53_health_result_plugin::MissionBinding::new(
            MissionId::new("mission-616").expect("Mission"),
            Revision::new(7).expect("Mission revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-616").expect("Project"),
            Revision::new(5).expect("Project revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-616").expect("Work Product"),
            Revision::new(4).expect("Work Product revision"),
        ),
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        HealthCheckBinding::new(
            HealthCheckId::new("abcdef12-3456-7890-abcd-ef1234567890").expect("health-check"),
            Revision::new(8).expect("health-check revision"),
            target,
        )
        .expect("health-check binding"),
        permission.digest(),
    )
    .expect("scope")
}

fn endpoint_scope() -> AwsRoute53HealthScope {
    scope_for(HealthCheckTarget::endpoint("api.example.test").expect("endpoint"))
}

fn permission() -> PermissionFence {
    PermissionFence::readonly(
        PermissionId::new("route53-read-permission").expect("permission id"),
        Revision::new(3).expect("permission revision"),
    )
    .expect("permission")
}

fn endpoint_configuration(scope: &AwsRoute53HealthScope) -> HealthCheckConfiguration {
    HealthCheckConfiguration::new(
        HealthCheckType::Https,
        scope.health_check.target.clone(),
        Some(443),
        Some("/health"),
        30,
        3,
        [scope.region.clone()],
        false,
        true,
        0,
    )
    .expect("configuration")
}

fn summary(scope: &AwsRoute53HealthScope) -> HealthCheckSummary {
    HealthCheckSummary::new(
        scope.health_check.id.clone(),
        scope.health_check.revision,
        "caller-reference-616",
        endpoint_configuration(scope),
    )
    .expect("summary")
}

fn read_request(
    scope: &AwsRoute53HealthScope,
    max_pages: u16,
    as_of: DateTime<Utc>,
) -> AwsRoute53HealthReadRequest {
    AwsRoute53HealthReadRequest::new(
        scope,
        ReadBounds {
            max_pages,
            ..ReadBounds::default()
        },
        as_of,
        None,
    )
    .expect("read request")
}

fn service_with_transport(transport: RecordingTransport) -> (AwsRoute53HealthScope, Service) {
    let scope = endpoint_scope();
    let secret = SecretReference::for_route53("keyring://route53/616", &scope.region)
        .expect("opaque secret");
    let provider = AwsRoute53Provider::new(transport).expect("provider");
    let service = AwsRoute53HealthService::new(scope.clone(), secret, permission(), provider)
        .expect("service");
    (scope, service)
}

fn queue_complete(
    transport: &mut RecordingTransport,
    scope: &AwsRoute53HealthScope,
    read: &AwsRoute53HealthReadRequest,
    summary: HealthCheckSummary,
    observations: Vec<HealthCheckObservation>,
) {
    let list_request = ListHealthChecksRequest::new(scope, read, None).expect("list request");
    transport.push_list_response(Ok(ListHealthChecksPage::new(
        &list_request,
        1,
        vec![summary.clone()],
        None,
        512,
        ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
    )
    .expect("list page")));
    let get_request = GetHealthCheckRequest::new(scope, read).expect("get request");
    transport.push_get_response(Ok(
        hartevo_aws_route53_health_result_plugin::GetHealthCheckResponse::new(
            &get_request,
            summary,
            512,
            ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
        )
        .expect("get response"),
    ));
    let status_request = GetHealthCheckStatusRequest::new(scope, read).expect("status request");
    transport.push_status_response(Ok(
        hartevo_aws_route53_health_result_plugin::GetHealthCheckStatusResponse::new(
            &status_request,
            observations,
            512,
            ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
        )
        .expect("status response"),
    ));
}

fn healthy_observation(
    scope: &AwsRoute53HealthScope,
    checked_at: DateTime<Utc>,
) -> HealthCheckObservation {
    HealthCheckObservation::new(
        scope.region.clone(),
        "checker-ip-1",
        ObservationStatus::Healthy,
        checked_at,
        Option::<String>::None,
    )
    .expect("observation")
}

#[test]
fn contract_scope_registration_and_capabilities_are_explicit() {
    AwsRoute53HealthContract::baseline().expect("contract");
    let scope = endpoint_scope();
    let secret =
        SecretReference::for_route53("keyring://route53/616", &scope.region).expect("secret");
    let provider = AwsRoute53Provider::new(RecordingTransport::default()).expect("provider");
    let service = AwsRoute53HealthService::new(scope.clone(), secret, permission(), provider)
        .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.live_execution);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.calculated_checks_supported);
    assert!(service.registration().is_active());
    assert_ne!(service.registration().registration_digest, Digest::zero());
    assert_ne!(service.registration().scope_digest, Digest::zero());
    assert_ne!(service.registration().permission_digest, Digest::zero());
    assert_ne!(
        service.registration().secret_reference_digest,
        Digest::zero()
    );
}

#[test]
fn secret_and_marker_are_opaque_and_never_serialize_raw_material() {
    let scope = endpoint_scope();
    let secret =
        SecretReference::for_route53("raw-secret-material", &scope.region).expect("secret");
    let marker = OpaqueMarker::new("raw-provider-marker").expect("marker");
    assert_eq!(
        serde_json::to_string(&secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert_eq!(
        serde_json::to_string(&marker).expect("marker JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("raw-secret-material"));
    assert!(!format!("{marker:?}").contains("raw-provider-marker"));
    assert!(
        !serde_json::to_string(&secret)
            .expect("secret JSON")
            .contains("raw-secret-material")
    );
    let request = read_request(&scope, 2, at(120));
    let request_with_marker = request
        .with_marker(Some(marker))
        .expect("marker-bound request");
    let encoded = serde_json::to_string(&request_with_marker).expect("request JSON");
    assert!(!encoded.contains("raw-provider-marker"));
}

#[test]
fn fixture_vertical_slice_is_healthy_review_only_and_verifiable() {
    let scope = endpoint_scope();
    let secret = SecretReference::for_route53("fixture-secret", &scope.region).expect("secret");
    let transport = FixtureTransport::for_scope(&scope, at(120)).expect("fixture transport");
    let provider = AwsRoute53Provider::new(transport).expect("fixture provider");
    let mut service = AwsRoute53HealthService::new(scope.clone(), secret, permission(), provider)
        .expect("service");
    let proposal = service
        .propose(service.default_request(at(120)).expect("request"), at(120))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Healthy);
    assert_eq!(
        proposal.evidence.provenance,
        hartevo_aws_route53_health_result_plugin::TransportProvenance::Fixture
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.certification_claim);
    assert!(!proposal.adopted_outcome);
    assert!(!proposal.truth_authority);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    let consumer = MissionAwsRoute53Consumer::new(scope.clone(), service.registration().clone())
        .expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(result.observed_health_state, EvidenceState::Healthy);
    assert_eq!(
        result.decision_state,
        MissionAwsRoute53DecisionState::HealthyReviewRequired
    );
    assert_eq!(result.project, scope.project);
    assert_eq!(result.mission, scope.mission);
    assert_eq!(result.work_product, scope.work_product);
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.work_product_adoption);
    let receipt = service.record_at(&proposal, at(180)).expect("record");
    let verified = service.verify(&receipt).expect("verified record");
    assert!(verified.verified);
    assert!(!verified.adopted_outcome);
    assert!(!verified.truth_authority);
}

#[test]
fn fixture_loopback_and_blocked_env_are_never_connected_native_or_first_party() {
    let scope = endpoint_scope();
    let secret = SecretReference::for_route53("transport-secret", &scope.region).expect("secret");
    let fixture = FixtureTransport::for_scope(&scope, at(120)).expect("fixture");
    let mut fixture_service = AwsRoute53HealthService::new(
        scope.clone(),
        secret.clone(),
        permission(),
        AwsRoute53Provider::new(fixture).expect("provider"),
    )
    .expect("service");
    let fixture_proposal = fixture_service
        .propose(
            fixture_service.default_request(at(120)).expect("request"),
            at(120),
        )
        .expect("proposal");
    assert!(
        !fixture_proposal.connected && !fixture_proposal.native && !fixture_proposal.first_party
    );

    let loopback =
        hartevo_aws_route53_health_result_plugin::LoopbackTransport::for_scope(&scope, at(120))
            .expect("loopback");
    let mut loopback_service = AwsRoute53HealthService::new(
        scope.clone(),
        secret.clone(),
        permission(),
        AwsRoute53Provider::new(loopback).expect("provider"),
    )
    .expect("service");
    let loopback_proposal = loopback_service
        .propose(
            loopback_service.default_request(at(120)).expect("request"),
            at(120),
        )
        .expect("proposal");
    assert_eq!(
        loopback_proposal.evidence.provenance,
        hartevo_aws_route53_health_result_plugin::TransportProvenance::Loopback
    );
    assert!(
        !loopback_proposal.connected && !loopback_proposal.native && !loopback_proposal.first_party
    );

    let blocked_provider = AwsRoute53Provider::new(
        hartevo_aws_route53_health_result_plugin::BlockedEnvAwsRoute53Transport,
    )
    .expect("blocked provider");
    let mut blocked_service =
        AwsRoute53HealthService::new(scope.clone(), secret, permission(), blocked_provider)
            .expect("service");
    let blocked = blocked_service
        .read(blocked_service.default_request(at(120)).expect("request"))
        .expect("blocked evidence");
    assert_eq!(blocked.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        blocked.evidence.provenance,
        hartevo_aws_route53_health_result_plugin::TransportProvenance::BlockedEnv
    );
    assert!(
        !blocked.evidence.connected && !blocked.evidence.native && !blocked.evidence.first_party
    );
}

#[test]
fn calculated_health_checks_are_explicitly_unsupported() {
    let scope = scope_for(HealthCheckTarget::calculated(2).expect("calculated target"));
    let secret = SecretReference::for_route53("calculated-secret", &scope.region).expect("secret");
    let transport = FixtureTransport::for_scope(&scope, at(120)).expect("fixture");
    let mut service = AwsRoute53HealthService::new(
        scope,
        secret,
        permission(),
        AwsRoute53Provider::new(transport).expect("provider"),
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(at(120)).expect("request"), at(120))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Unsupported);
    assert_eq!(
        proposal.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::CalculatedCheckUnsupported)
    );
    assert!(!proposal.is_review_only() || !proposal.can_be_adopted());
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
}

#[test]
fn revision_drift_is_partial_and_non_adoptable() {
    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let mut stale_scope = summary(&scope);
    stale_scope.revision = Revision::new(9).expect("stale revision");
    stale_scope.summary_digest = stale_scope.recomputed_digest();
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(ListHealthChecksPage::new(
            &list_request,
            1,
            vec![stale_scope],
            None,
            512,
            ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
        )
        .expect("page")));
    let result = service.read(request).expect("partial drift evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::HealthCheckRevisionDrift)
    );
}

#[test]
fn response_digest_tamper_is_rejected_fail_closed() {
    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    let mut page = ListHealthChecksPage::new(
        &list_request,
        1,
        vec![summary(&scope)],
        None,
        512,
        ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
    )
    .expect("page");
    page.page_digest = Digest::zero();
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(page));
    assert!(matches!(
        service.read(request),
        Err(hartevo_aws_route53_health_result_plugin::AwsRoute53HealthServiceError::Provider(_))
    ));
}

#[test]
fn pagination_loop_and_page_budget_become_partial_evidence() {
    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    let marker = OpaqueMarker::new("page-one-marker").expect("marker");
    let first = ListHealthChecksPage::new(
        &list_request,
        1,
        vec![summary(&scope)],
        Some(marker.clone()),
        512,
        ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
    )
    .expect("first page");
    let second_request = list_request
        .with_marker(Some(marker.clone()))
        .expect("second request");
    let second = ListHealthChecksPage::new(
        &second_request,
        2,
        Vec::new(),
        Some(marker),
        512,
        ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
    )
    .expect("second page");
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(second));
    let result = service.read(request).expect("loop evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::PaginationLoop)
    );

    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 1, at(120));
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    let page = ListHealthChecksPage::new(
        &list_request,
        1,
        vec![summary(&scope)],
        Some(OpaqueMarker::new("page-two").expect("marker")),
        512,
        ProviderRevision::new("aws-route53-health-read-r1").expect("revision"),
    )
    .expect("page");
    service
        .provider_mut()
        .transport_mut()
        .push_list_response(Ok(page));
    let result = service.read(request).expect("bounded evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::PaginationBudget)
    );
}

#[test]
fn access_loss_throttle_and_timeout_are_typed_non_adoptable_states() {
    let cases = [
        (TransportFailure::Unauthorized, EvidenceState::AccessLoss),
        (TransportFailure::AccessDenied, EvidenceState::AccessLoss),
        (TransportFailure::NotFound, EvidenceState::AccessLoss),
        (TransportFailure::Throttled, EvidenceState::Throttled),
        (TransportFailure::Timeout, EvidenceState::Timeout),
    ];
    for (failure, expected) in cases {
        let (scope, mut service) = service_with_transport(RecordingTransport::default());
        let request = read_request(&scope, 2, at(120));
        for _ in 0..3 {
            service
                .provider_mut()
                .transport_mut()
                .push_list_response(Err(TransportError::new(failure)));
        }
        let result = service.read(request).expect("typed provider failure");
        assert_eq!(result.evidence.state, expected);
        assert!(!result.evidence.provider_errors.is_empty());
        assert!(result.evidence.provider_errors.len() <= 3);
        assert!(result.evidence.state.is_fail_closed());
    }
}

#[test]
fn registration_revocation_invalidates_future_reads_records_and_verification() {
    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let observation = healthy_observation(&scope, at(90));
    queue_complete(
        service.provider_mut().transport_mut(),
        &scope,
        &request,
        summary(&scope),
        vec![observation],
    );
    let proposal = service.propose(request, at(120)).expect("proposal");
    let receipt = service.record_at(&proposal, at(180)).expect("receipt");
    let revocation = service.revoke_registration().expect("revoke");
    assert_eq!(
        service.registration().state,
        hartevo_aws_route53_health_result_plugin::RegistrationState::Revoked
    );
    assert_eq!(
        revocation.registration_digest,
        service.registration().registration_digest
    );
    assert!(service.record(&proposal).is_err());
    assert!(service.verify(&receipt).is_err());
    assert!(
        service
            .read(service.default_request(at(240)).expect("request"))
            .is_err()
    );
    assert!(service.revoke_registration().is_err());
}

#[test]
fn parser_retains_only_digests_and_bounded_status_fields() {
    let scope = endpoint_scope();
    let provider = AwsRoute53Provider::new(RecordingTransport::default()).expect("provider");
    let request = read_request(&scope, 2, at(120));
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    let body = br#"{
      "HealthChecks": [{
        "Id": "abcdef12-3456-7890-abcd-ef1234567890",
        "CallerReference": "raw-caller-reference",
        "HealthCheckVersion": 8,
        "HealthCheckConfig": {
          "Type": "HTTPS",
          "FullyQualifiedDomainName": "raw.customer.example",
          "Port": 443,
          "ResourcePath": "/private/health",
          "RequestInterval": 30,
          "FailureThreshold": 3,
          "Regions": ["us-east-1"],
          "EnableSNI": true
        }
      }],
      "NextMarker": "raw-next-marker"
    }"#;
    let page = provider
        .parse_list_health_checks_json(&list_request, 1, body)
        .expect("parsed list");
    let encoded = serde_json::to_string(&page.health_checks).expect("summary JSON");
    for raw in [
        "raw.customer.example",
        "/private/health",
        "raw-caller-reference",
        "raw-next-marker",
    ] {
        assert!(!encoded.contains(raw), "raw field survived: {raw}");
    }
    assert!(encoded.contains("configurationDigest"));

    let get_request = GetHealthCheckRequest::new(&scope, &request).expect("get request");
    let get_body = br#"{
      "Id": "abcdef12-3456-7890-abcd-ef1234567890",
      "CallerReference": "raw-caller-reference",
      "HealthCheckVersion": 8,
      "HealthCheckConfig": {
        "Type": "HTTPS",
        "FullyQualifiedDomainName": "raw.customer.example",
        "Port": 443,
        "ResourcePath": "/private/health",
        "RequestInterval": 30,
        "FailureThreshold": 3,
        "Regions": ["us-east-1"],
        "EnableSNI": true
      }
    }"#;
    let get = provider
        .parse_get_health_check_json(&get_request, get_body)
        .expect("parsed get");
    assert_eq!(
        get.health_check.revision,
        Revision::new(8).expect("revision")
    );
    let status_request =
        GetHealthCheckStatusRequest::new(&scope, &request).expect("status request");
    let status_body = br#"{
      "HealthCheckObservations": [{
        "Region": "us-east-1",
        "IPAddress": "203.0.113.9",
        "StatusReport": {
          "Status": "Failure",
          "CheckedTime": "2026-08-15T00:01:00Z",
          "RawFailure": "raw provider body"
        }
      }]
    }"#;
    let status = provider
        .parse_get_health_check_status_json(&status_request, status_body)
        .expect("parsed status");
    let encoded = serde_json::to_string(&status.observations).expect("status JSON");
    for raw in ["203.0.113.9", "raw provider body"] {
        assert!(!encoded.contains(raw), "raw status field survived: {raw}");
    }
    assert_eq!(status.observations[0].status, ObservationStatus::Unhealthy);
}

#[test]
fn scope_and_marker_revision_fences_reject_replay() {
    let scope = endpoint_scope();
    let request = read_request(&scope, 2, at(120));
    let marker = OpaqueMarker::new("marker").expect("marker");
    let bound = request
        .with_marker(Some(marker.clone()))
        .expect("bound marker");
    let other_scope =
        scope_for(HealthCheckTarget::endpoint("other.example.test").expect("endpoint"));
    assert!(bound.validate_against(&other_scope).is_err());
    let list_request = ListHealthChecksRequest::new(&scope, &request, None).expect("list request");
    let other = list_request.with_marker(Some(marker.bind(&Digest::from_text("other-query"))));
    assert!(other.is_err());
    let mut tampered = request.clone();
    tampered.scope_digest = Digest::zero();
    assert!(tampered.validate_against(&scope).is_err());
}

#[test]
fn observation_window_and_duplicate_checker_evidence_fail_closed() {
    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let duplicate = healthy_observation(&scope, at(90));
    queue_complete(
        service.provider_mut().transport_mut(),
        &scope,
        &request,
        summary(&scope),
        vec![duplicate.clone(), duplicate],
    );
    let result = service.read(request).expect("duplicate evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::DuplicateObservation)
    );

    let (scope, mut service) = service_with_transport(RecordingTransport::default());
    let request = read_request(&scope, 2, at(120));
    let old = healthy_observation(&scope, at(-90_000));
    queue_complete(
        service.provider_mut().transport_mut(),
        &scope,
        &request,
        summary(&scope),
        vec![old],
    );
    let result = service.read(request).expect("stale evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_route53_health_result_plugin::PartialReason::StaleObservation)
    );
}

#[test]
fn permission_fence_rejects_missing_read_action() {
    let scope = endpoint_scope();
    let incomplete = PermissionFence::new(
        PermissionId::new("incomplete").expect("permission"),
        Revision::new(1).expect("revision"),
        [PermissionAction::ListHealthChecks],
    )
    .expect("permission");
    let secret = SecretReference::for_route53("secret", &scope.region).expect("secret");
    let provider = AwsRoute53Provider::new(RecordingTransport::default()).expect("provider");
    assert!(AwsRoute53HealthService::new(scope, secret, incomplete, provider).is_err());
}
