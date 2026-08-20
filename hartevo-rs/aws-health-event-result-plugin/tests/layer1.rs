use hartevo_aws_health_event_result_plugin as aws;
use serde_json::json;

fn scope(with_event: bool, with_entities: bool) -> aws::AwsHealthEventScope {
    let event_arn = if with_event {
        Some(aws::AwsEventArn::new("arn:aws:health:us-east-1::event/evt-1").expect("event ARN"))
    } else {
        None
    };
    let permissions = if with_entities {
        aws::AwsHealthPermissionFence::with_affected_entities()
    } else {
        aws::AwsHealthPermissionFence::read_only()
    };
    let consent = if with_entities {
        aws::AwsHealthConsentScope::with_affected_entities()
    } else {
        aws::AwsHealthConsentScope::read_only()
    };
    aws::AwsHealthEventScope::new(
        aws::AwsAccountId::new("123456789012").expect("account"),
        aws::AwsRegion::new("us-east-1").expect("region"),
        aws::AwsServiceCode::new("ec2").expect("service"),
        event_arn,
        Some(aws::AwsEventTypeCode::new("AWS_EC2_MAINTENANCE").expect("event type")),
        [aws::AwsHealthEventStatus::Open],
        aws::AwsHealthTimeWindow::new(0, 3_600).expect("window"),
        aws::ProjectBinding::new(
            aws::ProjectId::new("project-1").expect("project"),
            aws::Revision::new(1).expect("project revision"),
        ),
        aws::MissionBinding::new(
            aws::MissionId::new("mission-1").expect("mission"),
            aws::Revision::new(2).expect("mission revision"),
        ),
        aws::WorkProductBinding::new(
            aws::WorkProductId::new("work-product-1").expect("work product"),
            aws::Revision::new(3).expect("work product revision"),
        ),
        permissions,
        consent,
    )
    .expect("scope")
    .with_affected_entities(with_entities)
}

fn event(scope: &aws::AwsHealthEventScope, revision: u64) -> aws::AwsHealthEventRecord {
    aws::AwsHealthEventRecord::new(
        scope.event_arn().cloned().unwrap_or_else(|| {
            aws::AwsEventArn::new("arn:aws:health:us-east-1::event/evt-1").expect("event ARN")
        }),
        scope.event_type_code().cloned().unwrap_or_else(|| {
            aws::AwsEventTypeCode::new("AWS_EC2_MAINTENANCE").expect("event type")
        }),
        scope.service_code().clone(),
        scope.region().clone(),
        aws::AwsHealthEventStatus::Open,
        aws::AwsHealthActionability::ActionRequired,
        100,
        Some(300),
        200,
        aws::Revision::new(revision).expect("event revision"),
    )
    .expect("event")
}

fn events_response(scope: &aws::AwsHealthEventScope, revision: u64) -> aws::DescribeEventsResponse {
    aws::DescribeEventsResponse::new(vec![event(scope, revision)], Vec::new(), None, false)
        .expect("events response")
}

fn provider_with_fixture(
    scope: &aws::AwsHealthEventScope,
) -> aws::AwsHealthProvider<aws::FixtureAwsHealthTransport> {
    let secret = aws::SecretReference::new("host-keyring-handle", scope, 9).expect("secret");
    aws::AwsHealthProvider::new(
        scope.clone(),
        secret,
        aws::FixtureAwsHealthTransport::new(events_response(scope, 1)),
    )
    .expect("provider")
}

#[test]
fn bounded_event_result_is_provider_reported_only_and_redacted() {
    let scope = scope(true, true);
    let event = event(&scope, 1);
    let details = aws::DescribeEventDetailsResponse::new(
        vec![aws::AwsHealthEventDetail::new(event.clone())],
        Vec::new(),
    )
    .expect("details response");
    let entities = aws::DescribeAffectedEntitiesResponse::new(
        scope.event_arn().expect("event ARN"),
        vec![
            aws::AffectedEntityReference::new(
                "i-raw-private-entity",
                aws::EntityType::new("instance").expect("entity type"),
                Some("active".to_owned()),
                Some(250),
            )
            .expect("entity reference"),
        ],
        Vec::new(),
        None,
        false,
    )
    .expect("entities response");
    let secret = aws::SecretReference::new("host-keyring-handle", &scope, 9).expect("secret");
    let provider = aws::AwsHealthProvider::new(
        scope.clone(),
        secret,
        aws::FixtureAwsHealthTransport::new(events_response(&scope, 1))
            .with_details(details)
            .with_affected_entities(entities),
    )
    .expect("provider");
    let mut service = aws::AwsHealthEventService::new(provider).expect("service");

    let proposal = service.compile_proposal().expect("proposal");
    assert!(proposal.decision_ready());
    assert_eq!(proposal.evidence.events.len(), 1);
    assert!(!proposal.native);
    assert!(!proposal.connected);
    assert!(!proposal.outage_causality);
    assert!(!proposal.operational_truth);
    assert!(proposal.evidence.provider_reported_only);
    let receipt = service
        .record_observation(&proposal)
        .expect("observation receipt");
    assert!(receipt.recorded);
    assert!(!receipt.durable && !receipt.native && !receipt.connected);
    let readback = service.read_back(&proposal).expect("readback seam");
    assert!(!readback.independent_native_readback);

    let detail_proposal = service
        .compile_event_details_proposal()
        .expect("detail proposal");
    assert_eq!(detail_proposal.evidence.details.len(), 1);
    let entity_proposal = service
        .compile_affected_entities_proposal()
        .expect("entity proposal");
    assert_eq!(entity_proposal.evidence.affected_entities.len(), 1);

    let serialized = serde_json::to_string(&entity_proposal).expect("proposal serializes");
    assert!(!serialized.contains("i-raw-private-entity"));
    assert!(!serialized.contains("host-keyring-handle"));
    assert!(!serialized.contains("description"));
    assert!(!serialized.contains("metadata"));
    assert!(serialized.contains("entity_id_digest"));
}

#[test]
fn mission_consumer_is_scope_bound_and_replay_fenced() {
    let scope = scope(false, false);
    let response = events_response(&scope, 1);
    let secret = aws::SecretReference::new("host-keyring-handle", &scope, 1).expect("secret");
    let provider = aws::AwsHealthProvider::new(
        scope,
        secret,
        aws::RecordingAwsHealthTransport::new(response),
    )
    .expect("provider");
    let mut consumer = aws::MissionAwsHealthConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        result.state,
        aws::MissionAwsHealthResultState::DecisionReady
    );
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected);
    assert!(!result.outage_causality && !result.operational_truth);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(aws::MissionAwsHealthConsumerError::ReplayDetected)
    ));
}

#[test]
fn partial_failed_sets_fail_closed_without_dropping_provenance() {
    let scope = scope(false, false);
    let event = event(&scope, 1);
    let failed = aws::AwsHealthFailedEvent::new(
        Some(event.event_arn()),
        aws::AwsHealthFailureKind::AccessDenied,
        Some(403),
        "raw partial provider message",
    );
    let response = aws::DescribeEventsResponse::new(vec![event], vec![failed], None, false)
        .expect("partial response");
    let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
    let provider =
        aws::AwsHealthProvider::new(scope, secret, aws::FixtureAwsHealthTransport::new(response))
            .expect("provider");
    let mut service = aws::AwsHealthEventService::new(provider).expect("service");
    let proposal = service
        .compile_proposal()
        .expect("proposal remains typed evidence");
    assert_eq!(
        proposal.evidence.state,
        aws::AwsHealthEvidenceState::PartialFailure
    );
    assert!(!proposal.decision_ready());
    assert_eq!(
        proposal.evidence.classification,
        aws::AwsHealthEvidenceClassification::PartialFailure
    );
    let serialized = serde_json::to_string(&proposal).expect("proposal serializes");
    assert!(!serialized.contains("raw partial provider message"));
}

#[test]
fn status_matrix_maps_400_401_403_404_409_429_5xx_and_timeout_fail_closed() {
    let cases = [
        (
            aws::TransportError::bad_request(),
            aws::AwsHealthEvidenceState::ProviderUnknown,
        ),
        (
            aws::TransportError::unauthorized(),
            aws::AwsHealthEvidenceState::AccessLost,
        ),
        (
            aws::TransportError::access_denied(),
            aws::AwsHealthEvidenceState::AccessLost,
        ),
        (
            aws::TransportError::not_found(),
            aws::AwsHealthEvidenceState::AccessLost,
        ),
        (
            aws::TransportError::conflict(),
            aws::AwsHealthEvidenceState::Stale,
        ),
        (
            aws::TransportError::throttled(),
            aws::AwsHealthEvidenceState::RateLimited,
        ),
        (
            aws::TransportError::server_failure(),
            aws::AwsHealthEvidenceState::ProviderUnknown,
        ),
        (
            aws::TransportError::timeout(),
            aws::AwsHealthEvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope(false, false);
        let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
        let mut transport = aws::RecordingAwsHealthTransport::default();
        transport.push_events(Err(error));
        let provider = aws::AwsHealthProvider::new(scope, secret, transport).expect("provider");
        let mut service = aws::AwsHealthEventService::new(provider).expect("service");
        let evidence = service.read().expect("typed failure evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.decision_ready());
        assert!(!evidence.native && !evidence.connected);
    }
}

#[test]
fn blocked_env_fixture_recording_and_loopback_never_claim_native() {
    let scope = scope(false, false);
    let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
    let fixture = aws::AwsHealthProvider::new(
        scope.clone(),
        secret.clone(),
        aws::FixtureAwsHealthTransport::new(events_response(&scope, 1)),
    )
    .expect("fixture provider");
    assert_eq!(fixture.provenance(), aws::ProviderProvenance::Fixture);
    assert!(!fixture.definition().native && !fixture.definition().connected);

    let recording = aws::AwsHealthProvider::new(
        scope.clone(),
        secret.clone(),
        aws::RecordingAwsHealthTransport::new(events_response(&scope, 1)),
    )
    .expect("recording provider");
    assert_eq!(recording.provenance(), aws::ProviderProvenance::Recording);

    let loopback = aws::AwsHealthProvider::new(
        scope.clone(),
        secret.clone(),
        aws::LoopbackAwsHealthTransport::new(events_response(&scope, 1)),
    )
    .expect("loopback provider");
    assert_eq!(loopback.provenance(), aws::ProviderProvenance::Loopback);

    let blocked = aws::AwsHealthProvider::new(scope, secret, aws::BlockedEnvAwsHealthTransport)
        .expect("blocked provider");
    let mut service = aws::AwsHealthEventService::new(blocked).expect("service");
    let evidence = service.read().expect("blocked evidence");
    assert_eq!(evidence.provenance, aws::ProviderProvenance::BlockedEnv);
    assert_eq!(
        evidence.classification,
        aws::AwsHealthEvidenceClassification::BlockedEnv
    );
    assert_eq!(evidence.state, aws::AwsHealthEvidenceState::AccessLost);
    assert!(!evidence.native && !evidence.connected);
}

#[test]
fn filters_are_identical_scope_fences_and_revision_drift_is_rejected() {
    let scope = scope(true, false);
    let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
    let provider = aws::AwsHealthProvider::new(
        scope.clone(),
        secret,
        aws::RecordingAwsHealthTransport::new(events_response(&scope, 1)),
    )
    .expect("provider");
    let mut mismatched_request = provider.events_request();
    mismatched_request.service_code = aws::AwsServiceCode::new("s3").expect("service");
    let mut provider = provider;
    assert!(matches!(
        provider.describe_events(mismatched_request),
        Err(aws::AwsHealthProviderError::ScopeMismatch)
    ));

    let mut recording = aws::RecordingAwsHealthTransport::new(events_response(&scope, 1));
    let detail = aws::DescribeEventDetailsResponse::new(
        vec![aws::AwsHealthEventDetail::new(event(&scope, 2))],
        Vec::new(),
    )
    .expect("detail response");
    recording.push_details(Ok(detail));
    let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
    let provider = aws::AwsHealthProvider::new(scope.clone(), secret, recording).expect("provider");
    let mut service = aws::AwsHealthEventService::new(provider).expect("service");
    service.read_events().expect("initial event read");
    assert!(matches!(
        service.read_event_details(),
        Err(aws::AwsHealthEventServiceError::EventRevisionDrift)
    ));
}

#[test]
fn registration_is_version_contract_provider_scope_bound_and_reversible() {
    let scope = scope(false, false);
    let provider = provider_with_fixture(&scope);
    let mut service = aws::AwsHealthEventService::new(provider).expect("service");
    let initial = service.registration().registration_digest.clone();
    let proposal = service.compile_proposal().expect("proposal");
    let revocation = service.revoke().expect("revoke");
    assert_eq!(revocation.previous_registration_digest, initial);
    assert_ne!(revocation.registration_digest, initial);
    assert!(matches!(
        service.read(),
        Err(aws::AwsHealthEventServiceError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert_ne!(service.registration().registration_digest, initial);
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(aws::AwsHealthEventServiceError::ProposalMismatch
            | aws::AwsHealthEventServiceError::EvidenceMismatch
            | aws::AwsHealthEventServiceError::RegistrationRevoked,)
    ));
}

#[test]
fn proposal_tamper_and_cursor_serialization_fail_closed() {
    let scope = scope(false, false);
    let response = events_response(&scope, 1);
    let secret = aws::SecretReference::new("secret", &scope, 1).expect("secret");
    let provider = aws::AwsHealthProvider::new(
        scope,
        secret,
        aws::RecordingAwsHealthTransport::new(response),
    )
    .expect("provider");
    let mut service = aws::AwsHealthEventService::new(provider).expect("service");
    let mut proposal = service.compile_proposal().expect("proposal");
    proposal.evidence.scope_digest = aws::Digest::from_text("tampered");
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(aws::AwsHealthEventServiceError::ProposalMismatch
            | aws::AwsHealthEventServiceError::EvidenceMismatch,)
    ));

    let cursor = aws::OpaqueCursor::new("opaque-provider-cursor").expect("cursor");
    let request = service.provider().events_request().with_cursor(cursor);
    let serialized = serde_json::to_string(&request).expect("request serializes");
    assert!(!serialized.contains("opaque-provider-cursor"));
    assert!(serialized.contains("secret_reference_digest"));
    assert_eq!(json!(request).get("cursor"), None);
}
