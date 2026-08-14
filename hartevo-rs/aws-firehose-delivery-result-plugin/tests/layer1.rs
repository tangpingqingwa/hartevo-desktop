use hartevo_aws_firehose_delivery_result_plugin as firehose;

const NOW: u64 = 1_800_000_000;

fn scope() -> firehose::AwsFirehoseDeliveryScope {
    let account = firehose::AwsAccountId::new("123456789012").expect("account");
    let region = firehose::AwsRegion::new("us-east-1").expect("region");
    let target = firehose::DeliveryStreamName::new("handoff-stream").expect("target");
    let audit = firehose::DeliveryStreamName::new("audit-stream").expect("audit");
    firehose::AwsFirehoseDeliveryScope::new(
        account,
        region,
        vec![target.clone(), audit],
        target,
        firehose::StreamVersionId::new("v17").expect("version"),
        firehose::Revision::new(9).expect("source revision"),
        firehose::MissionIdentity::new("mission-610", 4).expect("mission"),
        firehose::ProjectIdentity::new("project-610", 8).expect("project"),
        firehose::WorkProductIdentity::new("work-product-610", 12).expect("work product"),
        firehose::PermissionSnapshot::layer_one(3).expect("permissions"),
    )
    .expect("scope")
}

fn consent() -> firehose::ConsentScope {
    firehose::ConsentScope::for_layer_one("consent-610", 2, NOW + 10_000).expect("consent")
}

fn secret(scope: &firehose::AwsFirehoseDeliveryScope) -> firehose::SecretReference {
    firehose::SecretReference::sigv4("opaque-keyring-firehose-handle", scope, 6)
        .expect("secret reference")
}

fn fixture_service() -> firehose::AwsFirehoseDeliveryService<firehose::FixtureTransport> {
    let scope = scope();
    let provider =
        firehose::AwsFirehoseProvider::new(firehose::FixtureTransport::for_scope(&scope))
            .expect("fixture provider");
    firehose::AwsFirehoseDeliveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        NOW,
    )
    .expect("fixture service")
}

fn recording_service(
    transport: firehose::RecordingTransport,
    scope: &firehose::AwsFirehoseDeliveryScope,
) -> firehose::AwsFirehoseDeliveryService<firehose::RecordingTransport> {
    let provider = firehose::AwsFirehoseProvider::new(transport).expect("recording provider");
    firehose::AwsFirehoseDeliveryService::new(
        scope.clone(),
        secret(scope),
        consent(),
        provider,
        NOW,
    )
    .expect("recording service")
}

fn observation(
    scope: &firehose::AwsFirehoseDeliveryScope,
    status: firehose::StreamStatus,
    health: firehose::DestinationHealth,
    version: &str,
    destination_count: usize,
) -> firehose::DeliveryStreamObservation {
    let configuration = firehose::Digest::from_text("fixture-firehose-configuration");
    let encryption = Some(firehose::Digest::from_text("fixture-firehose-encryption"));
    let destinations = (0..destination_count)
        .map(|index| {
            firehose::DestinationObservation::new(
                firehose::DestinationId::new(format!("destination-{index}")).expect("destination"),
                firehose::DestinationType::ExtendedS3,
                health,
                configuration.clone(),
                encryption.clone(),
            )
            .expect("destination observation")
        })
        .collect();
    firehose::DeliveryStreamObservation::new(
        scope.provider_scope().target_stream().clone(),
        status,
        firehose::StreamVersionId::new(version).expect("version"),
        scope.provider_scope().source_revision(),
        destinations,
        encryption,
        configuration,
    )
    .expect("stream observation")
}

fn active_recording_service(
    scope: &firehose::AwsFirehoseDeliveryScope,
    status: firehose::StreamStatus,
    health: firehose::DestinationHealth,
    version: &str,
    destination_count: usize,
) -> firehose::AwsFirehoseDeliveryService<firehose::RecordingTransport> {
    let list_request = firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 100, None)
        .expect("list request");
    let list_response = firehose::ListDeliveryStreamsResponse::new(
        &list_request,
        vec![scope.provider_scope().target_stream().clone()],
        None,
        512,
        firehose::TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_request = firehose::DescribeDeliveryStreamRequest::new(scope.provider_scope());
    let describe_response = firehose::DescribeDeliveryStreamResponse::new(
        &describe_request,
        observation(scope, status, health, version, destination_count),
        768,
        firehose::TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = firehose::RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    recording_service(transport, scope)
}

#[test]
fn fixture_contract_scope_registration_and_secret_are_redacted() {
    let service = fixture_service();
    assert_eq!(
        service.registration().state(),
        firehose::RegistrationState::Active
    );
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 2);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    let registration_json = serde_json::to_string(service.registration()).expect("registration");
    let debug = format!("{service:?}");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains("opaque-keyring-firehose-handle"));
    assert!(!debug.contains("opaque-keyring-firehose-handle"));
    assert!(
        !format!("{:?}", service.secret_reference()).contains("opaque-keyring-firehose-handle")
    );
}

#[test]
fn fixture_produces_bounded_review_only_mission_decision_and_replay_safe_recording() {
    let mut service = fixture_service();
    let request = service.default_read_request().expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, firehose::AwsFirehoseEvidenceState::Complete);
    assert!(proposal.evidence.list_complete);
    assert_eq!(proposal.evidence.pages_observed, 1);
    assert_eq!(
        proposal.evidence.stream.as_ref().expect("stream").status,
        firehose::StreamStatus::Active
    );
    assert_eq!(
        proposal
            .evidence
            .stream
            .as_ref()
            .expect("stream")
            .destination
            .health,
        firehose::DestinationHealth::Healthy
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.delivery_completion_claim);
    assert!(!proposal.can_be_adopted());
    assert!(service.verify(&proposal).valid);

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission decision");
    assert!(result.accepted_for_review);
    assert!(result.requires_human_review);
    assert!(!result.data_handoff_verified);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    assert_eq!(result.mission.revision.get(), 4);
    assert_eq!(result.project.revision.get(), 8);
    assert_eq!(result.work_product.revision.get(), 12);
    let first = consumer
        .record(&proposal, "handoff-record-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "handoff-record-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert!(first.validate_integrity().is_ok());
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_connected_or_first_party() {
    let scope = scope();
    let loopback_provider =
        firehose::AwsFirehoseProvider::new(firehose::LoopbackTransport::for_scope(&scope))
            .expect("loopback provider");
    let mut loopback = firehose::AwsFirehoseDeliveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        loopback_provider,
        NOW,
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(loopback.default_read_request().expect("request"))
        .expect("loopback proposal");
    assert_eq!(
        loopback_proposal.provenance,
        firehose::TransportProvenance::Loopback
    );
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);

    let mut blocked = firehose::AwsFirehoseDeliveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        firehose::AwsFirehoseProvider::default(),
        NOW,
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_read_request().expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        firehose::AwsFirehoseEvidenceState::ProviderUnknown
    );
    assert_eq!(
        blocked_proposal.provenance,
        firehose::TransportProvenance::BlockedEnv
    );
    assert_eq!(
        blocked_proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "blocked_env"
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(!blocked_proposal.first_party);
}

#[test]
fn exclusive_start_pagination_is_bounded_and_raw_cursor_never_enters_recording() {
    let scope = scope();
    let first_request = firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 1, None)
        .expect("first request");
    let cursor =
        firehose::OpaqueExclusiveStart::for_next_page("opaque-exclusive-start", &first_request)
            .expect("cursor");
    let first_response = firehose::ListDeliveryStreamsResponse::new(
        &first_request,
        vec![firehose::DeliveryStreamName::new("audit-stream").expect("audit")],
        Some(cursor.clone()),
        256,
        firehose::TransportProvenance::Recording,
    )
    .expect("first response");
    let second_request =
        firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 1, Some(cursor.clone()))
            .expect("second request");
    let second_response = firehose::ListDeliveryStreamsResponse::new(
        &second_request,
        vec![scope.provider_scope().target_stream().clone()],
        None,
        256,
        firehose::TransportProvenance::Recording,
    )
    .expect("second response");
    let describe_request = firehose::DescribeDeliveryStreamRequest::new(scope.provider_scope());
    let describe_response = firehose::DescribeDeliveryStreamResponse::new(
        &describe_request,
        observation(
            &scope,
            firehose::StreamStatus::Active,
            firehose::DestinationHealth::Healthy,
            "v17",
            1,
        ),
        512,
        firehose::TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = firehose::RecordingTransport::default();
    transport.push_list_response(Ok(first_response));
    transport.push_list_response(Ok(second_response));
    transport.push_describe_response(Ok(describe_response));
    let mut service = recording_service(transport, &scope);
    let proposal = service
        .propose(
            firehose::AwsFirehoseReadRequest::new(service.scope(), 1, 4).expect("read request"),
        )
        .expect("paged proposal");
    assert_eq!(proposal.state, firehose::AwsFirehoseEvidenceState::Complete);
    assert_eq!(proposal.evidence.pages_observed, 2);
    assert_eq!(proposal.evidence.cursor_digests.len(), 1);
    let requests = service.provider_definition();
    assert_eq!(requests.api_revision, firehose::PROVIDER_API_REVISION);
    let transport = service.into_provider().into_transport();
    let recorded = transport.requests();
    assert_eq!(recorded.len(), 3);
    assert!(
        !serde_json::to_string(recorded)
            .expect("recorded requests")
            .contains("opaque-exclusive-start")
    );
}

#[test]
fn page_cap_returns_partial_and_is_not_adoptable() {
    let scope = scope();
    let first_request = firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 1, None)
        .expect("first request");
    let cursor = firehose::OpaqueExclusiveStart::for_next_page("page-cap-token", &first_request)
        .expect("cursor");
    let first_response = firehose::ListDeliveryStreamsResponse::new(
        &first_request,
        vec![firehose::DeliveryStreamName::new("audit-stream").expect("audit")],
        Some(cursor),
        256,
        firehose::TransportProvenance::Recording,
    )
    .expect("response");
    let mut transport = firehose::RecordingTransport::default();
    transport.push_list_response(Ok(first_response));
    let mut service = recording_service(transport, &scope);
    let proposal = service
        .propose(firehose::AwsFirehoseReadRequest::new(service.scope(), 1, 1).expect("request"))
        .expect("partial proposal");
    assert_eq!(proposal.state, firehose::AwsFirehoseEvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "page_cap"
    );
    assert!(!proposal.can_be_adopted());
}

#[test]
fn aggregate_response_byte_cap_is_partial_and_integrity_valid() {
    let scope = scope();
    let list_request = firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 100, None)
        .expect("list request");
    let list_response = firehose::ListDeliveryStreamsResponse::new(
        &list_request,
        vec![scope.provider_scope().target_stream().clone()],
        None,
        700_000,
        firehose::TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_request = firehose::DescribeDeliveryStreamRequest::new(scope.provider_scope());
    let describe_response = firehose::DescribeDeliveryStreamResponse::new(
        &describe_request,
        observation(
            &scope,
            firehose::StreamStatus::Active,
            firehose::DestinationHealth::Healthy,
            "v17",
            1,
        ),
        700_000,
        firehose::TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut transport = firehose::RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    let mut service = recording_service(transport, &scope);
    let proposal = service
        .propose(service.default_read_request().expect("request"))
        .expect("byte-cap proposal");
    assert_eq!(proposal.state, firehose::AwsFirehoseEvidenceState::Partial);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "response_byte_cap"
    );
    assert_eq!(
        proposal.evidence.cost.response_bytes,
        firehose::MAX_RESPONSE_BYTES
    );
    assert!(service.verify(&proposal).valid);
    assert!(!proposal.can_be_adopted());
}

#[test]
fn stream_version_drift_and_destination_ambiguity_fail_closed() {
    let scope = scope();
    let mut drifted = active_recording_service(
        &scope,
        firehose::StreamStatus::Active,
        firehose::DestinationHealth::Healthy,
        "v18",
        1,
    );
    let error = drifted
        .propose(drifted.default_read_request().expect("request"))
        .expect_err("version drift");
    assert_eq!(error, firehose::AwsFirehoseError::StreamVersionDrift);

    let mut ambiguous = active_recording_service(
        &scope,
        firehose::StreamStatus::Active,
        firehose::DestinationHealth::Healthy,
        "v17",
        2,
    );
    let error = ambiguous
        .propose(ambiguous.default_read_request().expect("request"))
        .expect_err("ambiguous destination");
    assert_eq!(error, firehose::AwsFirehoseError::DestinationAmbiguous);
}

#[test]
fn access_loss_throttle_timeout_and_partial_are_explicit_non_adoptable_states() {
    let cases = [
        (
            firehose::AwsFirehoseTransportError::Unauthorized,
            firehose::AwsFirehoseEvidenceState::AccessLoss,
        ),
        (
            firehose::AwsFirehoseTransportError::Throttled {
                retry_after_seconds: Some(3),
            },
            firehose::AwsFirehoseEvidenceState::Throttled,
        ),
        (
            firehose::AwsFirehoseTransportError::Timeout,
            firehose::AwsFirehoseEvidenceState::Timeout,
        ),
        (
            firehose::AwsFirehoseTransportError::Partial,
            firehose::AwsFirehoseEvidenceState::Partial,
        ),
    ];
    for (transport_error, expected_state) in cases {
        let scope = scope();
        let mut transport = firehose::RecordingTransport::default();
        transport.push_list_response(Err(transport_error));
        let mut service = recording_service(transport, &scope);
        let proposal = service
            .propose(service.default_read_request().expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected_state);
        assert!(!proposal.can_be_adopted());
        assert!(proposal.evidence.failure.is_some());
    }
}

#[test]
fn replay_tamper_scope_and_registration_revocation_fail_closed() {
    let scope = scope();
    let first_request = firehose::ListDeliveryStreamsRequest::new(scope.provider_scope(), 1, None)
        .expect("first request");
    let first_cursor =
        firehose::OpaqueExclusiveStart::for_next_page("replay-token", &first_request)
            .expect("first cursor");
    let second_request = firehose::ListDeliveryStreamsRequest::new(
        scope.provider_scope(),
        1,
        Some(first_cursor.clone()),
    )
    .expect("second request");
    let replay_cursor =
        firehose::OpaqueExclusiveStart::for_next_page("replay-token", &second_request)
            .expect("replay cursor");
    let first_response = firehose::ListDeliveryStreamsResponse::new(
        &first_request,
        vec![firehose::DeliveryStreamName::new("audit-stream").expect("audit")],
        Some(first_cursor),
        256,
        firehose::TransportProvenance::Recording,
    )
    .expect("first response");
    let second_response = firehose::ListDeliveryStreamsResponse::new(
        &second_request,
        vec![firehose::DeliveryStreamName::new("audit-stream").expect("audit")],
        Some(replay_cursor),
        256,
        firehose::TransportProvenance::Recording,
    )
    .expect("second response");
    let mut transport = firehose::RecordingTransport::default();
    transport.push_list_response(Ok(first_response));
    transport.push_list_response(Ok(second_response));
    let mut service = recording_service(transport, &scope);
    let error = service
        .propose(firehose::AwsFirehoseReadRequest::new(service.scope(), 1, 4).expect("request"))
        .expect_err("cursor replay");
    assert_eq!(error, firehose::AwsFirehoseError::ReplayDetected);

    let mut fixture = fixture_service();
    let proposal = fixture
        .propose(fixture.default_read_request().expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.state = firehose::AwsFirehoseEvidenceState::Partial;
    assert_eq!(
        fixture
            .consumer()
            .expect("consumer")
            .consume(&tampered)
            .expect_err("tamper")
            .to_string(),
        "Mission AWS Firehose proposal is tampered or invalid"
    );

    let mut consumer = fixture.consumer().expect("consumer");
    consumer.revoke().expect("revoke consumer");
    assert!(matches!(
        consumer.consume(&proposal),
        Err(firehose::ConsumerError::RegistrationRevoked)
    ));
    fixture
        .revoke_registration("issue-610 test revocation")
        .expect("registration revoke");
    assert!(matches!(
        fixture.propose(fixture.default_read_request().expect("request")),
        Err(firehose::AwsFirehoseError::RegistrationRevoked)
    ));
}

#[test]
fn registration_reverse_restore_and_revoke_are_digest_bound() {
    let mut service = fixture_service();
    let initial_digest = service.registration().registration_digest().clone();
    let reversed = service
        .reverse_registration("issue-610 reverse")
        .expect("reverse registration");
    assert_eq!(reversed.from, firehose::RegistrationState::Active);
    assert_eq!(reversed.to, firehose::RegistrationState::Reversed);
    assert_eq!(reversed.prior_registration_digest, initial_digest);
    assert_ne!(
        service.registration().registration_digest(),
        &initial_digest
    );
    assert!(service.registration().validate().is_ok());
    assert!(matches!(
        service.propose(service.default_read_request().expect("request")),
        Err(firehose::AwsFirehoseError::RegistrationReversed)
    ));

    service
        .restore_registration("issue-610 restore")
        .expect("restore registration");
    assert_eq!(
        service.registration().state(),
        firehose::RegistrationState::Active
    );
    assert!(service.registration().validate().is_ok());
    service
        .revoke_registration("issue-610 revoke")
        .expect("revoke registration");
    assert!(matches!(
        service.propose(service.default_read_request().expect("request")),
        Err(firehose::AwsFirehoseError::RegistrationRevoked)
    ));
}

#[test]
fn active_statuses_are_recorded_without_claiming_delivery_completion() {
    let cases = [
        (
            firehose::StreamStatus::Creating,
            firehose::AwsFirehoseEvidenceState::Creating,
        ),
        (
            firehose::StreamStatus::Deleting,
            firehose::AwsFirehoseEvidenceState::Deleting,
        ),
        (
            firehose::StreamStatus::CreatingFailed,
            firehose::AwsFirehoseEvidenceState::CreatingFailed,
        ),
        (
            firehose::StreamStatus::DeletingFailed,
            firehose::AwsFirehoseEvidenceState::DeletingFailed,
        ),
    ];
    for (status, expected) in cases {
        let scope = scope();
        let mut service = active_recording_service(
            &scope,
            status,
            firehose::DestinationHealth::Healthy,
            "v17",
            1,
        );
        let proposal = service
            .propose(service.default_read_request().expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.delivery_completion_claim);
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn unknown_destination_health_is_provider_unknown_and_not_complete() {
    let destination_scope = scope();
    let mut service = active_recording_service(
        &destination_scope,
        firehose::StreamStatus::Active,
        firehose::DestinationHealth::Unknown,
        "v17",
        1,
    );
    let proposal = service
        .propose(service.default_read_request().expect("request"))
        .expect("proposal");
    assert_eq!(
        proposal.state,
        firehose::AwsFirehoseEvidenceState::ProviderUnknown
    );
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .category,
        "destination_health_unknown"
    );
}
