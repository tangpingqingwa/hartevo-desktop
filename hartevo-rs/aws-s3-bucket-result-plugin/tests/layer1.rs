use chrono::{Duration, Utc};
use hartevo_aws_s3_bucket_result_plugin as plugin;
use plugin::provider::AwsS3ReadPage;
use plugin::{
    AwsAccountId, AwsRegion, AwsS3BucketError, AwsS3BucketScope, AwsS3BucketService,
    AwsS3EvidenceState, AwsS3Observation, AwsS3Operation, AwsS3OperationRequest, AwsS3Provider,
    AwsS3ReadRequest, AwsS3Transport, AwsS3TransportError, BlockedEnvTransport, BucketName,
    BucketReplicationObservation, BucketVersioningObservation, EncryptionAlgorithm,
    EncryptionPosture, FixtureTransport, LifecyclePosture, MissionAwsS3DecisionState,
    MissionIdentity, OpaqueMarker, PermissionSnapshot, ProjectIdentity, RecordingTransport,
    ReplicationPosture, Revision, SecretReference, TransportProvenance, VersioningPosture,
    WorkProductIdentity,
};

fn scope() -> AwsS3BucketScope {
    let provider_scope = plugin::AwsS3ProviderScope::for_bucket(
        AwsAccountId::new("123456789012").unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
        BucketName::new("durability-bucket").unwrap(),
        Revision::new(7).unwrap(),
    )
    .unwrap();
    AwsS3BucketScope::for_bucket(
        provider_scope,
        MissionIdentity::new("mission-655", 2).unwrap(),
        ProjectIdentity::new("project-655", 3).unwrap(),
        WorkProductIdentity::new("work-product-655", 4).unwrap(),
        PermissionSnapshot::layer_one(5).unwrap(),
    )
    .unwrap()
}

fn secret(scope: &AwsS3BucketScope) -> SecretReference {
    SecretReference::sigv4("host-owned-secret-reference", scope, 9).unwrap()
}

fn service_with_transport<T: AwsS3Transport>(
    scope: &AwsS3BucketScope,
    transport: T,
) -> AwsS3BucketService<T> {
    let provider = AwsS3Provider::new(transport).unwrap();
    AwsS3BucketService::new(scope.clone(), secret(scope), provider).unwrap()
}

fn fixture_service() -> AwsS3BucketService<FixtureTransport> {
    let scope = scope();
    service_with_transport(&scope, FixtureTransport::for_scope(&scope))
}

fn versioning_request(scope: &AwsS3BucketScope) -> AwsS3ReadRequest {
    let observed_at = Utc::now();
    AwsS3ReadRequest::versioning(scope, observed_at, observed_at + Duration::minutes(5)).unwrap()
}

#[test]
fn contract_scope_secret_and_provenance_are_redacted_and_fenced() {
    let document: serde_json::Value = serde_json::from_str(plugin::CONTRACT_JSON).unwrap();
    assert_eq!(document["contractDigest"], plugin::CONTRACT_DIGEST);
    assert_eq!(
        document["scope"]["required"],
        serde_json::json!([
            "awsAccountId",
            "awsRegion",
            "bucketAllowlist",
            "targetBucket",
            "resourceRevision",
            "projectIdAndRevision",
            "missionIdAndRevision",
            "workProductIdAndRevision",
            "permissionSnapshotAndRevision",
            "secretReferenceDigest",
            "scopeDigest"
        ])
    );
    assert_eq!(
        document["provider"]["operations"].as_array().unwrap().len(),
        5
    );

    let scope = scope();
    let serialized_scope = serde_json::to_string(&scope).unwrap();
    assert!(!serialized_scope.contains("durability-bucket"));
    assert!(!serialized_scope.contains("123456789012"));
    assert!(!serialized_scope.contains("mission-655"));

    let secret = secret(&scope);
    let debug = format!("{secret:?}");
    assert!(!debug.contains("host-owned-secret-reference"));
    assert!(debug.contains("reference_digest"));

    let marker = OpaqueMarker::new("raw-marker-token").unwrap();
    let marker_json = serde_json::to_string(&marker).unwrap();
    assert_eq!(marker_json, r#"{"opaque":true}"#);
    assert!(!marker_json.contains("raw-marker-token"));

    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Fake,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn fixture_read_proposal_record_verify_and_mission_consume_are_review_only() {
    let mut service = fixture_service();
    let proposal = service.propose(service.default_request().unwrap()).unwrap();

    assert_eq!(proposal.state, AwsS3EvidenceState::Complete);
    assert!(proposal.posture.is_complete());
    assert_eq!(
        proposal.posture.versioning.as_ref().unwrap().posture,
        VersioningPosture::Enabled
    );
    assert_eq!(
        proposal.posture.encryption.as_ref().unwrap().algorithm,
        EncryptionAlgorithm::Aes256
    );
    assert_eq!(
        proposal.posture.encryption.as_ref().unwrap().posture,
        EncryptionPosture::Encrypted
    );
    assert_eq!(
        proposal.posture.lifecycle.as_ref().unwrap().posture,
        LifecyclePosture::Configured
    );
    assert_eq!(
        proposal.posture.replication.as_ref().unwrap().posture,
        ReplicationPosture::NotConfigured
    );
    assert!(
        proposal
            .posture
            .location
            .as_ref()
            .unwrap()
            .matches_scope_region
    );
    assert!(proposal.validate_integrity().is_ok());
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);

    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);

    let receipt = service.record(&proposal).unwrap();
    assert!(receipt.validate_integrity().is_ok());
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(!receipt.first_party);
    assert!(!receipt.durable_native_receipt);
    assert!(!receipt.independent_native_reread);
    assert!(!receipt.work_product_adopted);
    assert!(service.verify_record(&receipt).is_ok());

    let mut consumer = service.consumer().unwrap();
    let mission_result = consumer.consume(&proposal).unwrap();
    assert_eq!(mission_result.state, AwsS3EvidenceState::Complete);
    assert_eq!(
        mission_result.decision_state,
        MissionAwsS3DecisionState::ReviewRequired
    );
    assert!(mission_result.requires_human_review);
    assert!(mission_result.accepted_for_review);
    assert!(!mission_result.truth_authority);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.first_party);
    assert!(!mission_result.outcome_adopted);
    assert!(!mission_result.work_product_adopted);

    let first = consumer.record(&proposal, "mission-655-review").unwrap();
    let replay = consumer.record(&proposal, "mission-655-review").unwrap();
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn registration_transitions_secret_revocation_and_drift_stop_reads() {
    let mut reversed = fixture_service();
    let transition = reversed.reverse_registration("review reversal").unwrap();
    assert_eq!(transition.to, plugin::RegistrationState::Reversed);
    assert_eq!(
        reversed.registration().state(),
        plugin::RegistrationState::Reversed
    );
    assert!(matches!(
        reversed.read(reversed.default_request().unwrap()),
        Err(AwsS3BucketError::RegistrationReversed)
    ));
    reversed
        .restore_registration("restore after review")
        .unwrap();
    reversed.revoke_registration("operator revocation").unwrap();
    assert!(matches!(
        reversed.read(reversed.default_request().unwrap()),
        Err(AwsS3BucketError::RegistrationRevoked)
    ));

    let mut revoked_secret = fixture_service();
    revoked_secret.revoke_secret_reference().unwrap();
    assert!(matches!(
        revoked_secret.read(revoked_secret.default_request().unwrap()),
        Err(AwsS3BucketError::ScopeMismatch(_))
    ));

    let mut drifted = fixture_service();
    drifted
        .registration_mut()
        .provider_version
        .push_str("-drift");
    assert!(matches!(
        drifted.read(drifted.default_request().unwrap()),
        Err(AwsS3BucketError::InvalidRegistration)
    ));
}

#[test]
fn tamper_and_recording_conflict_are_rejected() {
    let mut service = fixture_service();
    let proposal = service.propose(service.default_request().unwrap()).unwrap();
    let mut tampered = proposal.clone();
    tampered.evidence.evidence_digest = plugin::Digest::zero();
    assert!(!service.verify(&tampered).valid);
    assert!(matches!(
        service.consumer().unwrap().verify_proposal(&tampered),
        Err(plugin::ConsumerError::ProposalTampered)
    ));

    let mut consumer = service.consumer().unwrap();
    consumer.record(&proposal, "conflict-key").unwrap();
    let alternate = service
        .propose(versioning_request(service.scope()))
        .unwrap();
    assert_ne!(alternate.proposal_digest, proposal.proposal_digest);
    assert!(matches!(
        consumer.record(&alternate, "conflict-key"),
        Err(plugin::ConsumerError::RecordingConflict)
    ));
}

#[test]
fn pagination_is_bounded_marker_opaque_and_marker_replay_is_partial() {
    let scope = scope();
    let request = versioning_request(&scope).with_bounds(2, 3, 1024).unwrap();
    let first_request =
        AwsS3OperationRequest::new(&request, AwsS3Operation::GetBucketVersioning, 1, None).unwrap();
    let marker = OpaqueMarker::new("pagination-marker-secret").unwrap();
    let observation = AwsS3Observation::GetBucketVersioning(
        BucketVersioningObservation::new(
            scope.bucket_digest(),
            scope.resource_revision(),
            VersioningPosture::Enabled,
        )
        .unwrap(),
    );
    let first_page = AwsS3ReadPage::new(
        &first_request,
        observation.clone(),
        Some(marker.clone()),
        10,
        TransportProvenance::Recording,
    )
    .unwrap();
    let second_request = AwsS3OperationRequest::new(
        &request,
        AwsS3Operation::GetBucketVersioning,
        2,
        Some(marker.clone()),
    )
    .unwrap();
    let second_page = AwsS3ReadPage::new(
        &second_request,
        observation.clone(),
        None,
        10,
        TransportProvenance::Recording,
    )
    .unwrap();

    let mut transport = RecordingTransport::default();
    transport.push(Ok(first_page));
    transport.push(Ok(second_page));
    let mut service = service_with_transport(&scope, transport);
    let evidence = service.read(request.clone()).unwrap();
    assert_eq!(evidence.state, AwsS3EvidenceState::ConfigurationUnknown);
    assert_eq!(evidence.response.response_bytes, 20);
    assert_eq!(evidence.response.marker_digests.len(), 1);
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].page_number, 1);
    assert_eq!(requests[1].page_number, 2);
    assert!(requests[1].marker_digest.is_some());
    let request_json = serde_json::to_string(requests).unwrap();
    assert!(!request_json.contains("pagination-marker-secret"));

    let replay_request =
        AwsS3OperationRequest::new(&request, AwsS3Operation::GetBucketVersioning, 1, None).unwrap();
    let replay_first = AwsS3ReadPage::new(
        &replay_request,
        observation.clone(),
        Some(marker.clone()),
        10,
        TransportProvenance::Recording,
    )
    .unwrap();
    let replay_second_request = AwsS3OperationRequest::new(
        &request,
        AwsS3Operation::GetBucketVersioning,
        2,
        Some(marker.clone()),
    )
    .unwrap();
    let replay_second = AwsS3ReadPage::new(
        &replay_second_request,
        observation,
        Some(marker),
        10,
        TransportProvenance::Recording,
    )
    .unwrap();
    let mut replay_transport = RecordingTransport::default();
    replay_transport.push(Ok(replay_first));
    replay_transport.push(Ok(replay_second));
    let mut replay_service = service_with_transport(&scope, replay_transport);
    let replay_evidence = replay_service.read(request).unwrap();
    assert_eq!(replay_evidence.state, AwsS3EvidenceState::Partial);
    assert_eq!(
        replay_evidence
            .operations
            .get(&AwsS3Operation::GetBucketVersioning)
            .unwrap()
            .failure
            .as_ref()
            .unwrap()
            .kind,
        "marker_replay"
    );
}

#[test]
fn status_errors_and_expiry_are_redacted_and_classified() {
    let cases = vec![
        (
            AwsS3TransportError::BadRequest,
            AwsS3EvidenceState::Partial,
            Some(400),
            1,
        ),
        (
            AwsS3TransportError::Unauthorized,
            AwsS3EvidenceState::AccessLoss,
            Some(401),
            1,
        ),
        (
            AwsS3TransportError::Forbidden,
            AwsS3EvidenceState::AccessLoss,
            Some(403),
            1,
        ),
        (
            AwsS3TransportError::NotFound,
            AwsS3EvidenceState::AccessLoss,
            Some(404),
            1,
        ),
        (
            AwsS3TransportError::Throttled {
                retry_after_seconds: Some(4),
            },
            AwsS3EvidenceState::Partial,
            Some(429),
            3,
        ),
        (
            AwsS3TransportError::ServerFailure {
                status_code: Some(500),
            },
            AwsS3EvidenceState::Partial,
            Some(500),
            3,
        ),
        (
            AwsS3TransportError::ServerFailure {
                status_code: Some(503),
            },
            AwsS3EvidenceState::Partial,
            Some(503),
            3,
        ),
        (
            AwsS3TransportError::Timeout,
            AwsS3EvidenceState::Partial,
            None,
            3,
        ),
    ];

    for (error, expected_state, expected_status, repeats) in cases {
        let scope = scope();
        let mut transport = RecordingTransport::default();
        for _ in 0..repeats {
            transport.push(Err(error.clone()));
        }
        let mut service = service_with_transport(&scope, transport);
        let evidence = service.read(versioning_request(&scope)).unwrap();
        assert_eq!(evidence.state, expected_state, "{}", error.kind());
        let failure = evidence.failure.as_ref().unwrap();
        assert_eq!(failure.status_code, expected_status, "{}", error.kind());
        assert!(!evidence.response.raw_provider_payload_retained);
        assert!(!evidence.response.raw_marker_retained);
        assert!(evidence.validate_integrity().is_ok());
    }

    let mut expired = fixture_service();
    let observed_at = Utc::now();
    let request = AwsS3ReadRequest::versioning(
        expired.scope(),
        observed_at,
        observed_at + Duration::seconds(1),
    )
    .unwrap();
    expired.set_now(observed_at + Duration::seconds(2));
    let evidence = expired.read(request).unwrap();
    assert_eq!(evidence.state, AwsS3EvidenceState::Expired);
    assert!(evidence.posture.versioning.is_none());
    assert_eq!(evidence.response.response_bytes, 0);
}

#[test]
fn scope_drift_and_json_parsing_never_retain_sensitive_payloads() {
    let primary_scope = scope();
    let foreign_provider_scope = plugin::AwsS3ProviderScope::for_bucket(
        AwsAccountId::new("123456789012").unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
        BucketName::new("foreign-bucket").unwrap(),
        Revision::new(7).unwrap(),
    )
    .unwrap();
    let foreign_scope = AwsS3BucketScope::for_bucket(
        foreign_provider_scope,
        MissionIdentity::new("mission-655", 2).unwrap(),
        ProjectIdentity::new("project-655", 3).unwrap(),
        WorkProductIdentity::new("work-product-655", 4).unwrap(),
        PermissionSnapshot::layer_one(5).unwrap(),
    )
    .unwrap();
    let foreign_request = versioning_request(&foreign_scope);
    let foreign_operation_request = AwsS3OperationRequest::new(
        &foreign_request,
        AwsS3Operation::GetBucketVersioning,
        1,
        None,
    )
    .unwrap();
    let foreign_observation = AwsS3Observation::GetBucketVersioning(
        BucketVersioningObservation::new(
            foreign_scope.bucket_digest(),
            foreign_scope.resource_revision(),
            VersioningPosture::Enabled,
        )
        .unwrap(),
    );
    let foreign_page = AwsS3ReadPage::new(
        &foreign_operation_request,
        foreign_observation,
        None,
        10,
        TransportProvenance::Recording,
    )
    .unwrap();
    let mut transport = RecordingTransport::default();
    transport.push(Ok(foreign_page));
    let mut service = service_with_transport(&primary_scope, transport);
    let evidence = service.read(versioning_request(&primary_scope)).unwrap();
    assert_eq!(evidence.state, AwsS3EvidenceState::Partial);
    assert_eq!(evidence.failure.as_ref().unwrap().kind, "scope_drift");

    let request = AwsS3OperationRequest::new(
        &versioning_request(&primary_scope),
        AwsS3Operation::GetBucketVersioning,
        1,
        None,
    )
    .unwrap();
    let body = br#"{"Status":"Enabled","Role":"arn:aws:iam::123456789012:role/secret","KmsMasterKeyID":"kms-secret","Object":"raw-object-key"}"#;
    let page = AwsS3Provider::<FixtureTransport>::parse_json_page(&request, 1, 200, body).unwrap();
    let page_json = serde_json::to_string(&page).unwrap();
    assert!(!page_json.contains("arn:aws:iam"));
    assert!(!page_json.contains("kms-secret"));
    assert!(!page_json.contains("raw-object-key"));

    let replication_request = AwsS3OperationRequest::new(
        &AwsS3ReadRequest::replication(
            &primary_scope,
            Utc::now(),
            Utc::now() + Duration::minutes(5),
        )
        .unwrap(),
        AwsS3Operation::GetBucketReplication,
        1,
        None,
    )
    .unwrap();
    let replication_body = br#"{"Role":"arn:aws:iam::123456789012:role/replication-secret","Rules":[{"Status":"Enabled","Destination":{"Bucket":"arn:aws:s3:::other"}}]}"#;
    let replication_page = AwsS3Provider::<FixtureTransport>::parse_json_page(
        &replication_request,
        1,
        200,
        replication_body,
    )
    .unwrap();
    let replication_json = serde_json::to_string(&replication_page).unwrap();
    assert!(!replication_json.contains("replication-secret"));
    assert!(!replication_json.contains("arn:aws:s3"));
    match replication_page.observation {
        AwsS3Observation::GetBucketReplication(BucketReplicationObservation {
            rule_count, ..
        }) => assert_eq!(rule_count, 1),
        _ => panic!("replication parser returned the wrong operation"),
    }
}

#[test]
fn blocked_env_and_loopback_remain_non_native() {
    let scope = scope();
    let mut blocked = service_with_transport(&scope, BlockedEnvTransport);
    let blocked_evidence = blocked.read(versioning_request(&scope)).unwrap();
    assert_eq!(blocked_evidence.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(blocked_evidence.state, AwsS3EvidenceState::Partial);
    assert!(!blocked_evidence.connected);
    assert!(!blocked_evidence.native);
    assert!(!blocked_evidence.first_party);

    let mut loopback = service_with_transport(&scope, plugin::LoopbackTransport::for_scope(&scope));
    let loopback_evidence = loopback.read(loopback.default_request().unwrap()).unwrap();
    assert_eq!(loopback_evidence.provenance, TransportProvenance::Loopback);
    assert!(!loopback_evidence.connected);
    assert!(!loopback_evidence.native);
    assert!(!loopback_evidence.first_party);
    assert!(!loopback.describe_capabilities().connected);
    assert!(!loopback.describe_capabilities().native);
    assert!(!loopback.describe_capabilities().first_party);
}
