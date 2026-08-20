use hartevo_aws_ebs_volume_result_plugin::{
    AttachmentObservation, AttachmentState, AwsAccountId, AwsEbsOperation, AwsEbsProvider,
    AwsEbsTransportError, AwsEbsVolumeScope, AwsEbsVolumeService, ConsentScope,
    DescribeVolumeStatusRequest, DescribeVolumeStatusResponse, DescribeVolumesRequest,
    DescribeVolumesResponse, EvidenceState, FixtureTransport, InstanceId, MissionId,
    MissionIdentity, PageCursor, PermissionSnapshot, ProjectId, ProjectIdentity,
    RecordingTransport, SecretReference, SnapshotId, TransportProvenance, VerificationFailure,
    VolumeMetadataInput, VolumeState, VolumeStatusInput, VolumeStatusState, VolumeType,
    WorkProductId, WorkProductIdentity, WorkloadRevision, filter_digest,
};

const NOW: i64 = 1_780_000_000;
const RAW_VOLUME_ID: &str = "vol-0123456789abcdef0";
const RAW_SNAPSHOT_ID: &str = "snap-0123456789abcdef0";
const RAW_INSTANCE_ID: &str = "i-0123456789abcdef0";
const RAW_SECRET_HANDLE: &str = "opaque/sigv4/ebs/secret-handle";

fn scope() -> AwsEbsVolumeScope {
    AwsEbsVolumeScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_ebs_volume_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        [hartevo_aws_ebs_volume_result_plugin::VolumeId::new(RAW_VOLUME_ID).expect("volume")],
        [SnapshotId::new(RAW_SNAPSHOT_ID).expect("snapshot")],
        [InstanceId::new(RAW_INSTANCE_ID).expect("instance")],
        WorkloadRevision::new("workload-revision-7").expect("workload revision"),
        MissionIdentity::new(MissionId::new("mission-649").expect("mission"), 7)
            .expect("mission identity"),
        ProjectIdentity::new(ProjectId::new("project-649").expect("project"), 11)
            .expect("project identity"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-649").expect("work product"),
            13,
        )
        .expect("work product identity"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-649", 1, NOW + 86_400).expect("consent")
}

fn secret(scope: &AwsEbsVolumeScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET_HANDLE, scope, 1).expect("secret")
}

fn volume(scope: &AwsEbsVolumeScope, observed_at: i64) -> VolumeMetadataInput {
    VolumeMetadataInput::new(
        scope.volume_allowlist()[0].clone(),
        Some(scope.snapshot_allowlist()[0].clone()),
        VolumeState::InUse,
        VolumeType::Gp3,
        100,
        true,
        false,
        observed_at - 86_400,
        vec![
            AttachmentObservation::new(
                scope.attachment_allowlist()[0].clone(),
                AttachmentState::Attached,
                Some(observed_at - 600),
                false,
            )
            .expect("attachment"),
        ],
        observed_at,
    )
    .expect("volume")
}

fn fixture_service() -> AwsEbsVolumeService<FixtureTransport> {
    let scope = scope();
    let provider = AwsEbsProvider::new(FixtureTransport::for_scope(&scope, NOW).expect("fixture"));
    AwsEbsVolumeService::new(scope.clone(), secret(&scope), consent(), provider, NOW)
        .expect("service")
}

#[test]
fn fixture_produces_digest_only_review_evidence_and_records_idempotently() {
    let mut service = fixture_service();
    let request = service.default_request(NOW).expect("request");
    let proposal = service.propose(request).expect("proposal");

    assert_eq!(proposal.state, EvidenceState::Completed);
    assert_eq!(proposal.volumes.len(), 1);
    assert_eq!(proposal.statuses.len(), 1);
    assert_eq!(proposal.snapshots.len(), 1);
    assert_eq!(proposal.fast_snapshot_restores.len(), 1);
    assert!(proposal.volumes[0].encrypted);
    assert_eq!(proposal.volumes[0].size_gib, 100);
    assert!(proposal.snapshots[0].encrypted);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.recoverability_claim);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(service.verify(&proposal).valid);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_VOLUME_ID,
        RAW_SNAPSHOT_ID,
        RAW_INSTANCE_ID,
        RAW_SECRET_HANDLE,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }

    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert!(mission_result.accepted_for_review);
    assert!(!mission_result.connected);
    let first = consumer
        .record(&proposal, "recording-key-649")
        .expect("record");
    let replay = consumer
        .record(&proposal, "recording-key-649")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn registration_and_cursor_serialization_expose_only_digests() {
    let service = fixture_service();
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let registration_debug = format!("{:?}", service.registration());
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(registration_json.contains("evidenceDigest"));
    assert!(!registration_json.contains(RAW_SECRET_HANDLE));
    assert!(!registration_debug.contains(RAW_SECRET_HANDLE));

    let scope = scope();
    let filter = filter_digest(AwsEbsOperation::DescribeVolumes, &scope);
    let cursor = PageCursor::new(
        "opaque-provider-next-token",
        AwsEbsOperation::DescribeVolumes,
        &scope,
        filter,
        2,
    )
    .expect("cursor");
    let cursor_json = serde_json::to_string(&cursor).expect("cursor JSON");
    let cursor_debug = format!("{cursor:?}");
    assert!(cursor_json.contains("tokenDigest"));
    assert!(!cursor_json.contains("opaque-provider-next-token"));
    assert!(!cursor_debug.contains("opaque-provider-next-token"));

    let request = DescribeVolumesRequest::for_scope(&scope, 10, Some(cursor.clone()), NOW)
        .expect("same-operation cursor");
    assert_eq!(request.cursor().expect("cursor").page_number(), 2);
    assert!(
        !serde_json::to_string(&request)
            .expect("request JSON")
            .contains("opaque-provider-next-token")
    );
    assert!(DescribeVolumeStatusRequest::for_scope(&scope, 10, Some(cursor), NOW).is_err());
}

#[test]
fn stale_status_is_non_adoptable_and_verification_fails_closed() {
    let scope = scope();
    let mut service = AwsEbsVolumeService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsEbsProvider::new(RecordingTransport::default()),
        NOW,
    )
    .expect("service");
    let request = service.default_request(NOW).expect("request");
    let volume = volume(&scope, NOW);
    let volume_response = DescribeVolumesResponse::new(
        &request.volumes,
        vec![volume.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("volume response");
    let stale_status = VolumeStatusInput::new(
        scope.volume_allowlist()[0].clone(),
        "us-east-1a",
        VolumeStatusState::Ok,
        vec![("io-enabled".to_owned(), "passed".to_owned())],
        Vec::new(),
        Vec::new(),
        NOW - hartevo_aws_ebs_volume_result_plugin::MAX_STATUS_AGE_SECONDS - 1,
        volume.resource_digest.clone(),
    )
    .expect("stale status");
    let status_response = DescribeVolumeStatusResponse::new(
        &request.volume_status,
        vec![stale_status],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("status response");
    service
        .provider_mut()
        .transport_mut()
        .push_volumes_response(Ok(volume_response));
    service
        .provider_mut()
        .transport_mut()
        .push_volume_status_response(Ok(status_response));

    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::StaleStatus);
    assert!(!service.verify(&proposal).valid);
    assert!(
        service
            .verify(&proposal)
            .failures
            .contains(&VerificationFailure::StaleStatus)
    );
    assert!(!proposal.can_be_adopted());
}

#[test]
fn blocked_environment_and_provider_statuses_never_claim_native_evidence() {
    let mut service = AwsEbsVolumeService::new(
        scope(),
        secret(&scope()),
        consent(),
        AwsEbsProvider::default(),
        NOW,
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(NOW).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!service.verify(&proposal).valid);

    let error = AwsEbsTransportError::RateLimited {
        retry_after_seconds: Some(3),
    };
    assert_eq!(error.status_code(), Some(429));
    assert!(error.to_string().contains("rate limited"));
}

#[test]
fn pagination_response_binds_cursor_to_operation_and_exact_allowlists() {
    let scope = scope();
    let request = DescribeVolumesRequest::for_scope(&scope, 10, None, NOW).expect("request");
    let response = DescribeVolumesResponse::new(
        &request,
        vec![volume(&scope, NOW)],
        Some("opaque-next-token".to_owned()),
        512,
        TransportProvenance::Loopback,
    )
    .expect("response");
    response.validate_against(&request).expect("response fence");
    let next_request = request
        .with_cursor(response.next_cursor.clone())
        .expect("next request");
    assert_eq!(next_request.cursor().expect("cursor").page_number(), 2);
    assert_eq!(
        next_request.fence().operation(),
        AwsEbsOperation::DescribeVolumes
    );
    assert!(
        !serde_json::to_string(&next_request)
            .expect("request JSON")
            .contains("opaque-next-token")
    );
    assert!(
        DescribeVolumeStatusRequest::for_scope(&scope, 10, response.next_cursor, NOW,).is_err()
    );
}

#[test]
fn permission_snapshot_is_exactly_read_only() {
    let permissions = PermissionSnapshot::for_layer_one(3);
    assert_eq!(permissions.permissions.len(), 5);
    assert!(
        permissions
            .permissions
            .iter()
            .all(|permission| permission.starts_with("ec2:Describe")
                || permission == "mission.scope")
    );
}
