use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_backup_recovery_result_plugin::{
    AwsAccountId, AwsBackupProvider, AwsBackupRecoveryProposal, AwsBackupRecoveryScope,
    AwsBackupTransportError, BackupPlanArn, BackupPlanIdentity, BackupVaultIdentity,
    BackupVaultName, ConsentScope, Cursor, Digest, EncryptionKeyType, EncryptionMetadata,
    FixtureTransport, LifecycleMetadata, ListRecoveryPointsRequest, ListRecoveryPointsResponse,
    LoopbackTransport, MissionIdentity, PermissionSnapshot, ProjectIdentity,
    RecordedAwsBackupResult, RecordingTransport, RecoveryEvidenceState, RecoveryPointArn,
    RecoveryPointFilter, RecoveryPointIdentity, RecoveryPointMetadata, RecoveryPointMetadataInput,
    RecoveryPointStatus, ResourceArn, ResourceIdentity, ResourceType, SecretReference,
    StorageClass, TransportProvenance, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_RESOURCE_ARN: &str = "arn:aws:rds:us-east-1:123456789012:db:production";
const RAW_RECOVERY_POINT_ARN: &str =
    "arn:aws:backup:us-east-1:123456789012:recovery-point:fixture-point";
const RAW_KMS_ARN: &str = "arn:aws:kms:us-east-1:123456789012:key/fixture-key";
const RAW_STATUS_MESSAGE: &str = "provider-private-status-message";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsBackupRecoveryScope {
    AwsBackupRecoveryScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_backup_recovery_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        BackupVaultIdentity::new(
            BackupVaultName::new("production-vault").expect("vault"),
            Some("arn:aws:backup:us-east-1:123456789012:backup-vault:production-vault"),
        )
        .expect("vault identity"),
        RecoveryPointIdentity::new(
            RecoveryPointArn::new(RAW_RECOVERY_POINT_ARN).expect("recovery point"),
        ),
        ResourceIdentity::new(
            ResourceArn::new(RAW_RESOURCE_ARN).expect("resource"),
            ResourceType::new("RDS").expect("resource type"),
            Some("production"),
        )
        .expect("resource identity"),
        BackupPlanIdentity::new(
            BackupPlanArn::new("arn:aws:backup:us-east-1:123456789012:backup-plan:plan-1")
                .expect("plan arn"),
            "plan-1",
            Some("v3"),
            "rule-1",
            Some("daily-production"),
        )
        .expect("plan identity"),
        MissionIdentity::new("mission-1", 7).expect("mission"),
        ProjectIdentity::new("project-1", 11).expect("project"),
        WorkProductIdentity::new("work-product-1", 13).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsBackupRecoveryScope) -> SecretReference {
    SecretReference::sigv4("opaque-sigv4-handle", scope, 1).expect("secret reference")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 4, now() + Duration::days(7)).expect("consent")
}

fn metadata(
    scope: &AwsBackupRecoveryScope,
    status: RecoveryPointStatus,
    observed_at: DateTime<Utc>,
) -> RecoveryPointMetadata {
    RecoveryPointMetadata::new(scope, metadata_input(status, observed_at)).expect("metadata")
}

fn metadata_input(
    status: RecoveryPointStatus,
    observed_at: DateTime<Utc>,
) -> RecoveryPointMetadataInput {
    let expired = matches!(status, RecoveryPointStatus::Expired);
    let completed = matches!(
        status,
        RecoveryPointStatus::Completed | RecoveryPointStatus::Available
    );
    RecoveryPointMetadataInput {
        status,
        creation_date: observed_at - Duration::hours(2),
        initiation_date: Some(observed_at - Duration::hours(3)),
        completion_date: completed.then_some(observed_at - Duration::hours(1)),
        lifecycle: LifecycleMetadata::new(
            (!expired).then_some(observed_at + Duration::days(2)),
            Some(if expired {
                observed_at - Duration::hours(1)
            } else {
                observed_at + Duration::days(30)
            }),
            Some(2),
            Some(30),
            None,
            false,
        )
        .expect("lifecycle"),
        size_bytes: 4_096,
        encryption: EncryptionMetadata::new(
            true,
            EncryptionKeyType::CustomerManagedKmsKey,
            Some(RAW_KMS_ARN),
        )
        .expect("encryption"),
        storage_class: if expired {
            StorageClass::Deleted
        } else {
            StorageClass::Warm
        },
        status_message: Some(RAW_STATUS_MESSAGE.to_owned()),
        parent_recovery_point_arn: None,
    }
}

fn recording_service(
    status: RecoveryPointStatus,
) -> hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService<RecordingTransport> {
    let scope = scope();
    let filter = RecoveryPointFilter::for_scope(&scope, 10, None, None).expect("filter");
    let list_request = ListRecoveryPointsRequest::new(&scope, filter, None).expect("list request");
    let describe_request =
        hartevo_aws_backup_recovery_result_plugin::DescribeRecoveryPointRequest::for_scope(&scope)
            .expect("describe request");
    let point = metadata(&scope, status, now());
    let list_response = ListRecoveryPointsResponse::new(
        &list_request,
        vec![point.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let describe_response =
        hartevo_aws_backup_recovery_result_plugin::DescribeRecoveryPointResponse::new(
            &describe_request,
            point,
            512,
            TransportProvenance::Recording,
        )
        .expect("describe response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_describe_response(Ok(describe_response));
    let provider = AwsBackupProvider::new(transport).expect("provider");
    hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service")
}

fn list_error_service(
    error: AwsBackupTransportError,
) -> hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService<RecordingTransport> {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Err(error));
    let provider = AwsBackupProvider::new(transport).expect("provider");
    hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service")
}

#[test]
fn contract_scope_registration_and_endpoint_seams_are_digest_fenced() {
    let scope = scope();
    let filter = RecoveryPointFilter::for_scope(&scope, 10, None, None).expect("filter");
    let cursor = Cursor::new("opaque-next-token", &scope, &filter, 2).expect("cursor");
    let request = ListRecoveryPointsRequest::new(&scope, filter.clone(), Some(cursor.clone()))
        .expect("request");
    assert!(
        request
            .path_and_query()
            .contains("/backup-vaults/production-vault/recovery-points/")
    );
    assert!(request.path_and_query().contains("nextToken="));
    assert!(!request.path_and_query().contains("opaque-next-token"));
    assert_eq!(request.filter().digest(), filter.digest());
    assert_eq!(
        request.cursor().expect("cursor").filter_digest(),
        &filter.digest()
    );

    let service = hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsBackupProvider::default(),
        now(),
    )
    .expect("service");
    assert!(service.registration().validate().is_ok());
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("opaque-sigv4-handle"));
    assert!(!debug.contains("opaque-sigv4-handle"));
    assert_eq!(service.describe_capabilities().operations.len(), 2);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn fixture_complete_result_is_metadata_only_and_non_native() {
    let scope = scope();
    let provider = AwsBackupProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let mut service = hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
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
    assert_eq!(proposal.state, RecoveryEvidenceState::Completed);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.recovery_point.is_some());
    assert_eq!(
        proposal.recovery_point.as_ref().expect("point").size_bytes,
        4_096
    );
    assert!(
        proposal
            .recovery_point
            .as_ref()
            .expect("point")
            .encryption
            .encryption_key_reference_digest
            .is_some()
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.recoverability_claim);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{:?}", proposal.recovery_point);
    for secret in [
        RAW_RESOURCE_ARN,
        RAW_RECOVERY_POINT_ARN,
        RAW_KMS_ARN,
        RAW_STATUS_MESSAGE,
    ] {
        assert!(
            !serialized.contains(secret),
            "raw value leaked in JSON: {secret}"
        );
        assert!(
            !debug.contains(secret),
            "raw value leaked in Debug: {secret}"
        );
    }

    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);
    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(mission_result.state, RecoveryEvidenceState::Completed);
    assert!(!mission_result.can_be_adopted());
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn list_pages_allow_other_recovery_points_but_describe_stays_exact() {
    let scope = scope();
    let filter = RecoveryPointFilter::for_scope(&scope, 10, None, None).expect("filter");
    let request = ListRecoveryPointsRequest::new(&scope, filter, None).expect("request");
    let alternate = RecoveryPointMetadata::for_recovery_point(
        &scope,
        RecoveryPointIdentity::new(
            RecoveryPointArn::new("arn:aws:backup:us-east-1:123456789012:recovery-point:other")
                .expect("alternate recovery point"),
        ),
        metadata_input(RecoveryPointStatus::Completed, now()),
    )
    .expect("alternate metadata");
    let target = metadata(&scope, RecoveryPointStatus::Completed, now());
    let response = ListRecoveryPointsResponse::new(
        &request,
        vec![alternate, target],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    response
        .validate_integrity(&request)
        .expect("list integrity");
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let mut fixture_service =
        hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsBackupProvider::new(FixtureTransport::for_scope(&scope, now())).expect("fixture"),
            now(),
        )
        .expect("fixture service");
    let fixture = fixture_service
        .propose(fixture_service.default_request(now()).expect("request"))
        .expect("fixture proposal");
    assert_eq!(fixture.provenance, TransportProvenance::Fixture);
    assert!(!fixture.connected);
    assert!(!fixture.native);

    let mut loopback_service =
        hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsBackupProvider::new(LoopbackTransport::for_scope(&scope, now())).expect("loopback"),
            now(),
        )
        .expect("loopback service");
    let loopback = loopback_service
        .propose(loopback_service.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback.provenance, TransportProvenance::Loopback);
    assert!(!loopback.connected);
    assert!(!loopback.native);

    let mut blocked_service =
        hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
            scope.clone(),
            secret(&scope),
            consent(),
            AwsBackupProvider::default(),
            now(),
        )
        .expect("blocked service");
    let blocked = blocked_service
        .propose(blocked_service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(blocked.state, RecoveryEvidenceState::ProviderUnknown);
    assert_eq!(blocked.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!blocked.connected);
    assert!(!blocked.native);
}

#[test]
fn lifecycle_completion_expiry_and_deletion_states_are_distinct() {
    let cases = [
        (
            RecoveryPointStatus::Creating,
            RecoveryEvidenceState::InProgress,
        ),
        (
            RecoveryPointStatus::Completed,
            RecoveryEvidenceState::Completed,
        ),
        (
            RecoveryPointStatus::Available,
            RecoveryEvidenceState::Completed,
        ),
        (RecoveryPointStatus::Partial, RecoveryEvidenceState::Partial),
        (RecoveryPointStatus::Expired, RecoveryEvidenceState::Expired),
        (
            RecoveryPointStatus::Deleting,
            RecoveryEvidenceState::Deleting,
        ),
        (RecoveryPointStatus::Stopped, RecoveryEvidenceState::Stopped),
    ];
    for (status, expected) in cases {
        let mut service = recording_service(status);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, expected, "status {status:?}");
        assert!(proposal.recovery_point.is_some());
        assert!(!proposal.recoverability_claim);
    }
}

#[test]
fn cursor_filter_binding_and_bounded_partial_pages_fail_closed() {
    let scope = scope();
    let filter = RecoveryPointFilter::for_scope(&scope, 1, None, None).expect("filter");
    let other_filter =
        RecoveryPointFilter::for_scope(&scope, 1, Some(now() - Duration::days(1)), None)
            .expect("other filter");
    let cursor = Cursor::new("page-token", &scope, &filter, 2).expect("cursor");
    assert!(ListRecoveryPointsRequest::new(&scope, other_filter, Some(cursor)).is_err());

    let list_request = ListRecoveryPointsRequest::new(&scope, filter.clone(), None).expect("list");
    let point = metadata(&scope, RecoveryPointStatus::Completed, now());
    let next_cursor = Cursor::new("page-token", &scope, &filter, 2).expect("next cursor");
    let first_page = ListRecoveryPointsResponse::new(
        &list_request,
        vec![point.clone()],
        Some(next_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let describe_request =
        hartevo_aws_backup_recovery_result_plugin::DescribeRecoveryPointRequest::for_scope(&scope)
            .expect("describe");
    let describe = hartevo_aws_backup_recovery_result_plugin::DescribeRecoveryPointResponse::new(
        &describe_request,
        point,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    let mut recording = RecordingTransport::default();
    recording.push_list_response(Ok(first_page));
    recording.push_describe_response(Ok(describe));
    let mut service = hartevo_aws_backup_recovery_result_plugin::AwsBackupRecoveryService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        AwsBackupProvider::new(recording).expect("provider"),
        now(),
    )
    .expect("service");
    let request = service.request(filter, 1, now()).expect("bounded request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, RecoveryEvidenceState::Partial);
    assert!(!proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.evidence.cursor_digest.is_some());
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn transport_statuses_map_to_explicit_non_adoptable_evidence() {
    let cases = [
        (
            AwsBackupTransportError::BadRequest,
            RecoveryEvidenceState::ProviderUnknown,
            Some(400),
        ),
        (
            AwsBackupTransportError::Unauthorized,
            RecoveryEvidenceState::AccessLoss,
            Some(401),
        ),
        (
            AwsBackupTransportError::Forbidden,
            RecoveryEvidenceState::AccessLoss,
            Some(403),
        ),
        (
            AwsBackupTransportError::NotFound,
            RecoveryEvidenceState::NotFound,
            Some(404),
        ),
        (
            AwsBackupTransportError::Conflict,
            RecoveryEvidenceState::ProviderUnknown,
            Some(409),
        ),
        (
            AwsBackupTransportError::RateLimited {
                retry_after_seconds: Some(10),
            },
            RecoveryEvidenceState::Throttled,
            Some(429),
        ),
        (
            AwsBackupTransportError::ServerError { status: 500 },
            RecoveryEvidenceState::ProviderUnknown,
            Some(500),
        ),
        (
            AwsBackupTransportError::Timeout,
            RecoveryEvidenceState::ProviderUnknown,
            None,
        ),
        (
            AwsBackupTransportError::AccessLost,
            RecoveryEvidenceState::AccessLoss,
            None,
        ),
    ];
    for (error, expected, status_code) in cases {
        let mut service = list_error_service(error);
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
    }
}

#[test]
fn tamper_truncation_replacement_and_revocation_are_rejected() {
    let scope = scope();
    let filter = RecoveryPointFilter::for_scope(&scope, 1, None, None).expect("filter");
    let request = ListRecoveryPointsRequest::new(&scope, filter, None).expect("list request");
    let point = metadata(&scope, RecoveryPointStatus::Completed, now());
    let tampered = ListRecoveryPointsResponse::new(
        &request,
        vec![point],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    assert!(tampered.validate_integrity(&request).is_err());
    assert!(
        ListRecoveryPointsResponse::new(
            &request,
            vec![],
            None,
            hartevo_aws_backup_recovery_result_plugin::MAX_RESPONSE_BYTES + 1,
            TransportProvenance::Recording,
        )
        .is_err()
    );

    let mut service = recording_service(RecoveryPointStatus::Completed);
    let mut proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    proposal.list_complete = false;
    assert!(proposal.validate_integrity().is_err());

    let mut service = recording_service(RecoveryPointStatus::Completed);
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
}

#[test]
fn registration_and_recording_reject_scope_or_digest_conflicts() {
    let scope = scope();
    let mut service = recording_service(RecoveryPointStatus::Completed);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    assert!(consumer.record(&proposal, "key").is_ok());
    let mut tampered = proposal.clone();
    tampered.scope_digest = scope.project().digest();
    assert!(consumer.record(&tampered, "key-2").is_err());
    assert!(consumer.record(&proposal, "key").is_ok());
    assert!(consumer.record(&proposal, "").is_err());
}

#[test]
fn fixture_metadata_does_not_expose_raw_encryption_or_provider_text() {
    let scope = scope();
    let point = metadata(&scope, RecoveryPointStatus::Completed, now());
    let debug = format!("{point:?}");
    let serialized = serde_json::to_string(&point).expect("metadata JSON");
    for raw in [
        RAW_RESOURCE_ARN,
        RAW_RECOVERY_POINT_ARN,
        RAW_KMS_ARN,
        RAW_STATUS_MESSAGE,
    ] {
        assert!(!debug.contains(raw));
        assert!(!serialized.contains(raw));
    }
    assert!(serialized.contains("encryptionKeyReferenceDigest"));
    assert!(!serialized.contains("encryptionKeyArn"));
}

#[test]
fn provider_definition_is_version_and_permission_digest_bound() {
    let provider = AwsBackupProvider::default();
    provider
        .definition()
        .validate()
        .expect("provider definition");
    let permissions = PermissionSnapshot::for_layer_one(3);
    assert!(
        permissions
            .permissions
            .contains("backup:DescribeRecoveryPoint")
    );
    assert!(
        !permissions
            .permissions
            .iter()
            .any(|permission| permission.contains("write"))
    );
    assert_ne!(
        provider.definition().provider_digest,
        Digest::from_text("native")
    );
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
}

#[test]
fn no_mutation_surface_is_present_in_capabilities() {
    let service = recording_service(RecoveryPointStatus::Completed);
    let capability = service.describe_capabilities();
    let operations = capability.operations.join(" ").to_ascii_lowercase();
    assert!(!operations.contains("restore"));
    assert!(!operations.contains("delete"));
    assert!(!operations.contains("create"));
    assert!(capability.read_only);
    assert!(!capability.outcome_adoption);
}

#[allow(dead_code)]
fn assert_result_type(_: RecordedAwsBackupResult) {}

#[allow(dead_code)]
fn assert_proposal_type(_: AwsBackupRecoveryProposal) {}
