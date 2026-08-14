use chrono::{DateTime, Utc};
use hartevo_mongodb_atlas_backup_result_plugin::{
    AdoptionAvailability, AtlasCapability, CapabilitySet, ClusterMetadata, ClusterName, ConsentId,
    ConsentScope, Digest, EffectAuthority, EffectError, EffectKind, FixtureTransport,
    GetClusterMetadataRequest, GetProcessMeasurementsRequest, Layer1EffectBoundary,
    Layer1ReadBackBoundary, ListBackupSnapshotsRequest, LoopbackTransport, MeasurementGranularity,
    MeasurementPoint, MeasurementSeries, MeasurementWindow, Mission, MissionConsumerError,
    MissionId, MissionMongoDbAtlasConsumer, MissionResultState, ModelError,
    MongoDbAtlasBackupResultService, MongoDbAtlasBackupResultServiceError, MongoDbAtlasProvider,
    MongoDbAtlasScope, OrganizationId, ProcessId, ProjectId, ProviderMode, ReadBackError,
    ReadinessState, ReceiptReadBack, RecoveryEffectRequest, RecoveryReadinessRequest,
    RestoreVerification, RetryPolicy, Revision, SecretReference, Snapshot, SnapshotStatus,
    TransportError,
};

fn time(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn fixture_scope() -> MongoDbAtlasScope {
    let consent = ConsentScope::new(
        ConsentId::new("consent-1").expect("consent"),
        Revision::new(3).expect("consent revision"),
        CapabilitySet::read_only(),
        time("2026-12-31T00:00:00Z"),
    )
    .expect("consent");
    MongoDbAtlasScope::new(
        OrganizationId::new("aaaaaaaaaaaaaaaaaaaaaaaa").expect("organization"),
        ProjectId::new("bbbbbbbbbbbbbbbbbbbbbbbb").expect("project"),
        ClusterName::new("production-cluster").expect("cluster"),
        ProcessId::new("db.example.test:27017").expect("process"),
        Mission::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(7).expect("mission revision"),
        ),
        Revision::new(11).expect("project revision"),
        consent,
    )
    .expect("scope")
}

fn window() -> MeasurementWindow {
    MeasurementWindow::new(
        time("2026-08-14T00:00:00Z"),
        time("2026-08-14T01:00:00Z"),
        MeasurementGranularity::Pt5m,
    )
    .expect("window")
}

fn snapshot(
    scope: &MongoDbAtlasScope,
    status: SnapshotStatus,
) -> hartevo_mongodb_atlas_backup_result_plugin::BackupSnapshotPage {
    let request = ListBackupSnapshotsRequest::new(scope, 1, 10).expect("snapshot request");
    let value = Snapshot::new(
        "snapshot-1",
        status,
        time("2026-08-14T00:00:00Z"),
        Some(time("2026-08-21T00:00:00Z")),
        "onDemand",
        Some(128),
    )
    .expect("snapshot");
    hartevo_mongodb_atlas_backup_result_plugin::BackupSnapshotPage::new(
        &request,
        vec![value],
        1,
        false,
    )
}

fn healthy_responses(
    scope: &MongoDbAtlasScope,
    measurement_complete: bool,
    snapshot_status: Option<SnapshotStatus>,
) -> hartevo_mongodb_atlas_backup_result_plugin::RecordingTransport {
    let snapshot_request = ListBackupSnapshotsRequest::new(scope, 1, 10).expect("snapshot request");
    let measurement_request =
        GetProcessMeasurementsRequest::new(scope, window()).expect("measurement request");
    let cluster_request = GetClusterMetadataRequest::new(scope).expect("cluster request");
    let points = vec![
        MeasurementPoint::new(time("2026-08-14T00:00:00Z"), 10.0).expect("point"),
        MeasurementPoint::new(time("2026-08-14T01:00:00Z"), 11.0).expect("point"),
    ];
    let series = MeasurementSeries::new("NORMALIZED_CPU_USER", "PERCENT", points).expect("series");
    let metadata = ClusterMetadata::new(
        scope.project_id().clone(),
        scope.cluster_name().clone(),
        true,
        true,
        false,
        Some("8.0.0".to_owned()),
        Some("REPLICASET".to_owned()),
    );
    let mut transport = hartevo_mongodb_atlas_backup_result_plugin::RecordingTransport::default();
    let snapshots = snapshot_status
        .map(|status| snapshot(scope, status).snapshots().to_vec())
        .unwrap_or_default();
    transport.push_snapshot_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::BackupSnapshotPage::new(
            &snapshot_request,
            snapshots,
            1,
            false,
        ),
    ));
    transport.push_measurement_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::ProcessMeasurementsResponse::new(
            &measurement_request,
            vec![series],
            measurement_complete,
        ),
    ));
    transport.push_cluster_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::ClusterMetadataResponse::new(
            &cluster_request,
            metadata,
        ),
    ));
    transport
}

fn service_with<T: hartevo_mongodb_atlas_backup_result_plugin::MongoDbAtlasTransport>(
    scope: &MongoDbAtlasScope,
    transport: T,
    mode: ProviderMode,
) -> MongoDbAtlasBackupResultService<T> {
    let secret = SecretReference::new(
        "atlas-secret-reference",
        scope,
        Revision::new(2).expect("secret revision"),
    )
    .expect("secret");
    let provider = MongoDbAtlasProvider::new(transport, "2.0.0", mode).expect("provider");
    MongoDbAtlasBackupResultService::new(scope.clone(), secret, provider, RetryPolicy::default())
        .expect("service")
}

fn request<T: hartevo_mongodb_atlas_backup_result_plugin::MongoDbAtlasTransport>(
    service: &MongoDbAtlasBackupResultService<T>,
    scope: &MongoDbAtlasScope,
) -> RecoveryReadinessRequest {
    RecoveryReadinessRequest::new(
        scope,
        window(),
        service.provider().definition().provider_digest.clone(),
        time("2026-08-14T02:00:00Z"),
    )
    .expect("proposal request")
}

#[test]
fn recording_complete_result_is_digest_fenced_redacted_and_not_restore_success() {
    let scope = fixture_scope();
    let mut service = service_with(
        &scope,
        healthy_responses(&scope, true, Some(SnapshotStatus::Completed)),
        ProviderMode::Recording,
    );
    let secret_debug = format!(
        "{:?}",
        SecretReference::new(
            "atlas-secret-reference",
            &scope,
            Revision::new(2).expect("revision")
        )
        .expect("secret")
    );
    let proposal = service
        .propose(request(&service, &scope))
        .expect("proposal");
    assert_eq!(proposal.state, ReadinessState::Completed);
    assert_eq!(proposal.evidence.snapshots.snapshots.len(), 1);
    assert_eq!(proposal.mode, ProviderMode::Recording);
    assert!(!proposal.authority.connected());
    assert!(!proposal.authority.native_provider());
    assert!(!proposal.authority.restore_authority());
    assert!(!proposal.authority.truth_authority());
    assert!(!proposal.is_restore_success);
    assert_eq!(
        proposal.restore_verification,
        RestoreVerification::NotPerformedLayer1
    );
    assert_eq!(proposal.adoption, AdoptionAvailability::NotAdoptedLayer1);
    assert!(
        proposal
            .receipts
            .iter()
            .all(|receipt| receipt.redacted && !receipt.native)
    );
    assert!(!format!("{proposal:?}").contains("db.example.test"));
    assert!(!secret_debug.contains("atlas-secret-reference"));

    let consumer =
        MissionMongoDbAtlasConsumer::new(scope.clone(), service.registration()).expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.state, MissionResultState::PendingDecision);
    assert_eq!(
        result.restore_verification,
        RestoreVerification::NotPerformedLayer1
    );
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer1);
}

#[test]
fn rate_limit_retry_is_bounded_and_recorded_without_sleeping_or_native_claims() {
    let scope = fixture_scope();
    let mut transport = healthy_responses(&scope, true, Some(SnapshotStatus::Completed));
    transport.push_snapshot_response_front(Err(TransportError::RateLimited {
        retry_after_seconds: Some(1),
        limit: Some(10),
        remaining: Some(0),
    }));
    let secret = SecretReference::new(
        "atlas-secret-reference",
        &scope,
        Revision::new(2).expect("revision"),
    )
    .expect("secret");
    let provider =
        MongoDbAtlasProvider::new(transport, "2.0.0", ProviderMode::Recording).expect("provider");
    let mut service = MongoDbAtlasBackupResultService::new(
        scope.clone(),
        secret,
        provider,
        RetryPolicy::new(2, 60),
    )
    .expect("service");
    let proposal = service
        .propose(request(&service, &scope))
        .expect("proposal");
    assert_eq!(proposal.state, ReadinessState::Completed);
    assert_eq!(proposal.retry_evidence[0].attempts, 2);
    assert_eq!(proposal.retry_evidence[0].rate_limit_retries, 1);
}

#[test]
fn fixture_and_loopback_are_explicitly_non_native() {
    let scope = fixture_scope();
    let fixture = FixtureTransport::healthy(&scope, &window()).expect("fixture");
    let mut fixture_service = service_with(&scope, fixture, ProviderMode::Fixture);
    let fixture_proposal = fixture_service
        .propose(request(&fixture_service, &scope))
        .expect("fixture proposal");
    assert_eq!(fixture_proposal.mode, ProviderMode::Fixture);
    assert!(!fixture_proposal.authority.connected());
    assert!(!fixture_proposal.authority.native_provider());

    let loopback = LoopbackTransport::deterministic(&scope, &window()).expect("loopback");
    let mut loopback_service = service_with(&scope, loopback, ProviderMode::Loopback);
    let loopback_proposal = loopback_service
        .propose(request(&loopback_service, &scope))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.mode, ProviderMode::Loopback);
    assert!(!loopback_proposal.authority.connected());
    assert!(!loopback_proposal.authority.native_provider());
}

#[test]
fn blocked_env_is_provider_unknown_and_never_connected() {
    let scope = fixture_scope();
    let mut service = MongoDbAtlasBackupResultService::new(
        scope.clone(),
        SecretReference::new(
            "atlas-secret-reference",
            &scope,
            Revision::new(2).expect("revision"),
        )
        .expect("secret"),
        MongoDbAtlasProvider::default(),
        RetryPolicy::default(),
    )
    .expect("service");
    let proposal = service
        .propose(request(&service, &scope))
        .expect("blocked proposal");
    assert_eq!(proposal.state, ReadinessState::ProviderUnknown);
    assert_eq!(proposal.mode, ProviderMode::BlockedEnv);
    assert!(
        proposal
            .receipts
            .iter()
            .any(|receipt| receipt.status == "BLOCKED_ENV")
    );
    assert!(!proposal.authority.connected());
    assert!(!proposal.authority.native_provider());
    assert!(!proposal.authority.durable_receipt());
}

#[test]
fn all_snapshot_and_evidence_states_remain_distinct() {
    let cases = [
        (SnapshotStatus::Queued, ReadinessState::Queued),
        (SnapshotStatus::InProgress, ReadinessState::InProgress),
        (SnapshotStatus::Completed, ReadinessState::Completed),
        (SnapshotStatus::Expired, ReadinessState::Expired),
        (SnapshotStatus::Failed, ReadinessState::Failed),
    ];
    for (status, expected) in cases {
        let scope = fixture_scope();
        let mut service = service_with(
            &scope,
            healthy_responses(&scope, true, Some(status)),
            ProviderMode::Recording,
        );
        let proposal = service
            .propose(request(&service, &scope))
            .expect("proposal");
        assert_eq!(proposal.state, expected);
    }

    let scope = fixture_scope();
    let mut partial_service = service_with(
        &scope,
        healthy_responses(&scope, false, Some(SnapshotStatus::Completed)),
        ProviderMode::Recording,
    );
    assert_eq!(
        partial_service
            .propose(request(&partial_service, &scope))
            .expect("partial proposal")
            .state,
        ReadinessState::Partial
    );

    let scope = fixture_scope();
    let gap_transport = healthy_responses(&scope, true, None);
    let mut gap_service = service_with(&scope, gap_transport, ProviderMode::Recording);
    assert_eq!(
        gap_service
            .propose(request(&gap_service, &scope))
            .expect("gap proposal")
            .state,
        ReadinessState::RetentionGap
    );

    let scope = fixture_scope();
    let mut access_transport =
        hartevo_mongodb_atlas_backup_result_plugin::RecordingTransport::default();
    access_transport.push_snapshot_response(Err(TransportError::AccessLost));
    let mut access_service = service_with(&scope, access_transport, ProviderMode::Recording);
    assert_eq!(
        access_service
            .propose(request(&access_service, &scope))
            .expect("access-loss proposal")
            .state,
        ReadinessState::AccessLoss
    );
}

#[test]
fn stale_and_tampered_fences_fail_closed() {
    let scope = fixture_scope();
    let mut service = service_with(
        &scope,
        healthy_responses(&scope, true, Some(SnapshotStatus::Completed)),
        ProviderMode::Recording,
    );
    let stale = request(&service, &scope).with_revision_fences(
        Revision::new(8).expect("revision"),
        scope.project_revision(),
    );
    assert_eq!(
        service.propose(stale).expect_err("stale Mission revision"),
        MongoDbAtlasBackupResultServiceError::MissionRevisionMismatch
    );

    let scope = fixture_scope();
    let snapshot_request = ListBackupSnapshotsRequest::new(&scope, 1, 10).expect("request");
    let measurement_request =
        GetProcessMeasurementsRequest::new(&scope, window()).expect("request");
    let cluster_request = GetClusterMetadataRequest::new(&scope).expect("request");
    let mut transport = hartevo_mongodb_atlas_backup_result_plugin::RecordingTransport::default();
    transport.push_snapshot_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::BackupSnapshotPage::with_declared_digest(
            &snapshot_request,
            snapshot(&scope, SnapshotStatus::Completed)
                .snapshots()
                .to_vec(),
            1,
            false,
            Digest::from_text("tampered"),
        ),
    ));
    let series = MeasurementSeries::new(
        "NORMALIZED_CPU_USER",
        "PERCENT",
        vec![MeasurementPoint::new(time("2026-08-14T00:00:00Z"), 1.0).expect("point")],
    )
    .expect("series");
    transport.push_measurement_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::ProcessMeasurementsResponse::new(
            &measurement_request,
            vec![series],
            true,
        ),
    ));
    transport.push_cluster_response(Ok(
        hartevo_mongodb_atlas_backup_result_plugin::ClusterMetadataResponse::new(
            &cluster_request,
            ClusterMetadata::new(
                scope.project_id().clone(),
                scope.cluster_name().clone(),
                true,
                true,
                false,
                Some("8.0.0".to_owned()),
                Some("REPLICASET".to_owned()),
            ),
        ),
    ));
    let mut service = service_with(&scope, transport, ProviderMode::Recording);
    assert_eq!(
        service
            .propose(request(&service, &scope))
            .expect_err("tampered evidence")
            .to_string(),
        "provider response digest does not match its immutable fields"
    );
}

#[test]
fn registration_is_reversible_and_effect_read_back_are_layer_two_seams() {
    let scope = fixture_scope();
    let mut service = service_with(
        &scope,
        healthy_responses(&scope, true, Some(SnapshotStatus::Completed)),
        ProviderMode::Recording,
    );
    let proposal = service
        .propose(request(&service, &scope))
        .expect("proposal");
    let mut consumer =
        MissionMongoDbAtlasConsumer::new(scope.clone(), service.registration()).expect("consumer");
    consumer.revoke().expect("consumer revoke");
    assert!(matches!(
        consumer.consume(proposal.clone()),
        Err(MissionConsumerError::Revoked)
    ));
    service.revoke().expect("service revoke");
    assert!(!service.is_active());
    assert!(matches!(
        service.propose(request(&service, &scope)),
        Err(MongoDbAtlasBackupResultServiceError::Revoked)
    ));

    let effect = RecoveryEffectRequest {
        kind: EffectKind::RestoreCluster,
        scope_digest: scope.digest().clone(),
        consent_digest: scope.consent().digest().clone(),
        proposal_digest: proposal.proposal_digest.clone(),
    };
    assert_eq!(
        Layer1EffectBoundary.submit(&effect),
        Err(EffectError::Layer2Required)
    );
    let receipt = proposal.receipts.first().expect("receipt");
    assert_eq!(
        Layer1ReadBackBoundary.read_back(receipt),
        Err(ReadBackError::Layer2Required)
    );
}

#[test]
fn request_bounds_and_process_receipts_redact_sensitive_identity() {
    let scope = fixture_scope();
    assert!(matches!(
        ListBackupSnapshotsRequest::new(&scope, 9, 10),
        Err(ModelError::InvalidSnapshotBounds)
    ));
    assert!(matches!(
        ListBackupSnapshotsRequest::new(&scope, 1, 101),
        Err(ModelError::InvalidSnapshotPageSize)
    ));
    let request = GetProcessMeasurementsRequest::new(&scope, window()).expect("request");
    assert!(!request.redacted_path().contains("db.example.test"));
    assert!(!format!("{request:?}").contains("db.example.test"));
    assert_eq!(request.process_digest(), scope.process_id().digest());
}

#[test]
fn provider_capability_and_scope_digests_are_stable() {
    let scope = fixture_scope();
    let service = service_with(
        &scope,
        healthy_responses(&scope, true, Some(SnapshotStatus::Completed)),
        ProviderMode::Recording,
    );
    assert!(
        service
            .provider()
            .definition()
            .supports(AtlasCapability::BackupSnapshotRead)
    );
    assert!(
        service
            .provider()
            .definition()
            .supports(AtlasCapability::ProcessMeasurementRead)
    );
    assert!(
        service
            .provider()
            .definition()
            .supports(AtlasCapability::ClusterMetadataRead)
    );
    assert!(!service.provider().definition().native);
    assert!(!service.provider().definition().connected);
    assert_eq!(service.registration().scope_digest, *scope.digest());
    assert_eq!(
        service.registration().consent_digest,
        *scope.consent().digest()
    );
}
