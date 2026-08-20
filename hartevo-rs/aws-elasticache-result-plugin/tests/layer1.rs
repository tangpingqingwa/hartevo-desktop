use chrono::{DateTime, Duration, Utc};
use hartevo_aws_elasticache_result_plugin::{
    AwsAccountId, AwsElastiCacheError, AwsElastiCacheOperation, AwsElastiCacheProposal,
    AwsElastiCacheProvider, AwsElastiCacheScope, AwsElastiCacheService,
    AwsElastiCacheTransportError, CacheClusterId, CacheClusterMetadata, CacheEngine,
    DescribeCacheClustersRequest, DescribeCacheClustersResponse, DescribeEventsRequest,
    DescribeEventsResponse, Digest, ElastiCacheResource, EventSeverity, EventWindow, EvidenceState,
    FailoverPosture, FixtureTransport, HealthState, LAYER1_PERMISSIONS,
    MissionAwsElastiCacheConsumer, MissionAwsElastiCacheDecisionState, MissionBinding,
    NodeGroupBinding, NodeGroupId, OpaqueMarker, PermissionSnapshot, ProjectBinding, ProjectId,
    RecordingTransport, ReplicationGroupId, Revision, SecretReference, ServiceUpdateMetadata,
    ServiceUpdateStatus, TransportProvenance, UpdatePosture, WorkProductBinding, WorkProductId,
    transport_error_for_status,
};

fn now() -> DateTime<Utc> {
    Utc::now()
}

fn scope(resource: ElastiCacheResource) -> AwsElastiCacheScope {
    AwsElastiCacheScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_elasticache_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        resource,
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(2).expect("revision"),
        )
        .expect("project"),
        MissionBinding::new(
            hartevo_aws_elasticache_result_plugin::MissionId::new("mission-1").expect("mission"),
            Revision::new(3).expect("revision"),
        )
        .expect("mission"),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(4).expect("revision"),
        )
        .expect("work product"),
    )
    .expect("scope")
}

fn cluster_scope() -> AwsElastiCacheScope {
    scope(ElastiCacheResource::cache_cluster(
        CacheClusterId::new("cache-cluster-1").expect("cluster"),
        Revision::new(7).expect("resource revision"),
    ))
}

fn group_scope() -> AwsElastiCacheScope {
    scope(ElastiCacheResource::replication_group(
        ReplicationGroupId::new("replication-group-1").expect("group"),
        Revision::new(8).expect("resource revision"),
    ))
}

fn service_with_fixture(
    scope: AwsElastiCacheScope,
    observed_at: DateTime<Utc>,
) -> AwsElastiCacheService<FixtureTransport> {
    let secret = SecretReference::for_scope("sigv4-keyring-reference", &scope).expect("secret");
    let provider = AwsElastiCacheProvider::new(FixtureTransport::for_scope(&scope, observed_at))
        .expect("provider");
    AwsElastiCacheService::new(scope, secret, provider).expect("service")
}

#[test]
fn contract_scope_registration_and_opaque_secret_are_bound() {
    assert_eq!(LAYER1_PERMISSIONS.len(), 5);
    let scope = cluster_scope();
    let secret = SecretReference::new("raw-secret-handle-must-not-escape", &scope).expect("secret");
    assert_eq!(
        serde_json::to_string(&secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("raw-secret-handle"));
    let service = service_with_fixture(scope.clone(), now());
    assert!(service.is_active());
    assert_eq!(service.registration().scope_digest(), &scope.digest());
    assert_eq!(
        service.registration().api_revision(),
        hartevo_aws_elasticache_result_plugin::API_REVISION
    );
    assert_ne!(service.registration().evidence_digest(), &Digest::zero());
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().first_party);
}

#[test]
fn fixture_cluster_proposal_is_honest_and_mission_only() {
    let observed_at = now();
    let scope = cluster_scope();
    let mut service = service_with_fixture(scope.clone(), observed_at);
    let request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        20,
        2,
        true,
        true,
        observed_at,
    )
    .expect("read request");
    let proposal = service.propose(&request, observed_at).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Healthy);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.certification_claim);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
    assert!(proposal.evidence.cluster.is_some());
    assert!(
        proposal
            .evidence
            .cluster
            .as_ref()
            .expect("cluster")
            .status_digest
            .is_some()
    );

    let consumer =
        MissionAwsElastiCacheConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        result.decision_state,
        MissionAwsElastiCacheDecisionState::Healthy
    );
    assert!(result.review_only);
    assert!(result.requires_human_review);
    assert!(!result.certification_claim);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    assert!(!result.can_be_adopted());

    let recorded = service.record(&proposal, "record-key").expect("record");
    assert!(!recorded.replayed);
    assert!(!recorded.connected);
    assert!(!recorded.native);
    assert!(!recorded.provider_receipt);
    let replay = service.record(&proposal, "record-key").expect("replay");
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
    assert!(service.verify(&proposal, observed_at).valid);
}

#[test]
fn replication_group_projects_failover_and_update_posture_without_addresses() {
    let observed_at = now();
    let scope = group_scope();
    let mut service = service_with_fixture(scope.clone(), observed_at);
    let request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        20,
        2,
        false,
        true,
        observed_at,
    )
    .expect("read request");
    let proposal = service.propose(&request, observed_at).expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Healthy);
    let projection = proposal
        .evidence
        .replication_group
        .as_ref()
        .expect("replication group projection");
    assert_eq!(projection.failover, FailoverPosture::Enabled);
    assert_eq!(projection.update_posture, UpdatePosture::Current);
    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!json.contains("endpoint"));
    assert!(!json.contains("nodeAddress"));
    assert!(!json.contains("fixture event body"));
}

#[test]
fn pagination_is_opaque_and_bound_to_scope_filter_and_expiry() {
    let observed_at = now();
    let scope = cluster_scope();
    let mut transport = RecordingTransport::default();
    let first_request = DescribeCacheClustersRequest::new(&scope, 10, None).expect("request");
    let marker = OpaqueMarker::new(
        "provider-next-marker",
        AwsElastiCacheOperation::DescribeCacheClusters.as_str(),
        &scope,
        first_request.filter_digest().clone(),
        2,
        observed_at + Duration::minutes(5),
    )
    .expect("marker");
    let first = DescribeCacheClustersResponse::new(
        &first_request,
        Vec::new(),
        Some(marker.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_request = DescribeCacheClustersRequest::new(&scope, 10, Some(marker.clone()))
        .expect("second request");
    let cluster = CacheClusterMetadata::for_scope(
        &scope,
        HealthState::Healthy,
        FailoverPosture::NotApplicable,
        UpdatePosture::Current,
        1,
        observed_at,
        None,
    )
    .expect("cluster");
    let second = DescribeCacheClustersResponse::new(
        &second_request,
        vec![cluster],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("second response");
    transport.push_cache_cluster_response(Ok(first));
    transport.push_cache_cluster_response(Ok(second));
    let provider = AwsElastiCacheProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("opaque-marker-secret", &scope).expect("secret");
    let mut service = AwsElastiCacheService::new(scope.clone(), secret, provider).expect("service");
    let request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        2,
        false,
        false,
        observed_at,
    )
    .expect("read request");
    let read = service.read_bounded(&request, observed_at).expect("read");
    assert_eq!(read.cluster_pagination.pages, 2);
    assert!(read.cluster_pagination.complete);
    assert!(
        !serde_json::to_string(&read)
            .expect("read JSON")
            .contains("provider-next-marker")
    );

    let expired = OpaqueMarker::new(
        "expired-marker",
        AwsElastiCacheOperation::DescribeCacheClusters.as_str(),
        &scope,
        first_request.filter_digest().clone(),
        1,
        observed_at - Duration::minutes(1),
    )
    .expect("expired marker can be represented as opaque evidence");
    assert_eq!(
        DescribeCacheClustersRequest::new(&scope, 10, Some(expired)).expect_err("expired marker"),
        AwsElastiCacheError::MarkerExpired
    );
}

#[test]
fn status_and_transport_failures_are_explicit_and_never_native() {
    for (status, expected) in [
        (400, AwsElastiCacheTransportError::BadRequest),
        (401, AwsElastiCacheTransportError::Unauthorized),
        (403, AwsElastiCacheTransportError::Forbidden),
        (404, AwsElastiCacheTransportError::NotFound),
        (
            429,
            AwsElastiCacheTransportError::RateLimited {
                retry_after_seconds: None,
            },
        ),
        (
            500,
            AwsElastiCacheTransportError::ServerError { status: 500 },
        ),
        (
            503,
            AwsElastiCacheTransportError::ServerError { status: 503 },
        ),
    ] {
        assert_eq!(transport_error_for_status(status), expected);
        assert!(!expected.is_access_loss() || matches!(status, 401 | 403));
    }
    assert_eq!(AwsElastiCacheTransportError::Timeout.status_code(), None);
    assert!(!TransportProvenance::Fixture.connected());
    assert!(!TransportProvenance::Fixture.is_native());
    assert!(!TransportProvenance::Fixture.first_party());

    let observed_at = now();
    let scope = cluster_scope();
    let mut transport = RecordingTransport::default();
    transport.push_cache_cluster_response(Err(AwsElastiCacheTransportError::Forbidden));
    let provider = AwsElastiCacheProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("secret", &scope).expect("secret");
    let mut service = AwsElastiCacheService::new(scope.clone(), secret, provider).expect("service");
    let request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        1,
        false,
        false,
        observed_at,
    )
    .expect("read request");
    let proposal = service
        .propose(&request, observed_at)
        .expect("failure proposal");
    assert_eq!(proposal.state, EvidenceState::AccessLoss);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .expect("failure")
            .status_code,
        Some(403)
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
}

#[test]
fn registration_revocation_rejects_consumption_and_record_replay_conflicts() {
    let observed_at = now();
    let scope = cluster_scope();
    let mut service = service_with_fixture(scope.clone(), observed_at);
    let request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        1,
        false,
        false,
        observed_at,
    )
    .expect("request");
    let proposal = service.propose(&request, observed_at).expect("proposal");
    let other_request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        1,
        true,
        false,
        observed_at,
    )
    .expect("other request");
    let other_proposal = service
        .propose(&other_request, observed_at)
        .expect("other proposal");
    let consumer =
        MissionAwsElastiCacheConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.propose(&request, observed_at).expect_err("revoked"),
        AwsElastiCacheError::RegistrationRevoked
    );
    let mut consumer = consumer;
    let first = consumer
        .record(&proposal, "consumer-key")
        .expect("consumer record");
    assert!(!first.replayed);
    assert_eq!(
        consumer
            .record(&other_proposal, "consumer-key")
            .expect_err("replay conflict"),
        hartevo_aws_elasticache_result_plugin::ConsumerError::RecordingConflict
    );
}

#[test]
fn direct_read_models_retain_only_event_and_update_digests() {
    let observed_at = now();
    let scope = group_scope();
    let event = hartevo_aws_elasticache_result_plugin::CacheEvent::new(
        &scope.resource,
        "event-1",
        "failover-complete",
        EventSeverity::Info,
        observed_at,
        Some("raw event body".to_owned()),
    )
    .expect("event");
    let update = ServiceUpdateMetadata::new(
        &scope.resource,
        "update-1",
        ServiceUpdateStatus::Available,
        EventSeverity::Warning,
        UpdatePosture::Required,
        Some(observed_at),
        Some(observed_at + Duration::hours(1)),
        Some("raw service update payload".to_owned()),
    )
    .expect("update");
    let events_request = DescribeEventsRequest::for_scope(&scope).expect("events request");
    let events_response = DescribeEventsResponse::new(
        &events_request,
        vec![event],
        None,
        256,
        TransportProvenance::Fake,
    )
    .expect("events response");
    let json = serde_json::to_string(&events_response).expect("events JSON");
    assert!(!json.contains("raw event body"));
    let update_json = serde_json::to_string(&update).expect("update JSON");
    assert!(!update_json.contains("raw service update payload"));
}

#[test]
fn detailed_scope_and_sigv4_reference_are_digest_bound() {
    let observed_at = now();
    let scope = AwsElastiCacheScope::with_details(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_elasticache_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        ElastiCacheResource::cache_cluster(
            CacheClusterId::new("cache-cluster-detailed").expect("cluster"),
            Revision::new(7).expect("resource revision"),
        ),
        CacheEngine::Valkey,
        Some(
            NodeGroupBinding::new(
                NodeGroupId::new("0001").expect("node group"),
                Revision::new(2).expect("node revision"),
            )
            .expect("node group binding"),
        ),
        FailoverPosture::Enabled,
        EventWindow::recent(
            observed_at,
            Duration::hours(1),
            Revision::new(3).expect("window"),
        )
        .expect("window"),
        ProjectBinding::new(
            ProjectId::new("project-detailed").expect("project"),
            Revision::new(2).expect("project revision"),
        )
        .expect("project binding"),
        MissionBinding::new(
            hartevo_aws_elasticache_result_plugin::MissionId::new("mission-detailed")
                .expect("mission"),
            Revision::new(3).expect("mission revision"),
        )
        .expect("mission binding"),
        WorkProductBinding::new(
            WorkProductId::new("work-product-detailed").expect("work product"),
            Revision::new(4).expect("work product revision"),
        )
        .expect("work product binding"),
        Revision::new(5).expect("scope revision"),
    )
    .expect("detailed scope");
    let secret = SecretReference::sigv4("keyring-sigv4-reference", &scope).expect("secret");
    assert_eq!(secret.scope_digest(), &scope.digest());
    let scope_json = serde_json::to_string(&scope).expect("scope JSON");
    assert!(scope_json.contains("valkey"));
    assert!(scope_json.contains("nodeGroup"));
    assert!(scope_json.contains("eventWindow"));
    assert!(!scope_json.contains("keyring-sigv4-reference"));
}

fn proposal_for_cluster_state(
    scope: &AwsElastiCacheScope,
    observed_at: DateTime<Utc>,
    health: HealthState,
    failover: FailoverPosture,
    update: UpdatePosture,
    metadata_at: DateTime<Utc>,
) -> (
    AwsElastiCacheService<RecordingTransport>,
    AwsElastiCacheProposal,
) {
    let request = DescribeCacheClustersRequest::new(scope, 10, None).expect("request");
    let metadata =
        CacheClusterMetadata::for_scope(scope, health, failover, update, 1, metadata_at, None)
            .expect("metadata");
    let response = DescribeCacheClustersResponse::new(
        &request,
        vec![metadata],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("response");
    let mut transport = RecordingTransport::default();
    transport.push_cache_cluster_response(Ok(response));
    let provider = AwsElastiCacheProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4("state-secret", scope).expect("secret");
    let mut service = AwsElastiCacheService::new(scope.clone(), secret, provider).expect("service");
    let read_request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        scope,
        10,
        1,
        false,
        false,
        observed_at,
    )
    .expect("read request");
    let proposal = service
        .propose(&read_request, observed_at)
        .expect("proposal");
    (service, proposal)
}

#[test]
fn posture_states_stale_and_empty_resource_fail_closed() {
    let observed_at = now();
    for (health, expected) in [
        (HealthState::Available, EvidenceState::Healthy),
        (HealthState::Creating, EvidenceState::Creating),
        (HealthState::Modifying, EvidenceState::Modifying),
        (HealthState::Failing, EvidenceState::Failing),
        (HealthState::Replication, EvidenceState::Replication),
    ] {
        let scope = cluster_scope();
        let (service, proposal) = proposal_for_cluster_state(
            &scope,
            observed_at,
            health,
            FailoverPosture::Disabled,
            UpdatePosture::Current,
            observed_at,
        );
        assert_eq!(proposal.state, expected);
        assert!(service.verify(&proposal, observed_at).valid);
    }

    let scope = cluster_scope();
    let (service, stale_proposal) = proposal_for_cluster_state(
        &scope,
        observed_at,
        HealthState::Healthy,
        FailoverPosture::Disabled,
        UpdatePosture::Current,
        observed_at - Duration::seconds(901),
    );
    assert_eq!(stale_proposal.state, EvidenceState::Stale);
    assert!(!service.verify(&stale_proposal, observed_at).valid);

    let request = DescribeCacheClustersRequest::new(&scope, 10, None).expect("empty request");
    let response = DescribeCacheClustersResponse::new(
        &request,
        Vec::new(),
        None,
        128,
        TransportProvenance::Recording,
    )
    .expect("empty response");
    let mut transport = RecordingTransport::default();
    transport.push_cache_cluster_response(Ok(response));
    let provider = AwsElastiCacheProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4("empty-secret", &scope).expect("secret");
    let mut service = AwsElastiCacheService::new(scope.clone(), secret, provider).expect("service");
    let read_request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        1,
        false,
        false,
        observed_at,
    )
    .expect("empty read request");
    let empty_proposal = service
        .propose(&read_request, observed_at)
        .expect("empty proposal");
    assert_eq!(empty_proposal.state, EvidenceState::NotFound);
    assert!(!service.verify(&empty_proposal, observed_at).valid);
}

#[test]
fn marker_bounds_windows_permissions_tamper_and_consumer_replay_are_closed() {
    let observed_at = now();
    let scope = cluster_scope();
    let request = DescribeCacheClustersRequest::new(&scope, 10, None).expect("request");
    let page_four = OpaqueMarker::new(
        "page-four-marker",
        AwsElastiCacheOperation::DescribeCacheClusters.as_str(),
        &scope,
        request.filter_digest().clone(),
        4,
        observed_at + Duration::minutes(5),
    )
    .expect("last page marker");
    assert!(DescribeCacheClustersRequest::new(&scope, 10, Some(page_four)).is_ok());
    assert!(
        EventWindow::new(
            Some(observed_at - Duration::days(32)),
            Some(observed_at),
            Revision::new(1).expect("window revision"),
        )
        .is_err()
    );

    let custom_permissions = PermissionSnapshot::new(
        Revision::new(1).expect("permission revision"),
        [
            "elasticache:DescribeCacheClusters",
            "elasticache:ModifyCacheCluster",
        ],
    )
    .expect("custom permissions");
    let consent =
        hartevo_aws_elasticache_result_plugin::ConsentScope::valid_for(&scope, observed_at)
            .expect("consent");
    let provider = AwsElastiCacheProvider::new(RecordingTransport::default()).expect("provider");
    let secret = SecretReference::sigv4("permission-secret", &scope).expect("secret");
    assert_eq!(
        AwsElastiCacheService::with_registration(
            "permission-registration",
            scope.clone(),
            secret,
            custom_permissions,
            consent,
            provider,
            1,
        )
        .expect_err("extra permission rejected"),
        AwsElastiCacheError::InvalidPermissionSnapshot
    );

    let mut fixture = service_with_fixture(scope.clone(), observed_at);
    let read_request = hartevo_aws_elasticache_result_plugin::AwsElastiCacheReadRequest::new(
        &scope,
        10,
        1,
        false,
        false,
        observed_at,
    )
    .expect("read request");
    let proposal = fixture
        .propose(&read_request, observed_at)
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.digests.scope_digest = Digest::zero();
    assert!(!fixture.verify(&tampered, observed_at).valid);
    assert!(
        fixture
            .verify_evidence(&proposal.evidence, observed_at)
            .valid
    );

    let consumer = MissionAwsElastiCacheConsumer::new(scope, fixture.registration().clone())
        .expect("consumer");
    let mut consumer = consumer;
    let first = consumer
        .record(&proposal, "consumer-replay-key")
        .expect("record");
    let replay = consumer
        .record(&proposal, "consumer-replay-key")
        .expect("replay");
    assert!(replay.replayed);
    assert!(replay.validate_integrity().is_ok());
    assert!(!first.native);
}
