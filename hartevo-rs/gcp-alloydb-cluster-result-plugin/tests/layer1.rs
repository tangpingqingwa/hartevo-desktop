use hartevo_gcp_alloydb_cluster_result_plugin::{
    API_REVISION, AvailabilityType, BlockedEnvTransport, ClusterId, ClusterType, DatabaseVersion,
    DeploymentId, Digest, EvidenceState, FixtureGcpAlloyDbTransport, GcpAlloyDbAdminProvider,
    GcpAlloyDbClusterResultService, GcpAlloyDbClusterScope, GcpAlloyDbTarget, GetClusterRequest,
    GetClusterResponse, GetInstanceRequest, GetInstanceResponse, InstanceId, InstancePosture,
    InstanceType, LifecycleState, Location, MAX_RESPONSE_BYTES, MissionBinding,
    MissionGcpAlloyDbClusterConsumer, MissionId, ProjectId, ProviderProvenance, Revision,
    SecretReference, ServiceError, TransportError, WorkProductId,
};

const RAW_SECRET: &str = "fixture-secret-material-that-must-not-escape";
const RAW_BODY: &str = "raw provider body with endpoint and password=never-emit";

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}

fn scope() -> GcpAlloyDbClusterScope {
    let project = ProjectId::new("project-863").expect("project");
    let mission = MissionBinding::new(
        MissionId::new("mission-863").expect("mission"),
        revision(7),
        project.clone(),
        revision(11),
        WorkProductId::new("work-product-863").expect("work product"),
        revision(13),
        DeploymentId::new("deployment-863").expect("deployment"),
        revision(17),
    )
    .expect("mission binding");
    GcpAlloyDbClusterScope::new(
        GcpAlloyDbTarget::new(
            project,
            Location::new("us-central1").expect("location"),
            ClusterId::new("cluster-863").expect("cluster"),
            InstanceId::new("instance-863").expect("instance"),
            revision(19),
        )
        .expect("target"),
        mission,
        hartevo_gcp_alloydb_cluster_result_plugin::PermissionScope::read_only(revision(23)),
    )
    .expect("scope")
}

fn secret(scope: &GcpAlloyDbClusterScope) -> SecretReference {
    SecretReference::new(RAW_SECRET, scope, revision(29)).expect("secret")
}

fn postures(
    scope: &GcpAlloyDbClusterScope,
) -> (
    hartevo_gcp_alloydb_cluster_result_plugin::ClusterPosture,
    InstancePosture,
) {
    (
        hartevo_gcp_alloydb_cluster_result_plugin::ClusterPosture::new(
            LifecycleState::Ready,
            ClusterType::Primary,
            AvailabilityType::Regional,
            DatabaseVersion::Postgres15,
            2,
            scope.resource_revision(),
        )
        .expect("cluster posture"),
        InstancePosture::new(
            LifecycleState::Ready,
            InstanceType::Primary,
            AvailabilityType::Regional,
            8,
            2,
            scope.resource_revision(),
        )
        .expect("instance posture"),
    )
}

fn ready_service() -> GcpAlloyDbClusterResultService<FixtureGcpAlloyDbTransport> {
    let scope = scope();
    let initial_secret = secret(&scope);
    let provider =
        GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::default()).expect("provider");
    let mut service = GcpAlloyDbClusterResultService::new(scope.clone(), initial_secret, provider)
        .expect("service");
    let cluster_request = GetClusterRequest::new(
        &scope,
        service.secret_reference(),
        &service.registration().registration_digest,
        API_REVISION,
    )
    .expect("cluster request");
    let instance_request = GetInstanceRequest::new(
        &scope,
        service.secret_reference(),
        &service.registration().registration_digest,
        API_REVISION,
    )
    .expect("instance request");
    let (cluster, instance) = postures(&scope);
    let cluster_response = GetClusterResponse::new(
        &cluster_request,
        cluster,
        4_096,
        ProviderProvenance::Fixture,
    )
    .expect("cluster response");
    let instance_response = GetInstanceResponse::new(
        &instance_request,
        instance,
        8_192,
        ProviderProvenance::Fixture,
    )
    .expect("instance response");
    service
        .provider_mut()
        .transport_mut()
        .push_cluster_response(Ok(cluster_response));
    service
        .provider_mut()
        .transport_mut()
        .push_instance_response(Ok(instance_response));
    service
}

#[test]
fn ready_result_is_bounded_redacted_and_below_kernel_authority() {
    let mut service = ready_service();
    let proposal = service.propose().expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Ready);
    assert!(proposal.cluster.is_some());
    assert!(proposal.instance.is_some());
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);
    assert!(proposal.is_review_eligible());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.provider_receipt && !proposal.durable_provider_receipt);
    assert!(!format!("{service:?}").contains(RAW_SECRET));
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!serialized.contains("https://"));
    assert!(!serialized.contains("password"));

    let mut consumer: MissionGcpAlloyDbClusterConsumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.accepted && result.review_only && result.review_eligible);
    assert!(!result.adopted_outcome && !result.truth_authority);
    assert!(!result.connected && !result.native && !result.first_party);
    let record = consumer
        .record(&proposal, "idempotency-863")
        .expect("record");
    assert!(!record.replayed && !record.provider_receipt && !record.durable_provider_receipt);
    let replay = consumer
        .record(&proposal, "idempotency-863")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let scope = scope();
    let provider = GcpAlloyDbAdminProvider::new(BlockedEnvTransport).expect("provider");
    let service = GcpAlloyDbClusterResultService::new(scope.clone(), secret(&scope), provider)
        .expect("service");
    let mut service = service;
    let proposal = service.propose().expect("blocked proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn tamper_stale_and_pagination_fail_closed_without_raw_values() {
    let scope = scope();
    let initial_secret = secret(&scope);
    let provider =
        GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::default()).expect("provider");
    let mut service = GcpAlloyDbClusterResultService::new(scope.clone(), initial_secret, provider)
        .expect("service");
    let cluster_request = GetClusterRequest::new(
        &scope,
        service.secret_reference(),
        &service.registration().registration_digest,
        API_REVISION,
    )
    .expect("request");
    let (cluster, _instance) = postures(&scope);
    let tampered = GetClusterResponse::new(
        &cluster_request,
        cluster,
        1_024,
        ProviderProvenance::Fixture,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    service
        .provider_mut()
        .transport_mut()
        .push_cluster_response(Ok(tampered));
    let proposal = service.propose().expect("tampered proposal");
    assert_eq!(proposal.state, EvidenceState::Tampered);
    assert!(proposal.cluster.is_none());

    let provider =
        GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::default()).expect("provider");
    let mut stale_service =
        GcpAlloyDbClusterResultService::new(scope.clone(), secret(&scope), provider)
            .expect("service");
    let stale_request = GetClusterRequest::new(
        &scope,
        stale_service.secret_reference(),
        &stale_service.registration().registration_digest,
        API_REVISION,
    )
    .expect("request");
    let stale_posture = hartevo_gcp_alloydb_cluster_result_plugin::ClusterPosture::new(
        LifecycleState::Ready,
        ClusterType::Primary,
        AvailabilityType::Regional,
        DatabaseVersion::Postgres15,
        2,
        revision(99),
    )
    .expect("stale posture");
    stale_service
        .provider_mut()
        .transport_mut()
        .push_cluster_response(Ok(GetClusterResponse::new(
            &stale_request,
            stale_posture,
            1_024,
            ProviderProvenance::Fixture,
        )
        .expect("stale response")));
    let stale = stale_service.propose().expect("stale proposal");
    assert_eq!(stale.state, EvidenceState::StaleRevision);

    let provider =
        GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::default()).expect("provider");
    let mut loop_service =
        GcpAlloyDbClusterResultService::new(scope.clone(), secret(&scope), provider)
            .expect("service");
    let loop_request = GetClusterRequest::new(
        &scope,
        loop_service.secret_reference(),
        &loop_service.registration().registration_digest,
        API_REVISION,
    )
    .expect("request");
    let token = hartevo_gcp_alloydb_cluster_result_plugin::OpaquePageToken::new(
        "opaque-pagination-token-with-secret-looking-text",
        scope.digest(),
        hartevo_gcp_alloydb_cluster_result_plugin::AlloyDbReadOperation::GetCluster,
        1,
    )
    .expect("token");
    let loop_response = GetClusterResponse::new(
        &loop_request,
        postures(&scope).0,
        1_024,
        ProviderProvenance::Fixture,
    )
    .expect("response")
    .with_next_page_token(token);
    loop_service
        .provider_mut()
        .transport_mut()
        .push_cluster_response(Ok(loop_response));
    let loop_proposal = loop_service.propose().expect("loop proposal");
    assert_eq!(loop_proposal.state, EvidenceState::PaginationLoop);
    assert!(
        !serde_json::to_string(&loop_proposal)
            .expect("loop JSON")
            .contains("opaque-pagination-token")
    );
}

#[test]
fn access_loss_truncation_replay_and_revocation_are_fail_closed() {
    let scope = scope();
    let provider = GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::new(
        Err(TransportError::AccessDenied {
            status_code: Some(403),
        }),
        Err(TransportError::Unknown {
            reason_digest: Digest::from_text("unused"),
        }),
    ))
    .expect("provider");
    let mut service = GcpAlloyDbClusterResultService::new(scope.clone(), secret(&scope), provider)
        .expect("service");
    let access_loss = service.propose().expect("access proposal");
    assert_eq!(access_loss.state, EvidenceState::AccessLoss);
    assert_eq!(access_loss.failure.expect("failure").status_code, Some(403));

    let provider = GcpAlloyDbAdminProvider::new(FixtureGcpAlloyDbTransport::new(
        Err(TransportError::Truncated {
            response_bytes: MAX_RESPONSE_BYTES + 1,
        }),
        Err(TransportError::Unknown {
            reason_digest: Digest::from_text("unused"),
        }),
    ))
    .expect("provider");
    let mut truncated_service =
        GcpAlloyDbClusterResultService::new(scope.clone(), secret(&scope), provider)
            .expect("service");
    let truncated = truncated_service.propose().expect("truncated proposal");
    assert_eq!(truncated.state, EvidenceState::Truncated);

    let mut ready = ready_service();
    let proposal = ready.propose().expect("proposal");
    let record = ready.record(&proposal, "replay-key").expect("record");
    assert!(!record.replayed);
    let replay = ready.record(&proposal, "replay-key").expect("replay");
    assert!(replay.replayed);

    ready.revoke_registration().expect("revoke");
    assert_eq!(
        ready.propose().expect_err("revoked").to_string(),
        ServiceError::RegistrationRevoked.to_string()
    );
    ready.restore_registration().expect("restore");
    ready.revoke_secret_reference();
    assert!(matches!(ready.propose(), Err(ServiceError::SecretRevoked)));
}

#[test]
fn all_non_native_provenances_and_raw_body_errors_are_honest() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let error = TransportError::from_raw_body(Some(500), RAW_BODY.as_bytes());
    assert!(!format!("{error:?}").contains(RAW_BODY));
    assert!(!error.to_string().contains(RAW_BODY));
}

#[test]
fn registration_bound_digest_drift_is_rejected() {
    let mut service = ready_service();
    let proposal = service.propose().expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.contract_digest = Digest::from_text("different-contract");
    tampered.evidence.evidence_digest = Digest::from_text("unsealed");
    tampered.proposal_digest = Digest::from_text("unsealed");
    assert!(!service.verify(&tampered).valid);
}
