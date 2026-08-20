use serde_json::{json, to_string};

use crate::{
    BlockedEnvTransport, ClusterConfiguration, ClusterResource, ClusterState, ClusterStorageType,
    ColumnFamily, ConsumerError, Digest, FakeGcpBigtableTransport, GarbageCollectionRule,
    GcpBigtableAdminProvider, GcpBigtableTableResultService, GcpBigtableTableScope, GoogleAuthKind,
    Layer1Authority, MissionGcpBigtableTableConsumer, MissionId, PermissionFence, ProjectId,
    ProviderProvenance, Revision, SecretReference, TableClusterState, TableClusterStateEntry,
    TableConfiguration, TableGranularity, TableId, TablePosture, TableResource, TransportError,
    WorkProductId,
};

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

struct Fixture {
    scope: GcpBigtableTableScope,
    secret: SecretReference,
    table: TableConfiguration,
    cluster: ClusterConfiguration,
    fence: PermissionFence,
}

fn make_fixture() -> Fixture {
    let project = ProjectId::new("project-1").expect("project");
    let instance = crate::InstanceId::new("instance-1").expect("instance");
    let table_resource = TableResource::new(
        project.clone(),
        instance.clone(),
        TableId::new("table-1").expect("table"),
    );
    let cluster_resource = ClusterResource::new(
        project.clone(),
        instance.clone(),
        crate::ClusterId::new("cluster-1").expect("cluster"),
    );
    let scope = GcpBigtableTableScope::new(
        project,
        instance,
        table_resource.clone(),
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(3).expect("revision"),
        digest("permission"),
        digest("consent"),
    )
    .expect("scope");
    let secret = SecretReference::new(
        "bigtable-secret-reference",
        &scope,
        7,
        GoogleAuthKind::OAuth,
    )
    .expect("secret");
    let family =
        ColumnFamily::new("profile", GarbageCollectionRule::MaxVersions(3)).expect("family");
    let table = TableConfiguration::new(
        table_resource,
        vec![family],
        vec![TableClusterStateEntry::new(
            cluster_resource.clone(),
            TableClusterState::Ready,
        )],
        TableGranularity::Millis,
        Some(true),
        false,
    )
    .expect("table");
    let cluster = ClusterConfiguration::new(
        cluster_resource,
        Some(digest("zone")),
        ClusterState::Ready,
        Some(3),
        ClusterStorageType::Ssd,
        Some(digest("kms-key")),
    )
    .expect("cluster");
    let fence = scope.fence();
    Fixture {
        scope,
        secret,
        table,
        cluster,
        fence,
    }
}

fn queued_service(
    fixture: &Fixture,
    table: crate::GetTableResponse,
    cluster: crate::GetClusterResponse,
) -> GcpBigtableTableResultService<GcpBigtableAdminProvider<FakeGcpBigtableTransport>> {
    queued_service_with_results(fixture, Ok(table), Ok(cluster))
}

fn queued_service_with_results(
    fixture: &Fixture,
    table: Result<crate::GetTableResponse, TransportError>,
    cluster: Result<crate::GetClusterResponse, TransportError>,
) -> GcpBigtableTableResultService<GcpBigtableAdminProvider<FakeGcpBigtableTransport>> {
    let mut transport = FakeGcpBigtableTransport::new(ProviderProvenance::Fake);
    transport.push_table_response(table);
    transport.push_cluster_response(cluster);
    let provider = GcpBigtableAdminProvider::new(transport, "1.0.0", ProviderProvenance::Fake)
        .expect("provider");
    GcpBigtableTableResultService::new(fixture.scope.clone(), fixture.secret.clone(), provider)
        .expect("service")
}

#[test]
fn ready_projection_is_exact_scope_bound_redacted_and_replay_rejected() {
    let fixture = make_fixture();
    let mut service = queued_service(
        &fixture,
        crate::GetTableResponse::new(
            fixture.table.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    let proposal = service.inspect().expect("proposal");
    assert_eq!(proposal.status(), TablePosture::Ready);
    assert!(proposal.evidence.complete);
    assert_eq!(service.provider().transport().table_calls(), 1);
    assert_eq!(service.provider().transport().cluster_calls(), 1);
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| request.redacted)
    );
    assert!(!format!("{:?}", fixture.secret).contains("bigtable-secret-reference"));
    let consumer =
        MissionGcpBigtableTableConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let replay = proposal.clone();
    let result = consumer.consume(proposal).expect("result");
    assert!(result.review_only);
    assert!(!result.connected && !result.native && !result.first_party);
    assert!(
        !result.truth_authority
            && !result.consent_authority
            && !result.effect_authority
            && !result.receipt_authority
            && !result.verification_authority
            && !result.outcome_authority
    );
    assert!(
        !result.rows_read
            && !result.writes_performed
            && !result.durable_provider_receipt
            && !result.work_product_adopted
    );
    assert!(matches!(
        consumer.consume(replay),
        Err(ConsumerError::ReplayRejected)
    ));
    let serialized = to_string(&result).expect("redacted result");
    for forbidden in [
        "projects/project-1",
        "instances/instance-1",
        "tables/table-1",
        "profile",
        "bigtable-secret-reference",
        "kms-key",
        "row-value",
        "cell-value",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }
    assert_eq!(Layer1Authority::offline(), result.evidence.authority);
}

#[test]
fn all_offline_provenance_classes_cannot_claim_native_or_connected() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        let definition =
            crate::GcpBigtableProviderDefinition::new("1.0.0", provenance).expect("definition");
        assert!(!definition.connected && !definition.native && !definition.first_party);
        assert!(!provenance.connected() && !provenance.native() && !provenance.first_party());
    }
    let fixture = make_fixture();
    let provider =
        GcpBigtableAdminProvider::new(BlockedEnvTransport, "1.0.0", ProviderProvenance::BlockedEnv)
            .expect("blocked provider");
    let mut service = GcpBigtableTableResultService::new(fixture.scope, fixture.secret, provider)
        .expect("service");
    let proposal = service.inspect().expect("proposal");
    assert_eq!(proposal.status(), TablePosture::ProviderUnknown);
    assert!(
        !proposal.evidence.authority.connected
            && !proposal.evidence.authority.native_provider
            && !proposal.evidence.authority.first_party
    );
}

#[test]
fn tamper_stale_pagination_truncation_and_access_loss_fail_closed() {
    let fixture = make_fixture();
    let mut wrong_fence = fixture.fence.clone();
    wrong_fence.permission_digest = digest("different-permission");
    let mut tampered = queued_service(
        &fixture,
        crate::GetTableResponse::new(
            fixture.table.clone(),
            wrong_fence,
            fixture.secret.credential_revision(),
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    assert_eq!(
        tampered.inspect().expect("tampered").status(),
        TablePosture::Tampered
    );
    let mut pagination = queued_service(
        &fixture,
        crate::GetTableResponse::with_metadata(
            fixture.table.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
            200,
            true,
            false,
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    assert_eq!(
        pagination.inspect().expect("pagination").status(),
        TablePosture::Pagination
    );
    let mut truncated = queued_service(
        &fixture,
        crate::GetTableResponse::with_metadata(
            fixture.table.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
            200,
            false,
            true,
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    assert_eq!(
        truncated.inspect().expect("truncated").status(),
        TablePosture::Truncated
    );
    let mut stale = queued_service(
        &fixture,
        crate::GetTableResponse::new(
            fixture.table.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    stale.registration_mut().provider_id = "drifted-provider".to_owned();
    assert_eq!(
        stale.inspect().expect("stale").status(),
        TablePosture::Stale
    );
    let mut access = queued_service_with_results(
        &fixture,
        Err(TransportError::permission_denied()),
        Err(TransportError::permission_denied()),
    );
    assert_eq!(
        access.inspect().expect("access loss").status(),
        TablePosture::AccessLost
    );
}

#[test]
fn registration_and_secret_revocation_are_visible_and_irreversible() {
    let fixture = make_fixture();
    let mut service = queued_service(
        &fixture,
        crate::GetTableResponse::new(
            fixture.table.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
        crate::GetClusterResponse::new(
            fixture.cluster.clone(),
            fixture.fence.clone(),
            fixture.secret.credential_revision(),
        ),
    );
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.inspect().expect("revoked").status(),
        TablePosture::Revoked
    );
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.inspect().expect("reversed").status(),
        TablePosture::Revoked
    );
    let second_fixture = make_fixture();
    let mut service = queued_service(
        &second_fixture,
        crate::GetTableResponse::new(
            second_fixture.table.clone(),
            second_fixture.fence.clone(),
            second_fixture.secret.credential_revision(),
        ),
        crate::GetClusterResponse::new(
            second_fixture.cluster.clone(),
            second_fixture.fence.clone(),
            second_fixture.secret.credential_revision(),
        ),
    );
    service.revoke_secret().expect("secret revoke");
    assert_eq!(
        service.inspect().expect("secret revoked").status(),
        TablePosture::Revoked
    );
}

#[test]
fn documented_rest_shapes_are_parsed_without_retaining_raw_values() {
    let fixture = make_fixture();
    let table_request =
        crate::GetTableRequest::new(&fixture.scope, &fixture.secret).expect("table request");
    let table_body = json!({
        "name": "projects/project-1/instances/instance-1/tables/table-1",
        "clusterStates": {"projects/project-1/instances/instance-1/clusters/cluster-1": {"replicationState": "READY"}},
        "columnFamilies": {"profile": {"gcRule": {"maxAge": "3.5s"}, "valueType": {"stringType": {"encoding": {"utf8Bytes": {}}}}}},
        "granularity": "MILLIS", "deletionProtection": true, "changeStreamConfig": {}
    });
    let table = crate::parse_table_json_response(
        &table_request,
        200,
        table_body.to_string().as_bytes(),
        fixture.secret.credential_revision(),
    )
    .expect("table response");
    assert_eq!(
        table.configuration.cluster_states()[0].state(),
        TableClusterState::Ready
    );
    assert_eq!(
        table.configuration.families()[0]
            .projection()
            .gc_rule
            .max_age_millis,
        Some(3_500)
    );
    assert!(
        table.configuration.families()[0]
            .value_type_digest()
            .is_some()
    );
    let cluster_request = crate::GetClusterRequest::new(
        &fixture.scope,
        &fixture.secret,
        fixture.cluster.resource().clone(),
    )
    .expect("cluster request");
    let cluster_body = json!({"name": "projects/project-1/instances/instance-1/clusters/cluster-1", "location": "projects/project-1/locations/us-central1-a", "state": "READY", "serveNodes": 3, "defaultStorageType": "SSD", "encryptionConfig": {"kmsKeyName": "projects/project-1/locations/us/keyRings/r/cryptoKeys/k"}});
    let cluster = crate::parse_cluster_json_response(
        &cluster_request,
        200,
        cluster_body.to_string().as_bytes(),
        fixture.secret.credential_revision(),
    )
    .expect("cluster response");
    assert_eq!(cluster.configuration.state(), ClusterState::Ready);
    assert!(!format!("{:?}", cluster.configuration).contains("cryptoKeys"));
}
