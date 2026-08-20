use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use hartevo_azure_cosmosdb_container_result_plugin::{
    AccountName, AccountResourceProjection, ApiVersion, AzureCosmosContainerProposal,
    AzureCosmosContainerResultContract, AzureCosmosContainerResultService, AzureCosmosGetRequest,
    AzureCosmosOperation, AzureCosmosProviderError, AzureCosmosReadRequest,
    AzureCosmosResourceProjection, AzureCosmosResourceProvider, AzureCosmosResourceResponse,
    AzureCosmosScope, AzureCosmosTransport, BackupPolicy, BlockedEnvAzureCosmosTransport,
    ConsistencyPolicy, ConsumerError, ContainerName, DatabaseName, Digest, EvidenceState,
    FakeAzureCosmosTransport, FixtureAzureCosmosTransport, IndexingMode, Layer1Authority,
    MAX_REQUESTS_PER_READ, MissionAzureCosmosContainerConsumer, MissionBinding, PartialReason,
    PermissionSnapshot, ProjectBinding, ProviderId, ProviderRevision, RegionName,
    ReplicationTopologySummary, ResourceGroupName, Revision, SecretReference,
    ServiceVerificationStatus, SqlContainerResourceProjection, SqlDatabaseResourceProjection,
    SubscriptionId, TenantId, ThroughputInheritance, ThroughputResourceProjection,
    ThroughputTarget, TransportProvenance, WorkProductBinding,
};
use serde_json::json;

type RecordingService = AzureCosmosContainerResultService<
    hartevo_azure_cosmosdb_container_result_plugin::RecordingTransport,
>;

fn at(day: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, day, 0, 0, 0)
        .single()
        .expect("valid test timestamp")
}

fn scope() -> AzureCosmosScope {
    AzureCosmosScope::from_etags(
        TenantId::new("tenant-1").expect("tenant"),
        SubscriptionId::new("subscription-1").expect("subscription"),
        ResourceGroupName::new("rg-data").expect("resource group"),
        AccountName::new("cosmos-account").expect("account"),
        DatabaseName::new("database").expect("database"),
        ContainerName::new("container").expect("container"),
        ApiVersion::new("2024-11-01").expect("API version"),
        "account-etag-1",
        "database-etag-1",
        "container-etag-1",
        ProjectBinding::new(
            hartevo_azure_cosmosdb_container_result_plugin::ProjectId::new("project-1")
                .expect("Project"),
            Revision::new(2).expect("Project revision"),
        ),
        MissionBinding::new(
            hartevo_azure_cosmosdb_container_result_plugin::MissionId::new("mission-1")
                .expect("Mission"),
            Revision::new(3).expect("Mission revision"),
        ),
        WorkProductBinding::new(
            hartevo_azure_cosmosdb_container_result_plugin::WorkProductId::new("work-product-1")
                .expect("Work Product"),
            Revision::new(4).expect("Work Product revision"),
        ),
        ProviderId::new("azure.cosmosdb.resource").expect("provider"),
        ProviderRevision::new("azure-cosmosdb-arm-read-r1").expect("provider revision"),
        ThroughputTarget::ContainerOrDatabase,
    )
    .expect("scope")
    .with_throughput_revision(Digest::from_text("throughput-etag-1"))
    .expect("throughput revision")
}

fn permission() -> PermissionSnapshot {
    PermissionSnapshot::arm_read(Revision::new(1).expect("permission revision"))
        .expect("permission")
}

fn secret(scope: &AzureCosmosScope) -> SecretReference {
    SecretReference::for_arm_read(
        "entra-keyring-reference",
        &scope.tenant_id,
        Revision::new(1).expect("secret revision"),
    )
    .expect("secret reference")
}

fn new_service() -> (AzureCosmosScope, RecordingService) {
    let scope = scope();
    let provider = AzureCosmosResourceProvider::new(
        hartevo_azure_cosmosdb_container_result_plugin::RecordingTransport::new(),
    )
    .expect("provider");
    let service = AzureCosmosContainerResultService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        provider,
    )
    .expect("service");
    (scope, service)
}

fn queue_present(
    service: &mut RecordingService,
    scope: &AzureCosmosScope,
    include_throughput: bool,
) {
    let replication = ReplicationTopologySummary::new(
        Some(RegionName::new("eastus").expect("region")),
        [
            RegionName::new("eastus").expect("region"),
            RegionName::new("westus").expect("region"),
        ],
    )
    .expect("replication");
    for operation in [
        AzureCosmosOperation::DatabaseAccountsGet,
        AzureCosmosOperation::SqlDatabasesGet,
        AzureCosmosOperation::SqlContainersGet,
        AzureCosmosOperation::ThroughputSettingsGet,
    ] {
        if operation == AzureCosmosOperation::ThroughputSettingsGet && !include_throughput {
            continue;
        }
        let request = AzureCosmosGetRequest::for_scope(
            scope,
            operation,
            ThroughputTarget::ContainerOrDatabase,
            hartevo_azure_cosmosdb_container_result_plugin::model::MAX_RESPONSE_BYTES,
        )
        .expect("request");
        let resource = match operation {
            AzureCosmosOperation::DatabaseAccountsGet => AzureCosmosResourceProjection::Account(
                AccountResourceProjection::from_resource_id(
                    &request.resource_id,
                    scope.account_revision_digest.clone(),
                    Some(RegionName::new("eastus").expect("region")),
                    replication.clone(),
                    ConsistencyPolicy::Session,
                    BackupPolicy::Continuous,
                    Some(false),
                    Some(true),
                )
                .expect("account projection"),
            ),
            AzureCosmosOperation::SqlDatabasesGet => AzureCosmosResourceProjection::SqlDatabase(
                SqlDatabaseResourceProjection::from_resource_id(
                    &request.resource_id,
                    scope.database_revision_digest.clone(),
                )
                .expect("database projection"),
            ),
            AzureCosmosOperation::SqlContainersGet => AzureCosmosResourceProjection::SqlContainer(
                SqlContainerResourceProjection::from_resource_id(
                    &request.resource_id,
                    scope.container_revision_digest.clone(),
                    IndexingMode::Consistent,
                    Some(Digest::from_text("/tenantId")),
                )
                .expect("container projection"),
            ),
            AzureCosmosOperation::ThroughputSettingsGet => {
                AzureCosmosResourceProjection::Throughput(
                    ThroughputResourceProjection::manual(
                        &request.resource_id,
                        scope
                            .throughput_revision_digest
                            .clone()
                            .expect("throughput revision"),
                        400,
                        ThroughputInheritance::Container,
                    )
                    .expect("throughput projection"),
                )
            }
        };
        let response = AzureCosmosResourceResponse::new(
            &request,
            resource,
            512,
            TransportProvenance::Recording,
        )
        .expect("response");
        service
            .provider_mut()
            .transport_mut()
            .push_response(Ok(response));
    }
}

fn read_request(scope: &AzureCosmosScope) -> AzureCosmosReadRequest {
    AzureCosmosReadRequest::new(scope, at(2)).expect("read request")
}

#[test]
fn contract_and_provider_metadata_are_frozen_and_read_only() {
    AzureCosmosContainerResultContract::baseline().expect("contract");
    let (scope, service) = new_service();
    let capabilities = service.describe_capabilities();
    assert_eq!(
        capabilities.service_id,
        "hartevo.azure.cosmosdb.container-result"
    );
    assert_eq!(capabilities.provider_id, "azure.cosmosdb.resource");
    assert_eq!(capabilities.api_version, "2024-11-01");
    assert_eq!(capabilities.operations.len(), 8);
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.local_record_only);
    assert!(!capabilities.live_execution);
    assert!(!capabilities.data_plane);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.external_writes);
    assert_eq!(
        scope
            .account_resource_id()
            .as_str()
            .matches("/subscriptions/")
            .count(),
        1
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
}

#[test]
fn scope_binds_exact_resources_and_all_three_product_axes() {
    let scope = scope();
    assert_eq!(scope.tenant_id.as_str(), "tenant-1");
    assert_eq!(scope.subscription_id.as_str(), "subscription-1");
    assert_eq!(scope.resource_group.as_str(), "rg-data");
    assert!(
        scope
            .account_resource_id()
            .as_str()
            .ends_with("/cosmos-account")
    );
    assert!(
        scope
            .database_resource_id()
            .as_str()
            .ends_with("/sqlDatabases/database")
    );
    assert!(
        scope
            .container_resource_id()
            .as_str()
            .ends_with("/containers/container")
    );
    assert_eq!(scope.project.revision.get(), 2);
    assert_eq!(scope.mission.revision.get(), 3);
    assert_eq!(scope.work_product.revision.get(), 4);
    assert_ne!(scope.digest(), Digest::zero());
}

#[test]
fn secret_reference_is_opaque_and_only_arm_read_authority_is_represented() {
    let scope = scope();
    let secret = secret(&scope);
    assert!(secret.is_opaque());
    assert_eq!(
        secret.kind(),
        hartevo_azure_cosmosdb_container_result_plugin::SecretReferenceKind::EntraArmRead
    );
    assert_eq!(
        serde_json::to_string(&secret).expect("opaque JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("entra-keyring-reference"));
    assert!(
        !serde_json::to_string(&secret)
            .expect("opaque JSON")
            .contains("entra-keyring-reference")
    );
    assert!(
        SecretReference::for_arm_read("", &scope.tenant_id, Revision::new(1).expect("revision"))
            .is_err()
    );
}

#[test]
fn present_read_proposal_local_record_and_mission_review_are_bounded() {
    let (scope, mut service) = new_service();
    queue_present(&mut service, &scope, true);
    let evidence = service.read_bounded(&read_request(&scope)).expect("read");
    assert_eq!(evidence.state, EvidenceState::Present);
    assert!(evidence.posture.is_some());
    assert_eq!(evidence.provenance, TransportProvenance::Recording);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.raw_provider_payload_retained);
    let encoded = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!encoded.contains("/tenantId"));
    assert!(!encoded.contains("entra-keyring-reference"));
    let proposal = AzureCosmosContainerProposal::new(service.registration(), evidence, at(3))
        .expect("proposal");
    assert!(!proposal.can_be_adopted());
    let receipt = service.record(&proposal).expect("local record");
    assert!(receipt.local_record);
    assert!(!receipt.durable_receipt);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert_eq!(
        service.verify(&proposal).status,
        ServiceVerificationStatus::Verified
    );
    assert_eq!(
        service.verify_record(&receipt).status,
        ServiceVerificationStatus::Verified
    );
    let consumer =
        MissionAzureCosmosContainerConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        result.decision_state,
        hartevo_azure_cosmosdb_container_result_plugin::MissionDecisionState::ReviewRequired
    );
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.truth_authority);
    assert!(!result.consent_authority);
    assert!(!result.effect_authority);
    assert!(!result.outcome_authority);
    assert!(!result.adopted_work_product);
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let transports: Vec<TransportProvenance> = vec![
        FixtureAzureCosmosTransport::for_scope(&scope, at(2)).provenance(),
        FakeAzureCosmosTransport::for_scope(&scope, at(2)).provenance(),
        hartevo_azure_cosmosdb_container_result_plugin::LoopbackTransport::for_scope(&scope, at(2))
            .provenance(),
        BlockedEnvAzureCosmosTransport.provenance(),
    ];
    assert_eq!(
        transports,
        vec![
            TransportProvenance::Fixture,
            TransportProvenance::Fake,
            TransportProvenance::Loopback,
            TransportProvenance::BlockedEnv,
        ]
    );
    assert!(transports.iter().all(|provenance| !provenance.connected()
        && !provenance.native()
        && !provenance.first_party()));
    let provider =
        AzureCosmosResourceProvider::new(BlockedEnvAzureCosmosTransport).expect("blocked provider");
    let mut service = AzureCosmosContainerResultService::new(
        scope.clone(),
        secret(&scope),
        permission(),
        provider,
    )
    .expect("blocked service");
    let evidence = service
        .read_bounded(&read_request(&scope))
        .expect("blocked evidence");
    assert_eq!(evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
}

#[test]
fn account_database_container_and_throughput_requests_are_exact_get_only_paths() {
    let scope = scope();
    let requests = [
        AzureCosmosOperation::DatabaseAccountsGet,
        AzureCosmosOperation::SqlDatabasesGet,
        AzureCosmosOperation::SqlContainersGet,
        AzureCosmosOperation::ThroughputSettingsGet,
    ]
    .into_iter()
    .map(|operation| {
        AzureCosmosGetRequest::for_scope(
            &scope,
            operation,
            ThroughputTarget::ContainerOrDatabase,
            hartevo_azure_cosmosdb_container_result_plugin::model::MAX_RESPONSE_BYTES,
        )
        .expect("request")
    })
    .collect::<Vec<_>>();
    assert_eq!(requests.len(), 4);
    assert!(
        requests
            .iter()
            .all(|request| request.method == "GET" && !request.is_data_plane())
    );
    assert!(
        requests[0]
            .path_and_query()
            .contains("databaseAccounts/cosmos-account")
    );
    assert!(
        requests[1]
            .path_and_query()
            .contains("sqlDatabases/database")
    );
    assert!(
        requests[2]
            .path_and_query()
            .contains("containers/container")
    );
    assert!(
        requests[3]
            .path_and_query()
            .contains("throughputSettings/default")
    );
    assert!(
        requests
            .iter()
            .all(|request| request.path_and_query().contains("api-version=2024-11-01"))
    );
}

#[test]
fn raw_arm_json_projection_redacts_secrets_paths_network_rules_tags_and_properties() {
    let scope = scope();
    let request = AzureCosmosGetRequest::for_scope(
        &scope,
        AzureCosmosOperation::SqlContainersGet,
        ThroughputTarget::ContainerOrDatabase,
        hartevo_azure_cosmosdb_container_result_plugin::model::MAX_RESPONSE_BYTES,
    )
    .expect("request");
    let body = serde_json::to_vec(&json!({
        "id": request.resource_id.as_str(),
        "etag": "container-etag-1",
        "name": "container",
        "tags": {"secret-tag": "do-not-retain"},
        "properties": {
            "resource": {
                "id": "container",
                "_etag": "container-etag-1",
                "partitionKey": {"paths": ["/tenantId", "/secretPath"]},
                "indexingPolicy": {"indexingMode": "consistent", "includedPaths": [{"path": "/secret/*"}]}
            },
            "accountEndpoint": "https://secret.documents.azure.com",
            "ipRules": [{"ipAddressOrRange": "10.0.0.0/8"}],
            "identity": {"principalId": "identity-secret"}
        },
        "connectionStrings": ["AccountKey=secret"],
        "keys": ["secret-key"]
    }))
    .expect("JSON body");
    let response = AzureCosmosResourceProvider::<
        hartevo_azure_cosmosdb_container_result_plugin::RecordingTransport,
    >::parse_json_response(&request, 200, &body, TransportProvenance::Recording)
    .expect("redacted response");
    let encoded = serde_json::to_string(&response).expect("response JSON");
    for forbidden in [
        "do-not-retain",
        "secretPath",
        "https://secret.documents.azure.com",
        "10.0.0.0/8",
        "identity-secret",
        "AccountKey=secret",
        "secret-key",
        "includedPaths",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "redacted value survived: {forbidden}"
        );
    }
    assert!(encoded.contains("CONSISTENT"));
    assert!(encoded.contains("partition_key_digest"));
}

#[test]
fn explicit_missing_partial_access_revision_and_provider_states_fail_closed() {
    let cases = [
        (400_u16, EvidenceState::ProviderUnknown),
        (401, EvidenceState::AccessLost),
        (403, EvidenceState::AccessLost),
        (404, EvidenceState::NotFound),
        (409, EvidenceState::RevisionDrift),
    ];
    for (status, expected) in cases {
        let (scope, mut service) = new_service();
        service
            .provider_mut()
            .transport_mut()
            .push_error(AzureCosmosProviderError::from_status(status));
        let evidence = service
            .read_bounded(&read_request(&scope))
            .expect("typed status evidence");
        assert_eq!(evidence.state, expected, "status {status}");
        assert!(evidence.state.is_fail_closed());
    }

    let (scope, mut service) = new_service();
    queue_present(&mut service, &scope, false);
    service
        .provider_mut()
        .transport_mut()
        .push_error(AzureCosmosProviderError::from_status(404));
    let evidence = service
        .read_bounded(&read_request(&scope))
        .expect("throughput absent evidence");
    assert_eq!(evidence.state, EvidenceState::DegradedConfiguration);
    assert_eq!(
        evidence.partial_reason,
        Some(PartialReason::ThroughputUnavailable)
    );

    let (scope, mut service) = new_service();
    for _ in 0..3 {
        service
            .provider_mut()
            .transport_mut()
            .push_error(AzureCosmosProviderError::from_status(429));
    }
    let evidence = service
        .read_bounded(&read_request(&scope))
        .expect("rate limit evidence");
    assert_eq!(evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(evidence.provider_errors.len(), 3);
    assert!(service.provider().transport().requests().len() <= MAX_REQUESTS_PER_READ);
}

#[test]
fn tamper_replay_and_revocation_are_distinct_and_fail_closed() {
    let (scope, mut service) = new_service();
    queue_present(&mut service, &scope, true);
    let proposal = service.propose(&read_request(&scope)).expect("proposal");
    let mut tampered = proposal.clone();
    tampered.evidence.state = EvidenceState::NotFound;
    assert_eq!(
        service.verify(&tampered).status,
        ServiceVerificationStatus::Tampered
    );
    assert!(service.record(&tampered).is_err());
    let receipt = service.record(&proposal).expect("record");
    assert_eq!(
        service.verify_record(&receipt).status,
        ServiceVerificationStatus::Verified
    );
    assert_eq!(
        service.record(&proposal).expect_err("replay").to_string(),
        "Azure Cosmos proposal or record is a replay"
    );
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    let revoked = service
        .read_bounded(&read_request(&scope))
        .expect("revoked evidence");
    assert_eq!(revoked.state, EvidenceState::Revoked);
    assert_eq!(
        service.verify(&proposal).status,
        ServiceVerificationStatus::Revoked
    );
}

#[test]
fn stale_scope_registration_and_mission_revision_are_rejected() {
    let (scope, mut service) = new_service();
    queue_present(&mut service, &scope, true);
    let mut stale_request = read_request(&scope);
    stale_request.scope_digest = Digest::zero();
    assert!(service.read_bounded(&stale_request).is_err());
    let proposal = service.propose(&read_request(&scope)).expect("proposal");
    service.registration_mut().scope_digest = Digest::zero();
    assert!(service.read_bounded(&read_request(&scope)).is_err());
    let mut new_scope = scope.clone();
    new_scope.mission.revision = Revision::new(99).expect("new Mission revision");
    assert!(
        MissionAzureCosmosContainerConsumer::new(new_scope, service.registration().clone())
            .is_err()
    );
    assert!(matches!(
        MissionAzureCosmosContainerConsumer::new(scope, service.registration().clone()),
        Err(ConsumerError::RegistrationMismatch)
    ));
    assert_eq!(proposal.evidence.state, EvidenceState::Present);
}

#[test]
fn response_tamper_and_revision_etag_drift_are_detected_before_proposal() {
    let (scope, mut service) = new_service();
    let request = AzureCosmosGetRequest::for_scope(
        &scope,
        AzureCosmosOperation::DatabaseAccountsGet,
        ThroughputTarget::ContainerOrDatabase,
        hartevo_azure_cosmosdb_container_result_plugin::model::MAX_RESPONSE_BYTES,
    )
    .expect("request");
    let location = RegionName::new("eastus").expect("region");
    let account = AzureCosmosResourceProjection::Account(
        AccountResourceProjection::from_resource_id(
            &request.resource_id,
            scope.account_revision_digest.clone(),
            Some(location.clone()),
            ReplicationTopologySummary::single(location),
            ConsistencyPolicy::Session,
            BackupPolicy::Periodic,
            Some(false),
            Some(true),
        )
        .expect("account"),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(AzureCosmosResourceResponse::new(
            &request,
            account,
            512,
            TransportProvenance::Recording,
        )
        .expect("response")
        .with_declared_response_digest(Digest::zero())));
    let evidence = service
        .read_bounded(&read_request(&scope))
        .expect("tampered evidence");
    assert_eq!(evidence.state, EvidenceState::Tampered);

    let (scope, mut service) = new_service();
    let request = AzureCosmosGetRequest::for_scope(
        &scope,
        AzureCosmosOperation::DatabaseAccountsGet,
        ThroughputTarget::ContainerOrDatabase,
        hartevo_azure_cosmosdb_container_result_plugin::model::MAX_RESPONSE_BYTES,
    )
    .expect("request");
    let location = RegionName::new("eastus").expect("region");
    let drifted = AzureCosmosResourceProjection::Account(
        AccountResourceProjection::from_resource_id(
            &request.resource_id,
            Digest::from_text("different-etag"),
            Some(location.clone()),
            ReplicationTopologySummary::single(location),
            ConsistencyPolicy::Session,
            BackupPolicy::Periodic,
            Some(false),
            Some(true),
        )
        .expect("account"),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_response(Ok(AzureCosmosResourceResponse::new(
            &request,
            drifted,
            512,
            TransportProvenance::Recording,
        )
        .expect("response")));
    let evidence = service
        .read_bounded(&read_request(&scope))
        .expect("revision drift evidence");
    assert_eq!(evidence.state, EvidenceState::RevisionDrift);
    assert_eq!(
        evidence.partial_reason,
        Some(PartialReason::RevisionMismatch)
    );
}

#[test]
fn all_permission_actions_are_arm_read_only_and_no_data_plane_type_exists() {
    let permission = permission();
    assert!(permission.allows_all());
    let action_names = permission
        .actions
        .iter()
        .map(|action| action.arm_permission())
        .collect::<BTreeSet<_>>();
    assert_eq!(action_names.len(), 4);
    assert!(action_names.iter().all(|value| value.contains("/read")));
    assert!(!action_names.iter().any(|value| value.contains("documents")));
    assert!(!action_names.iter().any(|value| value.contains("write")));
}
