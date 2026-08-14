use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use hartevo_aws_msk_result_plugin::{
    AWS_MSK_API_REVISION, AccountId, AwsMskProvider, AwsMskReadPage, AwsMskReadRequest,
    AwsMskScope, AwsMskService, AwsMskServiceError, AwsRegion, BrokerCountClass, ClusterArn,
    ClusterBinding, ClusterName, ClusterState, ClusterType, ConfigurationArn, ConfigurationBinding,
    ConfigurationProjection, Digest, FixtureAwsMskTransport, KafkaVersion, MissionAwsMskConsumer,
    MskClusterObservation, MskConfigurationObservation, MskOperationObservation, OpaquePageMarker,
    OperationBinding, OperationId, OperationState, OperationType, PermissionAction,
    PermissionFence, PermissionId, ProviderRevision, ReadBounds, ReadinessState, Revision,
    SecurityPosture, SigV4SecretReference, TransportError, TriState,
};

struct Fixtures {
    scope: AwsMskScope,
    permission: PermissionFence,
    secret: SigV4SecretReference,
    cluster: MskClusterObservation,
    configuration: MskConfigurationObservation,
    operation: MskOperationObservation,
}

impl Fixtures {
    #[allow(clippy::too_many_lines)]
    fn new() -> Self {
        let account = AccountId::new("111111111111").unwrap();
        let region = AwsRegion::new("us-east-1").unwrap();
        let cluster_arn =
            ClusterArn::new("arn:aws:kafka:us-east-1:111111111111:cluster/mission-msk/cluster-1")
                .unwrap();
        let cluster_name = ClusterName::new("mission-msk").unwrap();
        let configuration_arn = ConfigurationArn::new(
            "arn:aws:kafka:us-east-1:111111111111:configuration/mission-msk-config/1",
        )
        .unwrap();
        let operation_id = OperationId::new(
            "arn:aws:kafka:us-east-1:111111111111:cluster-operation/mission-msk/op-1",
        )
        .unwrap();
        let revision = Revision::new(1).unwrap();
        let permission =
            PermissionFence::readonly(PermissionId::new("permission-657").unwrap(), revision)
                .unwrap();
        let deployment = hartevo_aws_msk_result_plugin::DeploymentBinding::new(
            hartevo_aws_msk_result_plugin::DeploymentId::new("deployment-657").unwrap(),
            revision,
        );
        let mission = hartevo_aws_msk_result_plugin::MissionBinding::new(
            hartevo_aws_msk_result_plugin::MissionId::new("mission-657").unwrap(),
            revision,
        );
        let project = hartevo_aws_msk_result_plugin::ProjectBinding::new(
            hartevo_aws_msk_result_plugin::ProjectId::new("project-657").unwrap(),
            revision,
        );
        let work_product = hartevo_aws_msk_result_plugin::WorkProductBinding::new(
            hartevo_aws_msk_result_plugin::WorkProductId::new("work-product-657").unwrap(),
            revision,
        );
        let cluster = ClusterBinding::new(
            cluster_arn.clone(),
            cluster_name.clone(),
            ClusterType::Provisioned,
            KafkaVersion::new("3.6.0").unwrap(),
            revision,
        )
        .unwrap();
        let configuration = ConfigurationBinding::new(configuration_arn.clone(), revision);
        let operation = OperationBinding::new(operation_id.clone(), revision);
        let scope = AwsMskScope::new(
            deployment,
            mission,
            project,
            work_product,
            account,
            region,
            cluster,
            configuration,
            [operation],
            permission.digest(),
        )
        .unwrap();
        let secret = SigV4SecretReference::for_msk("opaque-ref/msk/657", &scope).unwrap();
        let timestamp = "2026-08-15T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let cluster = MskClusterObservation::new(
            cluster_arn,
            cluster_name,
            ClusterType::Provisioned,
            KafkaVersion::new("3.6.0").unwrap(),
            ClusterState::Active,
            BrokerCountClass::Small,
            SecurityPosture {
                encryption_at_rest: TriState::Enabled,
                in_cluster_encryption: TriState::Enabled,
                client_broker_encryption:
                    hartevo_aws_msk_result_plugin::ClientBrokerEncryption::Tls,
                tls_authentication: TriState::Enabled,
                sasl_iam_authentication: TriState::Enabled,
                sasl_scram_authentication: TriState::Disabled,
                unauthenticated_access: TriState::Disabled,
            },
            ConfigurationProjection {
                arn: Some(configuration_arn.clone()),
                revision: Some(revision),
                readiness: ReadinessState::Ready,
            },
            Some(timestamp),
        )
        .with_revision(revision);
        let configuration = MskConfigurationObservation::new(
            configuration_arn,
            revision,
            true,
            hartevo_aws_msk_result_plugin::PropertyCountClass::Small,
            ReadinessState::Ready,
        );
        let operation = MskOperationObservation::new(
            operation_id,
            OperationType::new("UPDATE_CLUSTER_CONFIGURATION").unwrap(),
            OperationState::Successful,
            Some(timestamp),
            Some(timestamp + Duration::minutes(1)),
            false,
        )
        .with_revision(revision);
        Self {
            scope,
            permission,
            secret,
            cluster,
            configuration,
            operation,
        }
    }

    fn provider_revision() -> ProviderRevision {
        ProviderRevision::new(AWS_MSK_API_REVISION).unwrap()
    }

    fn service(
        &self,
        responses: impl IntoIterator<Item = Result<AwsMskReadPage, TransportError>>,
    ) -> AwsMskService<FixtureAwsMskTransport> {
        let mut transport = FixtureAwsMskTransport::fixture();
        for response in responses {
            transport.push_response(response);
        }
        let provider = AwsMskProvider::new(transport).unwrap();
        AwsMskService::new(
            self.scope.clone(),
            self.secret.clone(),
            self.permission.clone(),
            provider,
        )
        .unwrap()
    }
}

#[test]
fn all_four_read_seams_project_bounded_msk_posture() {
    let fixtures = Fixtures::new();
    let bounds = ReadBounds::default();
    let list_request = AwsMskReadRequest::list_clusters(&fixtures.scope, bounds).unwrap();
    let describe_request = AwsMskReadRequest::describe_cluster(&fixtures.scope, bounds).unwrap();
    let configuration_request =
        AwsMskReadRequest::describe_configuration_revision(&fixtures.scope, bounds).unwrap();
    let operations_request =
        AwsMskReadRequest::list_cluster_operations(&fixtures.scope, bounds).unwrap();
    let responses = [
        Ok(AwsMskReadPage::list_clusters(
            &list_request,
            1,
            vec![fixtures.cluster.clone()],
            None,
            640,
            Fixtures::provider_revision(),
        )
        .unwrap()),
        Ok(AwsMskReadPage::describe_cluster(
            &describe_request,
            1,
            fixtures.cluster.clone(),
            640,
            Fixtures::provider_revision(),
        )
        .unwrap()),
        Ok(AwsMskReadPage::describe_configuration_revision(
            &configuration_request,
            1,
            fixtures.configuration.clone(),
            256,
            Fixtures::provider_revision(),
        )
        .unwrap()),
        Ok(AwsMskReadPage::list_cluster_operations(
            &operations_request,
            1,
            vec![fixtures.operation.clone()],
            None,
            320,
            Fixtures::provider_revision(),
        )
        .unwrap()),
    ];
    let mut service = fixtures.service(responses);

    let list = service.read(list_request).unwrap();
    assert_eq!(list.evidence.clusters.len(), 1);
    assert_eq!(list.evidence.cluster_readiness, ReadinessState::Ready);
    assert!(!list.evidence.connected);
    assert!(!list.evidence.native);
    assert!(!list.evidence.first_party);

    let describe = service.read(describe_request).unwrap();
    assert_eq!(
        describe.evidence.cluster.as_ref().unwrap().state,
        ClusterState::Active
    );
    assert_eq!(
        describe.evidence.configuration_readiness,
        ReadinessState::Ready
    );

    let configuration = service.read(configuration_request).unwrap();
    assert_eq!(
        configuration
            .evidence
            .configuration
            .as_ref()
            .unwrap()
            .revision,
        Revision::new(1).unwrap()
    );

    let operations = service.read(operations_request).unwrap();
    assert_eq!(operations.evidence.operations.len(), 1);
    assert_eq!(
        operations.evidence.operations[0].state,
        OperationState::Successful
    );
    assert_eq!(
        operations.evidence.operation_readiness,
        ReadinessState::Ready
    );
}

#[test]
fn proposal_record_verify_and_mission_consumption_remain_non_authoritative() {
    let fixtures = Fixtures::new();
    let request =
        AwsMskReadRequest::describe_configuration_revision(&fixtures.scope, ReadBounds::default())
            .unwrap();
    let page = AwsMskReadPage::describe_configuration_revision(
        &request,
        1,
        fixtures.configuration.clone(),
        256,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let mut service = fixtures.service([Ok(page)]);
    let consumer =
        MissionAwsMskConsumer::new(fixtures.scope.clone(), service.registration().clone()).unwrap();
    let proposal = service
        .propose(request, "2026-08-15T00:02:00Z".parse().unwrap())
        .unwrap();
    let result = consumer.consume(proposal.clone()).unwrap();
    assert!(result.requires_human_review);
    assert!(!result.safe_to_promote);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.adopted_outcome);
    assert!(!result.work_product_adoption);

    let receipt = service
        .record_at(&proposal, "2026-08-15T00:03:00Z".parse().unwrap())
        .unwrap();
    let verified = service.verify(&receipt).unwrap();
    assert!(verified.verified);
    assert!(!verified.connected);
    assert!(!verified.native);
    assert!(!verified.first_party);
    assert!(!verified.adopted_outcome);
    assert!(!verified.work_product_adoption);

    consumer.verify_evidence(&proposal.evidence).unwrap();
    service.revoke_registration().unwrap();
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(AwsMskServiceError::RegistrationRevoked)
    ));
}

#[test]
fn pagination_marker_replay_and_retry_are_bounded_and_redacted() {
    let fixtures = Fixtures::new();
    let request = AwsMskReadRequest::list_clusters(&fixtures.scope, ReadBounds::default()).unwrap();
    let marker = OpaquePageMarker::new("raw-next-token-657").unwrap();
    let page_one = AwsMskReadPage::list_clusters(
        &request,
        1,
        vec![fixtures.cluster.clone()],
        Some(marker.clone()),
        256,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let request_two = request.with_marker(Some(marker.clone())).unwrap();
    let page_two = AwsMskReadPage::list_clusters(
        &request_two,
        2,
        Vec::new(),
        Some(marker.clone()),
        256,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let mut service = fixtures.service([
        Ok(page_one),
        Err(TransportError::RateLimited {
            retry_after_seconds: Some(1),
        }),
        Ok(page_two),
    ]);
    let result = service.read(request).unwrap();
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_msk_result_plugin::PartialReason::MarkerReplay)
    );
    assert!(result.evidence.truncated);
    assert_eq!(result.evidence.retry_count, 1);
    let serialized = serde_json::to_string(&result.evidence).unwrap();
    assert!(!serialized.contains("raw-next-token-657"));
    assert!(!format!("{marker:?}").contains("raw-next-token-657"));
}

#[test]
fn scope_revision_registration_drift_tamper_and_revocation_fail_closed() {
    let fixtures = Fixtures::new();
    let request = AwsMskReadRequest::list_clusters(&fixtures.scope, ReadBounds::default()).unwrap();
    let page = AwsMskReadPage::list_clusters(
        &request,
        1,
        vec![fixtures.cluster.clone()],
        None,
        256,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let mut service = fixtures.service([Ok(page)]);
    let proposal = service.propose(request, Utc::now()).unwrap();
    let mut tampered = proposal.clone();
    tampered.evidence.state = ReadinessState::NotReady;
    assert!(matches!(
        service.verify_proposal(&tampered),
        Err(AwsMskServiceError::ProposalTampered | AwsMskServiceError::EvidenceTampered)
    ));
    service.revoke_registration().unwrap();
    assert!(matches!(
        service.verify_proposal(&proposal),
        Err(AwsMskServiceError::RegistrationRevoked)
    ));
    assert!(service.revoke_registration().is_err());
}

#[test]
fn access_loss_and_provider_statuses_are_safe_projections() {
    let fixtures = Fixtures::new();
    let request =
        AwsMskReadRequest::describe_cluster(&fixtures.scope, ReadBounds::default()).unwrap();
    let mut service = fixtures.service([Err(TransportError::Forbidden)]);
    let result = service.read(request.clone()).unwrap();
    assert_eq!(result.evidence.state, ReadinessState::AccessLoss);
    assert_eq!(result.evidence.provider_errors[0].status_code, Some(403));

    for (status, expected_kind) in [
        (
            400,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::InvalidRequest,
        ),
        (
            401,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::Unauthorized,
        ),
        (
            403,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::Forbidden,
        ),
        (
            404,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::NotFound,
        ),
        (
            429,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::RateLimited,
        ),
        (
            500,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::ServerFailure,
        ),
        (
            503,
            hartevo_aws_msk_result_plugin::ProviderErrorKind::ServerFailure,
        ),
    ] {
        let parsed = AwsMskProvider::<FixtureAwsMskTransport>::parse_json_page(
            &request,
            1,
            status,
            b"{}",
            Fixtures::provider_revision(),
        );
        assert!(matches!(
            parsed,
            Err(hartevo_aws_msk_result_plugin::AwsMskProviderError::Transport(error))
                if error.kind() == expected_kind
        ));
    }

    let mut timeout_service = fixtures.service([
        Err(TransportError::Timeout),
        Err(TransportError::Timeout),
        Err(TransportError::Timeout),
    ]);
    let timeout_result = timeout_service.read(request.clone()).unwrap();
    assert_eq!(
        timeout_result.evidence.state,
        ReadinessState::ProviderUnknown
    );
    assert_eq!(timeout_result.evidence.retry_count, 2);

    let expired_marker = OpaquePageMarker::new("expired-marker")
        .unwrap()
        .with_expires_at(Utc::now() - Duration::seconds(1));
    let expired_request = request.with_marker(Some(expired_marker)).unwrap();
    let mut expired_service = fixtures.service(std::iter::empty());
    let expired_result = expired_service.read(expired_request).unwrap();
    assert_eq!(
        expired_result.evidence.partial_reason,
        Some(hartevo_aws_msk_result_plugin::PartialReason::MarkerExpired)
    );
}

#[test]
fn json_parser_redacts_endpoints_configuration_properties_operation_messages_and_markers() {
    let fixtures = Fixtures::new();
    let request =
        AwsMskReadRequest::describe_cluster(&fixtures.scope, ReadBounds::default()).unwrap();
    let body = serde_json::json!({
        "ClusterInfo": {
            "ClusterArn": fixtures.scope.cluster.arn.as_str(),
            "ClusterName": fixtures.scope.cluster.name.as_str(),
            "ClusterType": "PROVISIONED",
            "KafkaVersion": "3.6.0",
            "State": "ACTIVE",
            "CreationTime": "2026-08-15T00:00:00Z",
            "BootstrapBrokerString": "b-1.msk.example:9092",
            "Provisioned": {
                "NumberOfBrokerNodes": 3,
                "CurrentBrokerSoftwareInfo": {
                    "ConfigurationArn": fixtures.scope.configuration.arn.as_str(),
                    "ConfigurationRevision": 1
                },
                "BrokerNodeGroupInfo": {
                    "ConnectivityInfo": {
                        "PublicAccess": {"Type": "SERVICE_PROVIDED_EIPS", "Address": "10.0.0.1"}
                    }
                }
            },
            "EncryptionInfo": {
                "EncryptionAtRest": {"DataVolumeKMSKey": "arn:aws:kms:secret"},
                "EncryptionInTransit": {"ClientBroker": "TLS", "InCluster": true}
            },
            "ClientAuthentication": {
                "Tls": {"Enabled": true},
                "Sasl": {"Iam": {"Enabled": true}, "Scram": {"Enabled": false}},
                "Unauthenticated": {"Enabled": false}
            },
            "StateInfo": {"Message": "raw cluster provider message"}
        }
    });
    let body = serde_json::to_vec(&body).unwrap();
    let page = AwsMskProvider::<FixtureAwsMskTransport>::parse_json_page(
        &request,
        1,
        200,
        &body,
        Fixtures::provider_revision(),
    )
    .unwrap();
    let serialized_page = serde_json::to_string(&page).unwrap();
    assert!(!serialized_page.contains("b-1.msk.example"));
    assert!(!serialized_page.contains("10.0.0.1"));
    assert!(!serialized_page.contains("raw cluster provider message"));
    assert!(!serialized_page.contains("arn:aws:kms:secret"));

    let configuration_request =
        AwsMskReadRequest::describe_configuration_revision(&fixtures.scope, ReadBounds::default())
            .unwrap();
    let config_body = serde_json::json!({
        "Revision": 1,
        "ServerProperties": {"auto.create.topics.enable": "true", "secret.property": "do-not-retain"}
    });
    let config_page = AwsMskProvider::<FixtureAwsMskTransport>::parse_json_page(
        &configuration_request,
        1,
        200,
        &serde_json::to_vec(&config_body).unwrap(),
        Fixtures::provider_revision(),
    )
    .unwrap();
    let serialized_config = serde_json::to_string(&config_page).unwrap();
    assert!(!serialized_config.contains("secret.property"));
    assert!(!serialized_config.contains("do-not-retain"));

    let secret_json = serde_json::to_string(&fixtures.secret).unwrap();
    assert!(!secret_json.contains("opaque-ref/msk/657"));
    assert_eq!(secret_json, "{\"opaque\":true}");
}

#[test]
fn offline_transports_never_claim_native_or_first_party() {
    let fixtures = Fixtures::new();
    let provider =
        AwsMskProvider::new(hartevo_aws_msk_result_plugin::BlockedEnvAwsMskTransport).unwrap();
    assert!(!provider.identity().connected);
    assert!(!provider.identity().native);
    assert!(!provider.identity().first_party);
    let mut transport = hartevo_aws_msk_result_plugin::BlockedEnvAwsMskTransport;
    let request = AwsMskReadRequest::list_clusters(&fixtures.scope, ReadBounds::default()).unwrap();
    assert!(matches!(
        hartevo_aws_msk_result_plugin::AwsMskTransport::read(&mut transport, &request),
        Err(TransportError::BlockedEnvironment)
    ));
}

#[test]
fn contract_and_digest_fields_are_deterministic() {
    let contract = hartevo_aws_msk_result_plugin::AwsMskContract::baseline().unwrap();
    assert_eq!(
        contract.digest(),
        hartevo_aws_msk_result_plugin::contract_digest()
    );
    let fixtures = Fixtures::new();
    assert_ne!(fixtures.scope.digest(), Digest::zero());
    assert_eq!(fixtures.scope.operations.len(), 1);
    let actions = fixtures.permission.allowed_actions.clone();
    assert_eq!(
        actions,
        BTreeSet::from([
            PermissionAction::ListClustersV2,
            PermissionAction::DescribeClusterV2,
            PermissionAction::DescribeConfigurationRevision,
            PermissionAction::ListClusterOperations,
        ])
    );
}
