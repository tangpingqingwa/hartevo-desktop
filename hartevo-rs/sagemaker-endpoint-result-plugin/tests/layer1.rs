use hartevo_sagemaker_endpoint_result_plugin::*;

const TOKEN: &str = "sigv4-access-key-and-session-token-must-not-escape";

fn digest(seed: u8) -> Digest {
    Digest::from_bytes(&[seed; 16])
}

fn scope() -> SageMakerScope {
    let variant = ProductionVariantName::new("blue").expect("variant");
    SageMakerScope::new(
        AwsPartition::new("aws").expect("partition"),
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        SageMakerEndpointName::new("model-endpoint").expect("endpoint"),
        "arn:aws:sagemaker:us-east-1:123456789012:endpoint/model-endpoint",
        SageMakerEndpointConfigName::new("model-config").expect("config"),
        "arn:aws:sagemaker:us-east-1:123456789012:endpoint-config/model-config",
        variant.clone(),
        ModelName::new("model-v1").expect("model"),
        ModelRevision::new("revision-001").expect("model revision"),
        ImageReference::new("123456789012.dkr.ecr.us-east-1.amazonaws.com/model@sha256:container")
            .expect("image"),
        digest(2),
        digest(3),
        TrafficSnapshot::single(variant).expect("traffic"),
        DeploymentVerificationObjective::new(
            ObjectiveId::new("objective-1").expect("objective"),
            4,
            digest(4),
        )
        .expect("objective binding"),
        ProjectId::new("project-393").expect("Project"),
        MissionId::new("mission-393").expect("Mission"),
        WorkProductId::new("work-product-393").expect("Work Product"),
        11,
        13,
        SageMakerPermissionSnapshot::read_only_default("permissions-r1").expect("permissions"),
    )
    .expect("scope")
}

fn endpoint_variant(
    scope: &SageMakerScope,
    status: ProductionVariantStatus,
    weight: TrafficWeight,
) -> EndpointProductionVariantRecord {
    EndpointProductionVariantRecord::new(
        scope.production_variant_name.clone(),
        weight,
        Some(weight),
        status,
        None,
        scope.model_name.clone(),
        scope.model_revision.clone(),
        scope.image_reference.clone(),
        scope.code_digest.clone(),
        scope.config_digest.clone(),
    )
    .expect("endpoint variant")
}

fn endpoint(scope: &SageMakerScope, status: SageMakerEndpointStatus) -> EndpointDescriptionRecord {
    EndpointDescriptionRecord {
        aws_account_id: scope.aws_account_id.clone(),
        aws_region: scope.aws_region.clone(),
        endpoint_name: scope.endpoint_name.clone(),
        endpoint_arn_digest: scope.endpoint_arn_digest.clone(),
        endpoint_config_name: scope.endpoint_config_name.clone(),
        status,
        failure_reason: None,
        creation_time: Some(MetadataTimestamp::new("2026-08-14T00:00:00Z").expect("creation")),
        last_modified_time: Some(MetadataTimestamp::new("2026-08-14T00:01:00Z").expect("modified")),
        production_variants: vec![endpoint_variant(
            scope,
            ProductionVariantStatus::stable(),
            TrafficWeight::FULL,
        )],
        request_id_digest: Some(digest(5)),
        partial: false,
        access_lost: false,
    }
}

fn config_variant(scope: &SageMakerScope) -> EndpointConfigProductionVariantRecord {
    EndpointConfigProductionVariantRecord::new(
        scope.production_variant_name.clone(),
        TrafficWeight::FULL,
        scope.model_name.clone(),
        scope.model_revision.clone(),
        scope.image_reference.clone(),
        scope.code_digest.clone(),
    )
    .expect("config variant")
}

fn endpoint_config(scope: &SageMakerScope) -> EndpointConfigDescriptionRecord {
    EndpointConfigDescriptionRecord {
        aws_account_id: scope.aws_account_id.clone(),
        aws_region: scope.aws_region.clone(),
        endpoint_config_name: scope.endpoint_config_name.clone(),
        endpoint_config_arn_digest: scope.endpoint_config_arn_digest.clone(),
        config_digest: scope.config_digest.clone(),
        creation_time: Some(MetadataTimestamp::new("2026-08-14T00:00:00Z").expect("creation")),
        execution_role_digest: Some(digest(6)),
        network_isolation: Some(true),
        production_variants: vec![config_variant(scope)],
        partial: false,
        access_lost: false,
    }
}

fn registration(scope: &SageMakerScope) -> SageMakerRegistration {
    SageMakerRegistration::new(
        scope.clone(),
        SecretReference::new("opaque-sigv4-reference", scope, 2).expect("secret reference"),
        7,
    )
    .expect("registration")
}

fn make_provider(
    scope: &SageMakerScope,
    endpoint: EndpointDescriptionRecord,
    endpoint_config: EndpointConfigDescriptionRecord,
) -> SageMakerProvider<RecordingSageMakerTransport, StaticSigV4CredentialResolver> {
    SageMakerProvider::new(
        registration(scope),
        RecordingSageMakerTransport::recording(endpoint, endpoint_config),
        StaticSigV4CredentialResolver::new(TOKEN),
    )
    .expect("provider")
}

fn ready_service(
    scope: &SageMakerScope,
) -> SageMakerEndpointResultService<RecordingSageMakerTransport, StaticSigV4CredentialResolver> {
    SageMakerEndpointResultService::new(make_provider(
        scope,
        endpoint(scope, SageMakerEndpointStatus::InService),
        endpoint_config(scope),
    ))
    .expect("service")
}

#[test]
fn ready_flow_seals_exact_scope_and_mission_proposal() {
    let scope = scope();
    let registration = registration(&scope);
    let mut service = ready_service(&scope);
    let description = service.describe_endpoint().expect("endpoint description");
    assert_eq!(description.endpoint_config_name, scope.endpoint_config_name);
    assert!(!description.native_connected);
    assert!(!description.first_party);
    let config = service
        .describe_endpoint_config()
        .expect("config description");
    assert_eq!(config.config_digest, scope.config_digest);
    assert!(!config.native_connected);
    let evidence = service.read_evidence().expect("evidence");
    assert_eq!(evidence.state, SageMakerResultState::Ready);
    assert_eq!(evidence.endpoint_name, scope.endpoint_name);
    assert_eq!(evidence.variant_name, scope.production_variant_name);
    assert_eq!(evidence.traffic, scope.traffic);
    assert!(!evidence.provenance.is_connected());
    assert!(!evidence.provenance.is_native());
    assert!(!evidence.provenance.is_first_party());
    let receipt = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    let proposal = service
        .compile_model_deployment_proposal(&evidence)
        .expect("proposal");
    let verified = service
        .verify_deployment_result(&proposal, &evidence, &receipt)
        .expect("verified proposal");
    assert!(verified.verified());
    let consumer = MissionSageMakerDeploymentConsumer::from_registration(&registration)
        .expect("Mission consumer");
    let mission_result = consumer.consume_result(&verified).expect("Mission result");
    mission_result.validate().expect("Mission result validates");
    assert!(!mission_result.durable_adoption);
    assert!(!mission_result.kernel_authority);
}

#[test]
fn fixture_fake_loopback_and_blocked_env_never_claim_native_connected_or_first_party() {
    let scope = scope();
    for provenance_transport in [
        RecordingSageMakerTransport::fake(
            endpoint(&scope, SageMakerEndpointStatus::InService),
            endpoint_config(&scope),
        ),
        RecordingSageMakerTransport::fixture(
            endpoint(&scope, SageMakerEndpointStatus::InService),
            endpoint_config(&scope),
        ),
        RecordingSageMakerTransport::loopback(
            endpoint(&scope, SageMakerEndpointStatus::InService),
            endpoint_config(&scope),
        ),
    ] {
        let registration = registration(&scope);
        let mut provider = SageMakerProvider::new(
            registration,
            provenance_transport,
            StaticSigV4CredentialResolver::new(TOKEN),
        )
        .expect("provider");
        let evidence = provider.read_evidence().expect("evidence");
        assert!(!evidence.native_connected);
        assert!(!evidence.first_party);
        assert!(!evidence.provenance.is_connected());
        assert!(!evidence.provenance.is_native());
        assert!(!evidence.provenance.is_first_party());
    }
    let mut blocked = SageMakerProvider::new(
        registration(&scope),
        RecordingSageMakerTransport::blocked_env(
            endpoint(&scope, SageMakerEndpointStatus::InService),
            endpoint_config(&scope),
        ),
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.read_evidence(),
        Err(SageMakerEndpointResultError::BlockedEnv)
    );
    assert_eq!(blocked.state(), SageMakerProviderState::BlockedEnv);
}

#[test]
fn endpoint_status_transitions_and_failure_reasons_are_typed_non_adoptable_evidence() {
    let cases = [
        (
            SageMakerEndpointStatus::Creating,
            SageMakerResultState::Creating,
        ),
        (
            SageMakerEndpointStatus::Updating,
            SageMakerResultState::Updating,
        ),
        (
            SageMakerEndpointStatus::SystemUpdating,
            SageMakerResultState::SystemUpdating,
        ),
        (
            SageMakerEndpointStatus::RollingBack,
            SageMakerResultState::RollingBack,
        ),
        (
            SageMakerEndpointStatus::OutOfService,
            SageMakerResultState::OutOfService,
        ),
        (
            SageMakerEndpointStatus::Deleting,
            SageMakerResultState::Deleting,
        ),
        (
            SageMakerEndpointStatus::Failed,
            SageMakerResultState::Failed,
        ),
        (
            SageMakerEndpointStatus::UpdateRollbackFailed,
            SageMakerResultState::UpdateRollbackFailed,
        ),
        (
            SageMakerEndpointStatus::provider("FutureStatus").expect("unknown status"),
            SageMakerResultState::ProviderUnknown,
        ),
    ];
    for (status, expected) in cases {
        let scope = scope();
        let mut record = endpoint(&scope, status);
        if matches!(
            record.status,
            SageMakerEndpointStatus::Failed | SageMakerEndpointStatus::UpdateRollbackFailed
        ) {
            record.failure_reason =
                Some(FailureReason::new("container rollout failed").expect("reason"));
        }
        let mut provider = make_provider(&scope, record, endpoint_config(&scope));
        let evidence = provider.read_evidence().expect("typed status evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.is_adoptable());
        if matches!(
            expected,
            SageMakerResultState::Failed | SageMakerResultState::UpdateRollbackFailed
        ) {
            assert_eq!(
                evidence.failure_reason.as_ref().expect("failure").message,
                "container rollout failed"
            );
        }
        assert!(
            provider
                .compile_model_deployment_proposal(&evidence)
                .is_err()
        );
    }
}

#[test]
fn same_name_replacement_config_drift_and_model_fences_fail_closed() {
    let scope = scope();
    let mut replaced = endpoint(&scope, SageMakerEndpointStatus::InService);
    replaced.endpoint_arn_digest = digest(99);
    let mut provider = make_provider(&scope, replaced, endpoint_config(&scope));
    assert_eq!(
        provider.read_evidence().expect_err("replacement"),
        SageMakerEndpointResultError::SameNameReplacement
    );

    let mut drifted_config = endpoint_config(&scope);
    drifted_config.config_digest = digest(98);
    let mut provider = make_provider(
        &scope,
        endpoint(&scope, SageMakerEndpointStatus::InService),
        drifted_config,
    );
    assert_eq!(
        provider.read_evidence().expect_err("config drift"),
        SageMakerEndpointResultError::ConfigDigestMismatch
    );

    let mut drifted_variant = endpoint(&scope, SageMakerEndpointStatus::InService);
    drifted_variant.production_variants[0].model_revision =
        ModelRevision::new("revision-002").expect("revision");
    let mut provider = make_provider(&scope, drifted_variant, endpoint_config(&scope));
    assert_eq!(
        provider.read_evidence().expect_err("model revision drift"),
        SageMakerEndpointResultError::ModelRevisionDrift
    );
}

#[test]
fn traffic_and_variant_status_mismatch_are_non_adoptable_typed_states() {
    let scope = scope();
    let mut traffic_drift = endpoint(&scope, SageMakerEndpointStatus::InService);
    let other_variant = EndpointProductionVariantRecord::new(
        ProductionVariantName::new("green").expect("other variant"),
        TrafficWeight::from_percent(50).expect("weight"),
        None,
        ProductionVariantStatus::stable(),
        None,
        scope.model_name.clone(),
        scope.model_revision.clone(),
        scope.image_reference.clone(),
        scope.code_digest.clone(),
        scope.config_digest.clone(),
    )
    .expect("other variant");
    traffic_drift.production_variants[0].current_weight =
        TrafficWeight::from_percent(50).expect("weight");
    traffic_drift.production_variants.push(other_variant);
    let mut provider = make_provider(&scope, traffic_drift, endpoint_config(&scope));
    let evidence = provider.read_evidence().expect("traffic evidence");
    assert_eq!(evidence.state, SageMakerResultState::TrafficMismatch);
    assert!(!evidence.is_adoptable());

    let mut pending = endpoint(&scope, SageMakerEndpointStatus::InService);
    pending.production_variants[0].status = ProductionVariantStatus::Baking;
    let mut provider = make_provider(&scope, pending, endpoint_config(&scope));
    let evidence = provider.read_evidence().expect("variant status evidence");
    assert_eq!(evidence.state, SageMakerResultState::VariantStatusMismatch);
    assert!(!evidence.is_adoptable());
}

#[test]
fn http_faults_timeout_malformed_partial_and_access_loss_are_preserved() {
    let cases = [
        (
            SageMakerTransportError::BadRequest,
            SageMakerEndpointResultError::BadRequest,
        ),
        (
            SageMakerTransportError::Unauthorized,
            SageMakerEndpointResultError::Unauthorized,
        ),
        (
            SageMakerTransportError::Forbidden,
            SageMakerEndpointResultError::Forbidden,
        ),
        (
            SageMakerTransportError::NotFound,
            SageMakerEndpointResultError::NotFound,
        ),
        (
            SageMakerTransportError::Conflict,
            SageMakerEndpointResultError::Conflict,
        ),
        (
            SageMakerTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            SageMakerEndpointResultError::RateLimited {
                retry_after_seconds: Some(9),
            },
        ),
        (
            SageMakerTransportError::Timeout,
            SageMakerEndpointResultError::Timeout,
        ),
        (
            SageMakerTransportError::ServerError { status: 503 },
            SageMakerEndpointResultError::ServerError { status: 503 },
        ),
        (
            SageMakerTransportError::MalformedResponse,
            SageMakerEndpointResultError::MalformedResponse,
        ),
        (
            SageMakerTransportError::PartialResponse,
            SageMakerEndpointResultError::PartialResponse,
        ),
        (
            SageMakerTransportError::ResponseTooLarge,
            SageMakerEndpointResultError::ResponseTooLarge,
        ),
        (
            SageMakerTransportError::AccessLost,
            SageMakerEndpointResultError::AccessLost,
        ),
    ];
    for (fault, expected) in cases {
        let scope = scope();
        let transport = RecordingSageMakerTransport::recording(
            endpoint(&scope, SageMakerEndpointStatus::InService),
            endpoint_config(&scope),
        );
        transport.set_fault(fault);
        let mut provider = SageMakerProvider::new(
            registration(&scope),
            transport,
            StaticSigV4CredentialResolver::new(TOKEN),
        )
        .expect("provider");
        assert_eq!(
            provider.read_evidence().expect_err("transport fault"),
            expected
        );
    }

    let scope = scope();
    let mut endpoint_record = endpoint(&scope, SageMakerEndpointStatus::InService);
    endpoint_record.access_lost = true;
    let mut provider = make_provider(&scope, endpoint_record, endpoint_config(&scope));
    let evidence = provider.read_evidence().expect("access loss evidence");
    assert_eq!(evidence.state, SageMakerResultState::AccessLost);
    assert!(!evidence.is_adoptable());
}

#[test]
fn duplicate_replay_tamper_stale_mission_and_revocation_fail_closed() {
    let scope = scope();
    let mut service = ready_service(&scope);
    let evidence = service.read_evidence().expect("evidence");
    let first = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    let replay = service
        .record_deployment_receipt(&evidence)
        .expect("idempotent replay");
    assert_eq!(first, replay);
    let proposal = service
        .compile_model_deployment_proposal(&evidence)
        .expect("proposal");
    let report = service.verify_deployment_result_report(&proposal, &evidence, &first);
    assert!(report.verified());

    let mut tampered = evidence.clone();
    tampered.endpoint_digest = digest(77);
    assert_eq!(
        tampered.validate().expect_err("tamper"),
        SageMakerEndpointResultError::InvalidEvidence
    );
    let mut alternate = evidence.clone();
    alternate.observed_at = MetadataTimestamp::new("layer1-recorded-later").expect("timestamp");
    alternate.evidence_digest = alternate.computed_digest();
    assert_eq!(
        service
            .record_deployment_receipt(&alternate)
            .expect_err("divergent duplicate"),
        SageMakerEndpointResultError::DuplicateFingerprint
    );

    assert_eq!(
        SageMakerReadRequest::new(
            scope.clone(),
            scope.mission_revision + 1,
            scope.work_product_revision
        )
        .expect_err("stale Mission"),
        SageMakerEndpointResultError::StaleMissionRevision
    );
    assert_eq!(
        SageMakerReadRequest::new(
            scope.clone(),
            scope.mission_revision,
            scope.work_product_revision + 1
        )
        .expect_err("stale Work Product"),
        SageMakerEndpointResultError::StaleWorkProductRevision
    );
    service.revoke().expect("revocation");
    assert_eq!(
        service.read_evidence(),
        Err(SageMakerEndpointResultError::RegistrationRevoked)
    );
}

#[test]
fn bounded_redaction_and_mutation_fences_hold() {
    let scope = scope();
    let secret = SecretReference::new("private-sigv4-secret-key-session-token", &scope, 5)
        .expect("opaque reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("private-sigv4-secret"));
    assert!(
        !serde_json::to_string(&secret)
            .expect("secret JSON")
            .contains("session-token")
    );
    let reason = FailureReason::new("failed with secret token abc").expect("reason");
    assert_eq!(reason.message, "[REDACTED]");
    assert!(
        !serde_json::to_string(&ImageReference::new("secret-image-reference").expect("image"))
            .expect("image JSON")
            .contains("secret-image-reference")
    );

    let mut service = ready_service(&scope);
    let evidence = service.read_evidence().expect("evidence");
    let mut receipt = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    receipt.status_digest = digest(88);
    receipt.receipt_digest = receipt.computed_digest();
    assert_eq!(
        receipt
            .validate_against(&evidence, &evidence.registration_digest)
            .expect_err("receipt tamper"),
        SageMakerEndpointResultError::ReceiptMismatch
    );
    for operation in [
        "CreateEndpoint",
        "UpdateEndpoint",
        "DeleteEndpoint",
        "traffic mutation",
        "capacity mutation",
        "InvokeEndpoint",
        "raw logs",
        "data capture payload",
    ] {
        assert_eq!(
            service.reject_write(operation),
            Err(SageMakerEndpointResultError::MutationForbidden { operation })
        );
    }
    assert!(!format!("{:?}", service.provider()).contains(TOKEN));
}

#[test]
fn native_sigv4_transport_is_an_explicit_blocked_layer_two_gap() {
    let scope = scope();
    let provider = SageMakerProvider::new(
        registration(&scope),
        SigV4SageMakerTransport,
        BlockedEnvCredentialResolver,
    )
    .expect("provider");
    assert_eq!(provider.native_status(), NativeStatus::BlockedEnv);
    assert!(!provider.native_connected());
    assert_eq!(provider.provenance(), ProviderProvenance::BlockedEnv);
}
