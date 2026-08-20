use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_gcp_spanner_database_result_plugin::{
    ConfigurationPosture, DatabaseListItem, DatabaseMetadata, DatabaseMetadataInput, Digest,
    FakeTransport, FixtureTransport, GcpProjectId, GcpSpannerAdminProvider,
    GcpSpannerDatabaseEvidenceState, GcpSpannerDatabaseResultContract,
    GcpSpannerDatabaseResultService, GcpSpannerDatabaseScope, GcpSpannerError, GcpSpannerTransport,
    GcpSpannerTransportError, InstanceConfigId, InstanceId, InstanceMetadata,
    InstanceMetadataInput, ListDatabasesRequest, ListDatabasesResponse, MissionBinding,
    MissionGcpSpannerDatabaseConsumer, OpaquePageToken, OperationId, OperationMetadata,
    OperationMetadataInput, OrganizationId, PermissionSnapshot, ProjectBinding, RecordingTransport,
    SecretReference, SpannerDatabaseState, SpannerDialect, SpannerInstanceState,
    SpannerOperationState, TransportProvenance, WorkProductBinding,
};

const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope_with_operation(mission: &str, operation: Option<OperationId>) -> GcpSpannerDatabaseScope {
    GcpSpannerDatabaseScope::new(
        OrganizationId::new("organizations/123").expect("organization"),
        hartevo_gcp_spanner_database_result_plugin::FolderId::new("folders/456").expect("folder"),
        GcpProjectId::new("project-1").expect("gcp project"),
        InstanceId::new("instance-1").expect("instance"),
        hartevo_gcp_spanner_database_result_plugin::DatabaseId::new("database-1")
            .expect("database"),
        SpannerDialect::GoogleStandardSql,
        InstanceConfigId::new("regional-us-central1").expect("instance config"),
        operation,
        ProjectBinding::new("project-binding", 1).expect("project binding"),
        MissionBinding::new(mission, 1).expect("mission"),
        WorkProductBinding::new("work-product", 1).expect("work product"),
    )
    .expect("scope")
}

fn scope() -> GcpSpannerDatabaseScope {
    scope_with_operation(
        "mission-1",
        Some(OperationId::new("operation-1").expect("operation")),
    )
}

fn service(scope: GcpSpannerDatabaseScope) -> GcpSpannerDatabaseResultService<FixtureTransport> {
    let secret = SecretReference::oauth("opaque-oauth-handle", &scope, 1).expect("secret");
    let provider = GcpSpannerAdminProvider::new(
        FixtureTransport::for_scope(&scope, now()).expect("fixture transport"),
    )
    .expect("provider");
    GcpSpannerDatabaseResultService::new(
        scope,
        secret,
        PermissionSnapshot::least_privilege(1).expect("permissions"),
        provider,
        now(),
    )
    .expect("service")
}

fn configuration(scope: &GcpSpannerDatabaseScope) -> ConfigurationPosture {
    ConfigurationPosture::from_raw(
        true,
        Some("customer-key-name"),
        "private-configuration-description",
        scope.instance_config(),
    )
    .expect("configuration")
}

fn custom_recording_service(
    scope: &GcpSpannerDatabaseScope,
    state: SpannerDatabaseState,
) -> GcpSpannerDatabaseResultService<RecordingTransport> {
    let instance_request =
        hartevo_gcp_spanner_database_result_plugin::GetInstanceRequest::for_scope(scope)
            .expect("instance request");
    let database_request =
        hartevo_gcp_spanner_database_result_plugin::GetDatabaseRequest::for_scope(scope)
            .expect("database request");
    let instance = InstanceMetadata::new(
        scope,
        InstanceMetadataInput {
            instance: scope.instance().clone(),
            state: SpannerInstanceState::Ready,
            created_at: now() - Duration::days(2),
            updated_at: now() - Duration::hours(1),
            configuration: configuration(scope),
        },
    )
    .expect("instance metadata");
    let database = DatabaseMetadata::new(
        scope,
        DatabaseMetadataInput {
            project: scope.project().clone(),
            instance: scope.instance().clone(),
            database: scope.database().clone(),
            dialect: scope.dialect(),
            state,
            created_at: now() - Duration::days(1),
            updated_at: now() - Duration::minutes(5),
            configuration: configuration(scope),
        },
    )
    .expect("database metadata");
    let mut transport = RecordingTransport::default();
    transport.push_get_instance_response(Ok(
        hartevo_gcp_spanner_database_result_plugin::GetInstanceResponse::new(
            &instance_request,
            instance,
            512,
            TransportProvenance::Recording,
        )
        .expect("instance response"),
    ));
    transport.push_get_database_response(Ok(
        hartevo_gcp_spanner_database_result_plugin::GetDatabaseResponse::new(
            &database_request,
            database,
            768,
            TransportProvenance::Recording,
        )
        .expect("database response"),
    ));
    if let Some(operation) = scope.operation() {
        let request =
            hartevo_gcp_spanner_database_result_plugin::GetOperationRequest::for_scope(scope)
                .expect("operation request");
        let metadata = OperationMetadata::new(
            scope,
            OperationMetadataInput::new(
                operation.clone(),
                scope.database().clone(),
                SpannerOperationState::Done,
                now() - Duration::minutes(20),
                Some(now() - Duration::minutes(10)),
                Some("provider-private-description"),
            )
            .expect("operation input"),
        )
        .expect("operation metadata");
        transport.push_get_operation_response(Ok(
            hartevo_gcp_spanner_database_result_plugin::GetOperationResponse::new(
                &request,
                metadata,
                256,
                TransportProvenance::Recording,
            )
            .expect("operation response"),
        ));
    }
    let provider = GcpSpannerAdminProvider::new(transport).expect("provider");
    let secret = SecretReference::service_account("opaque-service-account-handle", scope, 1)
        .expect("secret");
    GcpSpannerDatabaseResultService::new(
        scope.clone(),
        secret,
        PermissionSnapshot::least_privilege(1).expect("permissions"),
        provider,
        now(),
    )
    .expect("service")
}

#[test]
fn contract_registration_and_secret_boundary_are_digest_bound() {
    let contract = GcpSpannerDatabaseResultContract::baseline().expect("contract");
    assert_eq!(
        contract.digest().as_str(),
        hartevo_gcp_spanner_database_result_plugin::CONTRACT_DIGEST
    );
    let scope = scope();
    let service = service(scope);
    assert!(service.registration().validate().is_ok());
    let serialized = serde_json::to_string(service.registration()).expect("registration json");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains("opaque-oauth-handle"));
    assert!(!debug.contains("opaque-oauth-handle"));
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().first_party);
    assert!(
        !format!("{:?}", service.registration().secret_reference()).contains("opaque-oauth-handle")
    );
}

#[test]
fn fixture_proposal_is_bounded_redacted_and_non_native() {
    let scope = scope();
    let mut service = service(scope);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, GcpSpannerDatabaseEvidenceState::Ready);
    assert!(proposal.evidence.complete);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    let serialized = serde_json::to_string(&proposal).expect("proposal json");
    for secret in [
        "fixture-key-name",
        "fixture-instance-configuration",
        "fixture-key",
        "private-configuration-description",
    ] {
        assert!(!serialized.contains(secret), "raw value leaked: {secret}");
    }
    let path =
        hartevo_gcp_spanner_database_result_plugin::GetDatabaseRequest::for_scope(service.scope())
            .expect("request")
            .path_and_query();
    assert!(!path.contains("database-1"));
    assert!(path.contains("databases/"));
}

#[test]
fn scope_dialect_and_operation_drift_fail_closed() {
    let scope = scope();
    let wrong_dialect = DatabaseMetadata::new(
        &scope,
        DatabaseMetadataInput {
            project: scope.project().clone(),
            instance: scope.instance().clone(),
            database: scope.database().clone(),
            dialect: SpannerDialect::PostgreSql,
            state: SpannerDatabaseState::Ready,
            created_at: now() - Duration::hours(2),
            updated_at: now() - Duration::hours(1),
            configuration: configuration(&scope),
        },
    );
    assert!(matches!(
        wrong_dialect,
        Err(hartevo_gcp_spanner_database_result_plugin::ModelError::ScopeMismatch { .. })
    ));
    let missing_operation_scope = scope_with_operation("mission-1", None);
    assert!(matches!(
        hartevo_gcp_spanner_database_result_plugin::GetOperationRequest::for_scope(
            &missing_operation_scope
        ),
        Err(GcpSpannerError::ForbiddenOperation)
    ));
    assert!(
        PermissionSnapshot::new(
            [
                hartevo_gcp_spanner_database_result_plugin::GcpSpannerPermission::InstancesGet,
                hartevo_gcp_spanner_database_result_plugin::GcpSpannerPermission::MissionScope,
            ],
            1,
        )
        .is_err()
    );
    assert!(
        PermissionSnapshot::new(
            [hartevo_gcp_spanner_database_result_plugin::GcpSpannerPermission::InstancesGet],
            1,
        )
        .is_err()
    );
}

#[test]
fn opaque_page_tokens_are_bound_and_pagination_is_bounded() {
    let scope = scope();
    let request = ListDatabasesRequest::new(&scope, 2, None).expect("list request");
    let token = OpaquePageToken::new(
        "provider-page-token",
        &scope,
        request.parent_digest().clone(),
        2,
    )
    .expect("opaque token");
    let item = DatabaseListItem::new(
        &scope,
        scope.project().clone(),
        scope.instance().clone(),
        scope.database().clone(),
        scope.dialect(),
        SpannerDatabaseState::Ready,
    )
    .expect("database item");
    let next_request = ListDatabasesRequest::new(&scope, 2, Some(token.clone())).expect("page 2");
    let response = ListDatabasesResponse::new(
        &request,
        vec![item],
        Some(token),
        512,
        TransportProvenance::Recording,
    );
    assert!(response.is_ok());
    assert_eq!(next_request.page_number(), 2);
    let serialized = serde_json::to_string(&next_request).expect("request json");
    assert!(!serialized.contains("provider-page-token"));
    assert!(!format!("{next_request:?}").contains("provider-page-token"));
}

#[test]
fn database_states_project_to_the_exact_layer_one_states() {
    for (provider_state, expected) in [
        (
            SpannerDatabaseState::Creating,
            GcpSpannerDatabaseEvidenceState::Creating,
        ),
        (
            SpannerDatabaseState::Ready,
            GcpSpannerDatabaseEvidenceState::Ready,
        ),
        (
            SpannerDatabaseState::Updating,
            GcpSpannerDatabaseEvidenceState::Updating,
        ),
        (
            SpannerDatabaseState::Restoring,
            GcpSpannerDatabaseEvidenceState::Restoring,
        ),
        (
            SpannerDatabaseState::BackingUp,
            GcpSpannerDatabaseEvidenceState::BackingUp,
        ),
        (
            SpannerDatabaseState::Failed,
            GcpSpannerDatabaseEvidenceState::Failed,
        ),
    ] {
        let scope = scope();
        let mut service = custom_recording_service(&scope, provider_state);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, expected);
        assert!(proposal.evidence.validate_integrity().is_ok());
    }
}

#[test]
fn provider_failures_are_redacted_and_projected_without_claims() {
    for (error, expected) in [
        (
            GcpSpannerTransportError::http_status("GetInstance", 401, "private-401-body"),
            GcpSpannerDatabaseEvidenceState::AccessLost,
        ),
        (
            GcpSpannerTransportError::http_status("GetInstance", 403, "private-403-body"),
            GcpSpannerDatabaseEvidenceState::AccessLost,
        ),
        (
            GcpSpannerTransportError::http_status("GetInstance", 404, "private-404-body"),
            GcpSpannerDatabaseEvidenceState::AccessLost,
        ),
        (
            GcpSpannerTransportError::http_status("GetInstance", 409, "private-409-body"),
            GcpSpannerDatabaseEvidenceState::Partial,
        ),
        (
            GcpSpannerTransportError::http_status("GetInstance", 429, "private-429-body"),
            GcpSpannerDatabaseEvidenceState::ProviderUnknown,
        ),
        (
            GcpSpannerTransportError::server_error("GetInstance", 503),
            GcpSpannerDatabaseEvidenceState::ProviderUnknown,
        ),
        (
            GcpSpannerTransportError::timeout("GetInstance", Digest::from_text("request")),
            GcpSpannerDatabaseEvidenceState::ProviderUnknown,
        ),
    ] {
        let scope = scope();
        let mut transport = RecordingTransport::default();
        transport.push_get_instance_response(Err(error));
        let provider = GcpSpannerAdminProvider::new(transport).expect("provider");
        let secret = SecretReference::oauth("opaque", &scope, 1).expect("secret");
        let mut service = GcpSpannerDatabaseResultService::new(
            scope,
            secret,
            PermissionSnapshot::least_privilege(1).expect("permissions"),
            provider,
            now(),
        )
        .expect("service");
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.evidence.complete);
        assert!(
            !serde_json::to_string(&proposal)
                .expect("json")
                .contains("private-")
        );
        assert!(!proposal.evidence.can_be_adopted());
    }
}

#[test]
fn tamper_replay_revocation_and_stale_mission_fail_closed() {
    let scope = scope();
    let mut svc = service(scope.clone());
    let request = svc.default_request(now()).expect("request");
    let proposal = svc.propose(request).expect("proposal");
    let first_record = svc.record(&proposal).expect("record");
    let replay = svc.record(&proposal).expect("replay");
    assert!(!first_record.replayed);
    assert!(replay.replayed);

    let mut tampered = proposal.clone();
    tampered.evidence.evidence_digest = Digest::from_text("tampered");
    assert!(!svc.verify(&tampered).valid);
    assert!(matches!(
        svc.revoke(),
        Ok(hartevo_gcp_spanner_database_result_plugin::RegistrationTransitionEvidence { .. })
    ));
    assert!(matches!(
        svc.propose(svc.default_request(now()).expect("request")),
        Err(GcpSpannerError::RegistrationInactive)
    ));
    svc.restore_registration().expect("restore");
    let mut consumer = MissionGcpSpannerDatabaseConsumer::new(svc).expect("consumer");
    let request = consumer.service().default_request(now()).expect("request");
    let proposal = consumer.service_mut().propose(request).expect("proposal");
    consumer.consume(&proposal).expect("consume");
    assert!(consumer.consume(&proposal).is_err());

    let stale_scope = scope_with_operation(
        "mission-2",
        Some(OperationId::new("operation-1").expect("operation")),
    );
    let stale_service = service(stale_scope);
    assert!(matches!(
        MissionGcpSpannerDatabaseConsumer::for_mission(stale_service, scope.mission().clone()),
        Err(hartevo_gcp_spanner_database_result_plugin::MissionGcpSpannerDatabaseConsumerError::StaleMission)
    ));
}

#[test]
fn every_local_transport_is_explicitly_non_native_non_connected() {
    let scope = scope();
    let fixture = FixtureTransport::for_scope(&scope, now()).expect("fixture");
    let fake = FakeTransport::for_scope(&scope, now()).expect("fake");
    let loopback =
        hartevo_gcp_spanner_database_result_plugin::LoopbackTransport::for_scope(&scope, now())
            .expect("loopback");
    for provenance in [
        fixture.provenance(),
        fake.provenance(),
        loopback.provenance(),
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }
    let blocked = hartevo_gcp_spanner_database_result_plugin::BlockedEnvTransport;
    assert!(matches!(
        GcpSpannerAdminProvider::new(blocked)
            .expect("provider")
            .provenance(),
        TransportProvenance::BlockedEnv
    ));
}
