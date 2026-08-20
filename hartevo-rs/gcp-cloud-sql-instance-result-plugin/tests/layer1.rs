use chrono::{DateTime, Utc};
use hartevo_gcp_cloud_sql_instance_result_plugin::*;
use serde_json::json;

type TestService = GcpCloudSqlInstanceResultService<RecordingGcpCloudSqlTransport>;

fn observed_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
        .expect("fixed test timestamp")
        .with_timezone(&Utc)
}

fn scope() -> GcpCloudSqlInstanceScope {
    let revision = Revision::new(1).expect("revision");
    GcpCloudSqlInstanceScope::new(
        OrganizationId::new("org-842").expect("organization"),
        ProjectId::new("cloud-project-842").expect("cloud project"),
        InstanceId::new("instance-842").expect("instance"),
        Region::new("us-central1").expect("region"),
        DatabaseVersion::new("MYSQL_8_0").expect("database version"),
        SettingsVersion::new(7).expect("settings version"),
        OperationBinding::new(
            OperationId::new("operation-842").expect("operation"),
            OperationType::Update,
        ),
        ProjectBinding::new(
            ProjectId::new("mission-project-842").expect("project binding"),
            revision,
        ),
        MissionBinding::new(MissionId::new("mission-842").expect("mission"), revision),
        WorkProductBinding::new(
            WorkProductId::new("work-product-842").expect("work product"),
            revision,
        ),
        PermissionFence::for_layer_one(1).expect("permission fence"),
        Digest::from_text("consent-842"),
    )
    .expect("scope")
}

fn service_with_transport<T: GcpCloudSqlAdminTransport>(
    transport: T,
) -> GcpCloudSqlInstanceResultService<T> {
    let scope = scope();
    let secret = SecretReference::for_cloud_sql("oauth-secret-842", &scope).expect("secret");
    let provider = GcpCloudSqlAdminProvider::new(transport).expect("provider");
    GcpCloudSqlInstanceResultService::new(scope, secret, provider).expect("service")
}

fn service() -> TestService {
    service_with_transport(RecordingGcpCloudSqlTransport::new())
}

fn queue_complete(
    service: &mut TestService,
    state: InstanceState,
    operation_status: OperationStatus,
) {
    let scope = service.scope().clone();
    let request = service.default_request(observed_at()).expect("request");
    let list_request =
        ListInstancesRequest::first(&scope, request.page_size()).expect("list request");
    let instance = CloudSqlInstanceSnapshot::minimal(
        &scope,
        state,
        scope.database_version().clone(),
        scope.settings_version(),
        observed_at(),
    )
    .expect("instance snapshot");
    let list_response = ListInstancesResponse::new(
        &list_request,
        vec![instance.clone()],
        None,
        512,
        ProviderProvenance::Recording,
    )
    .expect("list response");
    let get_request = GetInstanceRequest::for_scope(&scope).expect("get request");
    let get_response =
        GetInstanceResponse::new(&get_request, instance, 512, ProviderProvenance::Recording)
            .expect("get response");
    let operation_request = GetOperationRequest::for_scope(&scope).expect("operation request");
    let operation = CloudSqlOperationSnapshot::new(
        &scope,
        OperationSnapshotInput {
            operation_type: scope.operation().operation_type(),
            status: operation_status,
            start_time_digest: None,
            end_time_digest: None,
            error_category_digest: None,
            observed_at: observed_at(),
        },
    )
    .expect("operation snapshot");
    let operation_response = GetOperationResponse::new(
        &operation_request,
        operation,
        512,
        ProviderProvenance::Recording,
    )
    .expect("operation response");

    let transport = service.provider_mut().transport_mut();
    transport.push_list_instances_response(Ok(list_response));
    transport.push_get_instance_response(Ok(get_response));
    transport.push_get_operation_response(Ok(operation_response));
}

#[test]
fn contract_and_authority_are_explicit() {
    let contract = GcpCloudSqlContract::baseline().expect("contract");
    assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
    assert_eq!(
        contract.value()["apiBasis"]["instancesGet"],
        json!("https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances/get")
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
    assert!(!Layer1Authority::truth_authority());
    assert!(!Layer1Authority::consent_authority());
    assert!(!Layer1Authority::effect_authority());
    assert!(!Layer1Authority::verification_authority());
    assert!(!Layer1Authority::outcome_adoption());
}

#[test]
fn scope_secret_and_cursor_are_opaque_and_bound() {
    let scope = scope();
    let secret =
        SecretReference::for_cloud_sql("raw-secret-id-must-not-leak", &scope).expect("secret");
    assert!(secret.is_opaque());
    let secret_json = serde_json::to_string(&secret).expect("secret json");
    assert_eq!(secret_json, r#"{"opaque":true}"#);
    assert!(!format!("{secret:?}").contains("raw-secret-id-must-not-leak"));

    let request = ListInstancesRequest::first(&scope, 10).expect("list request");
    let token = OpaquePageToken::new(
        "provider-page-token-must-not-leak",
        request.binding_digest(),
        2,
    )
    .expect("token");
    assert_eq!(
        serde_json::to_string(&token).expect("token json"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{token:?}").contains("provider-page-token-must-not-leak"));
    assert!(ListInstancesRequest::next(&scope, 10, 2, token.clone()).is_ok());
    assert!(ListInstancesRequest::next(&scope, 11, 2, token).is_err());

    let scope_json = serde_json::to_string(&scope).expect("scope json");
    assert!(!scope_json.contains("org-842"));
    assert!(!scope_json.contains("cloud-project-842"));
    assert!(!scope_json.contains("operation-842"));
    assert!(scope_json.contains(scope.digest().as_str()));
}

#[test]
fn complete_read_proposal_record_consume_and_replay_are_below_kernel_authority() {
    let mut service = service();
    queue_complete(&mut service, InstanceState::Runnable, OperationStatus::Done);
    let proposal = service.propose_default(observed_at()).expect("proposal");
    assert_eq!(proposal.state, GcpCloudSqlResultState::OperationDone);
    assert!(proposal.review_only);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.sql_executed);
    let verification = service.verify(&proposal);
    assert!(verification.verified, "{verification:?}");
    let mut snapshot_tampered = proposal.clone();
    snapshot_tampered
        .instance
        .as_mut()
        .expect("instance evidence")
        .state = InstanceState::Failed;
    assert!(!service.verify(&snapshot_tampered).verified);

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("consume");
    assert!(result.is_review_only());
    assert!(!result.can_be_adopted());
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.outcome_adopted);
    let first_record = consumer
        .record(&proposal, "instance-read-842")
        .expect("record");
    assert!(!first_record.replayed);
    assert_eq!(consumer.record_count(), 1);
    let replay = consumer
        .record(&proposal, "instance-read-842")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.state, GcpCloudSqlResultState::Replay);

    let local_record = service
        .record(&proposal, "service-record-842")
        .expect("service record");
    assert!(!local_record.replayed);
    assert!(service.verify_record(&local_record).verified);
    let service_replay = service
        .record(&proposal, "service-record-842")
        .expect("service replay");
    assert!(service_replay.replayed);
}

#[test]
fn absent_partial_access_loss_and_provider_unknown_are_explicit() {
    let mut absent = service();
    let scope = absent.scope().clone();
    let request = absent.default_request(observed_at()).expect("request");
    let list_request =
        ListInstancesRequest::first(&scope, request.page_size()).expect("list request");
    let list = ListInstancesResponse::new(
        &list_request,
        Vec::new(),
        None,
        128,
        ProviderProvenance::Recording,
    )
    .expect("empty list");
    absent
        .provider_mut()
        .transport_mut()
        .push_list_instances_response(Ok(list));
    assert_eq!(
        absent.propose(request).expect("absent proposal").state,
        GcpCloudSqlResultState::Absent
    );

    let mut partial = service();
    let scope = partial.scope().clone();
    let request = partial
        .request(10, 1, observed_at())
        .expect("bounded request");
    let list_request =
        ListInstancesRequest::first(&scope, request.page_size()).expect("list request");
    let token = OpaquePageToken::new("next-page", list_request.binding_digest(), 2).expect("token");
    let list = ListInstancesResponse::new(
        &list_request,
        Vec::new(),
        Some(token),
        128,
        ProviderProvenance::Recording,
    )
    .expect("partial list");
    partial
        .provider_mut()
        .transport_mut()
        .push_list_instances_response(Ok(list));
    let partial_proposal = partial.propose(request).expect("partial proposal");
    assert_eq!(partial_proposal.state, GcpCloudSqlResultState::Partial);
    assert!(!partial.verify(&partial_proposal).verified);

    let mut access_loss = service();
    access_loss
        .provider_mut()
        .transport_mut()
        .push_list_instances_response(Err(TransportError::Unauthorized));
    let access_proposal = access_loss
        .propose_default(observed_at())
        .expect("access-loss proposal");
    assert_eq!(access_proposal.state, GcpCloudSqlResultState::AccessLoss);

    let mut unknown = service();
    unknown
        .provider_mut()
        .transport_mut()
        .push_list_instances_response(Err(TransportError::Timeout));
    let unknown_proposal = unknown
        .propose_default(observed_at())
        .expect("unknown proposal");
    assert_eq!(
        unknown_proposal.state,
        GcpCloudSqlResultState::ProviderUnknown
    );
}

#[test]
fn parser_is_bounded_redacted_and_binds_operation_identity() {
    let scope = scope();
    let get_request = GetInstanceRequest::for_scope(&scope).expect("get request");
    let body = serde_json::to_vec(&json!({
        "project": "cloud-project-842",
        "name": "instance-842",
        "region": "us-central1",
        "state": "RUNNABLE",
        "databaseVersion": "MYSQL_8_0",
        "replicaNames": ["replica-a"],
        "ipAddresses": [{"ipAddress": "203.0.113.9"}],
        "connectionName": "raw:connection/name",
        "labels": {"secret-label": "raw-label"},
        "settings": {
            "settingsVersion": 7,
            "edition": "ENTERPRISE",
            "availabilityType": "REGIONAL",
            "locationPreference": {"zone": "us-central1-a"},
            "backupConfiguration": {
                "enabled": true,
                "pointInTimeRecoveryEnabled": true,
                "backupRetentionSettings": {"retainedBackups": 4}
            },
            "maintenanceWindow": {"version": "maintenance-version", "description": "raw maintenance"},
            "dataDiskSizeGb": 20,
            "storageAutoResize": true,
            "storageAutoResizeLimit": 100,
            "authorizedNetworks": [{"value": "10.0.0.0/8"}],
            "userLabels": {"raw-user-label": "raw-value"},
            "databaseFlags": [{"name": "raw-flag", "value": "raw-value"}],
            "users": [{"name": "raw-user", "password": "raw-password"}],
            "serverCaCert": {"cert": "raw-cert"}
        }
    }))
    .expect("instance json");
    let response = GcpCloudSqlAdminProvider::<RecordingGcpCloudSqlTransport>::parse_instance_json(
        &get_request,
        200,
        &body,
        observed_at(),
        ProviderProvenance::Recording,
    )
    .expect("parsed instance");
    assert_eq!(response.instance.settings_version.get(), 7);
    assert_eq!(response.instance.replica_count, 1);
    let serialized = serde_json::to_string(&response).expect("redacted response json");
    for forbidden in [
        "203.0.113.9",
        "raw:connection/name",
        "raw-label",
        "10.0.0.0/8",
        "raw-user",
        "raw-cert",
        "raw maintenance",
        "raw-password",
        "raw-flag",
        "raw-value",
    ] {
        assert!(!serialized.contains(forbidden), "leaked {forbidden}");
    }

    let operation_request = GetOperationRequest::for_scope(&scope).expect("operation request");
    let operation_body =
        br#"{"name":"operations/operation-842","operationType":"UPDATE","status":"DONE"}"#;
    let operation =
        GcpCloudSqlAdminProvider::<RecordingGcpCloudSqlTransport>::parse_operation_json(
            &operation_request,
            200,
            operation_body,
            observed_at(),
            ProviderProvenance::Recording,
        )
        .expect("parsed operation");
    assert_eq!(operation.operation.status, OperationStatus::Done);
    let wrong_operation =
        br#"{"name":"operations/other-operation","operationType":"UPDATE","status":"DONE"}"#;
    assert!(matches!(
        GcpCloudSqlAdminProvider::<RecordingGcpCloudSqlTransport>::parse_operation_json(
            &operation_request,
            200,
            wrong_operation,
            observed_at(),
            ProviderProvenance::Recording,
        ),
        Err(GcpCloudSqlAdminProviderError::TamperedResponse)
    ));
}

#[test]
fn status_errors_and_all_fixture_provenances_remain_non_native() {
    let scope = scope();
    let request = GetInstanceRequest::for_scope(&scope).expect("request");
    for status in [400, 401, 403, 404, 409, 429, 500, 503] {
        assert!(
            GcpCloudSqlAdminProvider::<RecordingGcpCloudSqlTransport>::parse_instance_json(
                &request,
                status,
                b"{}",
                observed_at(),
                ProviderProvenance::Recording,
            )
            .is_err()
        );
    }
    for provenance in [
        ProviderProvenance::Recording,
        ProviderProvenance::Fixture,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }
    let blocked = service_with_transport(BlockedEnvGcpCloudSqlTransport);
    assert_eq!(
        blocked.provider().definition().provenance,
        ProviderProvenance::BlockedEnv
    );
}

#[allow(clippy::too_many_lines)]
#[test]
fn lifecycle_mapping_operation_monotonicity_and_topology_fences_are_deterministic() {
    assert_eq!(
        result_state_for_instance(InstanceState::Runnable),
        GcpCloudSqlResultState::Runnable
    );
    assert_eq!(
        result_state_for_instance(InstanceState::Maintenance),
        GcpCloudSqlResultState::Maintenance
    );
    assert_eq!(
        result_state_for_instance(InstanceState::Suspended),
        GcpCloudSqlResultState::Suspended
    );
    assert_eq!(
        result_state_for_instance(InstanceState::Failed),
        GcpCloudSqlResultState::Failed
    );
    assert_eq!(
        result_state_for_instance(InstanceState::PendingCreate),
        GcpCloudSqlResultState::PendingCreate
    );
    assert_eq!(
        result_state_for_instance(InstanceState::PendingDelete),
        GcpCloudSqlResultState::PendingDelete
    );
    assert_eq!(
        result_state_for_operation(OperationStatus::Running),
        GcpCloudSqlResultState::OperationRunning
    );
    assert_eq!(
        result_state_for_operation(OperationStatus::Done),
        GcpCloudSqlResultState::OperationDone
    );
    assert_eq!(
        result_state_for_operation(OperationStatus::Failed),
        GcpCloudSqlResultState::OperationFailed
    );

    let scope = scope();
    let running = CloudSqlOperationSnapshot::new(
        &scope,
        OperationSnapshotInput {
            operation_type: OperationType::Update,
            status: OperationStatus::Running,
            start_time_digest: None,
            end_time_digest: None,
            error_category_digest: None,
            observed_at: observed_at(),
        },
    )
    .expect("running operation");
    let done = CloudSqlOperationSnapshot::new(
        &scope,
        OperationSnapshotInput {
            operation_type: OperationType::Update,
            status: OperationStatus::Done,
            start_time_digest: None,
            end_time_digest: None,
            error_category_digest: None,
            observed_at: observed_at(),
        },
    )
    .expect("done operation");
    assert_eq!(
        running.merge(&done).expect("monotonic merge").status,
        OperationStatus::Done
    );
    assert!(done.merge(&running).is_err());
    let failed = CloudSqlOperationSnapshot::new(
        &scope,
        OperationSnapshotInput {
            operation_type: OperationType::Update,
            status: OperationStatus::Failed,
            start_time_digest: None,
            end_time_digest: None,
            error_category_digest: None,
            observed_at: observed_at(),
        },
    )
    .expect("failed operation");
    assert!(done.merge(&failed).is_err());

    let instance = CloudSqlInstanceSnapshot::minimal(
        &scope,
        InstanceState::Runnable,
        scope.database_version().clone(),
        scope.settings_version(),
        observed_at(),
    )
    .expect("instance");
    let fenced = scope
        .clone()
        .with_topology_fence(instance.topology_digest().clone())
        .expect("matching fence");
    assert!(
        CloudSqlInstanceSnapshot::minimal(
            &fenced,
            InstanceState::Runnable,
            fenced.database_version().clone(),
            fenced.settings_version(),
            observed_at(),
        )
        .is_ok()
    );
    let mismatched = scope
        .with_topology_fence(Digest::from_text("different-topology"))
        .expect("topology fence");
    assert!(
        CloudSqlInstanceSnapshot::minimal(
            &mismatched,
            InstanceState::Runnable,
            mismatched.database_version().clone(),
            mismatched.settings_version(),
            observed_at(),
        )
        .is_err()
    );
}

#[test]
fn registration_is_reversible_and_revocable_and_tamper_is_rejected() {
    let mut service = service();
    queue_complete(
        &mut service,
        InstanceState::Maintenance,
        OperationStatus::Running,
    );
    let proposal = service.propose_default(observed_at()).expect("proposal");
    assert_eq!(proposal.state, GcpCloudSqlResultState::OperationRunning);
    let mut tampered = proposal.clone();
    tampered.state = GcpCloudSqlResultState::Tampered;
    assert!(!service.verify(&tampered).verified);
    assert!(
        service
            .consumer()
            .expect("consumer")
            .consume(&tampered)
            .is_err()
    );

    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.new_state, RegistrationState::Revoked);
    assert!(!service.is_active());
    assert!(matches!(
        service.propose_default(observed_at()),
        Err(GcpCloudSqlInstanceResultServiceError::RegistrationRevoked)
    ));
    let report = service.verify(&proposal);
    assert!(!report.verified);
    assert!(
        report
            .failures
            .contains(&VerificationFailure::RegistrationInactive)
    );
    service.restore_registration().expect("restore");
    assert!(service.is_active());
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.new_state, RegistrationState::Reversed);
    assert!(service.restore_registration().is_err());
}
