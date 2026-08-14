use hartevo_fivetran_sync_result_plugin::*;

fn scope() -> FivetranScope {
    FivetranScope::new(
        FivetranAccountId::new("account-411").expect("account"),
        FivetranGroupId::new("group-411").expect("group"),
        FivetranDestinationId::new("destination-411").expect("destination"),
        FivetranConnectionId::new("connection-411").expect("connection"),
        FivetranSyncId::new("sync-411").expect("sync"),
        FivetranSchemaName::new("source_schema").expect("schema"),
        FivetranTableName::new("orders").expect("table"),
        ProjectId::new("project-411").expect("Project"),
        MissionId::new("mission-411").expect("Mission"),
        WorkProductId::new("work-product-411").expect("Work Product"),
        1,
        2,
        3,
        4,
        5,
        7,
    )
    .expect("scope")
}

fn status(
    setup_state: SetupState,
    sync_state: SyncState,
    update_state: UpdateState,
) -> FivetranStatusPayload {
    FivetranStatusPayload {
        setup_state,
        sync_state,
        update_state,
        schema_status: Some(SchemaStatus::Ready),
        rescheduled_for: None,
        state_revision: 10,
    }
}

fn timestamp(value: &str) -> MetadataTimestamp {
    MetadataTimestamp::new(value).expect("timestamp")
}

fn connection(scope: &FivetranScope, state: FivetranStatusPayload) -> FivetranConnectionPayload {
    FivetranConnectionPayload {
        account_id: Some(scope.account_id.clone()),
        id: scope.connection_id.clone(),
        service: "salesforce".to_owned(),
        schema_name: scope.schema_name.clone(),
        group_id: scope.group_id.clone(),
        destination_id: Some(scope.destination_id.clone()),
        destination_group_id: None,
        destination_type: Some("snowflake".to_owned()),
        status: state,
        succeeded_at: Some(timestamp("2026-08-14T08:00:00Z")),
        failed_at: Some(timestamp("2026-08-13T08:00:00Z")),
        created_at: Some(timestamp("2026-08-01T08:00:00Z")),
        revision: 10,
        partial: false,
    }
}

fn connection_state(
    scope: &FivetranScope,
    state: FivetranStatusPayload,
) -> FivetranConnectionStatePayload {
    FivetranConnectionStatePayload {
        id: Some(scope.connection_id.clone()),
        group_id: Some(scope.group_id.clone()),
        destination_id: Some(scope.destination_id.clone()),
        status: Some(state),
        succeeded_at: Some(timestamp("2026-08-14T08:00:00Z")),
        failed_at: Some(timestamp("2026-08-13T08:00:00Z")),
        revision: 10,
        partial: false,
        state_digest: Digest::from_text("opaque-connection-state-411"),
        state_field_count: 1,
    }
}

fn schemas(scope: &FivetranScope) -> FivetranSchemasPayload {
    FivetranSchemasPayload {
        schema_change_handling: Some(SchemaChangeHandling::AllowColumns),
        schemas: vec![FivetranSchemaMetadata {
            name: scope.schema_name.clone(),
            name_in_destination: Some("source_schema".to_owned()),
            enabled: Some(true),
            tables: vec![FivetranTableMetadata {
                name: scope.table_name.clone(),
                name_in_destination: Some("orders".to_owned()),
                enabled: Some(true),
                sync_mode: Some(SyncMode::Live),
                columns: vec![
                    FivetranColumnMetadata {
                        name: FivetranTableName::new("id").expect("column"),
                        name_in_destination: Some("id".to_owned()),
                        enabled: Some(true),
                        hashed: Some(false),
                        is_primary_key: Some(true),
                    },
                    FivetranColumnMetadata {
                        name: FivetranTableName::new("total").expect("column"),
                        name_in_destination: Some("total".to_owned()),
                        enabled: Some(true),
                        hashed: Some(false),
                        is_primary_key: Some(false),
                    },
                ],
            }],
        }],
        revision: 4,
        partial: false,
    }
}

fn response(endpoint: FivetranEndpoint, payload: FivetranResponsePayload) -> FivetranHttpResponse {
    FivetranHttpResponse::success(
        endpoint,
        payload,
        Some(Digest::from_text("request-411")),
        false,
    )
}

fn refresh_success_digest(response: &mut FivetranHttpResponse) {
    let payload = response.payload.as_ref().expect("success payload");
    response.response_digest =
        Digest::from_serializable(&(200_u16, response.endpoint, payload, response.partial));
}

fn recording_responses(scope: &FivetranScope) -> Vec<FivetranHttpResponse> {
    vec![
        response(
            FivetranEndpoint::GetConnection,
            FivetranResponsePayload::Connection(connection(
                scope,
                status(
                    SetupState::Connected,
                    SyncState::Scheduled,
                    UpdateState::OnSchedule,
                ),
            )),
        ),
        response(
            FivetranEndpoint::GetConnectionState,
            FivetranResponsePayload::ConnectionState(connection_state(
                scope,
                status(
                    SetupState::Connected,
                    SyncState::Scheduled,
                    UpdateState::OnSchedule,
                ),
            )),
        ),
        response(
            FivetranEndpoint::GetConnectionSchemas,
            FivetranResponsePayload::Schemas(schemas(scope)),
        ),
    ]
}

fn provider(
    scope: &FivetranScope,
    responses: Vec<FivetranHttpResponse>,
) -> FivetranProvider<RecordingFivetranTransport> {
    let secret =
        SecretReference::new("vault-ref-fivetran-411", scope, 9).expect("secret reference");
    let registration = FivetranRegistration::new(scope.clone(), secret, 10).expect("registration");
    FivetranProvider::new(
        registration,
        RecordingFivetranTransport::recording(responses),
    )
    .expect("provider")
}

#[test]
fn layer1_flow_captures_exact_scope_status_and_non_native_provenance() {
    validate_contract().expect("versioned contract");
    let scope = scope();
    let mut service = FivetranSyncResultService::new(provider(&scope, recording_responses(&scope)))
        .expect("service");
    service.definition().validate().expect("definition");
    assert!(service.definition().read_only);
    assert!(service.definition().proposal_only);
    assert!(service.definition().recording_only);
    assert!(!service.definition().external_writes);
    assert!(!service.definition().kernel_authority);

    let evidence = service.read_sync_evidence().expect("evidence");
    assert_eq!(evidence.setup_state, SetupState::Connected);
    assert_eq!(evidence.sync_state, SyncState::Scheduled);
    assert_eq!(evidence.update_state, UpdateState::OnSchedule);
    assert_eq!(
        evidence.latest_success_at.as_ref().unwrap().as_str(),
        "2026-08-14T08:00:00Z"
    );
    assert_eq!(
        evidence.latest_failure_at.as_ref().unwrap().as_str(),
        "2026-08-13T08:00:00Z"
    );
    assert!(evidence.schema_fingerprint.is_valid());
    assert!(evidence.table_fingerprint.is_valid());
    assert_eq!(evidence.destination.destination_id, scope.destination_id);
    assert!(evidence.destination.credentials_redacted);
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
    assert!(!evidence.provenance.first_party);
    evidence.validate().expect("evidence digest");

    let proposal = service
        .compile_sync_result_proposal(&evidence)
        .expect("proposal");
    assert!(proposal.verified());
    let recording = service
        .record_sync_projection(&evidence)
        .expect("recording");
    assert!(!recording.durable);
    assert!(!recording.raw_payload_retained);
    let verified = service
        .verify_sync_result(&proposal, &evidence)
        .expect("verified proposal");
    assert_eq!(verified, proposal);

    let consumer =
        MissionFivetranSyncConsumer::from_registration(service.provider().registration())
            .expect("consumer");
    let result = consumer
        .consume_result(proposal, evidence)
        .expect("Mission result");
    assert_eq!(result.observation.scope_digest, scope.digest());
    assert!(!result.observation.work_product_adopted);
    assert!(!result.observation.kernel_authority);
}

#[test]
fn setup_sync_and_update_variants_are_captured_without_native_claims() {
    for (setup_state, sync_state, update_state, expected) in [
        (
            SetupState::Broken,
            SyncState::Paused,
            UpdateState::Delayed,
            FivetranResultState::Broken,
        ),
        (
            SetupState::Incomplete,
            SyncState::Scheduled,
            UpdateState::OnSchedule,
            FivetranResultState::Incomplete,
        ),
        (
            SetupState::Connected,
            SyncState::Syncing,
            UpdateState::OnSchedule,
            FivetranResultState::Syncing,
        ),
        (
            SetupState::Connected,
            SyncState::Paused,
            UpdateState::OnSchedule,
            FivetranResultState::Paused,
        ),
        (
            SetupState::Connected,
            SyncState::Rescheduled,
            UpdateState::Delayed,
            FivetranResultState::Rescheduled,
        ),
        (
            SetupState::Connected,
            SyncState::Scheduled,
            UpdateState::Delayed,
            FivetranResultState::Delayed,
        ),
    ] {
        let scope = scope();
        let mut responses = recording_responses(&scope);
        responses[0] = response(
            FivetranEndpoint::GetConnection,
            FivetranResponsePayload::Connection(connection(
                &scope,
                status(setup_state, sync_state, update_state),
            )),
        );
        responses[1] = response(
            FivetranEndpoint::GetConnectionState,
            FivetranResponsePayload::ConnectionState(connection_state(
                &scope,
                status(setup_state, sync_state, update_state),
            )),
        );
        let mut provider = provider(&scope, responses);
        let evidence = provider.read_sync_evidence().expect("evidence variant");
        assert_eq!(evidence.result_state, expected);
        assert!(!evidence.provenance.is_connected());
        assert!(!evidence.provenance.is_native());
    }
}

#[test]
fn partial_payload_is_explicit_and_never_promoted_to_native() {
    let scope = scope();
    let mut responses = recording_responses(&scope);
    for response in &mut responses {
        response.partial = true;
        refresh_success_digest(response);
    }
    let mut provider = provider(&scope, responses);
    let evidence = provider.read_sync_evidence().expect("partial evidence");
    assert!(evidence.partial);
    assert_eq!(evidence.result_state, FivetranResultState::Partial);
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
}

#[test]
fn bounded_listing_paginates_and_emits_only_metadata() {
    let scope = scope();
    let item = FivetranConnectionSummary {
        id: scope.connection_id.clone(),
        service: "salesforce".to_owned(),
        schema_name: scope.schema_name.clone(),
        group_id: scope.group_id.clone(),
        destination_id: Some(scope.destination_id.clone()),
        status: status(
            SetupState::Connected,
            SyncState::Syncing,
            UpdateState::OnSchedule,
        ),
        succeeded_at: None,
        failed_at: None,
        revision: 10,
        partial: false,
    };
    let page_one = response(
        FivetranEndpoint::ListConnections,
        FivetranResponsePayload::ConnectionList(FivetranConnectionListPayload {
            items: vec![item.clone()],
            next_cursor: Some("cursor-2".to_owned()),
            partial: false,
        }),
    );
    let page_two = response(
        FivetranEndpoint::ListConnections,
        FivetranResponsePayload::ConnectionList(FivetranConnectionListPayload {
            items: vec![item],
            next_cursor: None,
            partial: false,
        }),
    );
    let mut provider = provider(&scope, vec![page_one, page_two]);
    let projection = provider
        .list_connections_bounded(&ConnectionListRequest::for_scope(&scope))
        .expect("listing");
    assert_eq!(projection.items.len(), 2);
    assert_eq!(projection.pages_read, 2);
    assert!(!projection.partial);
    assert_eq!(
        provider.transport().requests()[1].cursor.as_deref(),
        Some("cursor-2")
    );
    let serialized = serde_json::to_string(&projection).expect("projection serializes");
    assert!(!serialized.contains("config"));
    assert!(!serialized.contains("password"));
}

#[test]
fn pagination_replay_and_scope_drift_fail_closed() {
    let scope = scope();
    let item = FivetranConnectionSummary {
        id: scope.connection_id.clone(),
        service: "salesforce".to_owned(),
        schema_name: scope.schema_name.clone(),
        group_id: scope.group_id.clone(),
        destination_id: Some(scope.destination_id.clone()),
        status: status(
            SetupState::Connected,
            SyncState::Scheduled,
            UpdateState::OnSchedule,
        ),
        succeeded_at: None,
        failed_at: None,
        revision: 10,
        partial: false,
    };
    let repeated = response(
        FivetranEndpoint::ListConnections,
        FivetranResponsePayload::ConnectionList(FivetranConnectionListPayload {
            items: vec![item],
            next_cursor: Some("same".to_owned()),
            partial: false,
        }),
    );
    let repeated_again = repeated.clone();
    let mut repeated_provider = provider(&scope, vec![repeated, repeated_again]);
    assert_eq!(
        repeated_provider
            .list_connections_bounded(&ConnectionListRequest::for_scope(&scope))
            .expect_err("repeated cursor"),
        FivetranError::CursorRepeated
    );

    let mut drifted_item = FivetranConnectionSummary {
        id: scope.connection_id.clone(),
        service: "salesforce".to_owned(),
        schema_name: scope.schema_name.clone(),
        group_id: FivetranGroupId::new("other-group").expect("other group"),
        destination_id: None,
        status: status(
            SetupState::Connected,
            SyncState::Scheduled,
            UpdateState::OnSchedule,
        ),
        succeeded_at: None,
        failed_at: None,
        revision: 10,
        partial: false,
    };
    let drift_response = response(
        FivetranEndpoint::ListConnections,
        FivetranResponsePayload::ConnectionList(FivetranConnectionListPayload {
            items: vec![drifted_item.clone()],
            next_cursor: None,
            partial: false,
        }),
    );
    drifted_item.group_id = FivetranGroupId::new("other-group-2").expect("other group 2");
    let mut drift_provider = provider(&scope, vec![drift_response]);
    assert_eq!(
        drift_provider
            .list_connections_bounded(&ConnectionListRequest::for_scope(&scope))
            .expect_err("scope drift"),
        FivetranError::PaginationScopeDrift
    );
}

#[test]
fn monotonic_sync_revision_and_drift_are_enforced() {
    let scope = scope();
    let mut first = recording_responses(&scope);
    let mut second = recording_responses(&scope);
    for response in &mut second[0..2] {
        match response.payload.as_mut().expect("payload") {
            FivetranResponsePayload::Connection(payload) => {
                payload.revision = 9;
                payload.status.state_revision = 9;
            }
            FivetranResponsePayload::ConnectionState(payload) => {
                payload.revision = 9;
                payload
                    .status
                    .as_mut()
                    .expect("state status")
                    .state_revision = 9;
            }
            _ => unreachable!("connection response expected"),
        }
        refresh_success_digest(response);
    }
    first.append(&mut second);
    let mut monotonic_provider = provider(&scope, first);
    monotonic_provider
        .read_sync_evidence()
        .expect("first evidence");
    assert_eq!(
        monotonic_provider
            .read_sync_evidence()
            .expect_err("stale revision"),
        FivetranError::NonMonotonicSyncState {
            previous: 10,
            observed: 9,
        }
    );

    let mut destination_drift = recording_responses(&scope);
    if let Some(FivetranResponsePayload::Connection(payload)) =
        destination_drift[0].payload.as_mut()
    {
        payload.destination_id =
            Some(FivetranDestinationId::new("other-destination").expect("other destination"));
    }
    refresh_success_digest(&mut destination_drift[0]);
    let mut drift_provider = provider(&scope, destination_drift);
    assert_eq!(
        drift_provider
            .describe_connection()
            .expect_err("destination drift"),
        FivetranError::DestinationDrift
    );
}

#[test]
fn http_errors_backoff_and_blocked_env_are_explicit() {
    let scope = scope();
    for (status_code, expected) in [
        (401, FivetranError::Unauthorized),
        (403, FivetranError::Forbidden),
        (404, FivetranError::NotFound),
        (409, FivetranError::Conflict),
        (500, FivetranError::ServerFailure { status: 500 }),
    ] {
        let mut provider = provider(
            &scope,
            vec![FivetranHttpResponse::error(
                FivetranEndpoint::GetConnection,
                status_code,
                None,
            )],
        );
        assert_eq!(
            provider.describe_connection().expect_err("HTTP error"),
            expected
        );
    }

    let mut limited = provider(
        &scope,
        vec![FivetranHttpResponse::error(
            FivetranEndpoint::GetConnection,
            429,
            Some(17),
        )],
    );
    assert_eq!(
        limited.describe_connection().expect_err("rate limit"),
        FivetranError::RateLimited {
            retry_after_seconds: Some(17),
        }
    );
    assert_eq!(limited.backoff().suggested_delay_seconds, 17);
    assert!(!limited.backoff().sleeping_performed);

    let mut timed = provider(
        &scope,
        vec![FivetranHttpResponse::timeout(
            FivetranEndpoint::GetConnection,
        )],
    );
    assert_eq!(
        timed.describe_connection().expect_err("timeout"),
        FivetranError::Timeout
    );

    let secret = SecretReference::new("vault-ref-blocked", &scope, 1).expect("secret");
    let registration = FivetranRegistration::new(scope, secret, 1).expect("registration");
    let mut blocked =
        FivetranProvider::new(registration, BlockedEnvFivetranTransport).expect("blocked provider");
    assert_eq!(
        blocked.describe_connection().expect_err("blocked env"),
        FivetranError::BlockedEnv
    );
    assert_eq!(blocked.transport().mode(), TransportMode::BlockedEnv);
    assert!(!blocked.transport().mode().connected());
    assert!(!blocked.transport().mode().native());
}

#[test]
fn malformed_json_is_rejected_and_sensitive_wire_fields_are_not_retained() {
    let scope = scope();
    let json = format!(
        r#"{{"code":"Success","message":"ok","data":{{"id":"{}","service":"salesforce","schema":"{}","group_id":"{}","status":{{"setup_state":"connected","sync_state":"syncing","update_state":"on_schedule","tasks":[{{"details":"source secret"}}]}},"config":{{"password":"do-not-retain"}},"account_id":"{}","destination_id":"{}","succeeded_at":"2026-08-14T08:00:00Z","revision":10}}}}"#,
        scope.connection_id,
        scope.schema_name,
        scope.group_id,
        scope.account_id,
        scope.destination_id,
    );
    let parsed = response_from_json(FivetranEndpoint::GetConnection, 200, &json, None)
        .expect("bounded JSON response");
    let serialized = serde_json::to_string(&parsed).expect("typed response");
    assert!(!serialized.contains("do-not-retain"));
    assert!(!serialized.contains("source secret"));

    let state_response = response_from_json(
        FivetranEndpoint::GetConnectionState,
        200,
        r#"{"code":"Success","data":{"state":{"cursor":"source secret"}}}"#,
        None,
    )
    .expect("opaque connection state");
    let state_serialized = serde_json::to_string(&state_response).expect("state response");
    assert!(!state_serialized.contains("source secret"));
    match state_response.payload.expect("state payload") {
        FivetranResponsePayload::ConnectionState(state) => {
            assert!(state.state_digest.is_valid());
            assert_eq!(state.state_field_count, 1);
            assert!(state.id.is_none());
        }
        _ => panic!("state endpoint returned the wrong payload"),
    }

    let schema_response = response_from_json(
        FivetranEndpoint::GetConnectionSchemas,
        200,
        r#"{"code":"Success","data":{"enable_new_by_default":true,"schemas":{"source_schema":{"name_in_destination":"source_schema","enabled":true,"tables":{"orders":{"sync_mode":"LIVE","name_in_destination":"orders","enabled":true,"columns":{"id":{"name_in_destination":"id","enabled":true,"hashed":false,"is_primary_key":true}}}}}},"schema_change_handling":"ALLOW_ALL"}}"#,
        None,
    )
    .expect("schema map response");
    match schema_response.payload.expect("schema payload") {
        FivetranResponsePayload::Schemas(schemas) => {
            assert_eq!(schemas.schemas.len(), 1);
            assert_eq!(schemas.schemas[0].tables.len(), 1);
            assert_eq!(schemas.schemas[0].tables[0].columns.len(), 1);
        }
        _ => panic!("schema endpoint returned the wrong payload"),
    }
    assert!(response_from_json(FivetranEndpoint::GetConnection, 200, "not-json", None).is_err());
}

#[test]
fn secret_registration_is_opaque_reversible_and_revocable() {
    let scope = scope();
    let secret = SecretReference::new("vault-ref-opaque-411", &scope, 12).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("vault-ref-opaque-411"));
    let registration_json = serde_json::to_string(
        &FivetranRegistration::new(scope.clone(), secret, 12).expect("registration"),
    )
    .expect("registration serializes without secret");
    assert!(!registration_json.contains("vault-ref-opaque-411"));
    assert!(!registration_json.contains("api_secret"));

    let secret = SecretReference::new("vault-ref-transition-411", &scope, 12).expect("secret");
    let mut registration =
        FivetranRegistration::new(scope.clone(), secret, 12).expect("registration");
    assert_eq!(registration.status, RegistrationStatus::Active);
    registration.unmount().expect("unmount");
    assert_eq!(registration.status, RegistrationStatus::Unmounted);
    registration.remount().expect("remount");
    registration.revoke().expect("revoke");
    assert_eq!(registration.status, RegistrationStatus::Revoked);
    assert!(registration.secret_reference().is_revoked());
    registration.reverse().expect("reverse");
    assert_eq!(registration.status, RegistrationStatus::Reversed);
    assert!(FivetranProvider::new(registration, BlockedEnvFivetranTransport).is_err());
}

#[test]
fn stale_mission_revision_and_tamper_are_rejected() {
    let scope = scope();
    let mut provider = provider(&scope, recording_responses(&scope));
    let evidence = provider.read_sync_evidence().expect("evidence");
    let consumer = MissionFivetranSyncConsumer::new(scope.clone()).expect("consumer");
    let mut stale = evidence.clone();
    stale.mission_revision += 1;
    assert!(matches!(
        consumer.consume_evidence(stale),
        Err(FivetranError::StaleMissionRevision { .. })
    ));

    let proposal = FivetranSyncResultProposal::from_evidence(&evidence);
    let mut tampered = proposal.clone();
    tampered.work_product_adopted = true;
    assert!(provider.verify_sync_result(&tampered, &evidence).is_err());
    provider
        .record_sync_projection(&evidence)
        .expect("first recording");
    assert_eq!(
        provider
            .record_sync_projection(&evidence)
            .expect_err("replay"),
        FivetranError::ReplayDetected {
            subject: "sync evidence",
        }
    );
}

#[test]
fn no_layer1_mutation_surface_is_authoritative() {
    let scope = scope();
    let provider = provider(&scope, Vec::new());
    assert_eq!(
        provider
            .reject_write("trigger_sync")
            .expect_err("trigger blocked"),
        FivetranError::MutationForbidden {
            operation: "trigger_sync",
        }
    );
    assert_eq!(
        provider
            .reject_write("mutate_schema")
            .expect_err("schema mutation blocked"),
        FivetranError::MutationForbidden {
            operation: "mutate_schema",
        }
    );
}
