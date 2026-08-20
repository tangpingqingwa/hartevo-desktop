use hartevo_cockroach_cloud_result_plugin::{
    API_REVISION, BLOCKED_ENV, BranchId, BranchScope, CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, CloudProjectId, CloudProjectScope, ClusterId, ClusterScope, ClusterState,
    CockroachCloudPage, CockroachCloudProvider, CockroachCloudReadRequest,
    CockroachCloudResultError, CockroachCloudResultService, CockroachCloudScope,
    CockroachCloudTransportError, DatabaseId, DatabaseScope, Digest, EvidenceState,
    FixtureTransport, HealthPosture, HealthProjection, LAYER1_PERMISSIONS, Layer1Authority,
    MissionCockroachCloudConsumer, MissionId, MissionScope, OpaqueCursor, OrganizationId,
    OrganizationScope, PLUGIN_VERSION, PROVIDER_ID, PermissionSnapshot, ProjectId, ProjectScope,
    ReadReceipt, RecordingTransport, RegionId, RegionScope, Revision, SERVICE_ID, SecretReference,
    SettingsMetadataProjection, SettingsPosture, SqlActivityKind, SqlActivityPosture,
    SqlActivityProjection, SqlActivityScope, TransportProvenance, WorkProductId, WorkProductScope,
};

const OBSERVED_AT: u64 = 1_000;

fn make_scope(scope_revision: u64) -> CockroachCloudScope {
    CockroachCloudScope::new(
        OrganizationScope::new(
            OrganizationId::new("org-01").expect("organization"),
            Revision::new(2).expect("organization revision"),
        )
        .expect("organization scope"),
        CloudProjectScope::new(
            CloudProjectId::new("cloud-project-01").expect("cloud project"),
            Revision::new(3).expect("cloud project revision"),
        )
        .expect("cloud project scope"),
        ClusterScope::new(
            ClusterId::new("cluster-01").expect("cluster"),
            Revision::new(4).expect("cluster revision"),
        )
        .expect("cluster scope"),
        RegionScope::new(
            RegionId::new("aws-us-east-1").expect("region"),
            Revision::new(5).expect("region revision"),
        )
        .expect("region scope"),
        DatabaseScope::new(
            DatabaseId::new("app-db").expect("database"),
            Revision::new(6).expect("database revision"),
        )
        .expect("database scope"),
        BranchScope::new(
            BranchId::new("main").expect("branch"),
            Revision::new(7).expect("branch revision"),
        )
        .expect("branch scope"),
        SqlActivityScope::new(
            SqlActivityKind::Statements,
            OBSERVED_AT - 60,
            OBSERVED_AT,
            Revision::new(8).expect("SQL activity revision"),
        )
        .expect("SQL activity scope"),
        ProjectScope::new(
            ProjectId::new("hartevo-project-01").expect("Hartevo project"),
            Revision::new(9).expect("Hartevo project revision"),
        )
        .expect("Hartevo project scope"),
        MissionScope::new(
            MissionId::new("mission-01").expect("mission"),
            Revision::new(10).expect("mission revision"),
        )
        .expect("mission scope"),
        WorkProductScope::new(
            WorkProductId::new("work-product-01").expect("work product"),
            Revision::new(11).expect("work product revision"),
        )
        .expect("work product scope"),
        PermissionSnapshot::least_privilege(),
        Revision::new(scope_revision).expect("scope revision"),
    )
    .expect("CockroachDB Cloud scope")
}

fn fixture_service(scope: CockroachCloudScope) -> CockroachCloudResultService<FixtureTransport> {
    let secret = SecretReference::for_scope("keyring://cockroach-cloud/read-only", &scope)
        .expect("opaque secret reference");
    let provider = CockroachCloudProvider::new(FixtureTransport::for_scope(&scope, OBSERVED_AT))
        .expect("fixture provider");
    CockroachCloudResultService::new(provider, scope, secret).expect("fixture service")
}

fn request(scope: &CockroachCloudScope) -> CockroachCloudReadRequest {
    CockroachCloudReadRequest::new(scope, 20, 2, true, OBSERVED_AT).expect("read request")
}

#[test]
fn contract_and_authority_are_explicitly_layer_one() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract["pluginVersion"], PLUGIN_VERSION);
    assert_eq!(contract["layer"], "Layer-1");
    assert_eq!(contract["service"]["id"], SERVICE_ID);
    assert_eq!(contract["provider"]["id"], PROVIDER_ID);
    assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
    assert_eq!(contract["nativeGap"]["status"], BLOCKED_ENV);
    assert_eq!(LAYER1_PERMISSIONS.len(), 10);
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::first_party());
    assert!(!Layer1Authority::sql_execution());
    assert!(!Layer1Authority::external_writes());
}

#[test]
fn exact_scope_registration_and_secret_redaction_are_bound() {
    let scope = make_scope(12);
    let secret_material = "api-token-and-password-never-retained";
    let secret = SecretReference::for_scope(secret_material, &scope).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains(secret_material));
    assert!(!debug.contains("password"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(secret.revision(), scope.scope_revision());

    let service = fixture_service(scope.clone());
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(!registration_json.contains(secret_material));
    assert!(registration_json.contains("secretReferenceDigest"));
    assert_eq!(service.registration().scope_digest, scope.digest());
    assert_eq!(
        service.registration().revision_fence_digest,
        scope.revision_fence_digest()
    );
    assert_eq!(service.registration().api_revision, API_REVISION);
    assert!(service.is_active());
}

#[test]
fn fixture_read_proposal_record_verify_and_mission_projection_are_review_only() {
    let scope = make_scope(12);
    let mut service = fixture_service(scope.clone());
    let proposal = service
        .propose(&request(&scope), OBSERVED_AT + 1)
        .expect("fixture proposal");

    assert_eq!(proposal.state, EvidenceState::Healthy);
    assert_eq!(
        proposal.evidence.provider_provenance,
        TransportProvenance::Fixture
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(proposal.evidence.cluster.is_some());
    assert!(proposal.evidence.health.is_some());
    assert!(proposal.evidence.settings.is_some());
    assert_eq!(proposal.evidence.sql_activity.len(), 1);
    assert!(proposal.evidence.receipts.iter().all(|receipt| {
        !receipt.raw_provider_payload_retained
            && !receipt.raw_sql_retained
            && !receipt.raw_result_retained
            && !receipt.credential_material_retained
            && !receipt.connected
            && !receipt.native
            && !receipt.first_party
    }));
    assert!(proposal.evidence.pagination.complete);
    assert!(
        proposal
            .evidence
            .sql_activity
            .iter()
            .all(|activity| { !activity.raw_sql_retained && !activity.raw_result_retained })
    );

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("SELECT 1"));
    assert!(!serialized.contains("connectionString"));
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("fixture-provider-settings-names"));

    let record = service
        .record(&proposal, "mission-record-01")
        .expect("record");
    assert_eq!(
        record.disposition,
        hartevo_cockroach_cloud_result_plugin::RecordDisposition::New
    );
    assert!(!record.durable);
    assert!(!record.provider_receipt);
    let replay = service
        .record(&proposal, "mission-record-01")
        .expect("replay");
    assert_eq!(
        replay.disposition,
        hartevo_cockroach_cloud_result_plugin::RecordDisposition::Replay
    );
    assert_eq!(service.record_count(), 1);
    assert!(service.verify(&proposal, OBSERVED_AT + 1).valid);

    let mut consumer =
        MissionCockroachCloudConsumer::new(scope.clone(), service.registration().clone())
            .expect("Mission consumer");
    let mission_result = consumer.consume(&proposal).expect("Mission result");
    assert_eq!(
        mission_result.decision_state,
        hartevo_cockroach_cloud_result_plugin::MissionCockroachCloudDecisionState::Healthy
    );
    assert_eq!(mission_result.project.revision.get(), 9);
    assert_eq!(mission_result.mission.revision.get(), 10);
    assert_eq!(mission_result.work_product.revision.get(), 11);
    assert!(mission_result.review_only);
    assert!(mission_result.requires_human_review);
    assert!(!mission_result.health_certification_claim);
    assert!(!mission_result.security_truth_claim);
    assert!(!mission_result.outcome_adopted);
    assert!(!mission_result.work_product_adopted);
    assert!(!mission_result.can_be_adopted());
    assert!(
        !consumer
            .record(&proposal, "mission-record-01")
            .expect("consumer record")
            .replayed
    );
    assert!(
        consumer
            .record(&proposal, "mission-record-01")
            .expect("consumer replay")
            .replayed
    );
}

#[test]
fn pagination_cursor_is_opaque_and_bound_to_scope_query_page_and_expiry() {
    let scope = make_scope(12);
    let first_request = request(&scope);
    let cursor = OpaqueCursor::new(
        "provider-page-token-do-not-retain",
        &scope,
        &first_request.query_digest,
        2,
        OBSERVED_AT + 300,
    )
    .expect("opaque cursor");
    let first_page = CockroachCloudPage::new(
        &first_request,
        None,
        None,
        None,
        Vec::new(),
        Some(cursor.clone()),
        256,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let second_request = first_request
        .clone()
        .with_cursor(cursor.clone(), OBSERVED_AT + 1)
        .expect("second request");
    let second_page = CockroachCloudPage::new(
        &second_request,
        Some(
            hartevo_cockroach_cloud_result_plugin::ClusterProjection::for_scope(
                &scope,
                ClusterState::Running,
            ),
        ),
        Some(
            HealthProjection::for_scope(&scope, HealthPosture::ProviderHealthy, 1, "health-status")
                .expect("health"),
        ),
        Some(
            SettingsMetadataProjection::for_scope(
                &scope,
                2,
                "setting-names",
                SettingsPosture::Current,
            )
            .expect("settings"),
        ),
        vec![
            SqlActivityProjection::for_statement(
                &scope,
                "SELECT count(*) FROM app_table",
                SqlActivityPosture::Quiet,
                1,
                2,
                4,
            )
            .expect("activity"),
        ],
        None,
        256,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let mut transport = RecordingTransport::new();
    transport.push_page(Ok(first_page));
    transport.push_page(Ok(second_page));
    let provider = CockroachCloudProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("recording-secret", &scope).expect("secret");
    let mut service =
        CockroachCloudResultService::new(provider, scope.clone(), secret).expect("service");
    let evidence = service
        .read_bounded(&first_request, OBSERVED_AT + 1)
        .expect("read");
    assert_eq!(evidence.pagination.pages, 2);
    assert!(evidence.pagination.complete);
    assert_eq!(evidence.pagination.cursor_digests.len(), 1);
    let json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!json.contains("provider-page-token-do-not-retain"));
    assert!(!json.contains("SELECT count(*)"));

    let other_scope = make_scope(13);
    assert_eq!(
        first_request
            .clone()
            .with_cursor(
                OpaqueCursor::new(
                    "token",
                    &other_scope,
                    &first_request.query_digest,
                    2,
                    OBSERVED_AT + 300,
                )
                .expect("other cursor"),
                OBSERVED_AT + 1,
            )
            .expect_err("scope drift"),
        CockroachCloudResultError::CursorMismatch
    );
    let expired = OpaqueCursor::new(
        "expired-token",
        &scope,
        &first_request.query_digest,
        2,
        OBSERVED_AT + 1,
    )
    .expect("expired cursor representation");
    assert_eq!(
        first_request
            .with_cursor(expired, OBSERVED_AT + 1)
            .expect_err("expired cursor"),
        CockroachCloudResultError::CursorExpired
    );
}

#[test]
fn provider_failures_are_typed_and_never_native() {
    for (error, expected) in [
        (CockroachCloudTransportError::Absent, EvidenceState::Absent),
        (CockroachCloudTransportError::Denied, EvidenceState::Denied),
        (
            CockroachCloudTransportError::Partial,
            EvidenceState::Partial,
        ),
        (
            CockroachCloudTransportError::AccessLoss,
            EvidenceState::AccessLoss,
        ),
        (
            CockroachCloudTransportError::RateLimited {
                retry_after_seconds: 7,
            },
            EvidenceState::RateLimited,
        ),
        (
            CockroachCloudTransportError::ProviderUnknown,
            EvidenceState::ProviderUnknown,
        ),
    ] {
        let scope = make_scope(12);
        let mut transport = RecordingTransport::new();
        transport.set_fault(error);
        let provider = CockroachCloudProvider::new(transport).expect("provider");
        let secret = SecretReference::for_scope("failure-secret", &scope).expect("secret");
        let mut service =
            CockroachCloudResultService::new(provider, scope.clone(), secret).expect("service");
        let evidence = service
            .read_bounded(&request(&scope), OBSERVED_AT + 1)
            .expect("failure evidence");
        assert_eq!(evidence.state, expected);
        assert_eq!(evidence.failure.as_ref().expect("failure").state, expected);
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.first_party);
    }

    let scope = make_scope(12);
    let mut blocked = CockroachCloudResultService::new(
        CockroachCloudProvider::default(),
        scope.clone(),
        SecretReference::for_scope("blocked-secret", &scope).expect("secret"),
    )
    .expect("blocked service");
    let blocked_evidence = blocked
        .read_bounded(&request(&scope), OBSERVED_AT + 1)
        .expect("blocked evidence");
    assert_eq!(
        blocked_evidence.provider_provenance,
        TransportProvenance::BlockedEnv
    );
    assert_eq!(blocked_evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
}

#[test]
fn tamper_revision_registration_and_idempotency_fail_closed() {
    let scope = make_scope(12);
    let mut service = fixture_service(scope.clone());
    let proposal = service
        .propose(&request(&scope), OBSERVED_AT + 1)
        .expect("proposal");

    let mut tampered = proposal.clone();
    tampered.scope_digest = Digest::from_text("scope-drift");
    assert!(!service.verify(&tampered, OBSERVED_AT + 1).valid);
    assert_eq!(
        service
            .record(&proposal, "same-key")
            .expect("record")
            .disposition,
        hartevo_cockroach_cloud_result_plugin::RecordDisposition::New
    );
    assert_eq!(
        service
            .record(&proposal, "same-key")
            .expect("replay")
            .disposition,
        hartevo_cockroach_cloud_result_plugin::RecordDisposition::Replay
    );
    let other_request = CockroachCloudReadRequest::new(&scope, 19, 2, true, OBSERVED_AT)
        .expect("different request");
    let other_proposal = service
        .propose(&other_request, OBSERVED_AT + 2)
        .expect("second proposal");
    assert_eq!(
        service
            .record(&other_proposal, "same-key")
            .expect_err("idempotency conflict"),
        CockroachCloudResultError::RecordingConflict
    );

    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.current,
        hartevo_cockroach_cloud_result_plugin::RegistrationState::Reversed
    );
    assert_eq!(
        service.restore_registration().expect("restore").current,
        hartevo_cockroach_cloud_result_plugin::RegistrationState::Active
    );
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service
            .propose(&request(&scope), OBSERVED_AT + 1)
            .expect_err("revoked registration"),
        CockroachCloudResultError::RegistrationRevoked
    );
    assert!(!service.verify(&proposal, OBSERVED_AT + 1).valid);

    let mut drifted_page = CockroachCloudPage::new(
        &request(&scope),
        Some(
            hartevo_cockroach_cloud_result_plugin::ClusterProjection::for_scope(
                &scope,
                ClusterState::Running,
            ),
        ),
        None,
        None,
        Vec::new(),
        None,
        128,
        TransportProvenance::Recording,
    )
    .expect("page");
    drifted_page.cluster.as_mut().expect("cluster").revision = Revision::new(99).expect("drift");
    drifted_page.response_digest = drifted_page.calculate_digest();
    let mut transport = RecordingTransport::new();
    transport.push_page(Ok(drifted_page));
    let drift_provider = CockroachCloudProvider::new(transport).expect("drift provider");
    let drift_secret = SecretReference::for_scope("drift-secret", &scope).expect("secret");
    let mut drift_service =
        CockroachCloudResultService::new(drift_provider, scope.clone(), drift_secret)
            .expect("drift service");
    assert_eq!(
        drift_service
            .read_bounded(&request(&scope), OBSERVED_AT + 1)
            .expect_err("revision drift"),
        CockroachCloudResultError::Provider(CockroachCloudTransportError::InvalidResponse)
    );
}

#[test]
fn all_local_transport_modes_report_disconnected_non_native_evidence() {
    let scope = make_scope(12);
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let service = fixture_service(scope);
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.sql_execution);
    assert!(!capabilities.cluster_mutation);
    assert!(!capabilities.branch_mutation);
    assert!(!capabilities.settings_mutation);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
}

#[test]
fn raw_receipt_projection_is_rejected_when_tampered() {
    let receipt = ReadReceipt {
        operation: "bounded_cockroach_cloud_posture_read".to_owned(),
        page: 1,
        request_digest: Digest::from_text("request"),
        response_digest: Digest::from_text("response"),
        item_count: 1,
        sql_activity_count: 0,
        response_bytes: 64,
        provenance: TransportProvenance::Fixture,
        raw_provider_payload_retained: true,
        raw_sql_retained: false,
        raw_result_retained: false,
        credential_material_retained: false,
        connected: false,
        native: false,
        first_party: false,
        receipt_digest: Digest::from_text("tampered"),
    };
    assert_eq!(
        receipt
            .validate_integrity()
            .expect_err("raw receipt must fail"),
        CockroachCloudResultError::ReceiptTampered
    );
}
