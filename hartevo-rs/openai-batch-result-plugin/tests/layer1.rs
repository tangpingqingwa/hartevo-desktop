use hartevo_openai_batch_result_plugin::{
    ApiBinding, BatchId, BatchStatus, CONTRACT_JSON, CONTRACT_VERSION, Digest, Endpoint,
    EvidenceDisposition, HartevoProjectId, HttpMethod, MAX_RESPONSE_BYTES, MissionId, ModelBinding,
    ModelId, OpenAiBatchEvidence, OpenAiBatchHttpResponse, OpenAiBatchProvider,
    OpenAiBatchProviderDefinition, OpenAiBatchProviderError, OpenAiBatchResultError,
    OpenAiBatchResultService, OpenAiBatchScope, OpenAiBatchScopeIdentity, PLUGIN_ID,
    PLUGIN_VERSION, PermissionBinding, ProjectId, ProviderProvenance, ReadOnlyAuthority,
    RecordingOpenAiBatchTransport, Revision, SecretReference, WorkProductId,
};

fn scope(batch_id: Option<&str>) -> OpenAiBatchScope {
    let identity = OpenAiBatchScopeIdentity::new(
        hartevo_openai_batch_result_plugin::OrganizationId::new("org-test").expect("organization"),
        ProjectId::new("proj-test").expect("OpenAI project"),
        batch_id.map(|value| BatchId::new(value).expect("batch")),
        Some(Endpoint::new("/v1/responses").expect("endpoint")),
        Some(hartevo_openai_batch_result_plugin::FileId::new("file-input-test").expect("file")),
        ModelBinding::exact(
            ModelId::new("gpt-5").expect("model"),
            Revision::new(1).expect("model revision"),
        ),
        ApiBinding::official(Revision::new(1).expect("API revision")),
        PermissionBinding::read_only(Revision::new(1).expect("permission revision")),
        HartevoProjectId::new("project-test").expect("Hartevo project"),
        MissionId::new("mission-test").expect("Mission"),
        WorkProductId::new("work-product-test").expect("Work Product"),
        Revision::new(1).expect("project revision"),
        Revision::new(1).expect("Mission revision"),
        Revision::new(1).expect("Work Product revision"),
        Revision::new(1).expect("scope revision"),
    )
    .expect("scope identity");
    let secret = SecretReference::api_key(
        "opaque-api-key-reference",
        identity.digest(),
        Revision::new(3).expect("credential revision"),
    )
    .expect("opaque API-key reference");
    OpenAiBatchScope::new(identity, secret).expect("scope")
}

fn batch_json(
    scope: &OpenAiBatchScope,
    batch_id: &str,
    status: &str,
    has_error_files: bool,
) -> Vec<u8> {
    let mut value = serde_json::json!({
        "id": batch_id,
        "object": "batch",
        "endpoint": "/v1/responses",
        "input_file_id": "file-input-test",
        "completion_window": "24h",
        "status": status,
        "created_at": 1_700_000_000_u64,
        "expires_at": 1_700_086_400_u64,
        "request_counts": {"total": 10_u64, "completed": 8_u64, "failed": 2_u64},
        "model": "gpt-5",
        "metadata": {"prompt_like_key": "prompt-like-value", "source": "recording"}
    });
    if has_error_files {
        value["output_file_id"] = serde_json::json!("file-output-test");
        value["error_file_id"] = serde_json::json!("file-error-test");
        value["errors"] = serde_json::json!({
            "object": "list",
            "data": [{"code": "batch_error", "line": 2, "message": "raw error output", "param": null}]
        });
    }
    match status {
        "in_progress" => value["in_progress_at"] = serde_json::json!(1_700_000_010_u64),
        "finalizing" => value["finalizing_at"] = serde_json::json!(1_700_000_020_u64),
        "completed" => value["completed_at"] = serde_json::json!(1_700_000_030_u64),
        "failed" => value["failed_at"] = serde_json::json!(1_700_000_040_u64),
        "expired" => {
            value["expired_at"] = serde_json::json!(1_700_086_401_u64);
            value["expires_at"] = serde_json::json!(1_700_086_400_u64);
        }
        "cancelling" => value["cancelling_at"] = serde_json::json!(1_700_000_050_u64),
        "cancelled" => {
            value["cancelling_at"] = serde_json::json!(1_700_000_050_u64);
            value["cancelled_at"] = serde_json::json!(1_700_000_060_u64);
        }
        "validating" => {}
        _ => panic!("test status"),
    }
    let _ = scope;
    serde_json::to_vec(&value).expect("batch JSON")
}

fn list_json(batch_ids: &[&str], has_more: bool, last_id: Option<&str>) -> Vec<u8> {
    let data = batch_ids
        .iter()
        .map(|batch_id| {
            serde_json::from_slice::<serde_json::Value>(&batch_json(
                &scope(None),
                batch_id,
                "completed",
                false,
            ))
            .expect("batch value")
        })
        .collect::<Vec<_>>();
    serde_json::to_vec(&serde_json::json!({
        "object": "list",
        "data": data,
        "has_more": has_more,
        "last_id": last_id
    }))
    .expect("list JSON")
}

fn service_with(
    scope: OpenAiBatchScope,
    transport: &RecordingOpenAiBatchTransport,
    provenance: ProviderProvenance,
) -> OpenAiBatchResultService {
    let provider = OpenAiBatchProvider::new(transport.clone(), provenance).expect("provider");
    OpenAiBatchResultService::new(scope, provider).expect("service")
}

#[test]
fn contract_and_authority_are_layer_one_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract");
    assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract["plugin"]["id"], PLUGIN_ID);
    assert_eq!(contract["plugin"]["version"], PLUGIN_VERSION);
    assert_eq!(contract["layer"], 1);
    assert_eq!(
        contract["provider"]["readMethods"],
        serde_json::json!(["GET /v1/batches", "GET /v1/batches/{batch_id}"])
    );
    assert_eq!(
        contract["batchObject"]["statuses"]
            .as_array()
            .expect("statuses")
            .len(),
        8
    );
    assert!(!ReadOnlyAuthority::external_writes());
    assert!(!ReadOnlyAuthority::batch_creation());
    assert!(!ReadOnlyAuthority::file_upload());
    assert!(!ReadOnlyAuthority::batch_cancellation());
    assert!(!ReadOnlyAuthority::file_download());
    assert!(!ReadOnlyAuthority::prompt_retention());
    assert!(!ReadOnlyAuthority::output_retention());
    assert!(!ReadOnlyAuthority::model_execution());
    assert!(!ReadOnlyAuthority::tool_execution());
    assert!(!ReadOnlyAuthority::generic_model_registry());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::connected());
    assert!(!ReadOnlyAuthority::native());
}

#[test]
fn opaque_secret_is_not_retained_and_registration_binds_all_digests() {
    let scope = scope(Some("batch-fixture"));
    let debug = format!("{:?}", scope.secret_reference());
    assert!(!debug.contains("opaque-api-key-reference"));
    let identity_json = serde_json::to_string(scope.identity()).expect("scope identity JSON");
    assert!(!identity_json.contains("opaque-api-key-reference"));
    let transport = RecordingOpenAiBatchTransport::new();
    let service = service_with(scope.clone(), &transport, ProviderProvenance::Recording);
    let registration = service.registration();
    assert_eq!(registration.scope_digest, scope.scope_digest());
    assert_eq!(registration.api_digest, scope.identity().api.digest());
    assert_eq!(registration.model_digest, scope.identity().model.digest());
    assert_eq!(
        registration.permission_digest,
        scope.identity().permission.digest
    );
    assert_eq!(registration.revision_digest, scope.revision_digest());
    assert!(registration.reversible);
    assert!(registration.revocable);
}

#[test]
fn reads_are_get_only_bounded_and_paginated_by_after_cursor() {
    let scope = scope(None);
    let transport = RecordingOpenAiBatchTransport::new();
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, list_json(&["batch-one"], true, Some("batch-one")))
            .with_observed_at(100)
            .with_snapshot_revision(scope.identity().scope_revision),
    );
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, list_json(&["batch-two"], false, None))
            .with_observed_at(101)
            .with_snapshot_revision(scope.identity().scope_revision),
    );
    let mut service = service_with(scope, &transport, ProviderProvenance::Loopback);
    let evidence = service.paginate_batches(1, 100).expect("pages");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.batches.len(), 2);
    assert_eq!(evidence.disposition, EvidenceDisposition::Present);
    evidence.validate().expect("evidence");
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method(), HttpMethod::Get);
    assert_eq!(requests[0].target(), "/v1/batches?limit=1");
    assert_eq!(requests[1].target(), "/v1/batches?limit=1&after=batch-one");
    assert!(
        requests
            .iter()
            .all(|request| request.path().starts_with("/v1/batches"))
    );
}

#[test]
fn lifecycle_request_counts_expiry_and_file_digests_are_typed_without_payloads() {
    let scope = scope(Some("batch-fixture"));
    let transport = RecordingOpenAiBatchTransport::new();
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, batch_json(&scope, "batch-fixture", "completed", true))
            .with_observed_at(100)
            .with_snapshot_revision(scope.identity().scope_revision),
    );
    let mut service = service_with(scope, &transport, ProviderProvenance::Fixture);
    let evidence = service
        .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
        .expect("batch");
    let batch = &evidence.batches[0];
    assert_eq!(batch.status, BatchStatus::Completed);
    assert_eq!(batch.request_counts.total, 10);
    assert_eq!(batch.request_counts.completed, 8);
    assert_eq!(batch.request_counts.failed, 2);
    assert_eq!(batch.input_file_id().as_str(), "file-input-test");
    assert_eq!(
        batch.output_file_id().expect("output").as_str(),
        "file-output-test"
    );
    assert_eq!(
        batch.error_file_id().expect("error").as_str(),
        "file-error-test"
    );
    assert_eq!(batch.expiry.expires_at, Some(1_700_086_400));
    assert!(batch.metadata.is_some());
    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!evidence_json.contains("prompt-like-value"));
    assert!(!evidence_json.contains("raw error output"));
    assert!(!evidence_json.contains("output content"));
}

#[test]
fn all_official_lifecycle_statuses_are_typed() {
    let statuses = [
        "validating",
        "in_progress",
        "finalizing",
        "completed",
        "failed",
        "expired",
        "cancelling",
        "cancelled",
    ];
    for status in statuses {
        let batch_id = format!("batch-{status}");
        let scope = scope(Some(&batch_id));
        let transport = RecordingOpenAiBatchTransport::new();
        transport.push_response(
            OpenAiBatchHttpResponse::new(200, batch_json(&scope, &batch_id, status, false))
                .with_observed_at(100)
                .with_snapshot_revision(scope.identity().scope_revision),
        );
        let mut service = service_with(scope, &transport, ProviderProvenance::Recording);
        let evidence = service
            .read_batch(BatchId::new(batch_id).expect("batch"), 100)
            .expect("status");
        assert_eq!(
            evidence.batches[0].status,
            BatchStatus::parse(status).expect("status parse")
        );
    }
}

#[test]
fn stale_revision_tamper_access_loss_and_revocation_fences_fail_closed() {
    let stale_scope = scope(Some("batch-fixture"));
    let stale_transport = RecordingOpenAiBatchTransport::new();
    stale_transport.push_response(
        OpenAiBatchHttpResponse::new(
            200,
            batch_json(&stale_scope, "batch-fixture", "completed", false),
        )
        .with_observed_at(99)
        .with_snapshot_revision(stale_scope.identity().scope_revision),
    );
    let mut stale_service =
        service_with(stale_scope, &stale_transport, ProviderProvenance::Recording);
    assert_eq!(
        stale_service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .expect_err("stale"),
        OpenAiBatchResultError::StaleResult
    );

    let revision_scope = scope(Some("batch-fixture"));
    let revision_transport = RecordingOpenAiBatchTransport::new();
    revision_transport.push_response(
        OpenAiBatchHttpResponse::new(
            200,
            batch_json(&revision_scope, "batch-fixture", "completed", false),
        )
        .with_observed_at(100)
        .with_snapshot_revision(Revision::new(2).expect("drifted revision")),
    );
    let mut revision_service = service_with(
        revision_scope,
        &revision_transport,
        ProviderProvenance::Recording,
    );
    assert_eq!(
        revision_service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .expect_err("revision drift"),
        OpenAiBatchResultError::RevisionDrift
    );

    let good_scope = scope(Some("batch-fixture"));
    let good_transport = RecordingOpenAiBatchTransport::new();
    good_transport.push_response(
        OpenAiBatchHttpResponse::new(
            200,
            batch_json(&good_scope, "batch-fixture", "completed", false),
        )
        .with_observed_at(100)
        .with_snapshot_revision(good_scope.identity().scope_revision),
    );
    let mut good_service = service_with(good_scope, &good_transport, ProviderProvenance::Recording);
    let mut evidence = good_service
        .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
        .expect("evidence");
    evidence.batches[0].batch_digest = Digest::from_text("tampered");
    assert_eq!(
        good_service.verify_evidence(&evidence).expect_err("tamper"),
        OpenAiBatchResultError::EvidenceTampered
    );

    good_service.revoke_secret().expect("secret revoke");
    assert_eq!(
        good_service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .expect_err("secret revocation"),
        OpenAiBatchResultError::SecretRevoked
    );
    good_service.restore_secret().expect("secret restore");
    good_service.revoke().expect("registration revoke");
    assert_eq!(
        good_service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .expect_err("registration revocation"),
        OpenAiBatchResultError::RegistrationRevoked
    );
    good_service.restore().expect("registration restore");
}

#[test]
fn provider_provenance_and_blocked_env_are_honest() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
    ] {
        let scope = scope(Some("batch-fixture"));
        let transport = RecordingOpenAiBatchTransport::new();
        transport.push_response(
            OpenAiBatchHttpResponse::new(
                200,
                batch_json(&scope, "batch-fixture", "completed", false),
            )
            .with_observed_at(100)
            .with_snapshot_revision(scope.identity().scope_revision),
        );
        let mut service = service_with(scope, &transport, provenance);
        let capabilities = service.describe_capabilities().expect("capabilities");
        assert!(!capabilities.connected);
        assert!(!capabilities.native);
        let evidence = service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .expect("evidence");
        assert_eq!(evidence.provenance, provenance);
        assert!(!evidence.connected);
        assert!(!evidence.native);
    }

    let scope = scope(None);
    let provider = OpenAiBatchProvider::blocked_env().expect("blocked provider");
    let mut service = OpenAiBatchResultService::new(scope, provider).expect("service");
    let evidence = service
        .read_batches(10, None, 100)
        .expect("blocked evidence");
    assert_eq!(evidence.disposition, EvidenceDisposition::BlockedEnv);
    assert_eq!(
        evidence
            .provider_error
            .as_ref()
            .expect("provider error")
            .class,
        "blocked_env"
    );
    assert!(!evidence.connected);
    assert!(!evidence.native);
}

#[test]
fn mission_consumer_is_project_only_and_result_proposal_is_fenced() {
    let scope = scope(Some("batch-fixture"));
    let transport = RecordingOpenAiBatchTransport::new();
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, batch_json(&scope, "batch-fixture", "completed", false))
            .with_observed_at(100)
            .with_snapshot_revision(scope.identity().scope_revision),
    );
    let provider =
        OpenAiBatchProvider::new(transport, ProviderProvenance::Recording).expect("provider");
    let mut consumer =
        hartevo_openai_batch_result_plugin::MissionOpenAiBatchConsumer::new(scope, provider)
            .expect("consumer");
    let evidence = consumer
        .service_mut()
        .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
        .expect("evidence");
    let proposal = consumer
        .service()
        .compile_result_proposal(&evidence)
        .expect("proposal");
    consumer
        .service()
        .verify_result_proposal(&proposal, &evidence)
        .expect("verify");
    let mission = consumer
        .consume_proposal(&proposal, &evidence)
        .expect("Mission result");
    assert_eq!(mission.mission_id.as_str(), "mission-test");
    assert_eq!(mission.hartevo_project_id.as_str(), "project-test");
    assert_eq!(mission.work_product_id.as_str(), "work-product-test");
    assert!(!mission.work_product_adopted);
    assert!(!mission.kernel_authority);
    assert!(!mission.connected);
    assert!(!mission.native);
}

#[test]
fn response_byte_cap_and_invalid_counts_are_rejected() {
    let oversize_scope = scope(Some("batch-fixture"));
    let transport = RecordingOpenAiBatchTransport::new();
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, vec![b'x'; MAX_RESPONSE_BYTES + 1])
            .with_observed_at(100)
            .with_snapshot_revision(oversize_scope.identity().scope_revision),
    );
    let mut service = service_with(oversize_scope, &transport, ProviderProvenance::Recording);
    assert!(matches!(
        service.read_batch(BatchId::new("batch-fixture").expect("batch"), 100),
        Err(OpenAiBatchResultError::ResponseTooLarge { .. })
    ));

    let invalid_scope = scope(Some("batch-fixture"));
    let transport = RecordingOpenAiBatchTransport::new();
    let mut invalid = serde_json::from_slice::<serde_json::Value>(&batch_json(
        &invalid_scope,
        "batch-fixture",
        "completed",
        false,
    ))
    .expect("batch value");
    invalid["request_counts"]["completed"] = serde_json::json!(11_u64);
    transport.push_response(
        OpenAiBatchHttpResponse::new(200, serde_json::to_vec(&invalid).expect("invalid JSON"))
            .with_observed_at(100)
            .with_snapshot_revision(invalid_scope.identity().scope_revision),
    );
    let mut service = service_with(invalid_scope, &transport, ProviderProvenance::Recording);
    assert!(
        service
            .read_batch(BatchId::new("batch-fixture").expect("batch"), 100)
            .is_err()
    );
}

#[test]
fn provider_manifest_is_not_a_model_registry() {
    let definition = OpenAiBatchProviderDefinition::layer1();
    definition.validate().expect("manifest");
    assert_eq!(definition.operations().len(), 2);
    assert!(!definition.native());
    assert!(!definition.connected());
    assert!(!definition.external_writes());
    assert!(matches!(
        OpenAiBatchProviderError::AccessLoss,
        OpenAiBatchProviderError::AccessLoss
    ));
    let _ = OpenAiBatchEvidence::is_adoptable;
}
