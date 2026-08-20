use std::collections::BTreeSet;

use hartevo_cohere_inference_result_plugin::{
    AccountScope, BlockedEnvCode, COHERE_INFERENCE_CONTRACT_JSON,
    COHERE_INFERENCE_CONTRACT_VERSION, COHERE_INFERENCE_PLUGIN_VERSION,
    COHERE_INFERENCE_SCHEMA_VERSION, ChatMessage, ChatRole, CohereApiHost, CohereInferenceError,
    CohereInferenceResultService, CohereInferenceScope, CohereProvider, ConsentScope, Digest,
    EvidenceDisposition, FinishReason, GenerationBudget, InferenceInput, InferencePermission,
    InferencePolicy, InferenceRequest, InferenceResultState, InferenceTask,
    MissionCohereInferenceConsumer, ModelRevision, PluginRegistration, ProjectScope,
    ProviderFailureClass, ProviderMode, ProviderRoute, RecordedCohereResponse, RequestOptions,
    RevocationReason, SecretKind, SecretReference, WorkProductScope,
};

const MODEL: &str = "command-r-plus";
const MODEL_REVISION: &str = "cohere-model-revision-7";
const PROVIDER: &str = "cohere";

fn policy() -> InferencePolicy {
    InferencePolicy::new(
        "policy-revision-1",
        16 * 1024,
        8,
        4 * 1024,
        128,
        2 * 1024 * 1024,
        128,
    )
    .expect("policy")
}

fn scope(task: InferenceTask) -> CohereInferenceScope {
    let secret = SecretReference::new("opaque-cohere-secret-handle-7", SecretKind::CohereApiKey, 7)
        .expect("secret reference");
    let account = AccountScope::with_organization(
        "account-7",
        Some("organization-7"),
        InferencePermission::CohereInference,
        secret,
    )
    .expect("account scope");
    CohereInferenceScope::new(
        CohereApiHost::api(),
        account,
        ModelRevision::new(MODEL, MODEL_REVISION).expect("model"),
        task,
        ProviderRoute::cohere(),
        ProjectScope::new("project-7", 3).expect("project"),
        hartevo_cohere_inference_result_plugin::MissionScope::new("mission-7", 5).expect("mission"),
        WorkProductScope::new("work-product-7", 9).expect("work product"),
        ConsentScope::new("consent-7", 11).expect("consent"),
        policy(),
    )
    .expect("Cohere scope")
}

fn chat_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::Chat,
        InferenceInput::chat(vec![
            ChatMessage::new(ChatRole::System, "Answer with one bounded sentence.")
                .expect("system"),
            ChatMessage::new(ChatRole::User, "What is the next decision?").expect("user"),
        ])
        .expect("chat input"),
        GenerationBudget::new(32).expect("generation"),
    )
    .with_request_revision(7)
    .expect("request revision")
}

fn generate_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::Generate,
        InferenceInput::text("generate one bounded private sentence").expect("text"),
        GenerationBudget::new(16).expect("generation"),
    )
}

fn embed_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::Embed,
        InferenceInput::texts(["first private sentence", "second private sentence"])
            .expect("texts"),
        GenerationBudget::none(),
    )
}

fn chat_body(content: &str) -> Vec<u8> {
    serde_json::json!({
        "id": "chat-recording-1",
        "model": MODEL,
        "message": {
            "role": "assistant",
            "content": [{"type": "text", "text": content}]
        },
        "finish_reason": "COMPLETE",
        "usage": {"tokens": {"input_tokens": 11, "output_tokens": 7}}
    })
    .to_string()
    .into_bytes()
}

fn chat_response(id: &str, body: Vec<u8>) -> RecordedCohereResponse {
    RecordedCohereResponse::success(id, PROVIDER, MODEL, MODEL_REVISION, body, 37)
}

fn service(task: InferenceTask) -> CohereInferenceResultService {
    CohereInferenceResultService::new(scope(task), CohereProvider::recording())
        .expect("service registration")
}

#[test]
fn contract_and_registration_are_versioned_and_digest_bound() {
    let contract: serde_json::Value =
        serde_json::from_str(COHERE_INFERENCE_CONTRACT_JSON).expect("contract JSON");
    assert_eq!(contract["schemaVersion"], COHERE_INFERENCE_SCHEMA_VERSION);
    assert_eq!(
        contract["contractVersion"],
        COHERE_INFERENCE_CONTRACT_VERSION
    );
    assert_eq!(contract["pluginVersion"], COHERE_INFERENCE_PLUGIN_VERSION);
    assert_eq!(contract["layer"], 1);
    assert_eq!(
        contract["provider"]["tasks"],
        serde_json::json!(["chat", "generate", "embed"])
    );
    assert_eq!(contract["authority"]["connected"], false);
    assert_eq!(contract["authority"]["native"], false);
    assert_eq!(contract["authority"]["firstParty"], false);

    let service = service(InferenceTask::Chat);
    let registration: &PluginRegistration = service.registration();
    assert!(registration.version_digest().is_sha256());
    assert!(registration.contract_digest().is_sha256());
    assert!(registration.provider_digest().is_sha256());
    assert!(registration.model_digest().is_sha256());
    assert!(registration.task_digest().is_sha256());
    assert!(registration.permission_digest().is_sha256());
    assert!(registration.consent_digest().is_sha256());
    assert!(registration.policy_digest().is_sha256());
    assert!(registration.scope_digest().is_sha256());
    assert!(registration.registration_digest().is_sha256());
    assert!(service.scope().digest().is_sha256());
    assert!(service.is_active());
}

#[test]
fn chat_provenance_is_redacted_and_locally_verifiable() {
    let mut service = service(InferenceTask::Chat);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let response = chat_response(
        "chat-1",
        chat_body("sensitive completion that must not be retained"),
    )
    .with_request_revision(7)
    .with_provider_digest(service.scope().provider_digest())
    .with_result_revision(3);
    let evidence = service
        .record_inference_receipt(&proposal, &response)
        .expect("evidence");
    assert_eq!(evidence.state, InferenceResultState::Completed);
    assert_eq!(evidence.disposition, EvidenceDisposition::RecordedSuccess);
    assert_eq!(evidence.finish_reason, Some(FinishReason::Stop));
    assert_eq!(evidence.usage.as_ref().expect("usage").total_tokens, 18);
    assert_eq!(evidence.request_revision, 7);
    assert_eq!(evidence.result_revision, 3);
    assert!(
        evidence
            .content_digest()
            .expect("content digest")
            .is_sha256()
    );
    let proposal_json = serde_json::to_string(&proposal).expect("proposal serialization");
    let evidence_json = serde_json::to_string(&evidence).expect("evidence serialization");
    assert!(!proposal_json.contains("What is the next decision"));
    assert!(!evidence_json.contains("sensitive completion"));
    assert!(!evidence_json.contains("What is the next decision"));
    assert!(!format!("{response:?}").contains("sensitive completion"));
    assert!(!evidence.authority.connected());
    assert!(!evidence.authority.native());
    assert!(!evidence.authority.first_party());
    service
        .verify_inference_result(&proposal, &evidence)
        .expect("local binding verification");
}

#[test]
fn generate_and_embed_project_only_bounded_metadata() {
    let mut generate_service = service(InferenceTask::Generate);
    let generate_proposal = generate_service
        .compile_inference_proposal(&generate_request())
        .expect("generate proposal");
    let generate_body = serde_json::json!({
        "id": "generation-1",
        "model": MODEL,
        "generations": [{"id": "g-1", "text": "private generated answer", "finish_reason": "COMPLETE"}],
        "meta": {"tokens": {"input_tokens": 5, "output_tokens": 4}}
    })
    .to_string()
    .into_bytes();
    let generate_evidence = generate_service
        .record_inference_receipt(
            &generate_proposal,
            &chat_response("generate-1", generate_body),
        )
        .expect("generate evidence");
    assert_eq!(generate_evidence.state, InferenceResultState::Completed);
    assert_eq!(
        generate_evidence
            .content
            .as_ref()
            .expect("content")
            .byte_length,
        24
    );
    assert!(
        !serde_json::to_string(&generate_evidence)
            .expect("serialize generate")
            .contains("private generated answer")
    );

    let mut embed_service = service(InferenceTask::Embed);
    let embed_proposal = embed_service
        .compile_inference_proposal(&embed_request())
        .expect("embed proposal");
    let embed_body = serde_json::json!({
        "id": "embed-1",
        "model": MODEL,
        "embeddings": {"float": [[0.1, 0.2, 0.3], [0.4, 0.5, 0.6]]},
        "meta": {"billed_units": {"input_tokens": 10, "output_tokens": 0}}
    })
    .to_string()
    .into_bytes();
    let embed_evidence = embed_service
        .record_inference_receipt(&embed_proposal, &chat_response("embed-1", embed_body))
        .expect("embed evidence");
    let embedding = embed_evidence.embedding.as_ref().expect("embedding");
    assert_eq!(embedding.item_count, 2);
    assert_eq!(embedding.dimensions, 3);
    assert!(embedding.embedding_digest.is_sha256());
    let serialized = serde_json::to_string(&embed_evidence).expect("serialize embed");
    assert!(!serialized.contains("0.1"));
    assert!(!serialized.contains("first private sentence"));
}

#[test]
fn provider_failures_timeout_rate_limit_and_server_error_are_redacted() {
    let cases = [
        (401, ProviderFailureClass::Unauthorized, false),
        (400, ProviderFailureClass::InvalidRequest, false),
        (429, ProviderFailureClass::RateLimited, true),
        (503, ProviderFailureClass::ServerError, true),
    ];
    for (index, (status, class, retryable)) in cases.into_iter().enumerate() {
        let mut service = service(InferenceTask::Chat);
        let proposal = service
            .compile_inference_proposal(&chat_request())
            .expect("proposal");
        let response = RecordedCohereResponse::http_error(
            format!("error-{index}"),
            PROVIDER,
            MODEL,
            MODEL_REVISION,
            status,
            b"sensitive provider error body".to_vec(),
            11,
        );
        let evidence = service
            .record_inference_receipt(&proposal, &response)
            .expect("error projection");
        let error = evidence.provider_error.as_ref().expect("provider error");
        assert_eq!(error.class, class);
        assert_eq!(error.http_status, Some(status));
        assert_eq!(error.retryable, retryable);
        assert!(evidence.content.is_none());
        assert!(
            !serde_json::to_string(&evidence)
                .expect("error evidence serialization")
                .contains("sensitive provider error body")
        );
    }

    let mut service = service(InferenceTask::Chat);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("timeout proposal");
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedCohereResponse::timeout("timeout-1", PROVIDER, MODEL, MODEL_REVISION, 1000),
        )
        .expect("timeout evidence");
    assert_eq!(evidence.state, InferenceResultState::Timeout);
    assert_eq!(
        evidence.provider_error.expect("timeout error").class,
        ProviderFailureClass::Timeout
    );
}

#[test]
fn tamper_stale_revision_and_replay_fail_closed() {
    let mut service = service(InferenceTask::Chat);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let response = chat_response("tamper-1", chat_body("stable result"));
    let evidence = service
        .record_inference_receipt(&proposal, &response)
        .expect("evidence");

    let mut tampered_proposal = proposal.clone();
    tampered_proposal.request.request_digest = Digest::sha256(b"tampered-request");
    assert_eq!(
        service
            .record_inference_receipt(&tampered_proposal, &response)
            .expect_err("proposal tamper"),
        CohereInferenceError::ProposalTampered
    );

    let mut tampered_evidence = evidence.clone();
    tampered_evidence.latency_ms = 999;
    assert_eq!(
        service
            .verify_inference_result(&proposal, &tampered_evidence)
            .expect_err("evidence tamper"),
        CohereInferenceError::EvidenceTampered
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &response)
            .expect_err("recording replay"),
        CohereInferenceError::ReplayDetected
    );

    let stale = chat_response("stale-request", chat_body("stale")).with_request_revision(6);
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &stale)
            .expect_err("stale request revision"),
        CohereInferenceError::RequestRevisionMismatch
    );
    let zero_revision = chat_response("zero-result", chat_body("zero")).with_result_revision(0);
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &zero_revision)
            .expect_err("zero result revision"),
        CohereInferenceError::ResultRevisionMismatch
    );
}

#[test]
fn registration_revocation_is_reversible_but_replay_remains_fenced() {
    let mut service = service(InferenceTask::Chat);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let response = chat_response("revocation-1", chat_body("revocable"));
    let evidence = service
        .record_inference_receipt(&proposal, &response)
        .expect("evidence");
    let revocation = service
        .revoke(RevocationReason::UserRequested)
        .expect("revocation");
    assert_eq!(revocation.revision(), 1);
    assert!(!service.is_active());
    assert_eq!(
        service
            .compile_inference_proposal(&chat_request())
            .expect_err("revoked service"),
        CohereInferenceError::RegistrationRevoked
    );
    assert_eq!(
        service
            .verify_inference_result(&proposal, &evidence)
            .expect_err("revoked verification"),
        CohereInferenceError::RegistrationRevoked
    );
    service.restore().expect("restore");
    assert!(service.is_active());
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &response)
            .expect_err("replay remains fenced after restore"),
        CohereInferenceError::ReplayDetected
    );
    service
        .compile_inference_proposal(&chat_request())
        .expect("restored service compiles");
}

#[test]
fn bounded_options_partial_results_and_response_limits_fail_closed() {
    let options_service = service(InferenceTask::Chat);
    let streaming = chat_request().with_options(RequestOptions::new(true, false, false));
    assert_eq!(
        options_service
            .compile_inference_proposal(&streaming)
            .expect_err("streaming"),
        CohereInferenceError::StreamingForbidden
    );
    let tools = chat_request().with_options(RequestOptions::new(false, true, false));
    assert_eq!(
        options_service
            .compile_inference_proposal(&tools)
            .expect_err("tools"),
        CohereInferenceError::ToolCallsForbidden
    );
    let files = chat_request().with_options(RequestOptions::new(false, false, true));
    assert_eq!(
        options_service
            .compile_inference_proposal(&files)
            .expect_err("files"),
        CohereInferenceError::FileAuthorityForbidden
    );

    let small_provider = CohereProvider::recording()
        .with_response_bound(64)
        .expect("provider bound");
    let mut limited_service =
        CohereInferenceResultService::new(scope(InferenceTask::Chat), small_provider)
            .expect("limited service");
    let limited_proposal = limited_service
        .compile_inference_proposal(&chat_request())
        .expect("limited proposal");
    assert_eq!(
        limited_service
            .record_inference_receipt(
                &limited_proposal,
                &chat_response("truncated-1", chat_body("body exceeds recording bound")),
            )
            .expect_err("response truncation"),
        CohereInferenceError::ResponseTruncated
    );

    let mut partial_service = service(InferenceTask::Chat);
    let proposal = partial_service
        .compile_inference_proposal(&chat_request())
        .expect("partial proposal");
    let partial = RecordedCohereResponse::lifecycle(
        "partial-1",
        PROVIDER,
        MODEL,
        MODEL_REVISION,
        InferenceResultState::Partial,
        serde_json::json!({"message": {"content": [{"type": "text", "text": "partial"}]}})
            .to_string(),
        9,
    );
    let evidence = partial_service
        .record_inference_receipt(&proposal, &partial)
        .expect("partial evidence");
    assert_eq!(evidence.disposition, EvidenceDisposition::RecordedPartial);
    assert!(evidence.content.is_some());

    let tool_response = RecordedCohereResponse::success(
        "tool-response-1",
        PROVIDER,
        MODEL,
        MODEL_REVISION,
        serde_json::json!({
            "message": {"content": "do not execute", "tool_calls": [{"name": "secret"}]},
            "finish_reason": "COMPLETE"
        })
        .to_string(),
        1,
    );
    assert_eq!(
        partial_service
            .record_inference_receipt(&proposal, &tool_response)
            .expect_err("response tool authority"),
        CohereInferenceError::ToolCallsForbidden
    );
}

#[test]
fn all_fixture_modes_and_blocked_env_never_claim_connected_or_native() {
    for mode in [
        ProviderMode::Fixture,
        ProviderMode::Recording,
        ProviderMode::Fake,
        ProviderMode::Loopback,
        ProviderMode::BlockedEnv,
    ] {
        let provider = CohereProvider::new(mode);
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
        assert!(!mode.is_connected());
        assert!(!mode.is_native());
        assert!(!mode.is_first_party());
    }

    let mut service = CohereInferenceResultService::new(
        scope(InferenceTask::Chat),
        CohereProvider::blocked_env(),
    )
    .expect("BLOCKED_ENV service");
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal remains possible");
    let evidence = service
        .record_blocked_env(
            &proposal,
            "blocked-1",
            BlockedEnvCode::NativeTransportUnavailable,
            0,
        )
        .expect("blocked env evidence");
    assert_eq!(evidence.disposition, EvidenceDisposition::BlockedEnv);
    assert_eq!(evidence.state, InferenceResultState::ProviderUnknown);
    assert!(!evidence.authority.connected());
    assert!(!evidence.authority.native());
    assert!(!evidence.authority.first_party());
}

#[test]
fn mission_consumer_binds_exact_revisions_without_adoption_authority() {
    let mut consumer =
        MissionCohereInferenceConsumer::new(scope(InferenceTask::Chat), CohereProvider::loopback())
            .expect("consumer");
    let proposal = consumer
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let projection = consumer
        .consume_recorded_result(
            &proposal,
            &chat_response("mission-1", chat_body("next decision")),
        )
        .expect("projection");
    assert_eq!(projection.project_id, "project-7");
    assert_eq!(projection.project_revision, 3);
    assert_eq!(projection.mission_id, "mission-7");
    assert_eq!(projection.work_product_id, "work-product-7");
    assert_eq!(projection.consent_id, "consent-7");
    assert_eq!(projection.consent_revision, 11);
    assert_eq!(projection.state, InferenceResultState::Completed);
    assert!(projection.proposal_only());
    assert!(!projection.connected());
    assert!(!projection.native());
    assert!(!projection.first_party());
}

#[test]
fn opaque_secret_reference_never_leaks_handle() {
    let raw_handle = "cohere_api_key_bytes_must_not_be_retained";
    let secret = SecretReference::new(raw_handle, SecretKind::CohereApiKey, 4).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains(raw_handle));
    assert!(secret.reference_digest().is_sha256());
    let account = AccountScope::new(
        "account-secret",
        InferencePermission::CohereInference,
        secret,
    )
    .expect("account");
    assert!(!format!("{account:?}").contains(raw_handle));
    assert!(account.permission_digest().is_sha256());
}

#[test]
fn scope_digest_changes_when_consent_changes() {
    let first = scope(InferenceTask::Chat);
    let second = CohereInferenceScope::new(
        CohereApiHost::api(),
        AccountScope::new(
            "account-7",
            InferencePermission::CohereInference,
            SecretReference::new("opaque-cohere-secret-handle-7", SecretKind::CohereApiKey, 7)
                .expect("secret"),
        )
        .expect("account"),
        ModelRevision::new(MODEL, MODEL_REVISION).expect("model"),
        InferenceTask::Chat,
        ProviderRoute::cohere(),
        ProjectScope::new("project-7", 3).expect("project"),
        hartevo_cohere_inference_result_plugin::MissionScope::new("mission-7", 5).expect("mission"),
        WorkProductScope::new("work-product-7", 9).expect("work"),
        ConsentScope::new("consent-drifted", 12).expect("consent"),
        policy(),
    )
    .expect("scope");
    assert_ne!(first.consent_digest(), second.consent_digest());
    assert_ne!(first.digest(), second.digest());
}

#[test]
fn digest_ordering_is_stable_for_idempotency_keys() {
    let mut keys = BTreeSet::new();
    let service = service(InferenceTask::Chat);
    keys.insert(service.registration().registration_digest().clone());
    keys.insert(service.scope().digest());
    assert_eq!(keys.len(), 2);
}
