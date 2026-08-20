use std::collections::BTreeSet;

use hartevo_mistral_inference_result_plugin::{
    AccountScope, BlockedEnvCode, ChatMessage, ChatRole, ConsentScope, Digest, EvidenceDisposition,
    FinishReason, GenerationBudget, InferenceInput, InferencePermission, InferencePolicy,
    InferenceRequest, InferenceResultState, InferenceTask, MISTRAL_INFERENCE_CONTRACT_JSON,
    MISTRAL_INFERENCE_CONTRACT_VERSION, MISTRAL_INFERENCE_PLUGIN_VERSION,
    MISTRAL_INFERENCE_SCHEMA_VERSION, MistralApiHost, MistralInferenceError,
    MistralInferenceResultService, MistralInferenceScope, MistralModelListResponse,
    MistralProvider, ModelRevision, PluginRegistration, ProjectScope, ProviderFailureClass,
    ProviderMode, ProviderRoute, RecordedMistralResponse, RequestOptions, RevocationReason,
    SecretKind, SecretReference, WorkProductScope,
};

const MODEL: &str = "mistral-large-latest";
const MODEL_REVISION: &str = "mistral-model-revision-7";
const PROVIDER: &str = "mistral";

fn policy() -> InferencePolicy {
    InferencePolicy::new(
        "policy-revision-1",
        16 * 1024,
        8,
        4 * 1024,
        128,
        2 * 1024 * 1024,
        128,
        16,
        16,
    )
    .expect("policy")
}

fn scope(task: InferenceTask) -> MistralInferenceScope {
    let secret = SecretReference::new(
        "opaque-mistral-secret-handle-7",
        SecretKind::MistralApiKey,
        7,
    )
    .expect("secret reference");
    let account = AccountScope::with_organization(
        "account-7",
        Some("organization-7"),
        InferencePermission::MistralInference,
        secret,
    )
    .expect("account scope");
    MistralInferenceScope::new(
        MistralApiHost::api(),
        account,
        ModelRevision::new(MODEL, MODEL_REVISION).expect("model"),
        task,
        ProviderRoute::mistral(),
        ProjectScope::new("project-7", 3).expect("project"),
        hartevo_mistral_inference_result_plugin::MissionScope::new("mission-7", 5)
            .expect("mission"),
        WorkProductScope::new("work-product-7", 9).expect("work product"),
        ConsentScope::new("consent-7", 11).expect("consent"),
        policy(),
    )
    .expect("Mistral scope")
}

fn chat_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::ChatCompletion,
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

fn embedding_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::Embedding,
        InferenceInput::texts(["first private sentence", "second private sentence"])
            .expect("texts"),
        GenerationBudget::none(),
    )
}

fn classification_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::Classification,
        InferenceInput::text("classify this private text").expect("text"),
        GenerationBudget::none(),
    )
}

fn chat_body(content: &str) -> Vec<u8> {
    serde_json::json!({
        "id": "cmpl-recording-1",
        "object": "chat.completion",
        "model": MODEL,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
    })
    .to_string()
    .into_bytes()
}

fn chat_response(id: &str, body: Vec<u8>) -> RecordedMistralResponse {
    RecordedMistralResponse::success(id, PROVIDER, MODEL, MODEL_REVISION, body, 37)
}

fn service(task: InferenceTask) -> MistralInferenceResultService {
    MistralInferenceResultService::new(scope(task), MistralProvider::recording())
        .expect("service registration")
}

#[test]
fn contract_and_registration_are_versioned_and_digest_bound() {
    let contract: serde_json::Value =
        serde_json::from_str(MISTRAL_INFERENCE_CONTRACT_JSON).expect("contract JSON");
    assert_eq!(contract["schemaVersion"], MISTRAL_INFERENCE_SCHEMA_VERSION);
    assert_eq!(
        contract["contractVersion"],
        MISTRAL_INFERENCE_CONTRACT_VERSION
    );
    assert_eq!(contract["pluginVersion"], MISTRAL_INFERENCE_PLUGIN_VERSION);
    assert_eq!(contract["authority"]["connected"], false);
    assert_eq!(contract["authority"]["native"], false);
    assert_eq!(contract["authority"]["firstParty"], false);

    let service = service(InferenceTask::ChatCompletion);
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
fn model_list_is_bounded_and_requires_the_pinned_model() {
    let mut model_service = service(InferenceTask::ChatCompletion);
    let body = serde_json::json!({
        "object": "list",
        "data": [
            {"id": MODEL, "object": "model", "owned_by": "mistral-ai"},
            {"id": "mistral-small-latest", "object": "model"}
        ]
    })
    .to_string()
    .into_bytes();
    let evidence = model_service
        .record_model_list(&MistralModelListResponse::success(
            "models-1", PROVIDER, body, 4,
        ))
        .expect("allowlisted model list");
    assert!(evidence.pinned_model_allowlisted);
    assert_eq!(evidence.models.len(), 2);
    assert!(!evidence.authority.connected());
    assert!(!evidence.authority.native());
    model_service
        .verify_model_list(&evidence)
        .expect("model list verify");

    let missing = serde_json::json!({
        "object": "list",
        "data": [{"id": "mistral-small-latest", "object": "model"}]
    })
    .to_string()
    .into_bytes();
    let mut observer = service(InferenceTask::ChatCompletion);
    let observed = observer
        .observe_model_list(&MistralModelListResponse::success(
            "models-missing",
            PROVIDER,
            missing,
            4,
        ))
        .expect("bounded observation");
    assert!(!observed.pinned_model_allowlisted);
    assert_eq!(
        observer.verify_model_list(&observed),
        Err(MistralInferenceError::ModelNotAllowlisted)
    );
}

#[test]
fn chat_result_retains_only_bounded_metadata_and_digests() {
    let mut service = service(InferenceTask::ChatCompletion);
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
    let serialized = serde_json::to_string(&evidence).expect("evidence serialization");
    assert!(!serialized.contains("sensitive completion"));
    assert!(!serialized.contains("What is the next decision"));
    assert!(!format!("{response:?}").contains("sensitive completion"));
    assert!(!evidence.authority.connected());
    assert!(!evidence.authority.native());
    assert!(!evidence.authority.first_party());
    service
        .verify_inference_result(&proposal, &evidence)
        .expect("local binding verification");
}

#[test]
fn embeddings_and_classification_project_metadata_without_raw_values() {
    let mut embedding_service = service(InferenceTask::Embedding);
    let embedding_proposal = embedding_service
        .compile_inference_proposal(&embedding_request())
        .expect("embedding proposal");
    let embedding_body = serde_json::json!({
        "object": "list",
        "model": MODEL,
        "data": [
            {"object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3]},
            {"object": "embedding", "index": 1, "embedding": [0.4, 0.5, 0.6]}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10}
    })
    .to_string()
    .into_bytes();
    let embedding_evidence = embedding_service
        .record_inference_receipt(
            &embedding_proposal,
            &chat_response("embedding-1", embedding_body),
        )
        .expect("embedding evidence");
    let embedding = embedding_evidence
        .embedding
        .as_ref()
        .expect("embedding projection");
    assert_eq!(embedding.item_count, 2);
    assert_eq!(embedding.dimensions, 3);
    let serialized = serde_json::to_string(&embedding_evidence).expect("serialize embedding");
    assert!(!serialized.contains("0.1"));
    assert!(embedding.embedding_digest.is_sha256());

    let mut classification_service = service(InferenceTask::Classification);
    let classification_proposal = classification_service
        .compile_inference_proposal(&classification_request())
        .expect("classification proposal");
    let classification_body = serde_json::json!({
        "id": "moderation-1",
        "model": MODEL,
        "results": [{
            "categories": {"pii": true, "health": false},
            "category_scores": {"pii": 0.91, "health": 0.01}
        }]
    })
    .to_string()
    .into_bytes();
    let classification_evidence = classification_service
        .record_inference_receipt(
            &classification_proposal,
            &chat_response("classification-1", classification_body),
        )
        .expect("classification evidence");
    let classification = classification_evidence
        .classification
        .as_ref()
        .expect("classification projection");
    assert_eq!(classification.result_count, 1);
    assert_eq!(classification.flagged_count, 1);
    let serialized = serde_json::to_string(&classification_evidence).expect("serialize class");
    assert!(!serialized.contains("pii"));
    assert!(!serialized.contains("0.91"));
}

#[test]
fn lifecycle_states_are_explicit_and_provider_unknown_is_not_native() {
    let states = [
        (InferenceResultState::Submitted, "submitted"),
        (InferenceResultState::Queued, "queued"),
        (InferenceResultState::Running, "running"),
        (InferenceResultState::Expired, "expired"),
        (InferenceResultState::ProviderUnknown, "mystery"),
    ];
    for (index, (state, status)) in states.into_iter().enumerate() {
        let mut service = service(InferenceTask::ChatCompletion);
        let proposal = service
            .compile_inference_proposal(&chat_request())
            .expect("proposal");
        let response = RecordedMistralResponse::lifecycle(
            format!("lifecycle-{index}"),
            PROVIDER,
            MODEL,
            MODEL_REVISION,
            state,
            serde_json::json!({"status": status}).to_string(),
            5,
        );
        let evidence = service
            .record_inference_receipt(&proposal, &response)
            .expect("lifecycle evidence");
        assert_eq!(evidence.state, state);
        assert!(!evidence.authority.connected());
        assert!(!evidence.authority.native());
    }

    let mut partial_service = service(InferenceTask::ChatCompletion);
    let proposal = partial_service
        .compile_inference_proposal(&chat_request())
        .expect("partial proposal");
    let partial = RecordedMistralResponse::lifecycle(
        "partial-1",
        PROVIDER,
        MODEL,
        MODEL_REVISION,
        InferenceResultState::Partial,
        serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "partial"}}]
        })
        .to_string(),
        9,
    );
    let evidence = partial_service
        .record_inference_receipt(&proposal, &partial)
        .expect("partial evidence");
    assert_eq!(evidence.state, InferenceResultState::Partial);
    assert_eq!(evidence.disposition, EvidenceDisposition::RecordedPartial);
    assert!(evidence.content.is_some());
}

#[test]
fn provider_error_statuses_include_payment_and_rate_limit_without_body_retention() {
    let cases = [
        (401, ProviderFailureClass::Unauthorized, false),
        (402, ProviderFailureClass::PaymentRequired, false),
        (403, ProviderFailureClass::Forbidden, false),
        (404, ProviderFailureClass::NotFound, false),
        (429, ProviderFailureClass::RateLimited, true),
        (503, ProviderFailureClass::ServerError, true),
    ];
    for (index, (status, class, retryable)) in cases.into_iter().enumerate() {
        let mut service = service(InferenceTask::ChatCompletion);
        let proposal = service
            .compile_inference_proposal(&chat_request())
            .expect("proposal");
        let response = RecordedMistralResponse::http_error(
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

    let mut service = service(InferenceTask::ChatCompletion);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("timeout proposal");
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedMistralResponse::timeout("timeout-1", PROVIDER, MODEL, MODEL_REVISION, 1000),
        )
        .expect("timeout evidence");
    assert_eq!(evidence.state, InferenceResultState::Timeout);
    assert_eq!(
        evidence.provider_error.expect("timeout error").class,
        ProviderFailureClass::Timeout
    );
}

#[test]
fn tamper_stale_scope_and_replay_fail_closed() {
    let mut service = service(InferenceTask::ChatCompletion);
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
        MistralInferenceError::ProposalTampered
    );

    let mut tampered_evidence = evidence.clone();
    tampered_evidence.latency_ms = 999;
    assert_eq!(
        service
            .verify_inference_result(&proposal, &tampered_evidence)
            .expect_err("evidence tamper"),
        MistralInferenceError::EvidenceTampered
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &response)
            .expect_err("recording replay"),
        MistralInferenceError::ReplayDetected
    );

    let stale_response =
        chat_response("stale-request", chat_body("stale")).with_request_revision(6);
    let stale_proposal = service
        .compile_inference_proposal(&chat_request().with_request_revision(8).expect("request"))
        .expect("new proposal");
    assert_eq!(
        service
            .record_inference_receipt(&stale_proposal, &stale_response)
            .expect_err("stale request revision"),
        MistralInferenceError::RequestRevisionMismatch
    );

    let other_scope = MistralInferenceScope::new(
        MistralApiHost::api(),
        AccountScope::new(
            "account-7",
            InferencePermission::MistralInference,
            SecretReference::new(
                "opaque-mistral-secret-handle-7",
                SecretKind::MistralApiKey,
                7,
            )
            .expect("secret"),
        )
        .expect("account"),
        ModelRevision::new(MODEL, MODEL_REVISION).expect("model"),
        InferenceTask::ChatCompletion,
        ProviderRoute::mistral(),
        ProjectScope::new("project-7", 3).expect("project"),
        hartevo_mistral_inference_result_plugin::MissionScope::new("mission-7", 5)
            .expect("mission"),
        WorkProductScope::new("work-product-7", 9).expect("work product"),
        ConsentScope::new("consent-drifted", 12).expect("consent"),
        policy(),
    )
    .expect("other scope");
    let other_service =
        MistralInferenceResultService::new(other_scope, MistralProvider::recording())
            .expect("other service");
    let other_proposal = other_service
        .compile_inference_proposal(&chat_request())
        .expect("other proposal");
    let other_response = chat_response("scope-drift", chat_body("scope drift"));
    assert!(matches!(
        service.record_inference_receipt(&other_proposal, &other_response),
        Err(MistralInferenceError::ScopeMismatch(_))
    ));
}

#[test]
fn registration_revocation_is_reversible_but_does_not_restore_old_recordings() {
    let mut service = service(InferenceTask::ChatCompletion);
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
        MistralInferenceError::RegistrationRevoked
    );
    assert_eq!(
        service
            .verify_inference_result(&proposal, &evidence)
            .expect_err("revoked verification"),
        MistralInferenceError::RegistrationRevoked
    );
    service.restore().expect("restore");
    assert!(service.is_active());
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &response)
            .expect_err("replay remains fenced after restore"),
        MistralInferenceError::ReplayDetected
    );
    service
        .compile_inference_proposal(&chat_request())
        .expect("restored service compiles");
}

#[test]
fn bounded_options_partial_responses_and_response_limits_fail_closed() {
    let options_service = service(InferenceTask::ChatCompletion);
    let streaming = chat_request().with_options(RequestOptions::new(true, false, false));
    assert_eq!(
        options_service
            .compile_inference_proposal(&streaming)
            .expect_err("streaming"),
        MistralInferenceError::StreamingForbidden
    );
    let tools = chat_request().with_options(RequestOptions::new(false, true, false));
    assert_eq!(
        options_service
            .compile_inference_proposal(&tools)
            .expect_err("tools"),
        MistralInferenceError::ToolCallsForbidden
    );
    let files = chat_request().with_options(RequestOptions::new(false, false, true));
    assert_eq!(
        options_service
            .compile_inference_proposal(&files)
            .expect_err("files"),
        MistralInferenceError::FileAuthorityForbidden
    );

    let small_policy = InferencePolicy::new("small", 64, 1, 8, 16, 64, 4, 4, 4).expect("small");
    let small_scope = MistralInferenceScope::new(
        MistralApiHost::api(),
        AccountScope::new(
            "account-small",
            InferencePermission::MistralInference,
            SecretReference::new("opaque-small", SecretKind::MistralApiKey, 1).expect("secret"),
        )
        .expect("account"),
        ModelRevision::new(MODEL, MODEL_REVISION).expect("model"),
        InferenceTask::ChatCompletion,
        ProviderRoute::mistral(),
        ProjectScope::new("project-small", 1).expect("project"),
        hartevo_mistral_inference_result_plugin::MissionScope::new("mission-small", 1)
            .expect("mission"),
        WorkProductScope::new("work-small", 1).expect("work"),
        ConsentScope::new("consent-small", 1).expect("consent"),
        small_policy,
    )
    .expect("small scope");
    let small_service =
        MistralInferenceResultService::new(small_scope, MistralProvider::recording())
            .expect("small service");
    let too_large = InferenceRequest::new(
        InferenceTask::ChatCompletion,
        InferenceInput::chat(vec![
            ChatMessage::new(ChatRole::User, "this is too long").expect("msg"),
        ])
        .expect("input"),
        GenerationBudget::new(4).expect("budget"),
    );
    assert_eq!(
        small_service
            .compile_inference_proposal(&too_large)
            .expect_err("bounded input"),
        MistralInferenceError::ItemTooLarge
    );

    let large_provider = MistralProvider::recording()
        .with_response_bound(64)
        .expect("provider bound");
    let mut limited_provider_service =
        MistralInferenceResultService::new(scope(InferenceTask::ChatCompletion), large_provider)
            .expect("limited provider service");
    let limited_proposal = limited_provider_service
        .compile_inference_proposal(&chat_request())
        .expect("limited provider proposal");
    assert_eq!(
        limited_provider_service
            .record_inference_receipt(
                &limited_proposal,
                &chat_response("truncated-1", chat_body("body exceeds recording bound")),
            )
            .expect_err("response truncation"),
        MistralInferenceError::ResponseTruncated
    );

    let mut response_boundary = service(InferenceTask::ChatCompletion);
    let response_proposal = response_boundary
        .compile_inference_proposal(&chat_request())
        .expect("response boundary proposal");
    let tool_response = RecordedMistralResponse::success(
        "tool-response-1",
        PROVIDER,
        MODEL,
        MODEL_REVISION,
        serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "do not execute",
                    "tool_calls": [{"id": "tool-1", "arguments": "secret"}]
                },
                "finish_reason": "tool_calls"
            }]
        })
        .to_string(),
        1,
    );
    assert_eq!(
        response_boundary
            .record_inference_receipt(&response_proposal, &tool_response)
            .expect_err("response tool authority"),
        MistralInferenceError::ToolCallsForbidden
    );
}

#[test]
fn blocked_env_and_all_provider_modes_never_claim_native_or_connected() {
    for mode in [
        ProviderMode::Fixture,
        ProviderMode::Recording,
        ProviderMode::Loopback,
        ProviderMode::BlockedEnv,
    ] {
        let provider = MistralProvider::new(mode);
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
        assert!(!mode.is_connected());
        assert!(!mode.is_native());
        assert!(!mode.is_first_party());
    }

    let mut service = MistralInferenceResultService::new(
        scope(InferenceTask::ChatCompletion),
        MistralProvider::blocked_env(),
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
fn mission_consumer_binds_revisions_without_adoption_authority() {
    let mut consumer =
        hartevo_mistral_inference_result_plugin::MissionMistralInferenceConsumer::new(
            scope(InferenceTask::ChatCompletion),
            MistralProvider::loopback(),
        )
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
    assert_eq!(projection.mission_id, "mission-7");
    assert_eq!(projection.work_product_id, "work-product-7");
    assert_eq!(projection.consent_id, "consent-7");
    assert_eq!(projection.state, InferenceResultState::Completed);
    assert!(projection.proposal_only());
    assert!(!projection.connected());
    assert!(!projection.native());
    assert!(!projection.first_party());
}

#[test]
fn opaque_secret_reference_does_not_serialize_or_leak_the_handle() {
    let raw_handle = "mistral_api_key_bytes_must_not_be_retained";
    let secret = SecretReference::new(raw_handle, SecretKind::MistralApiKey, 4).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains(raw_handle));
    assert!(secret.reference_digest().is_sha256());
    let account = AccountScope::new(
        "account-secret",
        InferencePermission::MistralInference,
        secret,
    )
    .expect("account");
    assert!(!format!("{account:?}").contains(raw_handle));
    assert!(account.permission_digest().is_sha256());
}

#[test]
fn model_list_replay_guard_is_separate_and_deterministic() {
    let mut service = service(InferenceTask::ChatCompletion);
    let body = serde_json::json!({"object":"list","data":[{"id":MODEL} ]})
        .to_string()
        .into_bytes();
    let response = MistralModelListResponse::success("models-replay", PROVIDER, body, 1);
    service
        .record_model_list(&response)
        .expect("first model list");
    assert_eq!(
        service.record_model_list(&response).expect_err("replay"),
        MistralInferenceError::ReplayDetected
    );
    let mut keys = BTreeSet::new();
    keys.insert(service.registration().registration_digest().clone());
    assert_eq!(keys.len(), 1);
}
