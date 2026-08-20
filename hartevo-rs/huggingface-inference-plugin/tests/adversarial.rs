use hartevo_huggingface_inference_plugin::{
    AccountScope, BlockedEnvCode, ChatMessage, ChatRole, EvidenceDisposition, FinishReason,
    GenerationBudget, HuggingFaceApiHost, HuggingFaceInferenceError, HuggingFaceInferenceProvider,
    HuggingFaceInferenceResultService, HuggingFaceInferenceScope, InferenceInput,
    InferencePermission, InferencePolicy, InferenceRequest, InferenceTask,
    MissionHuggingFaceResultConsumer, MissionScope, ModelRevision, OutputRedactionMode,
    OutputRedactionPolicy, ProjectScope, ProviderFailureClass, ProviderMode, ProviderRoute,
    RecordedProviderResponse, RequestOptions, RevocationReason, SecretKind, SecretReference,
    WorkProductScope,
};

const PROVIDER: &str = "cerebras";
const MODEL: &str = "org/model";
const REVISION: &str = "immutable-revision-001";

fn scope(task: InferenceTask, redaction: OutputRedactionPolicy) -> HuggingFaceInferenceScope {
    let secret = SecretReference::new("host-secret-handle-7", SecretKind::HfToken, 7)
        .expect("opaque secret reference");
    let account = AccountScope::with_organization(
        "account-7",
        Some("org-7"),
        InferencePermission::InferenceProviders,
        secret,
    )
    .expect("account scope");
    let model = ModelRevision::new(MODEL, REVISION).expect("immutable model revision");
    let route = ProviderRoute::new(PROVIDER).expect("allowlisted route");
    let policy = InferencePolicy::new("policy-revision-1", 4096, 8, 1024, 128, redaction)
        .expect("bounded policy");
    HuggingFaceInferenceScope::new(
        HuggingFaceApiHost::router(),
        account,
        model,
        task,
        route,
        ProjectScope::new("project-7", 3).expect("project scope"),
        MissionScope::new("mission-7", 5).expect("mission scope"),
        WorkProductScope::new("work-product-7", 9).expect("work product scope"),
        policy,
    )
    .expect("HF inference scope")
}

fn chat_request() -> InferenceRequest {
    let messages = vec![
        ChatMessage::new(ChatRole::System, "Answer concisely.").expect("system message"),
        ChatMessage::new(ChatRole::User, "What is the next decision?").expect("user message"),
    ];
    InferenceRequest::new(
        InferenceTask::ChatCompletion,
        InferenceInput::chat(messages).expect("chat input"),
        GenerationBudget::new(32, Some(500), Some(900)).expect("generation budget"),
    )
}

fn text_request() -> InferenceRequest {
    InferenceRequest::new(
        InferenceTask::TextGeneration,
        InferenceInput::text("Summarize the bounded input.").expect("text input"),
        GenerationBudget::new(32, None, Some(900)).expect("generation budget"),
    )
}

fn chat_body(content: &str) -> Vec<u8> {
    serde_json::json!({
        "id": "chatcmpl-recorded-1",
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

fn service(task: InferenceTask) -> HuggingFaceInferenceResultService {
    HuggingFaceInferenceResultService::new(
        scope(task, OutputRedactionPolicy::digest_only()),
        HuggingFaceInferenceProvider::recording(),
    )
    .expect("service registration")
}

#[test]
fn registration_fences_every_scope_dimension_and_is_digest_bound() {
    let service = service(InferenceTask::ChatCompletion);
    let registration = service.registration();
    assert!(registration.version_digest().is_sha256());
    assert!(registration.contract_digest().is_sha256());
    assert!(registration.provider_digest().is_sha256());
    assert!(registration.model_digest().is_sha256());
    assert!(registration.task_digest().is_sha256());
    assert!(registration.scope_digest().is_sha256());
    assert!(registration.permission_digest().is_sha256());
    assert!(registration.registration_digest().is_sha256());
    assert!(
        service
            .scope()
            .account()
            .secret_reference()
            .reference_digest()
            .is_sha256()
    );
    assert!(service.is_active());
}

#[test]
fn chat_recording_projects_usage_latency_finish_and_redacts_content() {
    let mut service = service(InferenceTask::ChatCompletion);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedProviderResponse::success(
                "record-chat-1",
                PROVIDER,
                MODEL,
                REVISION,
                chat_body("sensitive answer that must not be retained"),
                37,
            ),
        )
        .expect("recorded result");

    assert_eq!(evidence.disposition, EvidenceDisposition::RecordedSuccess);
    assert_eq!(evidence.latency_ms, 37);
    assert_eq!(evidence.finish_reason, Some(FinishReason::Stop));
    assert_eq!(evidence.usage.as_ref().expect("usage").total_tokens, 18);
    let content = evidence.content.as_ref().expect("redacted content");
    assert_eq!(content.preview, None);
    assert!(content.content_digest.is_sha256());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence serialization")
            .contains("sensitive answer")
    );
    assert!(!evidence.authority.connected());
    assert!(!evidence.authority.native());
    service
        .verify_inference_result(&proposal, &evidence)
        .expect("local binding verification");
}

#[test]
fn explicit_prefix_redaction_is_bounded_and_marks_truncation() {
    let redaction = OutputRedactionPolicy::prefix(5).expect("prefix policy");
    assert_eq!(redaction.mode(), OutputRedactionMode::Prefix);
    let mut service = HuggingFaceInferenceResultService::new(
        scope(InferenceTask::ChatCompletion, redaction),
        HuggingFaceInferenceProvider::fixture(),
    )
    .expect("service");
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedProviderResponse::success(
                "record-prefix-1",
                PROVIDER,
                MODEL,
                REVISION,
                chat_body("123456789"),
                2,
            ),
        )
        .expect("recorded result");
    let content = evidence.content.expect("content projection");
    assert_eq!(content.preview.as_deref(), Some("12345"));
    assert!(content.preview_truncated);
}

#[test]
fn text_generation_projects_details_without_accepting_arbitrary_shape() {
    let mut service = service(InferenceTask::TextGeneration);
    let proposal = service
        .compile_inference_proposal(&text_request())
        .expect("proposal");
    let body = serde_json::json!({
        "model": MODEL,
        "generated_text": "generated result",
        "details": {
            "finish_reason": "eos_token",
            "input_length": 4,
            "generated_tokens": 6
        }
    });
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedProviderResponse::success(
                "record-text-1",
                PROVIDER,
                MODEL,
                REVISION,
                body.to_string().into_bytes(),
                19,
            ),
        )
        .expect("text result");
    assert_eq!(evidence.finish_reason, Some(FinishReason::EosToken));
    assert_eq!(evidence.usage.expect("text usage").total_tokens, 10);
}

#[test]
fn route_model_and_revision_drift_are_fail_closed_without_failover() {
    let mut service = service(InferenceTask::ChatCompletion);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");

    let wrong_provider = RecordedProviderResponse::success(
        "route-mismatch",
        "openai",
        MODEL,
        REVISION,
        chat_body("no failover"),
        1,
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &wrong_provider)
            .expect_err("route must not fail over"),
        HuggingFaceInferenceError::ProviderRouteMismatch
    );

    let wrong_model = RecordedProviderResponse::success(
        "model-mismatch",
        PROVIDER,
        "other/model",
        REVISION,
        chat_body("no model switch"),
        1,
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &wrong_model)
            .expect_err("model must remain pinned"),
        HuggingFaceInferenceError::ModelMismatch
    );

    let wrong_revision = RecordedProviderResponse::success(
        "revision-drift",
        PROVIDER,
        MODEL,
        "another-revision",
        chat_body("no revision drift"),
        1,
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &wrong_revision)
            .expect_err("revision must remain pinned"),
        HuggingFaceInferenceError::ModelRevisionDrift
    );
    assert_eq!(
        ProviderRoute::new("auto").expect_err("auto route is not allowlisted"),
        HuggingFaceInferenceError::InvalidField {
            field: "provider_route",
            reason: "must be one explicit allowlisted Inference Provider and cannot be auto",
        }
    );
}

#[test]
fn malformed_partial_and_tool_response_are_rejected() {
    let mut service = service(InferenceTask::ChatCompletion);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let malformed = RecordedProviderResponse::success(
        "malformed",
        PROVIDER,
        MODEL,
        REVISION,
        b"not-json".to_vec(),
        1,
    );
    assert!(matches!(
        service.record_inference_receipt(&proposal, &malformed),
        Err(HuggingFaceInferenceError::MalformedResponse(_))
    ));

    let partial = RecordedProviderResponse::success(
        "partial",
        PROVIDER,
        MODEL,
        REVISION,
        br#"{"choices":[{}]}"#.to_vec(),
        1,
    );
    assert!(matches!(
        service.record_inference_receipt(&proposal, &partial),
        Err(HuggingFaceInferenceError::MalformedResponse(_))
    ));

    let tool_call = serde_json::json!({
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "do not execute",
                "tool_calls": [{"id": "x"}]
            },
            "finish_reason": "stop"
        }]
    });
    let tool_response = RecordedProviderResponse::success(
        "tool-call",
        PROVIDER,
        MODEL,
        REVISION,
        tool_call.to_string().into_bytes(),
        1,
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &tool_response)
            .expect_err("tool calls must be refused"),
        HuggingFaceInferenceError::ToolCallsForbidden
    );
}

#[test]
fn provider_error_statuses_timeout_and_server_failures_are_projected() {
    let cases = [
        (401, ProviderFailureClass::Unauthorized, false),
        (403, ProviderFailureClass::Forbidden, false),
        (404, ProviderFailureClass::NotFound, false),
        (409, ProviderFailureClass::Conflict, false),
        (429, ProviderFailureClass::RateLimited, true),
        (503, ProviderFailureClass::ServerError, true),
    ];
    for (offset, (status, class, retryable)) in cases.into_iter().enumerate() {
        let mut service = service(InferenceTask::ChatCompletion);
        let proposal = service
            .compile_inference_proposal(&chat_request())
            .expect("proposal");
        let evidence = service
            .record_inference_receipt(
                &proposal,
                &RecordedProviderResponse::http_error(
                    format!("http-error-{offset}"),
                    PROVIDER,
                    MODEL,
                    REVISION,
                    status,
                    b"sensitive provider error body".to_vec(),
                    11,
                ),
            )
            .expect("known provider error projection");
        let error = evidence.provider_error.as_ref().expect("error projection");
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
        .expect("proposal");
    let evidence = service
        .record_inference_receipt(
            &proposal,
            &RecordedProviderResponse::timeout("timeout", PROVIDER, MODEL, REVISION, 1000),
        )
        .expect("timeout projection");
    assert_eq!(
        evidence.provider_error.expect("timeout error").class,
        ProviderFailureClass::Timeout
    );
}

#[test]
fn truncation_streaming_and_tool_options_are_rejected_before_or_at_boundary() {
    let mut truncation_service = HuggingFaceInferenceResultService::new(
        scope(
            InferenceTask::ChatCompletion,
            OutputRedactionPolicy::digest_only(),
        ),
        HuggingFaceInferenceProvider::recording()
            .with_response_bound(64)
            .expect("small response bound"),
    )
    .expect("service");
    let proposal = truncation_service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let too_large = RecordedProviderResponse::success(
        "truncated",
        PROVIDER,
        MODEL,
        REVISION,
        chat_body("body exceeds the recording bound"),
        1,
    );
    assert_eq!(
        truncation_service
            .record_inference_receipt(&proposal, &too_large)
            .expect_err("large response must fail closed"),
        HuggingFaceInferenceError::ResponseTruncated
    );

    let options_service = service(InferenceTask::ChatCompletion);
    let streaming = chat_request().with_options(RequestOptions::new(true, false));
    assert_eq!(
        options_service
            .compile_inference_proposal(&streaming)
            .expect_err("streaming is outside Layer-1"),
        HuggingFaceInferenceError::StreamingForbidden
    );
    let tools = chat_request().with_options(RequestOptions::new(false, true));
    assert_eq!(
        options_service
            .compile_inference_proposal(&tools)
            .expect_err("tools are outside Layer-1"),
        HuggingFaceInferenceError::ToolCallsForbidden
    );
}

#[test]
fn tamper_replay_and_reversible_revocation_fail_closed() {
    let mut service = service(InferenceTask::ChatCompletion);
    let proposal = service
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let response = RecordedProviderResponse::success(
        "tamper-replay-1",
        PROVIDER,
        MODEL,
        REVISION,
        chat_body("stable result"),
        3,
    );
    let evidence = service
        .record_inference_receipt(&proposal, &response)
        .expect("evidence");

    let mut tampered_proposal = proposal.clone();
    tampered_proposal.request.request_digest =
        hartevo_huggingface_inference_plugin::Digest::sha256(b"tampered-request");
    assert_eq!(
        service
            .record_inference_receipt(&tampered_proposal, &response)
            .expect_err("proposal tamper"),
        HuggingFaceInferenceError::ProposalTampered
    );

    let mut tampered_evidence = evidence.clone();
    tampered_evidence.latency_ms = 999;
    assert_eq!(
        service
            .verify_inference_result(&proposal, &tampered_evidence)
            .expect_err("evidence tamper"),
        HuggingFaceInferenceError::EvidenceTampered
    );
    assert_eq!(
        service
            .record_inference_receipt(&proposal, &response)
            .expect_err("recording replay"),
        HuggingFaceInferenceError::ReplayDetected
    );

    let revocation = service
        .revoke(RevocationReason::UserRequested)
        .expect("revocation");
    assert_eq!(revocation.revision(), 1);
    assert!(!service.is_active());
    assert_eq!(
        service
            .compile_inference_proposal(&chat_request())
            .expect_err("revoked service must not compile"),
        HuggingFaceInferenceError::RegistrationRevoked
    );
    assert_eq!(
        service
            .verify_inference_result(&proposal, &evidence)
            .expect_err("revoked evidence must not verify"),
        HuggingFaceInferenceError::RegistrationRevoked
    );
    service.restore().expect("reversible restore");
    assert!(service.is_active());
    service
        .compile_inference_proposal(&chat_request())
        .expect("restored service compiles");
}

#[test]
fn blocked_env_and_all_non_native_modes_never_claim_connected_or_native() {
    for mode in [
        ProviderMode::Fixture,
        ProviderMode::Fake,
        ProviderMode::Recording,
        ProviderMode::Loopback,
        ProviderMode::BlockedEnv,
    ] {
        assert!(!mode.is_connected());
        assert!(!mode.is_native());
        let provider = HuggingFaceInferenceProvider::new(mode);
        assert!(!provider.connected());
        assert!(!provider.native());
    }

    let mut consumer = MissionHuggingFaceResultConsumer::new(
        scope(
            InferenceTask::ChatCompletion,
            OutputRedactionPolicy::digest_only(),
        ),
        HuggingFaceInferenceProvider::blocked_env(),
    )
    .expect("BLOCKED_ENV consumer");
    let proposal = consumer
        .compile_inference_proposal(&chat_request())
        .expect("proposal remains possible");
    let projection = consumer
        .service_mut()
        .record_blocked_env(
            &proposal,
            "blocked-env-1",
            BlockedEnvCode::NativeTransportUnavailable,
            0,
        )
        .expect("blocked env projection");
    assert_eq!(projection.disposition, EvidenceDisposition::BlockedEnv);
    assert_eq!(projection.authority.mode(), ProviderMode::BlockedEnv);
    assert!(!projection.authority.connected());
    assert!(!projection.authority.native());
}

#[test]
fn mission_consumer_binds_project_mission_work_product_without_adoption_authority() {
    let mut consumer = MissionHuggingFaceResultConsumer::new(
        scope(
            InferenceTask::ChatCompletion,
            OutputRedactionPolicy::digest_only(),
        ),
        HuggingFaceInferenceProvider::loopback(),
    )
    .expect("consumer");
    let proposal = consumer
        .compile_inference_proposal(&chat_request())
        .expect("proposal");
    let projection = consumer
        .consume_recorded_result(
            &proposal,
            &RecordedProviderResponse::success(
                "mission-result-1",
                PROVIDER,
                MODEL,
                REVISION,
                chat_body("next decision"),
                4,
            ),
        )
        .expect("mission result projection");
    assert_eq!(projection.project_id, "project-7");
    assert_eq!(projection.mission_id, "mission-7");
    assert_eq!(projection.work_product_id, "work-product-7");
    assert!(projection.proposal_only());
    assert!(!projection.connected());
    assert!(!projection.native());
}

#[test]
fn opaque_secret_reference_never_serializes_the_input_handle() {
    let raw_handle = "hf_secret_bytes_must_not_be_retained";
    let secret = SecretReference::new(raw_handle, SecretKind::OAuth, 4).expect("secret ref");
    let debug = format!("{secret:?}");
    let json = serde_json::to_string(&secret).expect("secret reference JSON");
    assert!(!debug.contains(raw_handle));
    assert!(!json.contains(raw_handle));
    assert!(json.contains("referenceDigest"));
}
