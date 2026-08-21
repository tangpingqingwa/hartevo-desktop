use hartevo_vertex_ai_generation_result_plugin as vertex;
use serde_json::{Value, json};

fn scope() -> vertex::VertexAiGenerationScope {
    let secret = vertex::SecretReference::new(
        "host-keyring:vertex-ai:primary",
        vertex::SecretKind::ServiceAccount,
        7,
    )
    .expect("secret reference");
    vertex::VertexAiGenerationScope::new(
        vertex::GoogleCloudProject::new("project-1", 3).expect("Google project"),
        vertex::VertexLocation::new("us-central1").expect("regional location"),
        vertex::VertexPublisher::Google,
        vertex::ModelSnapshot::new("gemini-2.5-flash", "001").expect("model snapshot"),
        vertex::InputPolicy::bounded(),
        vertex::SafetyPolicy::strict("safety-policy/v1").expect("safety policy"),
        vertex::ToolGroundingPolicy::disabled("tool-policy/v1").expect("tool policy"),
        vertex::ResponseScope::bounded(),
        vertex::MissionScope::new("mission-1", 4).expect("Mission"),
        vertex::ProjectScope::new("project-scope-1", 5).expect("Project"),
        vertex::WorkProductScope::new("work-product-1", 6).expect("Work Product"),
        vertex::ConsentScope::new("consent-1", 8).expect("Consent"),
        vertex::PermissionScope::generate_content(secret).expect("permission"),
    )
    .expect("scope")
}

fn service() -> vertex::VertexAiGenerationResultService {
    vertex::VertexAiGenerationResultService::new(
        scope(),
        vertex::VertexAiGenerationProvider::recording(),
    )
    .expect("service")
}

fn request() -> vertex::GenerationRequest {
    vertex::GenerationRequest::new(
        vertex::GenerationInput::text("private prompt that must not be retained")
            .expect("text input"),
    )
    .with_max_output_tokens(64)
}

fn success_body() -> &'static str {
    r#"{
        "responseId": "response-1",
        "modelVersion": "gemini-2.5-flash-001",
        "candidates": [{
            "index": 0,
            "content": {"role": "model", "parts": [{"text": "private generated output"}]},
            "finishReason": "STOP",
            "safetyRatings": [{
                "category": "HARM_CATEGORY_HARASSMENT",
                "probability": "NEGLIGIBLE",
                "severity": "NEGLIGIBLE",
                "blocked": false
            }]
        }],
        "usageMetadata": {
            "promptTokenCount": 8,
            "candidatesTokenCount": 4,
            "totalTokenCount": 12
        }
    }"#
}

fn success_response(recording_id: &str) -> vertex::RecordedVertexAiResponse {
    vertex::RecordedVertexAiResponse::success(
        recording_id,
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "us-central1",
        "google",
        "gemini-2.5-flash",
        "001",
        success_body(),
        12,
    )
}

#[test]
fn secret_reference_is_opaque_and_non_serialized() {
    let secret = vertex::SecretReference::new(
        "opaque-native-credential-handle",
        vertex::SecretKind::OAuth,
        2,
    )
    .expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-native-credential-handle"));
    assert!(debug.contains("reference_digest"));
    assert_eq!(secret.credential_revision(), 2);
}

#[test]
fn scope_rejects_global_location_and_floating_or_non_gemini_models() {
    assert!(vertex::VertexLocation::new("global").is_err());
    assert!(vertex::ModelSnapshot::new("text-bison", "001").is_err());
    assert!(vertex::ModelSnapshot::new("gemini-2.5-flash", "latest").is_err());
    assert!(vertex::ToolGroundingPolicy::new("tool/v1", true, false, false, false).is_err());
}

#[test]
fn proposal_and_evidence_retain_digests_not_raw_content() {
    let mut service = service();
    let request = request();
    let proposal = service
        .compile_generation_proposal(&request)
        .expect("proposal");
    let proposal_json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!proposal_json.contains("private prompt"));
    assert!(!proposal_json.contains("generated output"));
    assert!(proposal_json.contains("inputDigest"));

    let evidence = service
        .record_generation_result(&proposal, &success_response("recording-1"))
        .expect("evidence");
    assert_eq!(evidence.state, vertex::ResponseState::Complete);
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
    assert_eq!(evidence.provenance, vertex::ProviderMode::Recording);
    assert_eq!(evidence.candidates.len(), 1);
    assert!(evidence.candidates[0].content_digest.is_sha256());
    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!evidence_json.contains("private generated output"));
    assert!(!evidence_json.contains("private prompt"));
    assert!(!evidence_json.contains("groundingChunks"));
    service
        .verify_generation_result(&proposal, &evidence)
        .expect("local evidence verification");
}

#[test]
fn response_parser_rejects_tools_grounding_reasoning_and_file_bytes() {
    for forbidden in [
        r#"{"responseId":"r","modelVersion":"gemini-2.5-flash-001","tools":[]}"#,
        r#"{"responseId":"r","modelVersion":"gemini-2.5-flash-001","groundingChunks":[]}"#,
        r#"{"responseId":"r","modelVersion":"gemini-2.5-flash-001","thought":"hidden"}"#,
        r#"{"responseId":"r","modelVersion":"gemini-2.5-flash-001","fileBytes":"raw"}"#,
    ] {
        assert!(vertex::VertexAiResponse::from_json(forbidden).is_err());
    }
}

#[test]
fn multimodal_input_is_allowlisted_and_bounded_without_file_bytes() {
    let image = vertex::InputPart::image_reference("file-handle-1", "image/png", 1024)
        .expect("image reference");
    let document = vertex::InputPart::document_reference("doc-handle-1", "application/pdf", 2048)
        .expect("document reference");
    let input = vertex::GenerationInput::multimodal(vec![
        vertex::InputPart::text("describe these references").expect("text"),
        image,
        document,
    ])
    .expect("multimodal input");
    assert_eq!(input.parts().len(), 3);
    assert!(input.input_digest().is_sha256());
    assert!(vertex::InputPart::image_reference("file-handle-2", "image/gif", 1).is_err());
    assert!(vertex::InputPart::document_reference("doc-handle-2", "application/zip", 1).is_err());
    assert!(
        vertex::InputPart::image_reference(
            "file-handle-3",
            "image/png",
            vertex::MAX_IMAGE_REFERENCE_BYTES + 1
        )
        .is_err()
    );
}

#[test]
fn request_enforces_policy_and_tool_grounding_gates() {
    let service = service();
    let proposal = service
        .compile_generation_proposal(
            &request().with_options(vertex::RequestOptions::new(false, true, false)),
        )
        .expect_err("tool calls must be rejected");
    assert_eq!(
        proposal,
        vertex::VertexAiGenerationError::ToolCallsForbidden
    );

    let grounding = service
        .compile_generation_proposal(
            &request().with_options(vertex::RequestOptions::new(false, false, true)),
        )
        .expect_err("grounding must be rejected");
    assert_eq!(
        grounding,
        vertex::VertexAiGenerationError::GroundingForbidden
    );

    let too_many_tokens = service
        .compile_generation_proposal(
            &request().with_max_output_tokens(vertex::MAX_OUTPUT_TOKENS + 1),
        )
        .expect_err("token bound");
    assert_eq!(
        too_many_tokens,
        vertex::VertexAiGenerationError::OutputTokenBudgetExceeded
    );
}

#[test]
fn optional_schema_is_digest_bound() {
    let schema = vertex::OutputSchema::from_json_schema(
        "answer",
        br#"{"type":"object","properties":{"answer":{"type":"string"}}}"#,
    )
    .expect("schema");
    let response = vertex::ResponseScope::bounded()
        .with_output_schema(schema.clone())
        .expect("response schema");
    let base = scope();
    let scoped = vertex::VertexAiGenerationScope::new(
        base.google_cloud_project().clone(),
        base.location().clone(),
        base.publisher(),
        base.model().clone(),
        base.input_policy().clone(),
        base.safety_policy().clone(),
        base.tool_grounding_policy().clone(),
        response,
        base.mission().clone(),
        base.project().clone(),
        base.work_product().clone(),
        base.consent().clone(),
        base.permission().clone(),
    )
    .expect("schema scope");
    let service = vertex::VertexAiGenerationResultService::new(
        scoped,
        vertex::VertexAiGenerationProvider::fixture(),
    )
    .expect("schema service");
    let request = request().with_output_schema(Some(schema));
    let proposal = service
        .compile_generation_proposal(&request)
        .expect("schema proposal");
    assert!(proposal.request().output_schema_digest().is_some());
}

#[test]
fn http_statuses_are_normalized_without_native_claims() {
    let statuses = [
        (400, vertex::ResponseState::Failed),
        (401, vertex::ResponseState::AccessLost),
        (403, vertex::ResponseState::AccessLost),
        (404, vertex::ResponseState::ProviderUnknown),
        (409, vertex::ResponseState::Failed),
        (429, vertex::ResponseState::RateLimited),
        (500, vertex::ResponseState::Failed),
        (503, vertex::ResponseState::Failed),
    ];
    for (index, (status, expected_state)) in statuses.into_iter().enumerate() {
        let mut service = service();
        let proposal = service
            .compile_generation_proposal(&request())
            .expect("proposal");
        let response = vertex::RecordedVertexAiResponse::http_error(
            format!("error-{index}"),
            vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
            "project-1",
            "us-central1",
            "google",
            "gemini-2.5-flash",
            "001",
            status,
            b"provider body is never retained",
            9,
        );
        let evidence = service
            .record_generation_result(&proposal, &response)
            .expect("normalized error evidence");
        assert_eq!(evidence.state, expected_state);
        assert!(!evidence.authority.native);
        assert!(!evidence.authority.connected);
    }
}

#[test]
fn safety_block_and_partial_response_are_visible() {
    let mut blocked_service = service();
    let blocked_proposal = blocked_service
        .compile_generation_proposal(&request())
        .expect("blocked proposal");
    let blocked_body = r#"{
        "responseId":"blocked-response",
        "modelVersion":"gemini-2.5-flash-001",
        "promptFeedback":{"blockReason":"SAFETY","safetyRatings":[]}
    }"#;
    let blocked = blocked_service
        .record_generation_result(
            &blocked_proposal,
            &vertex::RecordedVertexAiResponse::success(
                "safety-block-recording",
                vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
                "project-1",
                "us-central1",
                "google",
                "gemini-2.5-flash",
                "001",
                blocked_body,
                3,
            ),
        )
        .expect("blocked evidence");
    assert_eq!(blocked.state, vertex::ResponseState::Blocked);
    assert!(blocked.prompt_feedback.is_some());

    let mut partial_service = service();
    let partial_proposal = partial_service
        .compile_generation_proposal(&request())
        .expect("partial proposal");
    let partial_body = success_body().replace("\"STOP\"", "\"MAX_TOKENS\"");
    let partial = partial_service
        .record_generation_result(
            &partial_proposal,
            &vertex::RecordedVertexAiResponse::success(
                "partial-recording",
                vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
                "project-1",
                "us-central1",
                "google",
                "gemini-2.5-flash",
                "001",
                partial_body.as_bytes(),
                4,
            ),
        )
        .expect("partial evidence");
    assert_eq!(partial.state, vertex::ResponseState::Partial);
}

#[test]
fn malformed_candidate_is_fail_closed() {
    let mut service = service();
    let proposal = service
        .compile_generation_proposal(&request())
        .expect("proposal");
    let malformed = vertex::RecordedVertexAiResponse::success(
        "malformed-recording",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "us-central1",
        "google",
        "gemini-2.5-flash",
        "001",
        r#"{
            "responseId":"malformed",
            "modelVersion":"gemini-2.5-flash-001",
            "candidates":[{"content":{"parts":[{"functionCall":{"name":"secret"}}]}}]
        }"#,
        1,
    );
    assert!(matches!(
        service.record_generation_result(&proposal, &malformed),
        Err(vertex::VertexAiGenerationError::MalformedResponse(_))
    ));
}

#[test]
fn project_location_model_and_mission_drift_are_rejected() {
    let mut service = service();
    let proposal = service
        .compile_generation_proposal(&request())
        .expect("proposal");
    let wrong_project = vertex::RecordedVertexAiResponse::success(
        "wrong-project",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "other-project",
        "us-central1",
        "google",
        "gemini-2.5-flash",
        "001",
        success_body(),
        1,
    );
    assert_eq!(
        service.record_generation_result(&proposal, &wrong_project),
        Err(vertex::VertexAiGenerationError::ProjectMismatch)
    );
    let wrong_location = vertex::RecordedVertexAiResponse::success(
        "wrong-location",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "europe-west4",
        "google",
        "gemini-2.5-flash",
        "001",
        success_body(),
        1,
    );
    assert_eq!(
        service.record_generation_result(&proposal, &wrong_location),
        Err(vertex::VertexAiGenerationError::LocationMismatch)
    );
    let wrong_model = vertex::RecordedVertexAiResponse::success(
        "wrong-model",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "us-central1",
        "google",
        "gemini-2.5-pro",
        "001",
        success_body(),
        1,
    );
    assert_eq!(
        service.record_generation_result(&proposal, &wrong_model),
        Err(vertex::VertexAiGenerationError::ModelMismatch)
    );

    let stale_scope = {
        let base = scope();
        vertex::VertexAiGenerationScope::new(
            base.google_cloud_project().clone(),
            base.location().clone(),
            base.publisher(),
            base.model().clone(),
            base.input_policy().clone(),
            base.safety_policy().clone(),
            base.tool_grounding_policy().clone(),
            base.response().clone(),
            vertex::MissionScope::new("mission-1", 5).expect("stale Mission"),
            base.project().clone(),
            base.work_product().clone(),
            base.consent().clone(),
            base.permission().clone(),
        )
        .expect("stale scope")
    };
    let stale_service = vertex::VertexAiGenerationResultService::new(
        stale_scope,
        vertex::VertexAiGenerationProvider::recording(),
    )
    .expect("stale service");
    let stale_proposal = stale_service
        .compile_generation_proposal(&request())
        .expect("stale proposal");
    assert!(
        service
            .record_generation_result(&proposal, &success_response("fresh"))
            .is_ok()
    );
    assert!(matches!(
        service.record_generation_result(&stale_proposal, &success_response("stale")),
        Err(vertex::VertexAiGenerationError::ScopeMismatch(_))
    ));
}

#[test]
fn tamper_replay_revocation_and_blocked_env_fail_closed() {
    let mut service = service();
    let request = request();
    let proposal = service
        .compile_generation_proposal(&request)
        .expect("proposal");
    let mut fresh_service = vertex::VertexAiGenerationResultService::new(
        scope(),
        vertex::VertexAiGenerationProvider::recording(),
    )
    .expect("fresh service");
    assert_eq!(
        fresh_service.record_generation_result(&proposal, &success_response("tampered")),
        Err(vertex::VertexAiGenerationError::ScopeMismatch(
            "proposal has no trusted canonical request source"
        ))
    );

    let proposal = service
        .compile_generation_proposal(&request)
        .expect("proposal");
    let evidence = service
        .record_generation_result(&proposal, &success_response("replay"))
        .expect("first evidence");
    let mut tampered_evidence = evidence.clone();
    tampered_evidence.state = vertex::ResponseState::Failed;
    assert_eq!(
        service.verify_generation_result(&proposal, &tampered_evidence),
        Err(vertex::VertexAiGenerationError::EvidenceTampered)
    );
    assert_eq!(
        service.record_generation_result(&proposal, &success_response("replay")),
        Err(vertex::VertexAiGenerationError::ReplayDetected)
    );

    service
        .revoke(vertex::RevocationReason::UserRequested)
        .expect("revoke");
    assert!(matches!(
        service.compile_generation_proposal(&request),
        Err(vertex::VertexAiGenerationError::RegistrationRevoked)
    ));
    service.restore().expect("restore");
    assert!(service.compile_generation_proposal(&request).is_ok());

    let mut blocked_service = vertex::VertexAiGenerationResultService::new(
        scope(),
        vertex::VertexAiGenerationProvider::blocked_env(),
    )
    .expect("BLOCKED_ENV service");
    let blocked_proposal = blocked_service
        .compile_generation_proposal(&request)
        .expect("blocked proposal");
    let blocked = blocked_service
        .record_blocked_env(
            &blocked_proposal,
            "blocked-env-recording",
            vertex::BlockedEnvCode::CredentialResolutionUnavailable,
            0,
        )
        .expect("blocked evidence");
    assert_eq!(blocked.provenance, vertex::ProviderMode::BlockedEnv);
    assert_eq!(blocked.state, vertex::ResponseState::ProviderUnknown);
    assert!(!blocked.authority.connected);
    assert!(!blocked.authority.native);
}

#[test]
fn mission_consumer_is_proposal_only() {
    let mut consumer = vertex::MissionVertexAiResultConsumer::new(
        scope(),
        vertex::VertexAiGenerationProvider::loopback(),
    )
    .expect("consumer");
    let proposal = consumer
        .compile_generation_proposal(&request())
        .expect("proposal");
    let result = consumer
        .consume_recorded_result(&proposal, &success_response("mission-recording"))
        .expect("Mission result");
    assert!(result.proposal_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.durable_receipt);
    assert!(!result.independent_read_back);
    assert!(!result.adopted_outcome);
    assert_eq!(result.mission_revision, 4);
    assert_eq!(result.request_digest, *proposal.request().request_digest());
    assert_eq!(
        result.request_source_fence,
        *proposal.request().source_fence()
    );
    assert_eq!(
        result.response_accounting_policy_digest,
        *proposal.response_accounting_policy_digest()
    );
    assert_eq!(
        result.response_byte_accounting,
        vertex::ResponseByteAccounting::Exact(success_body().len() as u64)
    );
    let mission_json = serde_json::to_value(&result).expect("mission JSON");
    assert_eq!(
        mission_json["responseByteAccounting"]["exact"],
        json!(success_body().len() as u64)
    );
    result.verify_integrity().expect("mission integrity");

    let mut tampered_result = result.clone();
    tampered_result.response_byte_accounting = vertex::ResponseByteAccounting::Unknown;
    assert_eq!(
        tampered_result.verify_integrity(),
        Err(vertex::VertexAiGenerationError::EvidenceTampered)
    );
}

#[test]
fn contract_is_versioned_and_non_native() {
    let contract: Value =
        serde_json::from_str(vertex::VERTEX_AI_GENERATION_CONTRACT_JSON).expect("contract JSON");
    assert_eq!(
        contract["schemaVersion"],
        vertex::VERTEX_AI_GENERATION_SCHEMA_VERSION
    );
    assert_eq!(contract["operation"], "generateContent");
    assert_eq!(contract["endpoint"]["regional"], true);
    assert_eq!(contract["provenance"].as_array().map(Vec::len), Some(4));
    assert_eq!(contract["authority"]["connected"], false);
    assert_eq!(contract["authority"]["native"], false);
    assert_eq!(contract["layer2Gaps"].as_array().map(Vec::len), Some(6));
}

#[test]
fn serde_revalidates_nested_scopes_and_policy_bounds() {
    assert!(
        serde_json::from_value::<vertex::GoogleCloudProject>(json!({
            "projectId": "Project-1",
            "revision": 1
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<vertex::VertexLocation>(json!("global")).is_err());
    assert!(
        serde_json::from_value::<vertex::ModelSnapshot>(json!({
            "modelId": "text-bison",
            "immutableSnapshot": "001"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::ModelSnapshot>(json!({
            "modelId": "gemini-2.5-flash",
            "immutableSnapshot": "latest"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::ProjectScope>(json!({
            "id": "project-scope",
            "revision": 0
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::MissionScope>(json!({
            "id": "mission",
            "revision": 0
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::WorkProductScope>(json!({
            "id": "work-product",
            "revision": 0
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::InputPolicy>(json!({
            "revision": "latest",
            "allowedModalities": ["text"],
            "maxInputBytes": 1,
            "maxParts": 1,
            "maxTextBytes": 1,
            "maxImageBytes": 1,
            "maxDocumentBytes": 1
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::SafetyPolicy>(json!({
            "revision": "latest",
            "settings": [],
            "blockOnUnspecified": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::ToolGroundingPolicy>(json!({
            "revision": "tool/v1",
            "allowToolCalls": true,
            "allowGrounding": false,
            "allowSearchGrounding": false,
            "allowMapsGrounding": false
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::ResponseScope>(json!({
            "revision": "response/v1",
            "maxCandidates": 0,
            "maxOutputBytes": 1,
            "maxOutputTokens": 1,
            "outputSchema": null,
            "redaction": {
                "mode": "digest_only",
                "retainRawPrompts": false,
                "retainRawOutputs": false,
                "retainHiddenReasoning": false,
                "retainGroundingChunks": false,
                "retainToolArguments": false,
                "retainFileBytes": false
            }
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::ConsentScope>(json!({
            "consentDigest": vertex::Digest::sha256("consent"),
            "revision": 1,
            "purpose": "wrong-purpose"
        }))
        .is_err()
    );
}

#[test]
fn serde_generation_input_recomputes_bounds_count_total_and_digest() {
    let input = vertex::GenerationInput::text("bounded input").expect("input");
    let mut forged_total = serde_json::to_value(&input).expect("input JSON");
    forged_total["totalBytes"] = json!(0);
    assert!(serde_json::from_value::<vertex::GenerationInput>(forged_total).is_err());

    let mut forged_part = serde_json::to_value(&input).expect("input JSON");
    forged_part["parts"][0]["byteLength"] = json!(vertex::MAX_TEXT_INPUT_BYTES + 1);
    assert!(serde_json::from_value::<vertex::GenerationInput>(forged_part).is_err());

    let mut forged_digest = serde_json::to_value(&input).expect("input JSON");
    forged_digest["inputDigest"] = json!(vertex::Digest::sha256("wrong-input"));
    assert!(serde_json::from_value::<vertex::GenerationInput>(forged_digest).is_err());

    let image = vertex::GenerationInput::image_reference("image-handle", "image/png", 4)
        .expect("image input");
    let mut forged_media = serde_json::to_value(&image).expect("image JSON");
    forged_media["parts"][0]["mediaType"] = json!("image/gif");
    assert!(serde_json::from_value::<vertex::GenerationInput>(forged_media).is_err());
}

#[test]
fn recording_tombstone_is_global_across_clones_and_resealed_scopes() {
    let mut first_service = service();
    let first_proposal = first_service
        .compile_generation_proposal(&request())
        .expect("first proposal");
    first_service
        .record_generation_result(&first_proposal, &success_response("global-replay-clone"))
        .expect("first recording");

    let mut cloned_service = first_service.clone();
    assert_eq!(
        cloned_service
            .record_generation_result(&first_proposal, &success_response("global-replay-clone"),),
        Err(vertex::VertexAiGenerationError::ReplayDetected)
    );

    let base = scope();
    let resealed_scope = vertex::VertexAiGenerationScope::new(
        base.google_cloud_project().clone(),
        base.location().clone(),
        base.publisher(),
        base.model().clone(),
        base.input_policy().clone(),
        base.safety_policy().clone(),
        base.tool_grounding_policy().clone(),
        base.response().clone(),
        vertex::MissionScope::new("mission-1", 99).expect("resealed Mission"),
        base.project().clone(),
        vertex::WorkProductScope::new("work-product-1", 100).expect("resealed Work Product"),
        base.consent().clone(),
        base.permission().clone(),
    )
    .expect("resealed scope");
    let mut fresh_service = vertex::VertexAiGenerationResultService::new(
        resealed_scope,
        vertex::VertexAiGenerationProvider::recording(),
    )
    .expect("fresh service");
    let resealed_proposal = fresh_service
        .compile_generation_proposal(&request())
        .expect("resealed proposal");
    assert_ne!(
        resealed_proposal.proposal_digest(),
        first_proposal.proposal_digest()
    );
    assert_eq!(
        fresh_service.record_generation_result(
            &resealed_proposal,
            &success_response("global-replay-clone"),
        ),
        Err(vertex::VertexAiGenerationError::ReplayDetected)
    );
    assert!(!vertex::VertexAiGenerationProvider::recording().replay_fence_durable());
}

#[test]
fn canonical_request_source_binding_rejects_cross_request_and_fresh_service_use() {
    let mut service = service();
    let first_request = request();
    let second_request = request().with_max_output_tokens(128);
    let first_proposal = service
        .compile_generation_proposal(&first_request)
        .expect("first proposal");
    let second_proposal = service
        .compile_generation_proposal(&second_request)
        .expect("second proposal");
    assert_ne!(
        first_proposal.request().request_digest(),
        second_proposal.request().request_digest()
    );
    assert_ne!(
        first_proposal.request().source_fence(),
        second_proposal.request().source_fence()
    );

    let evidence = service
        .record_generation_result(
            &first_proposal,
            &success_response("canonical-request-binding"),
        )
        .expect("first evidence");
    assert_eq!(
        evidence.request_digest,
        *first_proposal.request().request_digest()
    );
    assert_eq!(
        evidence.request_source_fence,
        *first_proposal.request().source_fence()
    );

    let mut fresh_service = vertex::VertexAiGenerationResultService::new(
        scope(),
        vertex::VertexAiGenerationProvider::recording(),
    )
    .expect("fresh service");
    assert_eq!(
        fresh_service
            .record_generation_result(&first_proposal, &success_response("fresh-source-binding"),),
        Err(vertex::VertexAiGenerationError::ScopeMismatch(
            "proposal has no trusted canonical request source"
        ))
    );
}

#[test]
fn response_serde_and_ingress_revalidate_ceiling_and_metadata() {
    let candidate = json!({
        "index": 0,
        "contentDigest": vertex::Digest::sha256("candidate"),
        "contentByteLength": vertex::MAX_OUTPUT_BYTES + 1,
        "finishReason": "stop",
        "safetyRatings": []
    });
    assert!(serde_json::from_value::<vertex::VertexAiCandidate>(candidate.clone()).is_err());
    assert!(
        serde_json::from_value::<vertex::VertexAiResponse>(json!({
            "responseId": "response",
            "modelVersion": "gemini-2.5-flash-001",
            "candidates": [candidate],
            "promptFeedback": null,
            "usageMetadata": null
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::UsageMetadata>(json!({
            "promptTokenCount": 5,
            "candidatesTokenCount": 5,
            "totalTokenCount": 1,
            "cachedContentTokenCount": null,
            "thoughtsTokenCount": null
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<vertex::UsageMetadata>(json!({
            "promptTokenCount": u64::MAX,
            "candidatesTokenCount": 1,
            "totalTokenCount": u64::MAX,
            "cachedContentTokenCount": null,
            "thoughtsTokenCount": null
        }))
        .is_err()
    );

    let oversized = vec![b' '; vertex::MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        vertex::VertexAiResponse::from_json(&oversized),
        Err(vertex::VertexAiGenerationError::ResponseTooLarge)
    );

    let response = success_response("truthful-body-bytes");
    assert_eq!(response.body_bytes(), Some(success_body().len()));
    assert_eq!(
        response.response_byte_accounting(),
        vertex::ResponseByteAccounting::Exact(success_body().len() as u64)
    );
    assert!(response.response_digest().is_some());

    let mut service = service();
    let proposal = service
        .compile_generation_proposal(&request())
        .expect("proposal");
    let raw_evidence = service
        .record_generation_result(&proposal, &success_response("raw-accounting-evidence"))
        .expect("raw evidence");
    assert_eq!(
        raw_evidence.response_byte_accounting,
        vertex::ResponseByteAccounting::Exact(success_body().len() as u64)
    );
    assert_eq!(
        raw_evidence.response_accounting_policy_digest,
        *proposal.response_accounting_policy_digest()
    );
    let raw_evidence_json = serde_json::to_value(&raw_evidence).expect("raw evidence JSON");
    assert_eq!(
        raw_evidence_json["responseByteAccounting"]["exact"],
        json!(success_body().len() as u64)
    );
    service
        .verify_generation_result(&proposal, &raw_evidence)
        .expect("raw evidence verification");

    let parsed = vertex::VertexAiResponse::from_json(success_body()).expect("parsed response");
    let typed_fixture = vertex::RecordedVertexAiResponse::from_response(
        "typed-fixture-unknown-bytes",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "us-central1",
        "google",
        "gemini-2.5-flash",
        "001",
        parsed.clone(),
        0,
    );
    assert_eq!(typed_fixture.body_bytes(), None);
    assert_eq!(
        typed_fixture.response_byte_accounting(),
        vertex::ResponseByteAccounting::Unknown
    );
    let typed_evidence = service
        .record_generation_result(&proposal, &typed_fixture)
        .expect("typed fixture evidence");
    assert_eq!(typed_evidence.response_digest, parsed.response_digest());
    assert_eq!(
        typed_evidence.response_byte_accounting,
        vertex::ResponseByteAccounting::Unknown
    );
    let mut missing_accounting = serde_json::to_value(&typed_evidence).expect("evidence JSON");
    assert_eq!(
        missing_accounting["responseByteAccounting"],
        json!("unknown")
    );
    missing_accounting
        .as_object_mut()
        .expect("evidence object")
        .remove("responseByteAccounting");
    assert!(
        serde_json::from_value::<vertex::GenerationResultEvidence>(missing_accounting).is_err()
    );

    let mut unknown_resealed_as_exact = typed_evidence.clone();
    unknown_resealed_as_exact.response_byte_accounting = vertex::ResponseByteAccounting::Exact(0);
    unknown_resealed_as_exact.evidence_digest = unknown_resealed_as_exact.compute_digest();
    assert_eq!(
        service.verify_generation_result(&proposal, &unknown_resealed_as_exact),
        Err(vertex::VertexAiGenerationError::EvidenceTampered)
    );

    let mut exact_count_mismatch = raw_evidence.clone();
    exact_count_mismatch.response_byte_accounting =
        vertex::ResponseByteAccounting::Exact(success_body().len() as u64 + 1);
    exact_count_mismatch.evidence_digest = exact_count_mismatch.compute_digest();
    assert_eq!(
        service.verify_generation_result(&proposal, &exact_count_mismatch),
        Err(vertex::VertexAiGenerationError::EvidenceTampered)
    );

    let oversized_proposal = service
        .compile_generation_proposal(&request())
        .expect("oversized proposal");
    let oversized_response = vertex::RecordedVertexAiResponse::success(
        "forged-response-ceiling",
        vertex::VERTEX_AI_GENERATION_PROVIDER_ID,
        "project-1",
        "us-central1",
        "google",
        "gemini-2.5-flash",
        "001",
        vec![b' '; vertex::MAX_RESPONSE_BYTES + 1],
        0,
    );
    assert_eq!(
        oversized_response.body_bytes(),
        Some(vertex::MAX_RESPONSE_BYTES + 1)
    );
    assert_eq!(
        service.record_generation_result(&oversized_proposal, &oversized_response),
        Err(vertex::VertexAiGenerationError::ResponseTooLarge)
    );
}
