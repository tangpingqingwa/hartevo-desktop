use hartevo_openai_responses_result_plugin::{
    BlockedEnvCode, ConsentScope, EvidenceDisposition, FileReference, ImageReference, InputPolicy,
    MissionOpenAIResponsesConsumer, MissionScope, ModelSnapshot, OpenAIResponsesPermission,
    OpenAIResponsesProvider, OpenAIResponsesProviderScope, OpenAIResponsesRequest,
    OpenAIResponsesResultError, OpenAIResponsesResultService, OpenAIResponsesScope,
    OrganizationScope, OutputRetentionMode, OutputRetentionPolicy, PermissionScope, ProjectScope,
    ProviderMode, RecordedResponseFrame, RequestId, ResponseStatus, ResponsesInput,
    ResponsesInputItem, RevocationReason, SecretReference, StructuredOutputSchema, ToolPolicy,
    WorkProductScope,
};

use serde_json::json;

const PROVIDER: &str = "openai.responses";
const MODEL_ID: &str = "gpt-5.6-luna";
const MODEL_SNAPSHOT: &str = "gpt-5.6-luna-2026-08-01";

fn schema() -> StructuredOutputSchema {
    StructuredOutputSchema::new(
        "decision",
        json!({
            "type": "object",
            "properties": {
                "answer": {"type": "string"},
                "confidence": {"type": "number"}
            },
            "required": ["answer", "confidence"],
            "additionalProperties": false
        }),
        true,
    )
    .expect("strict schema")
}

fn policy(retention: OutputRetentionPolicy) -> InputPolicy {
    InputPolicy::new(
        "input-policy-v1",
        4096,
        4096,
        4096,
        1024,
        5_000,
        50_000,
        retention,
    )
    .expect("bounded input policy")
    .with_item_bounds(1024, 8, 2, 2)
    .expect("item bounds")
}

fn scope(
    structured_schema: Option<StructuredOutputSchema>,
    retention: OutputRetentionPolicy,
    declared_file: Option<&FileReference>,
    mission_revision: u64,
) -> OpenAIResponsesScope {
    let mut input_policy = policy(retention);
    if let Some(file) = declared_file {
        input_policy = input_policy.with_declared_file_reference(file);
    }
    let secret = SecretReference::new("host-owned-openai-key-handle", 3).expect("secret ref");
    let permission = PermissionScope::new(OpenAIResponsesPermission::ResponsesCreate, secret);
    OpenAIResponsesScope::new(
        OpenAIResponsesProviderScope::openai(),
        OrganizationScope::new("org-hartevo", 4).expect("organization"),
        ProjectScope::new("project-decision", 7).expect("project"),
        permission,
        ModelSnapshot::new(MODEL_ID, MODEL_SNAPSHOT).expect("model snapshot"),
        input_policy,
        structured_schema,
        ToolPolicy::disabled(),
        MissionScope::new("mission-next-decision", mission_revision).expect("mission"),
        WorkProductScope::new("work-product-answer", 2).expect("work product"),
        ConsentScope::new("consent-response", 1, retention).expect("consent"),
    )
    .expect("scope")
}

fn service(
    structured_schema: Option<StructuredOutputSchema>,
    retention: OutputRetentionPolicy,
) -> OpenAIResponsesResultService {
    OpenAIResponsesResultService::new(
        scope(structured_schema, retention, None, 5),
        OpenAIResponsesProvider::recording(),
    )
    .expect("service")
}

fn request(input: ResponsesInput) -> OpenAIResponsesRequest {
    OpenAIResponsesRequest::new(RequestId::new("request-1").expect("request id"), input)
}

fn success_body(content: &str, status: &str) -> Vec<u8> {
    json!({
        "id": "resp_123",
        "object": "response",
        "status": status,
        "model": MODEL_SNAPSHOT,
        "output_text": content,
        "usage": {
            "input_tokens": 12,
            "output_tokens": 8,
            "total_tokens": 20,
            "input_tokens_details": {"cached_tokens": 2}
        }
    })
    .to_string()
    .into_bytes()
}

fn success_frame(body: Vec<u8>, recording_id: &str) -> RecordedResponseFrame {
    RecordedResponseFrame::success(recording_id, PROVIDER, MODEL_ID, MODEL_SNAPSHOT, body, 37)
}

#[test]
fn registration_binds_version_provider_project_snapshot_policy_schema_tools_permission_and_consent()
{
    let service = service(None, OutputRetentionPolicy::digest_only());
    let registration = service.registration();
    assert!(registration.version_digest().is_sha256());
    assert!(registration.contract_digest().is_sha256());
    assert!(registration.provider_digest().is_sha256());
    assert!(registration.organization_digest().is_sha256());
    assert!(registration.project_digest().is_sha256());
    assert!(registration.model_snapshot_digest().is_sha256());
    assert!(registration.input_policy_digest().is_sha256());
    assert!(registration.structured_schema_digest().is_none());
    assert!(registration.tool_policy_digest().is_sha256());
    assert!(registration.permission_digest().is_sha256());
    assert!(registration.consent_digest().is_sha256());
    assert!(registration.scope_digest().is_sha256());
    assert!(registration.registration_digest().is_sha256());
    assert!(service.is_active());
    assert_eq!(
        service.scope().tool_policy().mode(),
        ToolPolicy::disabled().mode()
    );
    assert_eq!(service.scope().provider().provider_id(), PROVIDER);
    assert!(!service.provider().connected());
    assert!(!service.provider().native());

    let secret_debug = format!("{:?}", service.scope().permission().secret_reference());
    assert!(!secret_debug.contains("host-owned-openai-key-handle"));
    let scope_json = serde_json::to_string(service.scope()).expect("redacted scope JSON");
    assert!(!scope_json.contains("host-owned-openai-key-handle"));
    assert!(scope_json.contains("secretReferenceDigest"));
}

#[test]
fn completed_response_has_typed_ids_usage_latency_and_only_redacted_output() {
    let mut service = service(None, OutputRetentionPolicy::digest_only());
    let request = request(ResponsesInput::text("sensitive mission prompt").expect("input"));
    let proposal = service
        .compile_response_proposal(&request)
        .expect("proposal");
    let evidence = service
        .record_response(
            &proposal,
            &success_frame(
                success_body("sensitive model answer", "completed"),
                "record-success-1",
            ),
        )
        .expect("evidence");

    assert_eq!(
        evidence.response_id.as_ref().expect("response id").as_str(),
        "resp_123"
    );
    assert_eq!(evidence.status, ResponseStatus::Completed);
    assert_eq!(evidence.usage.expect("usage").total_tokens, 20);
    assert_eq!(evidence.latency_ms, 37);
    assert_eq!(evidence.provenance, ProviderMode::Recording);
    assert_eq!(evidence.disposition, EvidenceDisposition::RecordedSuccess);
    let output = evidence.output.as_ref().expect("output summary");
    assert!(output.preview.is_none());
    assert!(output.content_digest.is_sha256());
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains("sensitive model answer")
    );
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains("sensitive mission prompt")
    );
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
    assert!(!evidence.authority.kernel_truth);
    assert!(!evidence.authority.kernel_outcome_adoption);
    service
        .verify_response(&proposal, &evidence)
        .expect("local verify");
}

#[test]
fn consent_selected_prefix_is_bounded_and_marks_truncation() {
    let retention = OutputRetentionPolicy::bounded_prefix(5).expect("retention");
    let mut service = service(None, retention);
    let proposal = service
        .compile_response_proposal(&request(ResponsesInput::text("bounded").expect("input")))
        .expect("proposal");
    let evidence = service
        .record_response(
            &proposal,
            &success_frame(success_body("123456789", "completed"), "record-prefix-1"),
        )
        .expect("evidence");
    let output = evidence.output.expect("output");
    assert_eq!(output.preview.as_deref(), Some("12345"));
    assert!(output.preview_truncated);
    assert_eq!(evidence.redaction.mode, OutputRetentionMode::BoundedPrefix);
    assert!(!evidence.redaction.raw_content_retained);
}

#[test]
fn strict_structured_output_is_bound_and_validated_without_retaining_json() {
    let schema = schema();
    let mut schema_service = service(Some(schema.clone()), OutputRetentionPolicy::digest_only());
    let request_value = request(ResponsesInput::text("return a decision object").expect("input"))
        .with_structured_output_schema(schema.clone());
    let proposal = schema_service
        .compile_response_proposal(&request_value)
        .expect("proposal");
    let valid = success_body(r#"{"answer":"yes","confidence":0.9}"#, "completed");
    let evidence = schema_service
        .record_response(&proposal, &success_frame(valid, "record-schema-1"))
        .expect("valid structured output");
    assert!(
        evidence
            .output
            .expect("output")
            .structured_output_digest
            .is_some()
    );

    let mut invalid_service = service(Some(schema.clone()), OutputRetentionPolicy::digest_only());
    let invalid_request_value = request(ResponsesInput::text("return invalid").expect("input"))
        .with_structured_output_schema(schema);
    let invalid_proposal = invalid_service
        .compile_response_proposal(&invalid_request_value)
        .expect("invalid proposal still scoped");
    let invalid = success_body(r#"{"answer":"missing confidence"}"#, "completed");
    assert_eq!(
        invalid_service
            .record_response(
                &invalid_proposal,
                &success_frame(invalid, "record-schema-2")
            )
            .expect_err("schema must reject undeclared output shape"),
        OpenAIResponsesResultError::StructuredOutputInvalid
    );
}

#[test]
fn text_image_and_declared_file_references_are_bounded_allowlisted_inputs() {
    let file = FileReference::new("file-governed-1").expect("file reference");
    let image = ImageReference::new("image-ref-1", "image/png").expect("image reference");
    let governed_scope = scope(None, OutputRetentionPolicy::digest_only(), Some(&file), 5);
    let governed =
        OpenAIResponsesResultService::new(governed_scope, OpenAIResponsesProvider::fixture())
            .expect("governed service");
    let input = ResponsesInput::items(vec![
        ResponsesInputItem::text("describe these bounded references").expect("text item"),
        ResponsesInputItem::image_reference(image),
        ResponsesInputItem::file_reference(file.clone()),
    ])
    .expect("multimodal input");
    let proposal = governed
        .compile_response_proposal(&request(input))
        .expect("declared input proposal");
    assert_eq!(proposal.input.image_references(), 1);
    assert_eq!(proposal.input.file_references(), 1);

    let undeclared = OpenAIResponsesResultService::new(
        scope(None, OutputRetentionPolicy::digest_only(), None, 5),
        OpenAIResponsesProvider::fixture(),
    )
    .expect("undeclared service");
    let undeclared_input =
        ResponsesInput::items(vec![ResponsesInputItem::file_reference(file)]).expect("file input");
    assert_eq!(
        undeclared
            .compile_response_proposal(&request(undeclared_input))
            .expect_err("undeclared file must be rejected"),
        OpenAIResponsesResultError::UndeclaredFileReference
    );
    assert!(ImageReference::new("data:image/png;base64,bytes", "image/png").is_err());
    assert!(FileReference::new("/tmp/secret.txt").is_err());
}

#[test]
fn statuses_and_http_failures_are_normalized_without_provider_failover() {
    let mut service = service(None, OutputRetentionPolicy::digest_only());
    let proposal = service
        .compile_response_proposal(&request(
            ResponsesInput::text("status probe").expect("input"),
        ))
        .expect("proposal");
    for (index, (status, expected)) in [
        (400, ResponseStatus::Failed),
        (401, ResponseStatus::AccessLost),
        (403, ResponseStatus::AccessLost),
        (404, ResponseStatus::Failed),
        (409, ResponseStatus::Failed),
        (429, ResponseStatus::RateLimited),
        (500, ResponseStatus::Failed),
        (503, ResponseStatus::Failed),
        (302, ResponseStatus::ProviderUnknown),
    ]
    .into_iter()
    .enumerate()
    {
        let frame = RecordedResponseFrame::http(
            format!("http-error-{index}"),
            PROVIDER,
            MODEL_ID,
            MODEL_SNAPSHOT,
            status,
            br#"{"error":{"code":"opaque_error","message":"do not retain this"}}"#,
            4,
        );
        let evidence = service
            .record_response(&proposal, &frame)
            .expect("error evidence");
        assert_eq!(evidence.status, expected);
        assert!(evidence.output.is_none());
        assert!(evidence.error.is_some());
        assert!(
            !serde_json::to_string(&evidence)
                .expect("error evidence JSON")
                .contains("do not retain this")
        );
    }
    let error = service
        .record_response(
            &proposal,
            &RecordedResponseFrame::success(
                "status-incomplete",
                PROVIDER,
                MODEL_ID,
                MODEL_SNAPSHOT,
                success_body("partial answer is not adopted", "incomplete"),
                5,
            ),
        )
        .expect("incomplete evidence");
    assert_eq!(error.status, ResponseStatus::Incomplete);
    assert!(error.output.is_none());
}

#[test]
fn mismatches_oversize_tool_reasoning_timeout_and_cost_fail_closed() {
    let mut service = service(None, OutputRetentionPolicy::digest_only());
    let proposal = service
        .compile_response_proposal(&request(ResponsesInput::text("bounded").expect("input")))
        .expect("proposal");
    let wrong_model = RecordedResponseFrame::success(
        "wrong-model",
        PROVIDER,
        MODEL_ID,
        "other-snapshot",
        success_body("no drift", "completed"),
        1,
    );
    assert_eq!(
        service
            .record_response(&proposal, &wrong_model)
            .expect_err("snapshot drift"),
        OpenAIResponsesResultError::ModelSnapshotMismatch
    );
    let wrong_provider = RecordedResponseFrame::success(
        "wrong-provider",
        "other.provider",
        MODEL_ID,
        MODEL_SNAPSHOT,
        success_body("no failover", "completed"),
        1,
    );
    assert_eq!(
        service
            .record_response(&proposal, &wrong_provider)
            .expect_err("provider failover"),
        OpenAIResponsesResultError::ProviderIdentityMismatch
    );
    let reasoning = RecordedResponseFrame::success(
        "reasoning",
        PROVIDER,
        MODEL_ID,
        MODEL_SNAPSHOT,
        json!({
            "id":"resp_reasoning",
            "status":"completed",
            "model":MODEL_SNAPSHOT,
            "reasoning_content":"hidden chain of thought",
            "output_text":"answer",
            "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}
        })
        .to_string()
        .into_bytes(),
        1,
    );
    assert_eq!(
        service
            .record_response(&proposal, &reasoning)
            .expect_err("reasoning must not be captured"),
        OpenAIResponsesResultError::ToolPolicyViolation
    );
    assert_eq!(
        service
            .record_response(
                &proposal,
                &RecordedResponseFrame::timeout("timeout", PROVIDER, MODEL_ID, MODEL_SNAPSHOT, 12,),
            )
            .expect("timeout evidence")
            .status,
        ResponseStatus::ProviderUnknown
    );
    assert_eq!(
        service
            .record_response(
                &proposal,
                &success_frame(success_body("too costly", "completed"), "too-costly")
                    .with_cost_micros(50_001),
            )
            .expect_err("cost ceiling"),
        OpenAIResponsesResultError::CostCeilingExceeded
    );
    assert_eq!(
        ToolPolicy::with_tools(1, false).expect_err("tools are disabled"),
        OpenAIResponsesResultError::ToolPolicyViolation
    );
}

#[test]
fn replay_tamper_revocation_and_blocked_environment_remain_fail_closed() {
    let mut service = service(None, OutputRetentionPolicy::digest_only());
    let proposal = service
        .compile_response_proposal(&request(ResponsesInput::text("replay").expect("input")))
        .expect("proposal");
    let frame = success_frame(success_body("answer", "completed"), "same-recording");
    let evidence = service
        .record_response(&proposal, &frame)
        .expect("first recording");
    assert_eq!(
        service
            .record_response(&proposal, &frame)
            .expect_err("duplicate recording"),
        OpenAIResponsesResultError::ReplayDetected
    );
    let mut tampered = proposal.clone();
    tampered.proposal_digest = hartevo_openai_responses_result_plugin::Digest::sha256(b"tampered");
    assert_eq!(
        service
            .record_response(&tampered, &frame)
            .expect_err("tampered proposal"),
        OpenAIResponsesResultError::ProposalTampered
    );
    let mut tampered_evidence = evidence.clone();
    tampered_evidence.status = ResponseStatus::Failed;
    assert_eq!(
        service
            .verify_response(&proposal, &tampered_evidence)
            .expect_err("tampered evidence"),
        OpenAIResponsesResultError::EvidenceTampered
    );
    service
        .revoke(RevocationReason::UserRequested)
        .expect("revoke");
    assert_eq!(
        service
            .compile_response_proposal(&request(ResponsesInput::text("revoked").expect("input")))
            .expect_err("revoked registration"),
        OpenAIResponsesResultError::RegistrationRevoked
    );

    let mut blocked = OpenAIResponsesResultService::new(
        scope(None, OutputRetentionPolicy::digest_only(), None, 5),
        OpenAIResponsesProvider::blocked_env(),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .compile_response_proposal(&request(ResponsesInput::text("native gap").expect("input")))
        .expect("blocked proposal");
    let blocked_evidence = blocked
        .record_blocked_env(
            &blocked_proposal,
            "blocked-record",
            BlockedEnvCode::NativeCredentialResolutionUnavailable,
            0,
        )
        .expect("blocked evidence");
    assert_eq!(
        blocked_evidence.disposition,
        EvidenceDisposition::BlockedEnv
    );
    assert_eq!(blocked_evidence.provenance, ProviderMode::BlockedEnv);
    assert!(!blocked_evidence.authority.connected);
    assert!(!blocked_evidence.authority.native);
}

#[test]
fn mission_consumer_is_proposal_only_and_never_claims_truth_or_native_connection() {
    let mut consumer = MissionOpenAIResponsesConsumer::new(
        scope(None, OutputRetentionPolicy::digest_only(), None, 5),
        OpenAIResponsesProvider::loopback(),
    )
    .expect("consumer");
    let request = request(ResponsesInput::text("next decision").expect("input"));
    let proposal = consumer
        .compile_response_proposal(&request)
        .expect("proposal");
    let projection = consumer
        .consume_recorded_response(
            &proposal,
            &success_frame(success_body("proposal only", "completed"), "loopback-1"),
        )
        .expect("projection");
    assert!(projection.proposal_only());
    assert!(!projection.connected());
    assert!(!projection.native());
    assert!(!projection.factual_truth_authority());
    assert!(!projection.kernel_outcome_adoption());
}

#[test]
fn input_and_response_ceiling_validation_is_bounded() {
    let tight_policy = InputPolicy::new(
        "tight",
        64,
        4_096,
        128,
        128,
        100,
        100,
        OutputRetentionPolicy::digest_only(),
    )
    .expect("tight policy")
    .with_item_bounds(8, 2, 1, 1)
    .expect("tight item bounds");
    let scope = OpenAIResponsesScope::new(
        OpenAIResponsesProviderScope::openai(),
        OrganizationScope::new("org", 1).expect("org"),
        ProjectScope::new("project", 1).expect("project"),
        PermissionScope::new(
            OpenAIResponsesPermission::ResponsesCreate,
            SecretReference::new("secret", 1).expect("secret"),
        ),
        ModelSnapshot::new(MODEL_ID, MODEL_SNAPSHOT).expect("model"),
        tight_policy,
        None,
        ToolPolicy::disabled(),
        MissionScope::new("mission", 1).expect("mission"),
        WorkProductScope::new("work", 1).expect("work"),
        ConsentScope::digest_only("consent", 1).expect("consent"),
    )
    .expect("tight scope");
    let service = OpenAIResponsesResultService::new(scope, OpenAIResponsesProvider::fixture())
        .expect("tight service");
    assert_eq!(
        service
            .compile_response_proposal(&request(
                ResponsesInput::text("this is too long").expect("input")
            ))
            .expect_err("text ceiling"),
        OpenAIResponsesResultError::TextInputTooLarge
    );
}
