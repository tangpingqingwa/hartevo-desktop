use hartevo_openai_moderation_result_plugin::{
    AuthorityClaims, BlockedEnvCode, CategoryAllowlist, CategoryOutcome, ImageReference,
    MissionOpenAiModerationConsumer, MissionScope, ModelSnapshot, ModerationCategory,
    ModerationInput, ModerationPolicy, ModerationRequest, ModerationStatus, OpenAiModerationError,
    OpenAiModerationEvidence, OpenAiModerationProvider, OpenAiModerationProviderScope,
    OpenAiModerationScope, OpenAiModerationService, PermissionScope, ProjectScope, ProviderMode,
    RecordedModerationFrame, RequestId, ResponseId, RevocationReason, ScoreProjection, SecretKind,
    SecretReference, WorkProductScope,
};
use serde_json::json;

fn policy() -> ModerationPolicy {
    ModerationPolicy::new(
        "policy-2026-08-15",
        CategoryAllowlist::new([ModerationCategory::Harassment]).expect("category allowlist"),
    )
    .expect("policy")
    .with_limits(4096, 2048, 4096, 2, 32 * 1024)
    .expect("policy limits")
}

fn scope_with_secret(secret: SecretReference) -> OpenAiModerationScope {
    let permission = PermissionScope::new(
        hartevo_openai_moderation_result_plugin::OpenAiModerationPermission::ModerationsCreate,
        secret,
    );
    OpenAiModerationScope::new(
        OpenAiModerationProviderScope::openai(),
        ProjectScope::new("project-1", 3).expect("project"),
        MissionScope::new("mission-1", 4).expect("mission"),
        WorkProductScope::new("work-product-1", 5).expect("work product"),
        ModelSnapshot::new("omni-moderation-latest", "omni-moderation-2024-09-26").expect("model"),
        policy(),
        permission,
    )
    .expect("scope")
}

fn scope() -> OpenAiModerationScope {
    scope_with_secret(SecretReference::api_key("host-api-key-handle", 7).expect("secret"))
}

fn request(input: ModerationInput) -> ModerationRequest {
    ModerationRequest::new(RequestId::new("request-1").expect("request id"), input)
}

fn success_frame(input: &ModerationInput, recording_id: &str) -> RecordedModerationFrame {
    RecordedModerationFrame::success(
        recording_id,
        "omni-moderation-latest",
        input.input_digest(),
        Some(ResponseId::new("modr-1").expect("response id")),
        true,
        vec![CategoryOutcome::new(
            ModerationCategory::Harassment,
            true,
            Some(ScoreProjection::from_basis_points(9_876).expect("score")),
        )],
    )
    .expect("frame")
}

fn service(provider: OpenAiModerationProvider) -> OpenAiModerationService {
    OpenAiModerationService::new(scope(), provider).expect("service")
}

#[test]
fn registration_binds_all_scope_and_evidence_digests_without_secret_serialization() {
    let secret =
        SecretReference::new("super-secret-api-key", SecretKind::ApiKey, 7).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("super-secret-api-key"));
    assert_eq!(secret.kind(), SecretKind::ApiKey);
    assert!(secret.reference_digest().is_sha256());

    let scope_json = serde_json::to_string(&scope_with_secret(secret)).expect("safe scope JSON");
    assert!(!scope_json.contains("super-secret-api-key"));
    assert!(scope_json.contains("secretReferenceDigest"));

    let service = service(OpenAiModerationProvider::fixture());
    let registration = service.registration();
    assert!(registration.verify_integrity().is_ok());
    assert!(registration.is_active());
    assert!(registration.plugin_version_digest().is_sha256());
    assert!(registration.contract_digest().is_sha256());
    assert!(registration.provider_digest().is_sha256());
    assert!(registration.evidence_digest().is_sha256());
    assert!(registration.scope_digest().is_sha256());
    assert!(service.provider().provider_digest().is_sha256());
    assert!(!service.provider().connected());
    assert!(!service.provider().native());
    assert!(!service.provider().first_party());
}

#[test]
fn text_and_image_inputs_are_digest_only_and_type_bounded() {
    let prompt = "private prompt with a user email user@example.invalid";
    let text = ModerationInput::text(prompt).expect("text");
    let debug = format!("{text:?}");
    let json = serde_json::to_string(&text).expect("safe input JSON");
    assert!(!debug.contains(prompt));
    assert!(!json.contains(prompt));
    assert!(text.input_digest().is_sha256());

    let image = ImageReference::new("image-handle-1", 1_024, "image/png").expect("image");
    let image_debug = format!("{image:?}");
    assert!(!image_debug.contains("image-handle-1"));
    assert_eq!(image.media_type().as_str(), "image/png");
    assert!(ModerationInput::image(image).input_digest().is_sha256());

    assert_eq!(
        ImageReference::new("https://private.invalid/image", 1_024, "image/png")
            .expect_err("URLs are not opaque handles"),
        OpenAiModerationError::InvalidField {
            field: "opaque_image_reference",
            reason: "must be a bounded non-URL host handle",
        }
    );
    assert_eq!(
        ImageReference::new("image-handle-2", 1_024, "image/gif")
            .expect_err("GIF is not in the explicit Layer-1 allowlist"),
        OpenAiModerationError::ImageTypeForbidden
    );
    assert!(matches!(
        ModerationInput::text(
            "x".repeat(hartevo_openai_moderation_result_plugin::MAX_TEXT_BYTES + 1,)
        ),
        Err(OpenAiModerationError::TextTooLarge)
    ));

    let policy = policy()
        .with_allowed_types(true, false)
        .expect("text-only policy");
    assert!(
        ModerationInput::text("safe")
            .expect("text")
            .validate(&policy)
            .is_ok()
    );
    let image =
        ModerationInput::image_reference("image-handle-3", 64, "image/jpeg").expect("image input");
    assert_eq!(
        image.validate(&policy),
        Err(OpenAiModerationError::InputTypeForbidden)
    );
}

#[test]
fn proposal_read_record_verify_and_mission_projection_are_redacted() {
    let input = ModerationInput::text("sensitive prompt that is never retained").expect("text");
    let mut service = service(OpenAiModerationProvider::fixture());
    let proposal = service
        .compile_moderation_proposal(request(input.clone()))
        .expect("proposal");
    assert!(proposal.verify_integrity().is_ok());
    assert!(proposal.request_fingerprint().is_sha256());
    assert_eq!(proposal.request_fingerprint(), proposal.idempotency_key());
    let proposal_json = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!proposal_json.contains("sensitive prompt"));

    let frame = success_frame(&input, "fixture-1");
    let read = service.read_moderation(&proposal, &frame).expect("read");
    assert_eq!(read.status(), ModerationStatus::Completed);
    assert_eq!(read.flagged(), Some(true));
    assert!(!read.recorded());
    assert_eq!(
        read.categories()[0].category(),
        ModerationCategory::Harassment
    );
    assert_eq!(
        read.categories()[0].score().expect("score").basis_points(),
        9_876
    );
    assert!(!read.redaction().raw_content_retained());
    assert!(!read.redaction().raw_provider_json_retained());
    assert!(!read.redaction().hidden_reasoning_retained());
    assert!(!read.redaction().user_pii_retained());
    assert!(read.verify_integrity().is_ok());

    let recorded = service
        .record_moderation(&proposal, &frame)
        .expect("record");
    assert!(recorded.recorded());
    service
        .verify_moderation(&proposal, &recorded)
        .expect("verify");
    let consumer = MissionOpenAiModerationConsumer::from_service(service);
    let projection = consumer
        .verify_moderation(&proposal, &recorded)
        .expect("mission projection");
    assert!(projection.requires_safety_review());
    assert!(projection.proposal_only());
    assert!(!projection.connected());
    assert!(!projection.native());
    assert!(!projection.first_party());
    assert!(!projection.kernel_authority());
    assert!(!projection.automatic_blocking());
    assert!(!projection.notification());
    assert!(consumer.provider().evidence_binding_digest().is_sha256());
}

#[test]
fn provider_failures_are_typed_fail_closed_states() {
    let input = ModerationInput::text("safe input").expect("text");
    let service = service(OpenAiModerationProvider::fixture());
    let proposal = service
        .compile_moderation_proposal(request(input.clone()))
        .expect("proposal");
    let cases = [
        (401, ModerationStatus::Unauthorized),
        (403, ModerationStatus::Forbidden),
        (413, ModerationStatus::PayloadTooLarge),
        (429, ModerationStatus::RateLimited),
        (500, ModerationStatus::ServerError),
        (408, ModerationStatus::ProviderUnknown),
    ];
    for (status, expected) in cases {
        let frame = RecordedModerationFrame::http_status(
            format!("http-{status}"),
            "omni-moderation-latest",
            input.input_digest(),
            status,
        )
        .expect("http frame");
        let evidence = service
            .read_moderation(&proposal, &frame)
            .expect("typed status");
        assert_eq!(evidence.status(), expected);
        assert!(evidence.flagged().is_none());
        assert!(evidence.categories().is_empty());
        assert!(evidence.status().fail_closed());
        service
            .verify_moderation(&proposal, &evidence)
            .expect("verify failure evidence");
    }

    let timeout = RecordedModerationFrame::timeout(
        "timeout-1",
        "omni-moderation-latest",
        input.input_digest(),
    )
    .expect("timeout");
    assert_eq!(
        service
            .read_moderation(&proposal, &timeout)
            .expect("timeout evidence")
            .status(),
        ModerationStatus::Timeout
    );
    let blocked = RecordedModerationFrame::blocked_env(
        "blocked-1",
        "omni-moderation-latest",
        input.input_digest(),
        BlockedEnvCode::NativeTransportDisabled,
    )
    .expect("blocked env");
    let blocked_evidence = service
        .read_moderation(&proposal, &blocked)
        .expect("blocked evidence");
    assert_eq!(blocked_evidence.status(), ModerationStatus::BlockedEnv);
    assert!(!blocked_evidence.authority().connected());
    assert!(!blocked_evidence.authority().native());
}

#[test]
fn malformed_partial_and_oversized_provider_content_is_not_retained() {
    let input = ModerationInput::text("private input").expect("text");
    let digest = input.input_digest();
    assert_eq!(
        RecordedModerationFrame::from_json("bad-json", digest.clone(), b"not-json")
            .expect_err("malformed"),
        OpenAiModerationError::MalformedProviderResponse
    );
    let body = br#"{"id":"modr-1","model":"omni-moderation-latest","results":[]}"#;
    assert_eq!(
        RecordedModerationFrame::from_json("partial", digest.clone(), body).expect_err("partial"),
        OpenAiModerationError::PartialProviderResponse
    );
    let unknown = br#"{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"future/category":false},"category_scores":{"future/category":0.1}}]}"#;
    let error = RecordedModerationFrame::from_json("unknown", digest.clone(), unknown)
        .expect_err("unknown category");
    assert_eq!(error, OpenAiModerationError::MalformedProviderResponse);
    let oversized = vec![b'x'; hartevo_openai_moderation_result_plugin::MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        RecordedModerationFrame::from_json("oversized", digest, &oversized).expect_err("oversized"),
        OpenAiModerationError::ResponseTooLarge
    );
    assert!(!error.to_string().contains("future/category"));
}

#[test]
fn replay_tamper_drift_and_revocation_fences_are_fail_closed() {
    let input = ModerationInput::text("replay input").expect("text");
    let mut service = service(OpenAiModerationProvider::recording());
    let proposal = service
        .compile_moderation_proposal(request(input.clone()))
        .expect("proposal");
    let frame = success_frame(&input, "recording-1");
    let evidence = service
        .record_moderation(&proposal, &frame)
        .expect("record");
    assert_eq!(
        service.record_moderation(&proposal, &frame),
        Err(OpenAiModerationError::ReplayDetected)
    );

    let mut proposal_json = serde_json::to_value(&proposal).expect("proposal value");
    proposal_json["requestFingerprint"] = json!("tampered");
    let tampered_proposal: hartevo_openai_moderation_result_plugin::OpenAiModerationProposal =
        serde_json::from_value(proposal_json).expect("tampered proposal shape");
    assert_eq!(
        service.read_moderation(&tampered_proposal, &frame),
        Err(OpenAiModerationError::ProposalTampered)
    );

    let mut evidence_json = serde_json::to_value(&evidence).expect("evidence value");
    evidence_json["evidenceDigest"] = json!("tampered");
    let tampered_evidence: OpenAiModerationEvidence =
        serde_json::from_value(evidence_json).expect("tampered evidence shape");
    assert_eq!(
        service.verify_moderation(&proposal, &tampered_evidence),
        Err(OpenAiModerationError::EvidenceTampered)
    );

    let revocation = service
        .revoke(RevocationReason::CredentialRotated)
        .expect("revoke");
    assert_eq!(revocation.reason(), RevocationReason::CredentialRotated);
    assert_eq!(
        service.compile_moderation_proposal(request(input.clone())),
        Err(OpenAiModerationError::RegistrationRevoked)
    );
    assert_eq!(
        service.verify_moderation(&proposal, &evidence),
        Err(OpenAiModerationError::RegistrationRevoked)
    );
    service.restore().expect("restore");
    let restored = service
        .compile_moderation_proposal(request(input))
        .expect("restored proposal");
    assert_eq!(
        restored.request_fingerprint(),
        proposal.request_fingerprint()
    );

    let mut drifted_scope = scope();
    drifted_scope = OpenAiModerationScope::new(
        drifted_scope.provider().clone(),
        ProjectScope::new("project-2", 3).expect("drifted project"),
        drifted_scope.mission().clone(),
        drifted_scope.work_product().clone(),
        drifted_scope.model().clone(),
        drifted_scope.policy().clone(),
        PermissionScope::new(
            hartevo_openai_moderation_result_plugin::OpenAiModerationPermission::ModerationsCreate,
            SecretReference::oauth("oauth-handle", 1).expect("oauth"),
        ),
    )
    .expect("drifted scope");
    let drifted_service =
        OpenAiModerationService::new(drifted_scope, OpenAiModerationProvider::recording())
            .expect("drifted service");
    assert_eq!(
        drifted_service.read_moderation(&proposal, &frame),
        Err(OpenAiModerationError::ProjectRevisionDrift)
    );
}

#[test]
fn all_evidence_modes_are_honest_and_native_execution_is_a_gap() {
    let input = ModerationInput::text("mode check").expect("text");
    for (mode, provider) in [
        (ProviderMode::Fixture, OpenAiModerationProvider::fixture()),
        (
            ProviderMode::Recording,
            OpenAiModerationProvider::recording(),
        ),
        (ProviderMode::Loopback, OpenAiModerationProvider::loopback()),
        (
            ProviderMode::BlockedEnv,
            OpenAiModerationProvider::blocked_env(),
        ),
    ] {
        assert!(!mode.is_connected());
        assert!(!mode.is_native());
        assert!(!mode.is_first_party());
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.first_party());
        let service = service(provider);
        let description = service.describe_model().expect("model description");
        assert!(!description.connected());
        assert!(!description.native());
        assert!(!description.first_party());
        assert_eq!(service.evidence_mode(), mode);
    }
    let provider = OpenAiModerationProvider::fixture();
    assert_eq!(
        provider.execute_native(&input),
        Err(OpenAiModerationError::NativeExecutionUnavailable)
    );
    assert!(!AuthorityClaims::layer_one().connected());
}
