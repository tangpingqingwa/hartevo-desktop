use hartevo_bedrock_inference_plugin::{
    AwsAccountId, AwsPartition, AwsRegion, BedrockConverseProvider, BedrockError,
    BedrockInferenceService, BedrockScope, BudgetPolicy, ContentDigests, ContentMessageDigest,
    ContentRole, DestinationEvidence, Digest, FakeTransport, GuardrailBinding, GuardrailProjection,
    InferenceConfig, InferenceRequest, Layer1Provenance, MissionBedrockInferenceConsumer,
    MissionContext, ModelCapabilitySnapshot, ModelTarget, ProviderContentBlock, ProviderResponse,
    RegistrationSpec, ResultDisposition, RevocationReason, RoutingPolicy, SecretReference,
    StopReason, TokenUsage, ToolSchemaDigest, TransportErrorClass, VerificationFailure,
};

struct Fixture {
    scope: BedrockScope,
    spec: RegistrationSpec,
    context: MissionContext,
    request: InferenceRequest,
    response: ProviderResponse,
}

fn fixture() -> Fixture {
    let region = AwsRegion::new("us-east-1").expect("region");
    let partition = AwsPartition::new("aws").expect("partition");
    let account = AwsAccountId::new("123456789012").expect("account");
    let model = ModelTarget::model_id("anthropic.claude-3-haiku-20240307-v1:0").expect("model");
    let project = hartevo_bedrock_inference_plugin::ProjectId::new("project-326").expect("project");
    let mission = hartevo_bedrock_inference_plugin::MissionId::new("mission-326").expect("mission");
    let budget = BudgetPolicy::new(7, 1_024, 256, 1_280, 30_000).expect("budget");
    let routing = RoutingPolicy::regional(vec![region.clone()]).expect("routing");
    let guardrail = Some(GuardrailBinding::new("gr-326", "1").expect("guardrail"));
    let scope = BedrockScope::new(
        partition,
        account,
        region.clone(),
        model.clone(),
        routing,
        guardrail,
        project.clone(),
        mission.clone(),
        3,
        budget.clone(),
    )
    .expect("scope");
    let capability = ModelCapabilitySnapshot::new(&scope, 11, true, 256).expect("capability");
    let secret = SecretReference::temporary_role_session(
        "secret://bedrock/mission-326/session-1",
        "arn:aws:iam::123456789012:role/hartevo-bedrock-layer1",
        "mission-326",
        4_000_000_000,
    )
    .expect("temporary role session reference");
    let spec = RegistrationSpec::new(scope.clone(), capability.clone(), secret).expect("spec");
    let context = MissionContext::new(project, mission, 3, budget).expect("context");
    let content = ContentDigests::new(
        Some(Digest::of_str("system content")),
        vec![
            ContentMessageDigest::new(
                ContentRole::User,
                Digest::of_str("raw user prompt never retained"),
                1,
            )
            .expect("message"),
        ],
        Some(Digest::of_str("document bytes")),
    )
    .expect("content digests");
    let tool_schema = ToolSchemaDigest::new(Digest::of_str("tool schema"), 1).expect("tool schema");
    let request = InferenceRequest::new(content, Some(tool_schema), InferenceConfig::explicit(128));
    let response = ProviderResponse::new(
        Some("aws-request-326".to_owned()),
        Some(model),
        StopReason::EndTurn,
        TokenUsage::new(12, 8, 20),
        42,
        GuardrailProjection::not_intervened(),
        vec![ProviderContentBlock::text(Digest::of_str("model output"))],
        DestinationEvidence::ProviderVerified { region },
        Layer1Provenance::Fixture,
    )
    .expect("provider response");
    Fixture {
        scope,
        spec,
        context,
        request,
        response,
    }
}

fn registered_service(
    response: ProviderResponse,
) -> (
    BedrockInferenceService,
    hartevo_bedrock_inference_plugin::RegistrationId,
    Fixture,
) {
    let fixture = fixture();
    let mut service = BedrockInferenceService::new(BedrockConverseProvider::fake(response));
    let registration = service
        .register(fixture.spec.clone())
        .expect("registration");
    (service, registration, fixture)
}

#[test]
fn typed_consumer_compiles_canonical_non_streaming_proposal_and_receipts() {
    let fixture = fixture();
    let (service, registration, fixture) = registered_service(fixture.response.clone());
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context.clone());
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request.clone())
        .expect("proposal");
    assert_eq!(proposal.operation(), "Converse");
    assert!(!proposal.streaming());
    assert_eq!(proposal.scope().runtime_service(), "bedrock-runtime");
    assert_eq!(
        proposal.scope().model_or_inference_profile(),
        fixture.scope.model_or_inference_profile()
    );
    assert_eq!(proposal.request().config().max_tokens(), Some(128));
    assert!(!proposal.canonical().contains("raw user prompt"));
    assert!(!proposal.canonical().contains("model output"));

    let (receipt, result) = service
        .invoke_and_project(&proposal)
        .expect("recording/fake invocation");
    assert_eq!(receipt.request_digest(), proposal.request_digest());
    assert_eq!(receipt.content_digest(), proposal.content_digest());
    assert_eq!(receipt.tool_schema_digest(), proposal.tool_schema_digest());
    assert_eq!(receipt.config_digest(), proposal.config_digest());
    assert_eq!(
        receipt.service_tier(),
        hartevo_bedrock_inference_plugin::ServiceTier::Standard
    );
    assert_eq!(receipt.usage().total_tokens(), 20);
    assert_eq!(receipt.stop_reason(), StopReason::EndTurn);
    assert_eq!(receipt.provenance(), Layer1Provenance::Fixture);
    assert_eq!(result.disposition(), ResultDisposition::ProposalOnly);
    assert!(!result.adopts_outcome());
    let report = service
        .verify_inference_result(&proposal, &receipt, &result)
        .expect("verification report");
    assert!(report.verified());
}

#[test]
fn explicit_max_tokens_is_required_bounded_and_model_fields_are_closed() {
    let fixture = fixture();
    let mut service = BedrockInferenceService::new(BedrockConverseProvider::blocked_env());
    let registration = service
        .register(fixture.spec.clone())
        .expect("registration");
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context.clone());

    let omitted = InferenceRequest::new(
        fixture.request.content().clone(),
        fixture.request.tool_schema().cloned(),
        InferenceConfig::new(None),
    );
    assert_eq!(
        consumer.compile_invocation_proposal(&service, omitted),
        Err(BedrockError::MaxTokensRequired)
    );

    let oversized = InferenceRequest::new(
        fixture.request.content().clone(),
        fixture.request.tool_schema().cloned(),
        InferenceConfig::explicit(257),
    );
    assert_eq!(
        consumer.compile_invocation_proposal(&service, oversized),
        Err(BedrockError::MaxTokensExceedsPolicy {
            requested: 257,
            maximum: 256,
        })
    );

    let unsupported_config = InferenceConfig::explicit(128)
        .with_unsupported_field("provider_specific_payload")
        .expect("field name");
    let unsupported = InferenceRequest::new(
        fixture.request.content().clone(),
        fixture.request.tool_schema().cloned(),
        unsupported_config,
    );
    assert!(matches!(
        consumer.compile_invocation_proposal(&service, unsupported),
        Err(BedrockError::UnsupportedFields(_))
    ));
}

#[test]
fn registration_revoke_restore_is_reversible_without_reviving_old_proposals() {
    let fixture = fixture();
    let (mut service, registration, fixture) = registered_service(fixture.response.clone());
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context.clone());
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request.clone())
        .expect("proposal");
    service
        .revoke(registration, RevocationReason::PolicyDrift)
        .expect("revoke");
    assert_eq!(
        service.invoke_converse(&proposal),
        Err(BedrockError::RegistrationRevoked)
    );
    let replacement = service.restore(registration).expect("restore");
    assert_ne!(replacement, registration);
    assert_eq!(
        service.invoke_converse(&proposal),
        Err(BedrockError::RegistrationRevoked)
    );
    let replacement_consumer = MissionBedrockInferenceConsumer::new(replacement, fixture.context);
    let replacement_proposal = replacement_consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("new-generation proposal");
    assert_ne!(
        replacement_proposal.request_digest(),
        proposal.request_digest()
    );
}

#[test]
fn blocked_env_never_claims_connected_or_native_and_never_calls_live_bedrock() {
    let fixture = fixture();
    let mut service = BedrockInferenceService::new(BedrockConverseProvider::blocked_env());
    let registration = service.register(fixture.spec).expect("registration");
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("proposal");
    assert_eq!(service.provider_provenance(), Layer1Provenance::BlockedEnv);
    assert!(!service.provider_provenance().claims_connected());
    assert!(!service.provider_provenance().claims_native());
    assert_eq!(
        service.invoke_converse(&proposal),
        Err(BedrockError::BlockedEnv)
    );
}

#[test]
fn tool_use_is_an_untrusted_non_executing_proposal() {
    let fixture = fixture();
    let response = fixture
        .response
        .clone()
        .with_stop_reason(StopReason::ToolUse)
        .with_usage(TokenUsage::new(12, 4, 16));
    let (service, registration, fixture) = registered_service(response);
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("proposal");
    let response = ProviderResponse::new(
        Some("aws-request-tool".to_owned()),
        Some(fixture.scope.model_or_inference_profile().clone()),
        StopReason::ToolUse,
        TokenUsage::new(12, 4, 16),
        11,
        GuardrailProjection::not_intervened(),
        vec![ProviderContentBlock::tool_use(
            Digest::of_str("tool-use-id"),
            Digest::of_str("tool-name"),
            Digest::of_str("tool-input"),
        )],
        DestinationEvidence::NotDisclosed,
        Layer1Provenance::Fixture,
    )
    .expect("tool response");
    let receipt = service
        .record_invocation_receipt(&proposal, &response)
        .expect("receipt");
    let result = service
        .project_inference_result(&proposal, &receipt, &response)
        .expect("result");
    assert_eq!(result.disposition(), ResultDisposition::NeedsKernelConsent);
    assert!(!result.adopts_outcome());
    let tools = result.tool_use_proposals();
    assert_eq!(tools.len(), 1);
    assert!(!tools[0].executed());
    assert!(tools[0].requires_kernel_consent());
}

#[test]
fn safety_stop_reasons_are_distinct_and_never_silently_successful() {
    let cases = [
        (
            StopReason::GuardrailIntervened,
            GuardrailProjection::intervened(Digest::of_str("safety")),
            ResultDisposition::SafetyBlocked,
        ),
        (
            StopReason::ContentFiltered,
            GuardrailProjection::content_filtered(Digest::of_str("filter")),
            ResultDisposition::SafetyBlocked,
        ),
        (
            StopReason::MaxTokens,
            GuardrailProjection::not_intervened(),
            ResultDisposition::Truncated,
        ),
        (
            StopReason::Unknown,
            GuardrailProjection::not_intervened(),
            ResultDisposition::ProviderUnknown,
        ),
    ];
    for (stop_reason, safety, disposition) in cases {
        let fixture = fixture();
        let response = fixture
            .response
            .clone()
            .with_stop_reason(stop_reason)
            .with_safety(safety);
        let (service, registration, fixture) = registered_service(response.clone());
        let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
        let proposal = consumer
            .compile_invocation_proposal(&service, fixture.request)
            .expect("proposal");
        let receipt = service
            .record_invocation_receipt(&proposal, &response)
            .expect("receipt");
        let result = service
            .project_inference_result(&proposal, &receipt, &response)
            .expect("result");
        assert_eq!(result.stop_reason(), stop_reason);
        assert_eq!(result.disposition(), disposition);
        assert!(!result.disposition().is_adoptable());
    }
}

#[test]
fn usage_routing_tamper_and_stale_mission_cases_fail_closed() {
    let fixture = fixture();
    let bad_usage = fixture
        .response
        .clone()
        .with_usage(TokenUsage::new(12, 8, 999));
    let (service, registration, fixture) = registered_service(fixture.response.clone());
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context.clone());
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request.clone())
        .expect("proposal");
    assert_eq!(
        service.record_invocation_receipt(&proposal, &bad_usage),
        Err(BedrockError::UsageMismatch)
    );

    let other_region = AwsRegion::new("eu-west-1").expect("other region");
    let bad_routing =
        fixture
            .response
            .clone()
            .with_destination(DestinationEvidence::ProviderVerified {
                region: other_region,
            });
    assert_eq!(
        service.record_invocation_receipt(&proposal, &bad_routing),
        Err(BedrockError::ProviderRoutingMismatch)
    );

    let receipt = service
        .record_invocation_receipt(&proposal, &fixture.response)
        .expect("receipt");
    let result = service
        .project_inference_result(&proposal, &receipt, &fixture.response)
        .expect("result");
    let tampered = result.with_result_digest(Digest::of_str("tampered"));
    let report = service
        .verify_inference_result(&proposal, &receipt, &tampered)
        .expect("verification report");
    assert!(!report.verified());
    assert!(
        report
            .failures()
            .contains(&VerificationFailure::ResultDigestMismatch)
    );

    let stale_context = MissionContext::new(
        fixture.scope.project_id().clone(),
        fixture.scope.mission_id().clone(),
        fixture.scope.mission_revision() + 1,
        fixture.scope.budget_policy().clone(),
    )
    .expect("stale context");
    let stale_consumer = MissionBedrockInferenceConsumer::new(registration, stale_context);
    assert_eq!(
        stale_consumer.compile_invocation_proposal(&service, fixture.request),
        Err(BedrockError::MissionScopeMismatch)
    );
}

#[test]
fn temporary_role_reference_rejects_long_lived_credentials_and_redacts_opaque_handle() {
    assert_eq!(
        SecretReference::long_lived_iam_user("AKIAEXAMPLE", "raw-secret"),
        Err(BedrockError::LongLivedCredentialsRejected)
    );
    let reference = SecretReference::temporary_role_session(
        "secret://bedrock/redacted",
        "arn:aws:iam::123456789012:role/hartevo-bedrock-layer1",
        "session-326",
        4_000_000_000,
    )
    .expect("reference");
    let debug = format!("{reference:?}");
    assert!(!debug.contains("secret://bedrock/redacted"));
    assert!(!debug.contains("AKIA"));
    assert!(reference.is_temporary_role_session());
}

#[test]
fn every_layer_one_provenance_class_is_non_native() {
    for provenance in [
        Layer1Provenance::Fixture,
        Layer1Provenance::Recording,
        Layer1Provenance::Loopback,
        Layer1Provenance::BlockedEnv,
    ] {
        assert!(!provenance.claims_connected());
        assert!(!provenance.claims_native());
        assert!(!provenance.claims_first_party());
        assert!(!provenance.is_live());
    }
}

#[test]
fn fake_transport_can_exercise_bounded_retry_classes_without_live_calls() {
    let fixture = fixture();
    let mut service = BedrockInferenceService::new(BedrockConverseProvider::new(
        FakeTransport::error(TransportErrorClass::Throttled),
    ));
    let registration = service.register(fixture.spec).expect("registration");
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("proposal");
    assert_eq!(
        service.invoke_converse(&proposal),
        Err(BedrockError::Transport { class: "throttled" })
    );
}

#[test]
fn recording_transport_preserves_only_request_digest_and_labels_recording_provenance() {
    let fixture = fixture();
    let (provider, recording) =
        BedrockConverseProvider::with_recording_transport(fixture.response.clone());
    let mut service = BedrockInferenceService::new(provider);
    let registration = service.register(fixture.spec).expect("registration");
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("proposal");
    let receipt = service
        .invoke_converse(&proposal)
        .expect("recorded response");
    assert_eq!(
        recording.seen_request_digests(),
        vec![proposal.request_digest()]
    );
    assert_eq!(receipt.provenance(), Layer1Provenance::Recording);
}

#[test]
fn global_routing_requires_provider_evidence_but_accepts_a_verified_remote_region() {
    let fixture = fixture();
    let global_scope = BedrockScope::new(
        fixture.scope.partition().clone(),
        fixture.scope.account_id().clone(),
        fixture.scope.source_region().clone(),
        fixture.scope.model_or_inference_profile().clone(),
        RoutingPolicy::global(),
        fixture.scope.guardrail().cloned(),
        fixture.scope.project_id().clone(),
        fixture.scope.mission_id().clone(),
        fixture.scope.mission_revision(),
        fixture.scope.budget_policy().clone(),
    )
    .expect("global scope");
    let capability =
        ModelCapabilitySnapshot::new(&global_scope, 12, true, 256).expect("capability");
    let secret = SecretReference::temporary_role_session(
        "secret://bedrock/global-session",
        "arn:aws:iam::123456789012:role/hartevo-bedrock-layer1",
        "global-326",
        4_000_000_000,
    )
    .expect("secret reference");
    let spec = RegistrationSpec::new(global_scope, capability, secret).expect("spec");
    let remote_region = AwsRegion::new("eu-west-1").expect("remote region");
    let response = fixture
        .response
        .with_destination(DestinationEvidence::ProviderVerified {
            region: remote_region,
        });
    let mut service = BedrockInferenceService::new(BedrockConverseProvider::fake(response));
    let registration = service.register(spec).expect("registration");
    let consumer = MissionBedrockInferenceConsumer::new(registration, fixture.context);
    let proposal = consumer
        .compile_invocation_proposal(&service, fixture.request)
        .expect("proposal");
    let receipt = service.invoke_converse(&proposal).expect("global response");
    assert!(matches!(
        receipt.routing(),
        DestinationEvidence::ProviderVerified { .. }
    ));
}

#[test]
fn model_arn_scope_must_match_partition_account_and_source_region() {
    let region = AwsRegion::new("us-east-1").expect("region");
    let bad_target = ModelTarget::model_arn(
        "arn:aws-us-gov:bedrock:us-east-1:123456789012:foundation-model/example.model",
    )
    .expect("target syntax");
    let result = BedrockScope::new(
        AwsPartition::new("aws").expect("partition"),
        AwsAccountId::new("123456789012").expect("account"),
        region,
        bad_target,
        RoutingPolicy::global(),
        None,
        hartevo_bedrock_inference_plugin::ProjectId::new("project").expect("project"),
        hartevo_bedrock_inference_plugin::MissionId::new("mission").expect("mission"),
        1,
        BudgetPolicy::new(1, 1_000, 128, 1_128, 10_000).expect("budget"),
    );
    assert_eq!(result, Err(BedrockError::InvalidModelTarget));
}
