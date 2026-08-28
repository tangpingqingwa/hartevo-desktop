use hartevo_anthropic_message_result_plugin::{
    AnthropicMessage, AnthropicMessageRequest, AnthropicMessageResultError,
    AnthropicMessageResultService, AnthropicProvider, BlockedEnvCode, ContentBlockKind,
    ProviderErrorClass, ProviderProvenance, RecordedAnthropicResponse, ResultStatus, StopReason,
    TransportOutcome, UsageProjection,
};
use serde_json::{Value, json};

fn scope() -> hartevo_anthropic_message_result_plugin::AnthropicScope {
    hartevo_anthropic_message_result_plugin::AnthropicScope::fixture()
}

fn request(
    scope: &hartevo_anthropic_message_result_plugin::AnthropicScope,
    request_id: &str,
) -> AnthropicMessageRequest {
    AnthropicMessageRequest::new(
        hartevo_anthropic_message_result_plugin::RequestId::new_request(request_id)
            .expect("request id"),
        scope.model.clone(),
        128,
        vec![
            AnthropicMessage::new(
                hartevo_anthropic_message_result_plugin::MessageRole::User,
                "PRIVATE PROMPT: do not retain this text",
            )
            .expect("message"),
        ],
    )
    .expect("request")
    .with_system("PRIVATE SYSTEM PROMPT")
    .expect("system")
}

fn response_body(stop_reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "msg_private_provider_id",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{
            "type": "text",
            "text": "PRIVATE RAW OUTPUT THAT MUST NOT BE RETAINED",
            "citations": [{
                "type": "web_search_result_location",
                "url": "https://example.invalid/private-source",
                "title": "Private source title",
                "cited_text": "Private citation text"
            }]
        }],
        "stop_reason": stop_reason,
        "stop_sequence": null,
        "usage": {
            "input_tokens": 17,
            "output_tokens": 9,
            "cache_creation_input_tokens": 2,
            "cache_read_input_tokens": 3
        }
    }))
    .expect("response JSON")
}

fn service_with_request(
    request_id: &str,
) -> (
    AnthropicMessageResultService,
    hartevo_anthropic_message_result_plugin::AnthropicMessageResultProposal,
) {
    let scope = scope();
    let request = request(&scope, request_id);
    let service =
        AnthropicMessageResultService::new(scope, AnthropicProvider::recording()).expect("service");
    let proposal = service
        .compile_message_proposal(&request)
        .expect("proposal");
    (service, proposal)
}

#[test]
fn success_projects_stop_usage_latency_citation_and_digest_without_raw_content() {
    let (mut service, proposal) = service_with_request("request-success");
    let raw_prompt = "PRIVATE PROMPT: do not retain this text";
    let raw_output = "PRIVATE RAW OUTPUT THAT MUST NOT BE RETAINED";
    let body = response_body("end_turn");
    let response = RecordedAnthropicResponse::success("recording-success", &body, 42)
        .with_provenance(ProviderProvenance::Recording)
        .with_provider_request_id("msg_private_request_id");
    let evidence = service
        .record_message_result(&proposal, &response)
        .expect("evidence");

    assert_eq!(evidence.status, ResultStatus::Complete);
    assert_eq!(evidence.stop_reason, Some(StopReason::EndTurn));
    assert_eq!(evidence.latency_ms, 42);
    assert_eq!(
        evidence.usage,
        Some(UsageProjection::new(17, 9, Some(2), Some(3)).expect("usage"),)
    );
    assert_eq!(evidence.citations.len(), 1);
    assert_eq!(evidence.content_blocks[0].kind, ContentBlockKind::Text);
    assert_eq!(evidence.response_bytes, body.len());
    assert!(!evidence.is_adoptable());
    assert!(evidence.authority.is_non_authoritative());
    service
        .verify_message_result(&proposal, &evidence)
        .expect("verification");

    let evidence_json = serde_json::to_string(&evidence).expect("evidence JSON");
    let debug = format!("{evidence:?} {proposal:?} {response:?}");
    assert!(!evidence_json.contains(raw_prompt));
    assert!(!evidence_json.contains(raw_output));
    assert!(!debug.contains(raw_prompt));
    assert!(!debug.contains(raw_output));
    assert!(!debug.contains("msg_private_provider_id"));
}

#[test]
fn all_stop_reason_projections_are_typed_and_non_native() {
    let cases = [
        ("end_turn", StopReason::EndTurn, ResultStatus::Complete),
        ("max_tokens", StopReason::MaxTokens, ResultStatus::Complete),
        ("tool_use", StopReason::ToolUse, ResultStatus::ToolUse),
        (
            "stop_sequence",
            StopReason::StopSequence,
            ResultStatus::Complete,
        ),
        ("refusal", StopReason::Refusal, ResultStatus::Refused),
        (
            "future_provider_stop",
            StopReason::ProviderUnknown,
            ResultStatus::ProviderUnknown,
        ),
    ];
    for (index, (wire, expected_reason, expected_status)) in cases.into_iter().enumerate() {
        let request_id = format!("request-stop-{index}");
        let (mut service, proposal) = service_with_request(&request_id);
        let mut body = response_body(wire);
        if wire == "refusal" {
            let mut value: Value = serde_json::from_slice(&body).expect("body");
            value["refusal"] = Value::String("PRIVATE REFUSAL DETAIL".to_owned());
            body = serde_json::to_vec(&value).expect("refusal body");
        }
        let response = RecordedAnthropicResponse::success("recording-stop", &body, 5);
        let evidence = service
            .record_message_result(&proposal, &response)
            .expect("stop evidence");
        assert_eq!(evidence.stop_reason, Some(expected_reason));
        assert_eq!(evidence.status, expected_status);
        assert!(!evidence.provenance.connected());
        assert!(!evidence.provenance.native());
        assert!(evidence.authority.is_non_authoritative());
        if expected_reason == StopReason::ToolUse {
            assert_eq!(evidence.content_blocks[0].kind, ContentBlockKind::Text);
        }
    }
}

#[test]
fn http_faults_timeout_and_blocked_env_are_preserved_as_error_classes() {
    let statuses = [
        (400, ProviderErrorClass::BadRequest),
        (401, ProviderErrorClass::Unauthorized),
        (403, ProviderErrorClass::Forbidden),
        (404, ProviderErrorClass::NotFound),
        (409, ProviderErrorClass::Conflict),
        (429, ProviderErrorClass::RateLimited),
        (503, ProviderErrorClass::ServerError),
    ];
    for (index, (status, expected)) in statuses.into_iter().enumerate() {
        let (mut service, proposal) = service_with_request(&format!("request-http-{index}"));
        let body = b"provider body containing private token";
        let response =
            RecordedAnthropicResponse::http("recording-http", status, body, 7).with_retry_after(11);
        let evidence = service
            .record_message_result(&proposal, &response)
            .expect("HTTP error evidence");
        let error = evidence.provider_error.as_ref().expect("provider error");
        assert_eq!(error.class, expected);
        assert_eq!(error.http_status, Some(status));
        if status == 429 {
            assert_eq!(error.retry_after_seconds, Some(11));
        }
        assert!(
            !serde_json::to_string(&evidence)
                .expect("evidence JSON")
                .contains("private token")
        );
    }

    let (mut timeout_service, timeout_proposal) = service_with_request("request-timeout");
    let timeout = timeout_service
        .record_message_result(
            &timeout_proposal,
            &RecordedAnthropicResponse::timeout("recording-timeout", 99),
        )
        .expect("timeout evidence");
    assert_eq!(
        timeout.provider_error.expect("timeout error").class,
        ProviderErrorClass::Timeout
    );

    let (mut blocked_service, blocked_proposal) = service_with_request("request-blocked");
    let blocked = blocked_service
        .record_blocked_env(
            &blocked_proposal,
            "recording-blocked",
            BlockedEnvCode::NativeCredentialResolutionUnavailable,
            0,
        )
        .expect("blocked evidence");
    assert_eq!(blocked.status, ResultStatus::BlockedEnv);
    assert_eq!(
        blocked.provider_error.expect("blocked error").class,
        ProviderErrorClass::BlockedEnv
    );
    assert!(!blocked.provenance.connected());
    assert!(!blocked.provenance.native());
}

#[test]
fn malformed_partial_and_model_drift_fail_closed_without_raw_body_retention() {
    let (mut malformed_service, malformed_proposal) = service_with_request("request-malformed");
    let malformed_body = b"not JSON and contains SECRET OUTPUT";
    let malformed = malformed_service
        .record_message_result(
            &malformed_proposal,
            &RecordedAnthropicResponse::success("recording-malformed", malformed_body, 4),
        )
        .expect("malformed projection");
    assert_eq!(malformed.status, ResultStatus::Partial);
    assert_eq!(
        malformed
            .provider_error
            .as_ref()
            .expect("malformed error")
            .class,
        ProviderErrorClass::MalformedResponse
    );
    assert_eq!(malformed.response_bytes, malformed_body.len());
    assert!(
        !serde_json::to_string(&malformed)
            .expect("evidence JSON")
            .contains("SECRET OUTPUT")
    );

    let (mut partial_service, partial_proposal) = service_with_request("request-partial");
    let partial_body = serde_json::to_vec(&json!({
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 1, "output_tokens": 1}
    }))
    .expect("partial body");
    let partial = partial_service
        .record_message_result(
            &partial_proposal,
            &RecordedAnthropicResponse::success("recording-partial", &partial_body, 4),
        )
        .expect("partial projection");
    assert_eq!(
        partial.provider_error.expect("partial error").class,
        ProviderErrorClass::PartialResponse
    );

    let (mut drift_service, drift_proposal) = service_with_request("request-drift");
    let mut drift_value: Value =
        serde_json::from_slice(&response_body("end_turn")).expect("drift body");
    drift_value["model"] = Value::String("claude-future-unknown".to_owned());
    let drift_body = serde_json::to_vec(&drift_value).expect("drift JSON");
    assert_eq!(
        drift_service
            .record_message_result(
                &drift_proposal,
                &RecordedAnthropicResponse::success("recording-drift", &drift_body, 4),
            )
            .expect_err("model drift")
            .to_string(),
        "model identity or immutable version drifted"
    );
}

#[test]
fn request_replay_revocation_and_restore_are_reversible_but_fail_closed() {
    let (mut service, proposal) = service_with_request("request-replay");
    let body = response_body("end_turn");
    let first = service
        .record_message_result(
            &proposal,
            &RecordedAnthropicResponse::success("recording-first", &body, 1),
        )
        .expect("first evidence");
    assert_eq!(
        service
            .record_message_result(
                &proposal,
                &RecordedAnthropicResponse::success("recording-second", &body, 1),
            )
            .expect_err("replay")
            .to_string(),
        "request replay was detected"
    );
    service
        .verify_message_result(&proposal, &first)
        .expect("first remains verifiable");

    let revocation = service.revoke_registration().expect("revocation");
    assert_ne!(revocation.previous_digest, revocation.revoked_digest);
    assert_eq!(
        service
            .compile_message_proposal(&request(service.scope(), "request-after-revoke"))
            .expect_err("revoked compile")
            .to_string(),
        "registration has been revoked"
    );
    service.restore_registration().expect("restore");
    let restored_request = request(service.scope(), "request-after-restore");
    let restored_proposal = service
        .compile_message_proposal(&restored_request)
        .expect("restored proposal");
    assert_eq!(
        restored_proposal.registration_digest,
        proposal.registration_digest
    );
}

#[test]
fn mission_consumer_rejects_stale_revisions_and_never_adopts_outcome() {
    let (mut service, proposal) = service_with_request("request-consumer");
    let body = response_body("max_tokens");
    let evidence = service
        .record_message_result(
            &proposal,
            &RecordedAnthropicResponse::success("recording-consumer", &body, 8),
        )
        .expect("evidence");
    let consumer = hartevo_anthropic_message_result_plugin::MissionAnthropicResultConsumer::new(
        service.scope().clone(),
    )
    .expect("consumer");
    let result = consumer.consume(&evidence).expect("mission result");
    assert!(!result.is_adopted());
    assert!(!result.has_kernel_authority());
    assert_eq!(result.status, ResultStatus::Complete);
    assert_eq!(result.citation_count, 1);

    let scope = service.scope();
    assert_eq!(
        consumer
            .consume_at_revisions(
                &evidence,
                scope.project.revision,
                scope.mission.revision + 1,
                scope.work_product.revision,
            )
            .expect_err("stale Mission"),
        AnthropicMessageResultError::StaleMissionRevision
    );
    assert_eq!(
        consumer
            .consume_at_revisions(
                &evidence,
                scope.project.revision,
                scope.mission.revision,
                scope.work_product.revision + 1,
            )
            .expect_err("stale Work Product"),
        AnthropicMessageResultError::StaleWorkProductRevision
    );
}

#[test]
fn transport_seam_is_exactly_post_messages_and_native_is_blocked_env() {
    let transport_scope = scope();
    let transport_request = request(&transport_scope, "request-transport");
    let mut service =
        AnthropicMessageResultService::new(transport_scope, AnthropicProvider::recording())
            .expect("service");
    let proposal = service
        .compile_message_proposal(&transport_request)
        .expect("proposal");
    let body = response_body("end_turn");
    let mut transport =
        hartevo_anthropic_message_result_plugin::RecordingAnthropicTransport::fixture(body.clone());
    let evidence = service
        .record_via_transport(&proposal, &transport_request, &mut transport, 13)
        .expect("transport evidence");
    assert_eq!(evidence.provenance, ProviderProvenance::Fixture);
    assert!(!evidence.provenance.connected());
    assert!(!evidence.provenance.native());
    let seen = transport.seen_requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/messages");
    assert_eq!(
        seen[0].body_bytes,
        hartevo_anthropic_message_result_plugin::allowlisted_request(&transport_request).body_bytes
    );

    let native_scope = scope();
    let native_request = request(&native_scope, "request-native-gap");
    let mut native_service =
        AnthropicMessageResultService::new(native_scope, AnthropicProvider::recording())
            .expect("native-gap service");
    let proposal = native_service
        .compile_message_proposal(&native_request)
        .expect("native-gap proposal");
    let mut native = hartevo_anthropic_message_result_plugin::NativeAnthropicTransport;
    let blocked = native_service
        .record_via_transport(&proposal, &native_request, &mut native, 0)
        .expect("blocked native evidence");
    assert_eq!(blocked.status, ResultStatus::BlockedEnv);
    assert_eq!(blocked.provenance, ProviderProvenance::BlockedEnv);
    assert!(!blocked.authority.connected);
    assert!(!blocked.authority.native);
}

#[test]
fn secret_reference_and_forbidden_capabilities_are_redacted_or_rejected() {
    let scope = scope();
    let secret_debug = format!("{:?}", scope.secret_reference);
    let secret_json = serde_json::to_string(&scope.secret_reference).expect("secret JSON");
    assert!(!secret_debug.contains("fixture-api-key"));
    assert!(!secret_json.contains("fixture-api-key"));

    let streaming = AnthropicMessageRequest::new(
        hartevo_anthropic_message_result_plugin::RequestId::new_request("request-stream")
            .expect("request id"),
        scope.model.clone(),
        128,
        vec![
            AnthropicMessage::new(
                hartevo_anthropic_message_result_plugin::MessageRole::User,
                "bounded content",
            )
            .expect("message"),
        ],
    )
    .expect("request")
    .with_stream(true);
    let service =
        AnthropicMessageResultService::new(scope, AnthropicProvider::fixture()).expect("service");
    assert_eq!(
        service
            .compile_message_proposal(&streaming)
            .expect_err("streaming")
            .to_string(),
        "streaming is forbidden by the Layer-1 contract"
    );
    assert_eq!(
        service
            .reject_write("tool execution")
            .expect_err("write")
            .to_string(),
        "operation is forbidden in Layer 1: tool execution"
    );
}

#[test]
fn transport_fault_outcomes_preserve_blocked_and_timeout_classes() {
    let scope = scope();
    let request = request(&scope, "request-transport-fault");
    let mut service =
        AnthropicMessageResultService::new(scope, AnthropicProvider::recording()).expect("service");
    let proposal = service
        .compile_message_proposal(&request)
        .expect("proposal");
    let mut transport = hartevo_anthropic_message_result_plugin::RecordingAnthropicTransport::new(
        ProviderProvenance::Loopback,
        TransportOutcome::timeout(),
    );
    let timeout = service
        .record_via_transport(&proposal, &request, &mut transport, 21)
        .expect("timeout evidence");
    assert_eq!(
        timeout.provider_error.expect("timeout").class,
        ProviderErrorClass::Timeout
    );
}
