use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use futures_util::StreamExt;
use hartevo_cordis::{
    LlmAdapter, SessionCallConfig, SessionContentBlock, SessionFinishReason, SessionId,
    SessionMessage, SessionMessageRole, SessionMessageSource, SessionStreamBlockType,
    SessionStreamChunk, SessionToolSchema,
};

use super::*;

#[derive(Clone)]
struct ObservedCall {
    connection: DeepSeekConnection,
    credential: String,
    request: Value,
}

#[derive(Clone)]
struct RecordingTransport {
    calls: Arc<Mutex<Vec<ObservedCall>>>,
    responses: Arc<Mutex<VecDeque<Result<DeepSeekWireResponse, SessionLlmFailure>>>>,
}

impl RecordingTransport {
    fn new(responses: Vec<Result<DeepSeekWireResponse, SessionLlmFailure>>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into())),
        }
    }
}

impl DeepSeekTransport for RecordingTransport {
    fn execute(
        &self,
        connection: &DeepSeekConnection,
        api_key: &str,
        request: &Value,
        cancellation: &LifecycleCancellation,
    ) -> Result<DeepSeekWireResponse, SessionLlmFailure> {
        assert!(!cancellation.is_cancelled());
        self.calls.lock().unwrap().push(ObservedCall {
            connection: connection.clone(),
            credential: api_key.to_owned(),
            request: request.clone(),
        });
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("planned response")
    }
}

fn response(payloads: &[&str]) -> DeepSeekWireResponse {
    DeepSeekWireResponse::new(
        payloads
            .iter()
            .map(|payload| (*payload).to_owned())
            .collect(),
        Some("request-fixture".into()),
    )
}

fn request(session: &str) -> LlmGenerateRequest {
    LlmGenerateRequest::new(
        SessionCallConfig {
            provider: DEEPSEEK_PROVIDER_ID.into(),
            model: "deepseek-chat".into(),
            reasoning_effort: Some("high".into()),
            temperature: Some(serde_json::Number::from_f64(0.2).unwrap()),
            max_tokens: Some(4_096),
            stop: Some(vec!["done".into()]),
        },
        vec![
            SessionMessage {
                id: "user-1".into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::Text {
                    text: "inspect".into(),
                }],
                source: SessionMessageSource::User,
            },
            SessionMessage {
                id: "assistant-1".into(),
                role: SessionMessageRole::Assistant,
                content: vec![
                    SessionContentBlock::Reasoning {
                        text: "need tool".into(),
                    },
                    SessionContentBlock::ToolCall {
                        id: "call-1".into(),
                        name: "inspect".into(),
                        arguments: r#"{"target":"desktop"}"#.into(),
                    },
                ],
                source: SessionMessageSource::Model {
                    provider: DEEPSEEK_PROVIDER_ID.into(),
                    model: "deepseek-chat".into(),
                },
            },
            SessionMessage {
                id: "tool-1".into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::ToolResult {
                    tool_call_id: "call-1".into(),
                    content: vec![SessionContentBlock::Text { text: "ok".into() }],
                    is_error: false,
                }],
                source: SessionMessageSource::Tool {
                    call_id: "call-1".into(),
                },
            },
        ],
    )
    .with_system(Some("system".into()))
    .with_tools(vec![SessionToolSchema {
        name: "inspect".into(),
        description: "Inspect one target".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"]
        })
        .as_object()
        .unwrap()
        .clone(),
    }])
    .with_session_id(SessionId::new(session).unwrap())
}

fn collect(adapter: &DeepSeekAdapter, request: LlmGenerateRequest) -> Vec<SessionStreamChunk> {
    let stream = adapter.stream(request).expect("stream");
    futures_executor::block_on(stream.collect::<Vec<_>>())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("chunks")
}

fn stream_error(adapter: &DeepSeekAdapter, request: LlmGenerateRequest) -> SessionLlmFailure {
    match adapter.stream(request) {
        Ok(_) => panic!("request unexpectedly produced a stream"),
        Err(error) => error,
    }
}

#[test]
fn connection_is_https_and_contains_only_a_credential_name() {
    assert!(DeepSeekConnection::official("DEEPSEEK_API_KEY").is_ok());
    assert!(
        DeepSeekConnection::new(
            "http://api.deepseek.com",
            "DEEPSEEK_API_KEY",
            1,
            1,
            Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(DeepSeekConnection::official("not-a-safe-name").is_err());
    assert!(
        DeepSeekConnection::new(
            "https://user@example.com",
            "DEEPSEEK_API_KEY",
            1,
            1,
            Duration::from_secs(1)
        )
        .is_err()
    );

    let adapter = DeepSeekAdapter::new(
        DeepSeekConnection::official("DEEPSEEK_API_KEY").unwrap(),
        |_name: &str| Ok(Zeroizing::new("fixture-secret".into())),
        RecordingTransport::new(Vec::new()),
    );
    assert!(
        adapter
            .prepare_model("other-provider", "deepseek-chat")
            .is_err()
    );
    let wrong_route = LlmGenerateRequest::new(
        SessionCallConfig {
            provider: "other-provider".into(),
            model: "deepseek-chat".into(),
            reasoning_effort: None,
            temperature: None,
            max_tokens: None,
            stop: None,
        },
        Vec::new(),
    );
    assert_eq!(stream_error(&adapter, wrong_route).code, "INVALID_MODEL");

    let response_debug = format!("{:?}", response(&["private model output"]));
    assert!(response_debug.contains("[REDACTED]"));
    assert!(!response_debug.contains("private model output"));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table-like journey keeps native request history and mixed SSE output assertions together"
)]
fn reusable_adapter_preserves_native_history_and_resolves_each_call() {
    let transport = RecordingTransport::new(vec![
        Ok(response(&[
            r#"{"choices":[{"delta":{"reasoning_content":"check "}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-2","function":{"name":"inspect","arguments":"{\"target\""}}]}}]}"#,
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":":\"child\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16,"prompt_cache_hit_tokens":2,"completion_tokens_details":{"reasoning_tokens":1}}}"#,
            "[DONE]",
        ])),
        Ok(response(&[
            r#"{"choices":[{"delta":{"content":"finished"},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":2,"total_tokens":22}}"#,
            "[DONE]",
        ])),
    ]);
    let calls = Arc::clone(&transport.calls);
    let connection_resolutions = Arc::new(AtomicUsize::new(0));
    let credential_resolutions = Arc::new(AtomicUsize::new(0));
    let connection_counter = Arc::clone(&connection_resolutions);
    let credential_counter = Arc::clone(&credential_resolutions);
    let adapter = DeepSeekAdapter::new(
        move || {
            let generation = connection_counter.fetch_add(1, Ordering::SeqCst) + 1;
            DeepSeekConnection::new(
                format!("https://api.deepseek.com/v{generation}"),
                format!("DEEPSEEK_KEY_{generation}"),
                100_000 + generation as u64,
                8_192,
                Duration::from_secs(5),
            )
        },
        move |name: &str| {
            credential_counter.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new(format!("secret-for-{name}")))
        },
        transport,
    );

    let first = collect(&adapter, request("parent"));
    let second = collect(&adapter, request("child"));

    assert!(matches!(
        first.as_slice(),
        [
            SessionStreamChunk::BlockStart { index: 0, block_type: SessionStreamBlockType::Reasoning },
            SessionStreamChunk::ReasoningDelta { index: 0, text },
            SessionStreamChunk::BlockStart { index: 1, block_type: SessionStreamBlockType::ToolCall },
            SessionStreamChunk::ToolCallDelta { index: 1, id, name: Some(name), arguments_delta: first_arguments },
            SessionStreamChunk::ToolCallDelta { index: 1, arguments_delta: second_arguments, .. },
            SessionStreamChunk::BlockEnd { index: 0, block: SessionContentBlock::Reasoning { text: full_reasoning } },
            SessionStreamChunk::BlockEnd { index: 1, block: SessionContentBlock::ToolCall { id: full_id, name: full_name, arguments } },
            SessionStreamChunk::Usage { usage },
            SessionStreamChunk::Finish { reason: SessionFinishReason::ToolCalls, .. },
        ] if text == "check "
            && id == "call-2"
            && name == "inspect"
            && first_arguments == "{\"target\""
            && second_arguments == ":\"child\"}"
            && full_reasoning == "check "
            && full_id == "call-2"
            && full_name == "inspect"
            && arguments == "{\"target\":\"child\"}"
            && usage.input_tokens == 10
            && usage.output_tokens == 4
            && usage.total_tokens == Some(16)
            && usage.cache_read_tokens == Some(2)
            && usage.reasoning_tokens == Some(1)
    ));
    assert!(matches!(
        second.last(),
        Some(SessionStreamChunk::Finish {
            reason: SessionFinishReason::Stop,
            ..
        })
    ));
    assert_eq!(connection_resolutions.load(Ordering::SeqCst), 2);
    assert_eq!(credential_resolutions.load(Ordering::SeqCst), 2);

    let calls = calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].connection.api_key_env(), "DEEPSEEK_KEY_1");
    assert_eq!(calls[1].connection.api_key_env(), "DEEPSEEK_KEY_2");
    assert_eq!(calls[0].credential, "secret-for-DEEPSEEK_KEY_1");
    assert_eq!(calls[1].credential, "secret-for-DEEPSEEK_KEY_2");
    assert_eq!(calls[0].request["model"], "deepseek-chat");
    assert_eq!(
        calls[0].request["messages"][0],
        json!({"role":"system","content":"system"})
    );
    assert_eq!(
        calls[0].request["messages"][1],
        json!({"role":"user","content":"inspect"})
    );
    assert_eq!(
        calls[0].request["messages"][2]["reasoning_content"],
        "need tool"
    );
    assert_eq!(
        calls[0].request["messages"][2]["tool_calls"][0]["id"],
        "call-1"
    );
    assert_eq!(
        calls[0].request["messages"][3],
        json!({"role":"tool","tool_call_id":"call-1","content":"ok"})
    );
    assert_eq!(calls[0].request["tools"][0]["function"]["name"], "inspect");
    assert_eq!(calls[0].request["thinking"], json!({"type":"enabled"}));
    assert_eq!(calls[0].request["reasoning_effort"], "high");
    assert_eq!(calls[0].request["max_tokens"], 4_096);
    assert_eq!(calls[0].request["stop"], json!(["done"]));
}

#[test]
fn malformed_and_truncated_provider_streams_fail_closed() {
    let malformed_transport = RecordingTransport::new(vec![Ok(response(&[
        r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#,
        "[DONE]",
    ]))]);
    let adapter = DeepSeekAdapter::new(
        DeepSeekConnection::official("DEEPSEEK_API_KEY").unwrap(),
        |_name: &str| Ok(Zeroizing::new("fixture-secret".into())),
        malformed_transport,
    );
    assert_eq!(
        stream_error(&adapter, request("missing-call-identity")).code,
        "MALFORMED_RESPONSE"
    );

    let truncated_transport = RecordingTransport::new(vec![Ok(response(&[
        r#"{"choices":[{"delta":{"content":"partial"}}]}"#,
    ]))]);
    let adapter = DeepSeekAdapter::new(
        DeepSeekConnection::official("DEEPSEEK_API_KEY").unwrap(),
        |_name: &str| Ok(Zeroizing::new("fixture-secret".into())),
        truncated_transport,
    );
    assert_eq!(
        stream_error(&adapter, request("truncated")).code,
        "MALFORMED_RESPONSE"
    );
}

#[test]
fn oversized_transport_response_is_rejected() {
    let oversized = "x".repeat(usize::try_from(MAX_RESPONSE_BYTES).unwrap() + 1);
    let transport = RecordingTransport::new(vec![Ok(DeepSeekWireResponse::new(
        vec![oversized],
        Some("oversized-fixture".into()),
    ))]);
    let adapter = DeepSeekAdapter::new(
        DeepSeekConnection::official("DEEPSEEK_API_KEY").unwrap(),
        |_name: &str| Ok(Zeroizing::new("fixture-secret".into())),
        transport,
    );
    let error = stream_error(&adapter, request("oversized"));
    assert_eq!(error.code, "RESPONSE_TOO_LARGE");
    assert_eq!(error.request_id.as_deref(), Some("oversized-fixture"));
}

#[test]
fn caller_cancellation_prevents_connection_and_credential_resolution() {
    let connection_resolutions = Arc::new(AtomicUsize::new(0));
    let credential_resolutions = Arc::new(AtomicUsize::new(0));
    let connection_counter = Arc::clone(&connection_resolutions);
    let credential_counter = Arc::clone(&credential_resolutions);
    let adapter = DeepSeekAdapter::new(
        move || {
            connection_counter.fetch_add(1, Ordering::SeqCst);
            DeepSeekConnection::official("DEEPSEEK_API_KEY")
        },
        move |_name: &str| {
            credential_counter.fetch_add(1, Ordering::SeqCst);
            Ok(Zeroizing::new("fixture-secret".into()))
        },
        RecordingTransport::new(Vec::new()),
    );
    let cancellation = LifecycleCancellation::default();
    cancellation.cancel();
    let cancelled = request("cancelled").with_cancellation(cancellation);
    assert_eq!(stream_error(&adapter, cancelled).code, "ABORTED");
    assert_eq!(connection_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(credential_resolutions.load(Ordering::SeqCst), 0);
}

#[test]
fn sse_framing_requires_a_blank_line_terminated_done_event() {
    let parsed = DeepSeekWireResponse::from_sse_bytes(
        b"\xef\xbb\xbf: keepalive\r\ndata: {\"choices\":[]}\r\n\r\ndata: [DONE]\r\n\r\n",
        None,
    )
    .unwrap();
    assert_eq!(parsed.payloads(), [r#"{"choices":[]}"#, "[DONE]"]);

    let failure =
        DeepSeekWireResponse::from_sse_bytes(b"data: {\"choices\":[]}\n\ndata: [DONE]", None)
            .unwrap_err();
    assert_eq!(failure.code, "MALFORMED_RESPONSE");
}

#[test]
fn http_errors_are_normalized_without_returning_provider_body() {
    assert_eq!(
        http_error_code(401, br#"{"error":{"message":"secret"}}"#),
        "AUTH"
    );
    assert_eq!(
        http_error_code(429, br#"{"error":{"message":"quota exceeded"}}"#),
        "QUOTA_EXCEEDED"
    );
    assert_eq!(http_error_code(429, b"{}"), "RATE_LIMIT");
    assert_eq!(http_error_code(503, b"{}"), "SERVER");
    assert_eq!(
        http_error_code(400, br#"{"error":{"message":"maximum context length"}}"#),
        "CONTEXT_WINDOW_EXCEEDED"
    );
}
