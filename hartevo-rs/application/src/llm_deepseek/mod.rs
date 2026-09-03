//! Direct DeepSeek chat-completions transport for the Rust Cordis LLM seam.
//!
//! Provider-specific HTTP and credentials stay in the Application adapter
//! layer, outside `hartevo-cordis`.
//! Connection facts and the named credential are resolved once for every
//! request, while one adapter instance can serve any number of parent or child
//! Cordis calls.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream;
use hartevo_cordis::{
    LifecycleCancellation, LlmAdapter, LlmAdapterStream, LlmError, LlmGenerateRequest,
    LlmModelReasoning, LlmResolvedModel, LlmRetryPolicy, SessionContentBlock, SessionFinishReason,
    SessionLlmFailure, SessionMessageRole, SessionStreamBlockType, SessionStreamChunk,
    SessionTokenUsage,
};
use serde_json::{Map, Value, json};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

pub const DEEPSEEK_PROVIDER_ID: &str = "deepseek-official";
pub const DEFAULT_BASE_URL: &str = "https://api.deepseek.com/";
pub const DEFAULT_CONTEXT_WINDOW: u64 = 1_000_000;
pub const DEFAULT_MAX_TOKENS: u64 = 256_000;
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 1_024;
const MAX_TIMEOUT: Duration = Duration::from_mins(10);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DeepSeekAdapterError {
    #[error("DeepSeek connection facts are invalid")]
    InvalidConnection,
    #[error("the configured DeepSeek credential is unavailable")]
    CredentialUnavailable,
    #[error("the configured DeepSeek credential is invalid")]
    InvalidCredential,
}

/// One validated connection generation. It contains only a credential name,
/// never secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeepSeekConnection {
    base_url: Url,
    api_key_env: String,
    context_window: u64,
    max_tokens: u64,
    timeout: Duration,
}

impl DeepSeekConnection {
    pub fn official(api_key_env: impl Into<String>) -> Result<Self, DeepSeekAdapterError> {
        Self::new(
            DEFAULT_BASE_URL,
            api_key_env,
            DEFAULT_CONTEXT_WINDOW,
            DEFAULT_MAX_TOKENS,
            Duration::from_mins(5),
        )
    }

    pub fn new(
        base_url: impl AsRef<str>,
        api_key_env: impl Into<String>,
        context_window: u64,
        max_tokens: u64,
        timeout: Duration,
    ) -> Result<Self, DeepSeekAdapterError> {
        let mut base_url =
            Url::parse(base_url.as_ref()).map_err(|_| DeepSeekAdapterError::InvalidConnection)?;
        let api_key_env = api_key_env.into();
        if base_url.scheme() != "https"
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || !valid_environment_name(&api_key_env)
            || context_window == 0
            || max_tokens == 0
            || timeout.is_zero()
            || timeout > MAX_TIMEOUT
        {
            return Err(DeepSeekAdapterError::InvalidConnection);
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        Ok(Self {
            base_url,
            api_key_env,
            context_window,
            max_tokens,
            timeout,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn api_key_env(&self) -> &str {
        &self.api_key_env
    }

    pub const fn context_window(&self) -> u64 {
        self.context_window
    }

    pub const fn max_tokens(&self) -> u64 {
        self.max_tokens
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    fn endpoint(&self) -> Result<Url, DeepSeekAdapterError> {
        self.base_url
            .join("chat/completions")
            .map_err(|_| DeepSeekAdapterError::InvalidConnection)
    }
}

pub trait DeepSeekConnectionResolver: Send + Sync + 'static {
    fn resolve(&self) -> Result<DeepSeekConnection, DeepSeekAdapterError>;
}

impl DeepSeekConnectionResolver for DeepSeekConnection {
    fn resolve(&self) -> Result<DeepSeekConnection, DeepSeekAdapterError> {
        Ok(self.clone())
    }
}

impl<F> DeepSeekConnectionResolver for F
where
    F: Fn() -> Result<DeepSeekConnection, DeepSeekAdapterError> + Send + Sync + 'static,
{
    fn resolve(&self) -> Result<DeepSeekConnection, DeepSeekAdapterError> {
        self()
    }
}

pub trait DeepSeekCredentialResolver: Send + Sync + 'static {
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, DeepSeekAdapterError>;
}

impl<F> DeepSeekCredentialResolver for F
where
    F: Fn(&str) -> Result<Zeroizing<String>, DeepSeekAdapterError> + Send + Sync + 'static,
{
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, DeepSeekAdapterError> {
        self(name)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentCredentialResolver;

impl DeepSeekCredentialResolver for EnvironmentCredentialResolver {
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, DeepSeekAdapterError> {
        let value = std::env::var(name)
            .map(Zeroizing::new)
            .map_err(|_| DeepSeekAdapterError::CredentialUnavailable)?;
        validate_credential(value)
    }
}

/// Parsed transport response. The raw HTTP body and bearer token never enter
/// Cordis or the durable Session log.
#[derive(Clone, Eq, PartialEq)]
pub struct DeepSeekWireResponse {
    payloads: Vec<String>,
    request_id: Option<String>,
}

impl fmt::Debug for DeepSeekWireResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepSeekWireResponse")
            .field("payload_count", &self.payloads.len())
            .field("request_id", &self.request_id)
            .field("payloads", &"[REDACTED]")
            .finish()
    }
}

impl DeepSeekWireResponse {
    pub fn new(payloads: Vec<String>, request_id: Option<String>) -> Self {
        Self {
            payloads,
            request_id: request_id.filter(|value| bounded_identifier(value, 256)),
        }
    }

    pub fn from_sse_bytes(
        body: &[u8],
        request_id: Option<String>,
    ) -> Result<Self, SessionLlmFailure> {
        if usize_exceeds_response_bound(body.len()) {
            return Err(response_too_large(request_id.as_deref()));
        }
        Ok(Self::new(parse_sse(body)?, request_id))
    }

    pub fn payloads(&self) -> &[String] {
        &self.payloads
    }

    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }

    fn exceeds_bound(&self) -> bool {
        self.payloads
            .iter()
            .try_fold(0_u64, |total, payload| {
                let bytes = u64::try_from(payload.len()).ok()?;
                total.checked_add(bytes)
            })
            .is_none_or(|total| total > MAX_RESPONSE_BYTES)
    }
}

/// Injectable request boundary. Fixtures can return exact SSE payloads; the
/// production implementation performs one bounded HTTPS request.
pub trait DeepSeekTransport: Send + Sync + 'static {
    fn execute(
        &self,
        connection: &DeepSeekConnection,
        api_key: &str,
        request: &Value,
        cancellation: &LifecycleCancellation,
    ) -> Result<DeepSeekWireResponse, SessionLlmFailure>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UreqDeepSeekTransport;

impl DeepSeekTransport for UreqDeepSeekTransport {
    fn execute(
        &self,
        connection: &DeepSeekConnection,
        api_key: &str,
        request: &Value,
        cancellation: &LifecycleCancellation,
    ) -> Result<DeepSeekWireResponse, SessionLlmFailure> {
        if cancellation.is_cancelled() {
            return Err(failure("ABORTED", "DeepSeek request cancelled", None, None));
        }
        let endpoint = connection.endpoint().map_err(config_failure)?;
        let authorization = Zeroizing::new(format!("Bearer {api_key}"));
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .user_agent("hartevo-llm-deepseek/1")
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(true)
            .http_status_as_error(false)
            .timeout_global(Some(connection.timeout()))
            .build()
            .into();
        let mut response = agent
            .post(endpoint.as_str())
            .header("Authorization", authorization.as_str())
            .header("Accept", "text/event-stream")
            .header("Content-Type", "application/json")
            .send_json(request)
            .map_err(|error| transport_failure(&error))?;
        if cancellation.is_cancelled() {
            return Err(failure("ABORTED", "DeepSeek request cancelled", None, None));
        }
        let status = response.status().as_u16();
        let request_id = bounded_header(&response, "x-request-id")
            .or_else(|| bounded_header(&response, "x-deepseek-request-id"));
        let retry_after_ms = bounded_header(&response, "retry-after")
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|seconds| seconds.checked_mul(1_000))
            .filter(|delay| *delay > 0);
        let content_type = bounded_header(&response, "content-type");
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|error| body_failure(&error))?;
        if !(200..300).contains(&status) {
            let code = http_error_code(status, &body);
            return Err(failure(
                &code,
                "DeepSeek provider rejected the request",
                Some(u64::from(status)),
                request_id,
            )
            .with_retry_after(retry_after_ms));
        }
        if content_type.as_deref().is_none_or(|value| {
            !value.eq_ignore_ascii_case("text/event-stream")
                && !value.to_ascii_lowercase().starts_with("text/event-stream;")
        }) {
            return Err(failure(
                "MALFORMED_RESPONSE",
                "DeepSeek response is not an event stream",
                Some(u64::from(status)),
                request_id,
            ));
        }
        if cancellation.is_cancelled() {
            return Err(failure(
                "ABORTED",
                "DeepSeek request cancelled",
                None,
                request_id,
            ));
        }
        DeepSeekWireResponse::from_sse_bytes(&body, request_id)
    }
}

trait FailureExt {
    fn with_retry_after(self, retry_after_ms: Option<u64>) -> Self;
}

impl FailureExt for SessionLlmFailure {
    fn with_retry_after(mut self, retry_after_ms: Option<u64>) -> Self {
        self.provider_retry_after_ms = retry_after_ms;
        self
    }
}

/// Reusable direct adapter. No request identity, Session id, credential, or
/// response is consumed from adapter state, so child and continuation calls
/// use the same exact provider route safely.
#[derive(Clone)]
pub struct DeepSeekAdapter {
    connection: Arc<dyn DeepSeekConnectionResolver>,
    credentials: Arc<dyn DeepSeekCredentialResolver>,
    transport: Arc<dyn DeepSeekTransport>,
}

impl fmt::Debug for DeepSeekAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeepSeekAdapter")
            .field("provider", &DEEPSEEK_PROVIDER_ID)
            .finish_non_exhaustive()
    }
}

impl DeepSeekAdapter {
    pub fn new<C, R, T>(connection: C, credentials: R, transport: T) -> Self
    where
        C: DeepSeekConnectionResolver,
        R: DeepSeekCredentialResolver,
        T: DeepSeekTransport,
    {
        Self {
            connection: Arc::new(connection),
            credentials: Arc::new(credentials),
            transport: Arc::new(transport),
        }
    }

    pub fn production<C>(connection: C) -> Self
    where
        C: DeepSeekConnectionResolver,
    {
        Self::new(
            connection,
            EnvironmentCredentialResolver,
            UreqDeepSeekTransport,
        )
    }

    fn connection(&self) -> Result<DeepSeekConnection, SessionLlmFailure> {
        self.connection.resolve().map_err(config_failure)
    }
}

impl LlmAdapter for DeepSeekAdapter {
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        if provider != DEEPSEEK_PROVIDER_ID || !bounded_identifier(model, MAX_IDENTIFIER_BYTES) {
            return Err(LlmError::InvalidModelInfo {
                provider: provider.to_owned(),
                model: model.to_owned(),
                expected: "a bounded model on the deepseek-official route",
            });
        }
        let connection = self
            .connection
            .resolve()
            .map_err(|_| LlmError::InvalidModelInfo {
                provider: provider.to_owned(),
                model: model.to_owned(),
                expected: "valid current DeepSeek connection facts",
            })?;
        let retry_policy = LlmRetryPolicy::normal(
            5,
            vec![
                "RATE_LIMIT".into(),
                "SERVER".into(),
                "TRANSPORT".into(),
                "TIMEOUT".into(),
            ],
            500,
            30_000,
            0.2,
        )?;
        Ok(LlmResolvedModel::new(provider, model)
            .with_context_window(connection.context_window())
            .with_default_max_tokens(connection.max_tokens())
            .with_reasoning(LlmModelReasoning::new(
                vec!["off".into(), "low".into(), "high".into(), "max".into()],
                Some("high".into()),
            ))
            .with_retry_policy(retry_policy))
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        if request.config().provider != DEEPSEEK_PROVIDER_ID
            || !bounded_identifier(&request.config().model, MAX_IDENTIFIER_BYTES)
        {
            return Err(failure(
                "INVALID_MODEL",
                "DeepSeek request route does not match the adapter",
                None,
                None,
            ));
        }
        if request.cancellation().is_cancelled() {
            return Err(failure("ABORTED", "DeepSeek request cancelled", None, None));
        }
        let connection = self.connection()?;
        let wire_request = serialize_request(&request)?;
        let request_bytes = serde_json::to_vec(&wire_request).map_err(|_| {
            failure(
                "INVALID_REQUEST",
                "DeepSeek request could not be encoded",
                None,
                None,
            )
        })?;
        if request_bytes.len() > MAX_REQUEST_BYTES {
            return Err(failure(
                "INVALID_REQUEST",
                "DeepSeek request exceeds the transport bound",
                None,
                None,
            ));
        }
        if request.cancellation().is_cancelled() {
            return Err(failure("ABORTED", "DeepSeek request cancelled", None, None));
        }
        let credential = self
            .credentials
            .resolve(connection.api_key_env())
            .and_then(validate_credential)
            .map_err(config_failure)?;
        let response = self.transport.execute(
            &connection,
            credential.as_str(),
            &wire_request,
            request.cancellation(),
        )?;
        if response.exceeds_bound() {
            return Err(response_too_large(response.request_id()));
        }
        let chunks = translate_payloads(response.payloads(), response.request_id())?;
        Ok(Box::pin(stream::iter(chunks.into_iter().map(Ok))))
    }
}

fn serialize_request(request: &LlmGenerateRequest) -> Result<Value, SessionLlmFailure> {
    let mut messages = Vec::new();
    if let Some(system) = request.system() {
        messages.push(json!({"role": "system", "content": system}));
    }
    for message in request.messages() {
        match message.role {
            SessionMessageRole::Assistant => messages.push(serialize_assistant(&message.content)?),
            SessionMessageRole::User => serialize_user(&message.content, &mut messages)?,
        }
    }
    let mut body = Map::from_iter([
        (
            "model".into(),
            Value::String(request.config().model.clone()),
        ),
        ("messages".into(), Value::Array(messages)),
        ("stream".into(), Value::Bool(true)),
        ("stream_options".into(), json!({"include_usage": true})),
    ]);
    if let Some(tools) = request.tools()
        && !tools.is_empty()
    {
        body.insert(
            "tools".into(),
            Value::Array(
                tools
                    .iter()
                    .map(|tool| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": tool.name,
                                "description": tool.description,
                                "parameters": tool.parameters,
                            }
                        })
                    })
                    .collect(),
            ),
        );
    }
    match request.config().reasoning_effort.as_deref() {
        None => {}
        Some("off") => {
            body.insert("thinking".into(), json!({"type": "disabled"}));
        }
        Some(effort @ ("low" | "high" | "max")) => {
            body.insert("thinking".into(), json!({"type": "enabled"}));
            body.insert("reasoning_effort".into(), Value::String(effort.into()));
        }
        Some(_) => {
            return Err(failure(
                "UNSUPPORTED_REASONING_EFFORT",
                "DeepSeek reasoning effort is unsupported",
                None,
                None,
            ));
        }
    }
    if let Some(temperature) = request.config().temperature.as_ref() {
        body.insert("temperature".into(), Value::Number(temperature.clone()));
    }
    if let Some(max_tokens) = request.config().max_tokens {
        body.insert("max_tokens".into(), Value::from(max_tokens));
    }
    if let Some(stop) = request.config().stop.as_ref() {
        body.insert(
            "stop".into(),
            Value::Array(stop.iter().cloned().map(Value::String).collect()),
        );
    }
    Ok(Value::Object(body))
}

fn serialize_assistant(content: &[SessionContentBlock]) -> Result<Value, SessionLlmFailure> {
    let mut text = String::new();
    let mut reasoning = String::new();
    let mut calls = Vec::new();
    for block in content {
        match block {
            SessionContentBlock::Text { text: delta } => text.push_str(delta),
            SessionContentBlock::Reasoning { text: delta } => reasoning.push_str(delta),
            SessionContentBlock::ToolCall {
                id,
                name,
                arguments,
            } => calls.push(json!({
                "id": id,
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            })),
            SessionContentBlock::ToolResult { .. } => return Err(unsupported_history()),
        }
    }
    let mut message = Map::from_iter([
        ("role".into(), Value::String("assistant".into())),
        ("content".into(), Value::String(text)),
    ]);
    if !reasoning.is_empty() {
        message.insert("reasoning_content".into(), Value::String(reasoning));
    }
    if !calls.is_empty() {
        message.insert("tool_calls".into(), Value::Array(calls));
    }
    Ok(Value::Object(message))
}

fn serialize_user(
    content: &[SessionContentBlock],
    messages: &mut Vec<Value>,
) -> Result<(), SessionLlmFailure> {
    let mut text = String::new();
    let mut results = Vec::new();
    for block in content {
        match block {
            SessionContentBlock::Text { text: delta } => text.push_str(delta),
            SessionContentBlock::ToolResult {
                tool_call_id,
                content,
                ..
            } => results.push((tool_call_id, flatten_tool_result(content)?)),
            SessionContentBlock::Reasoning { .. } | SessionContentBlock::ToolCall { .. } => {
                return Err(unsupported_history());
            }
        }
    }
    if !text.is_empty() || results.is_empty() {
        messages.push(json!({"role": "user", "content": text}));
    }
    for (tool_call_id, content) in results {
        messages.push(json!({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": if content.is_empty() { "(no output)" } else { &content },
        }));
    }
    Ok(())
}

fn flatten_tool_result(content: &[SessionContentBlock]) -> Result<String, SessionLlmFailure> {
    let mut text = String::new();
    for block in content {
        match block {
            SessionContentBlock::Text { text: delta } => text.push_str(delta),
            SessionContentBlock::Reasoning { .. }
            | SessionContentBlock::ToolCall { .. }
            | SessionContentBlock::ToolResult { .. } => return Err(unsupported_history()),
        }
    }
    Ok(text)
}

fn unsupported_history() -> SessionLlmFailure {
    failure(
        "UNSUPPORTED_CONTENT",
        "DeepSeek request history contains an unsupported block placement",
        None,
        None,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenKind {
    Text,
    Reasoning,
    ToolCall,
}

#[derive(Debug)]
struct OpenBlock {
    index: u64,
    kind: OpenKind,
    text: String,
    id: Option<String>,
    name: Option<String>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one state machine keeps DeepSeek SSE block ordering and terminal validation explicit"
)]
fn translate_payloads(
    payloads: &[String],
    request_id: Option<&str>,
) -> Result<Vec<SessionStreamChunk>, SessionLlmFailure> {
    let mut output = Vec::new();
    let mut blocks = Vec::<OpenBlock>::new();
    let mut text_block = None;
    let mut reasoning_block = None;
    let mut tool_blocks = BTreeMap::<u64, usize>::new();
    let mut finish = None;
    let mut usage = None;

    for payload in payloads {
        if payload == "[DONE]" {
            for block in blocks {
                let value =
                    match block.kind {
                        OpenKind::Text => SessionContentBlock::Text { text: block.text },
                        OpenKind::Reasoning => SessionContentBlock::Reasoning { text: block.text },
                        OpenKind::ToolCall => SessionContentBlock::ToolCall {
                            id: block.id.filter(|value| !value.is_empty()).ok_or_else(|| {
                                malformed("DeepSeek tool call omitted its id", request_id)
                            })?,
                            name: block.name.filter(|value| !value.is_empty()).ok_or_else(
                                || malformed("DeepSeek tool call omitted its name", request_id),
                            )?,
                            arguments: block.text,
                        },
                    };
                output.push(SessionStreamChunk::BlockEnd {
                    index: block.index,
                    block: value,
                });
            }
            if let Some(usage) = usage {
                output.push(SessionStreamChunk::Usage { usage });
            }
            let reason = finish.unwrap_or(SessionFinishReason::Stop);
            if output
                .iter()
                .all(|chunk| !matches!(chunk, SessionStreamChunk::BlockStart { .. }))
                && reason == SessionFinishReason::Stop
            {
                output.push(SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Error {
                        failure: failure(
                            "EMPTY_RESPONSE",
                            "DeepSeek returned no model content",
                            None,
                            request_id.map(str::to_owned),
                        ),
                    },
                    replay_state: None,
                });
            } else {
                output.push(SessionStreamChunk::Finish {
                    reason,
                    replay_state: None,
                });
            }
            return Ok(output);
        }

        let value: Value = serde_json::from_str(payload)
            .map_err(|_| malformed("DeepSeek SSE payload is malformed", request_id))?;
        if let Some(choices) = value.get("choices") {
            let choices = choices
                .as_array()
                .ok_or_else(|| malformed("DeepSeek choices are malformed", request_id))?;
            for choice in choices {
                let delta = choice.get("delta").unwrap_or(&Value::Null);
                if !delta.is_null() && !delta.is_object() {
                    return Err(malformed("DeepSeek delta is malformed", request_id));
                }
                if let Some(reasoning) =
                    nullable_string(delta.get("reasoning_content"), request_id)?
                    && !reasoning.is_empty()
                {
                    let slot = open_block(
                        &mut blocks,
                        &mut output,
                        &mut reasoning_block,
                        OpenKind::Reasoning,
                    )?;
                    blocks[slot].text.push_str(reasoning);
                    output.push(SessionStreamChunk::ReasoningDelta {
                        index: blocks[slot].index,
                        text: reasoning.to_owned(),
                    });
                }
                if let Some(content) = nullable_string(delta.get("content"), request_id)?
                    && !content.is_empty()
                {
                    let slot =
                        open_block(&mut blocks, &mut output, &mut text_block, OpenKind::Text)?;
                    blocks[slot].text.push_str(content);
                    output.push(SessionStreamChunk::TextDelta {
                        index: blocks[slot].index,
                        text: content.to_owned(),
                    });
                }
                if let Some(calls) = delta.get("tool_calls") {
                    let calls = calls.as_array().ok_or_else(|| {
                        malformed("DeepSeek tool-call deltas are malformed", request_id)
                    })?;
                    for call in calls {
                        let wire_index =
                            call.get("index").and_then(Value::as_u64).ok_or_else(|| {
                                malformed("DeepSeek tool-call index is missing", request_id)
                            })?;
                        let slot = if let Some(slot) = tool_blocks.get(&wire_index).copied() {
                            slot
                        } else {
                            let index = u64::try_from(blocks.len()).map_err(|_| {
                                malformed("DeepSeek block count overflowed", request_id)
                            })?;
                            let slot = blocks.len();
                            blocks.push(OpenBlock {
                                index,
                                kind: OpenKind::ToolCall,
                                text: String::new(),
                                id: None,
                                name: None,
                            });
                            tool_blocks.insert(wire_index, slot);
                            output.push(SessionStreamChunk::BlockStart {
                                index,
                                block_type: SessionStreamBlockType::ToolCall,
                            });
                            slot
                        };
                        if let Some(id) = nullable_string(call.get("id"), request_id)? {
                            set_stable(&mut blocks[slot].id, id, request_id)?;
                        }
                        let function = call.get("function").unwrap_or(&Value::Null);
                        if !function.is_null() && !function.is_object() {
                            return Err(malformed(
                                "DeepSeek tool-call function is malformed",
                                request_id,
                            ));
                        }
                        if let Some(name) = nullable_string(function.get("name"), request_id)? {
                            set_stable(&mut blocks[slot].name, name, request_id)?;
                        }
                        let arguments = nullable_string(function.get("arguments"), request_id)?
                            .unwrap_or_default();
                        blocks[slot].text.push_str(arguments);
                        output.push(SessionStreamChunk::ToolCallDelta {
                            index: blocks[slot].index,
                            id: blocks[slot].id.clone().unwrap_or_default(),
                            name: blocks[slot].name.clone(),
                            arguments_delta: arguments.to_owned(),
                        });
                    }
                }
                if let Some(reason) = nullable_string(choice.get("finish_reason"), request_id)? {
                    let mapped = map_finish_reason(reason, request_id);
                    if finish.as_ref().is_some_and(|current| current != &mapped) {
                        return Err(malformed("DeepSeek finish reason changed", request_id));
                    }
                    finish = Some(mapped);
                }
            }
        }
        if let Some(value) = value.get("usage")
            && !value.is_null()
        {
            usage = Some(map_usage(value, request_id)?);
        }
    }
    Err(malformed(
        "DeepSeek SSE stream ended before [DONE]",
        request_id,
    ))
}

fn open_block(
    blocks: &mut Vec<OpenBlock>,
    output: &mut Vec<SessionStreamChunk>,
    slot: &mut Option<usize>,
    kind: OpenKind,
) -> Result<usize, SessionLlmFailure> {
    if let Some(slot) = *slot {
        return Ok(slot);
    }
    let index = u64::try_from(blocks.len())
        .map_err(|_| malformed("DeepSeek block count overflowed", None))?;
    let block_type = match kind {
        OpenKind::Text => SessionStreamBlockType::Text,
        OpenKind::Reasoning => SessionStreamBlockType::Reasoning,
        OpenKind::ToolCall => SessionStreamBlockType::ToolCall,
    };
    let next = blocks.len();
    blocks.push(OpenBlock {
        index,
        kind,
        text: String::new(),
        id: None,
        name: None,
    });
    output.push(SessionStreamChunk::BlockStart { index, block_type });
    *slot = Some(next);
    Ok(next)
}

fn set_stable(
    target: &mut Option<String>,
    value: &str,
    request_id: Option<&str>,
) -> Result<(), SessionLlmFailure> {
    if target.as_deref().is_some_and(|current| current != value) {
        return Err(malformed("DeepSeek tool-call identity changed", request_id));
    }
    *target = Some(value.to_owned());
    Ok(())
}

fn nullable_string<'a>(
    value: Option<&'a Value>,
    request_id: Option<&str>,
) -> Result<Option<&'a str>, SessionLlmFailure> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(malformed("DeepSeek string field is malformed", request_id)),
    }
}

fn map_finish_reason(reason: &str, request_id: Option<&str>) -> SessionFinishReason {
    match reason {
        "stop" => SessionFinishReason::Stop,
        "tool_calls" => SessionFinishReason::ToolCalls,
        "length" => SessionFinishReason::MaxTokens,
        other => SessionFinishReason::Error {
            failure: failure(
                &other.to_ascii_uppercase(),
                "DeepSeek stopped the response",
                None,
                request_id.map(str::to_owned),
            ),
        },
    }
}

fn map_usage(
    value: &Value,
    request_id: Option<&str>,
) -> Result<SessionTokenUsage, SessionLlmFailure> {
    let prompt = required_u64(value, "prompt_tokens", request_id)?;
    let output = required_u64(value, "completion_tokens", request_id)?;
    let cache = value
        .get("prompt_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .or_else(|| value.get("prompt_cache_hit_tokens").and_then(Value::as_u64));
    if cache.is_some_and(|cache| cache > prompt) {
        return Err(malformed("DeepSeek usage is inconsistent", request_id));
    }
    let combined = prompt.checked_add(output);
    let reported_total = value.get("total_tokens").and_then(Value::as_u64);
    let total_tokens =
        combined.filter(|combined| reported_total.is_none_or(|total| total == *combined));
    let reasoning_tokens = value
        .get("completion_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64);
    Ok(SessionTokenUsage {
        input_tokens: prompt - cache.unwrap_or(0),
        output_tokens: output,
        total_tokens,
        cache_read_tokens: cache,
        cache_write_tokens: None,
        reasoning_tokens,
    })
}

fn required_u64(
    value: &Value,
    field: &str,
    request_id: Option<&str>,
) -> Result<u64, SessionLlmFailure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed("DeepSeek usage is malformed", request_id))
}

fn parse_sse(body: &[u8]) -> Result<Vec<String>, SessionLlmFailure> {
    let text = std::str::from_utf8(body)
        .map_err(|_| malformed("DeepSeek SSE is not UTF-8", None))?
        .strip_prefix('\u{feff}')
        .unwrap_or_else(|| std::str::from_utf8(body).expect("validated UTF-8"));
    let mut payloads = Vec::new();
    let mut data = Vec::new();
    let mut terminated = false;
    for line in text.split_inclusive('\n') {
        let line = line
            .strip_suffix('\n')
            .unwrap_or(line)
            .strip_suffix('\r')
            .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));
        if line.is_empty() {
            if data.is_empty() {
                continue;
            }
            let payload = data.join("\n");
            terminated = payload == "[DONE]";
            payloads.push(payload);
            data.clear();
            if terminated {
                break;
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(value) = line.strip_prefix("data:") {
            data.push(value.strip_prefix(' ').unwrap_or(value));
        }
    }
    if !data.is_empty() || !terminated {
        return Err(malformed(
            "DeepSeek SSE stream ended before a terminated [DONE] event",
            None,
        ));
    }
    Ok(payloads)
}

fn http_error_code(status: u16, body: &[u8]) -> String {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("error").cloned())
        .map(|error| error.to_string().to_ascii_lowercase())
        .unwrap_or_default();
    if status == 401 || status == 403 {
        "AUTH".into()
    } else if status == 413 {
        "INVALID_REQUEST".into()
    } else if detail.contains("quota") || detail.contains("insufficient balance") {
        "QUOTA_EXCEEDED".into()
    } else if status == 429 {
        "RATE_LIMIT".into()
    } else if status == 400
        && (detail.contains("context length") || detail.contains("maximum context"))
    {
        "CONTEXT_WINDOW_EXCEEDED".into()
    } else if status == 400 {
        "INVALID_REQUEST".into()
    } else if status >= 500 {
        "SERVER".into()
    } else {
        format!("HTTP_{status}")
    }
}

fn bounded_header(response: &ureq::http::Response<ureq::Body>, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| bounded_identifier(value, 256))
        .map(str::to_owned)
}

fn validate_credential(
    value: Zeroizing<String>,
) -> Result<Zeroizing<String>, DeepSeekAdapterError> {
    if value.is_empty()
        || value.len() > MAX_CREDENTIAL_BYTES
        || value.as_str() != value.trim()
        || value.chars().any(char::is_control)
    {
        return Err(DeepSeekAdapterError::InvalidCredential);
    }
    Ok(value)
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
}

fn bounded_identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn failure(
    code: &str,
    message: &str,
    status: Option<u64>,
    request_id: Option<String>,
) -> SessionLlmFailure {
    SessionLlmFailure {
        message: message.into(),
        code: code.into(),
        status,
        provider_retry_after_ms: None,
        request_id,
    }
}

fn malformed(message: &str, request_id: Option<&str>) -> SessionLlmFailure {
    failure(
        "MALFORMED_RESPONSE",
        message,
        None,
        request_id.map(str::to_owned),
    )
}

fn response_too_large(request_id: Option<&str>) -> SessionLlmFailure {
    failure(
        "RESPONSE_TOO_LARGE",
        "DeepSeek response exceeds the transport bound",
        None,
        request_id.map(str::to_owned),
    )
}

fn usize_exceeds_response_bound(value: usize) -> bool {
    u64::try_from(value).map_or(true, |value| value > MAX_RESPONSE_BYTES)
}

fn config_failure(_error: DeepSeekAdapterError) -> SessionLlmFailure {
    failure(
        "INVALID_CONFIGURATION",
        "DeepSeek connection or credential configuration is unavailable",
        None,
        None,
    )
}

fn transport_failure(error: &ureq::Error) -> SessionLlmFailure {
    let code = match error {
        ureq::Error::Timeout(_) => "TIMEOUT",
        ureq::Error::BodyExceedsLimit(_) => "RESPONSE_TOO_LARGE",
        _ => "TRANSPORT",
    };
    failure(code, "DeepSeek transport failed", None, None)
}

fn body_failure(error: &ureq::Error) -> SessionLlmFailure {
    let code = match error {
        ureq::Error::Timeout(_) => "TIMEOUT",
        ureq::Error::BodyExceedsLimit(_) => "RESPONSE_TOO_LARGE",
        _ => "TRANSPORT",
    };
    failure(code, "DeepSeek response body failed", None, None)
}

#[cfg(test)]
mod tests;
