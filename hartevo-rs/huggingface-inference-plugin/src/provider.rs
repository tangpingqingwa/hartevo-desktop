//! Recording-only provider boundary and response projection.

use std::fmt;

use serde_json::Value;

use crate::{
    HUGGINGFACE_INFERENCE_PROVIDER_ID, digest_bytes, digest_serializable,
    model::{
        EvidenceDisposition, FinishReason, HuggingFaceInferenceError, InferenceResultEvidence,
        InferenceResultProposal, ModelDescription, ProviderErrorProjection, ProviderFailureClass,
        ProviderMode, RedactedContent, UsageProjection,
    },
};

pub const DEFAULT_PROVIDER_RESPONSE_BYTES: usize = crate::model::MAX_RESPONSE_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockedEnvCode {
    NativeCredentialResolutionUnavailable,
    NativeTransportUnavailable,
    ProviderReadBackUnavailable,
}

impl BlockedEnvCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::NativeCredentialResolutionUnavailable => {
                "native_credential_resolution_unavailable"
            }
            Self::NativeTransportUnavailable => "native_transport_unavailable",
            Self::ProviderReadBackUnavailable => "provider_read_back_unavailable",
        }
    }
}

#[derive(Clone)]
pub enum ProviderResponseOutcome {
    Http { status: u16, body: Vec<u8> },
    Timeout,
    TransportUnavailable,
    BlockedEnv { code: BlockedEnvCode },
}

impl fmt::Debug for ProviderResponseOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { status, body } => formatter
                .debug_struct("Http")
                .field("status", status)
                .field("body_bytes", &body.len())
                .field("body_digest", &digest_bytes(body))
                .finish(),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::TransportUnavailable => formatter.write_str("TransportUnavailable"),
            Self::BlockedEnv { code } => formatter
                .debug_struct("BlockedEnv")
                .field("code", code)
                .finish(),
        }
    }
}

/// A borrowed-host recording envelope.  It is intentionally not serializable
/// and its Debug implementation exposes only lengths and digests.
#[derive(Clone)]
pub struct RecordedProviderResponse {
    recording_id: String,
    provider_id: String,
    model_id: String,
    model_revision: String,
    latency_ms: u64,
    outcome: ProviderResponseOutcome,
}

impl RecordedProviderResponse {
    pub fn new(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        latency_ms: u64,
        outcome: ProviderResponseOutcome,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            model_revision: model_revision.into(),
            latency_ms,
            outcome,
        }
    }

    pub fn success(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
            ProviderResponseOutcome::Http {
                status: 200,
                body: body.into(),
            },
        )
    }

    pub fn http_error(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        status: u16,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
            ProviderResponseOutcome::Http {
                status,
                body: body.into(),
            },
        )
    }

    pub fn timeout(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
            ProviderResponseOutcome::Timeout,
        )
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
            ProviderResponseOutcome::BlockedEnv { code },
        )
    }

    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub fn outcome(&self) -> &ProviderResponseOutcome {
        &self.outcome
    }
}

impl fmt::Debug for RecordedProviderResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedProviderResponse")
            .field("recording_key", &recording_key(&self.recording_id))
            .field("provider_id", &self.provider_id)
            .field("model_id", &self.model_id)
            .field("model_revision", &self.model_revision)
            .field("latency_ms", &self.latency_ms)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct HuggingFaceInferenceProvider {
    mode: ProviderMode,
    max_response_bytes: usize,
}

impl HuggingFaceInferenceProvider {
    pub fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            max_response_bytes: DEFAULT_PROVIDER_RESPONSE_BYTES,
        }
    }

    pub fn fixture() -> Self {
        Self::new(ProviderMode::Fixture)
    }

    pub fn fake() -> Self {
        Self::new(ProviderMode::Fake)
    }

    pub fn recording() -> Self {
        Self::new(ProviderMode::Recording)
    }

    pub fn loopback() -> Self {
        Self::new(ProviderMode::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderMode::BlockedEnv)
    }

    pub fn with_response_bound(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, HuggingFaceInferenceError> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "max_response_bytes",
                reason: "must be a positive Layer-1 response bound",
            });
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn describe_model(
        &self,
        scope: &crate::model::HuggingFaceInferenceScope,
    ) -> ModelDescription {
        ModelDescription::from_scope(scope)
    }

    pub fn record(
        &self,
        proposal: &InferenceResultProposal,
        response: &RecordedProviderResponse,
        redaction: crate::model::OutputRedactionPolicy,
    ) -> Result<InferenceResultEvidence, HuggingFaceInferenceError> {
        validate_recording_identity(proposal, response)?;
        let recording_key = recording_key(response.recording_id());
        match &response.outcome {
            ProviderResponseOutcome::Timeout => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                digest_bytes(b"timeout"),
                response.latency_ms,
                ProviderFailureClass::Timeout,
                None,
            )),
            ProviderResponseOutcome::TransportUnavailable => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                digest_bytes(b"transport-unavailable"),
                response.latency_ms,
                ProviderFailureClass::TransportUnavailable,
                None,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => {
                if self.mode != ProviderMode::BlockedEnv {
                    return Err(HuggingFaceInferenceError::BlockedEnvironment(
                        "blocked-environment frame requires BLOCKED_ENV provider mode",
                    ));
                }
                let response_digest = digest_bytes(code.as_str().as_bytes());
                Ok(InferenceResultEvidence::new(
                    self.mode,
                    recording_key,
                    proposal,
                    response_digest.clone(),
                    None,
                    None,
                    response.latency_ms,
                    None,
                    EvidenceDisposition::BlockedEnv,
                    Some(ProviderErrorProjection {
                        class: ProviderFailureClass::TransportUnavailable,
                        http_status: None,
                        retryable: true,
                        error_digest: response_digest,
                    }),
                ))
            }
            ProviderResponseOutcome::Http { status, body } => {
                if body.len() > self.max_response_bytes {
                    return Err(HuggingFaceInferenceError::ResponseTruncated);
                }
                let response_digest = digest_bytes(body);
                if (200..300).contains(status) {
                    if self.mode == ProviderMode::BlockedEnv {
                        return Err(HuggingFaceInferenceError::BlockedEnvironment(
                            "BLOCKED_ENV cannot assert a successful provider response",
                        ));
                    }
                    let projection = parse_success(proposal, body, redaction)?;
                    Ok(InferenceResultEvidence::new(
                        self.mode,
                        recording_key,
                        proposal,
                        response_digest,
                        Some(projection.content),
                        projection.usage,
                        response.latency_ms,
                        projection.finish_reason,
                        EvidenceDisposition::RecordedSuccess,
                        None,
                    ))
                } else {
                    let (class, retryable) = failure_for_status(*status)?;
                    Ok(error_evidence(
                        self.mode,
                        recording_key,
                        proposal,
                        response_digest.clone(),
                        response.latency_ms,
                        class,
                        Some((*status, retryable, response_digest)),
                    ))
                }
            }
        }
    }
}

fn validate_recording_identity(
    proposal: &InferenceResultProposal,
    response: &RecordedProviderResponse,
) -> Result<(), HuggingFaceInferenceError> {
    proposal.verify_integrity()?;
    if response.recording_id.trim().is_empty()
        || response.recording_id.len() > crate::model::MAX_IDENTIFIER_BYTES
        || response.recording_id.chars().any(char::is_control)
    {
        return Err(HuggingFaceInferenceError::InvalidField {
            field: "recording_id",
            reason: "must be a bounded non-empty identifier",
        });
    }
    if response.provider_id != proposal.provider_route.provider_id() {
        return Err(HuggingFaceInferenceError::ProviderRouteMismatch);
    }
    if response.model_id != proposal.model.model_id() {
        return Err(HuggingFaceInferenceError::ModelMismatch);
    }
    if response.model_revision != proposal.model.immutable_revision() {
        return Err(HuggingFaceInferenceError::ModelRevisionDrift);
    }
    Ok(())
}

fn recording_key(recording_id: &str) -> crate::model::Digest {
    digest_serializable(&("hartevo:huggingface-recording:v1", recording_id))
}

struct SuccessProjection {
    content: RedactedContent,
    usage: Option<UsageProjection>,
    finish_reason: Option<FinishReason>,
}

fn parse_success(
    proposal: &InferenceResultProposal,
    body: &[u8],
    redaction: crate::model::OutputRedactionPolicy,
) -> Result<SuccessProjection, HuggingFaceInferenceError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| HuggingFaceInferenceError::MalformedResponse("body is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or(HuggingFaceInferenceError::MalformedResponse(
            "response must be a JSON object",
        ))?;
    reject_forbidden_fields(&value)?;
    validate_optional_identity(object, "model", proposal.model.model_id())?;
    if let Some(revision) = object
        .get("model_revision")
        .or_else(|| object.get("revision"))
    {
        let revision = revision
            .as_str()
            .ok_or(HuggingFaceInferenceError::MalformedResponse(
                "model revision field must be text",
            ))?;
        if revision != proposal.model.immutable_revision() {
            return Err(HuggingFaceInferenceError::ModelRevisionDrift);
        }
    }
    if let Some(provider) = object.get("provider") {
        let provider = provider
            .as_str()
            .ok_or(HuggingFaceInferenceError::MalformedResponse(
                "provider field must be text",
            ))?;
        if provider != proposal.provider_route.provider_id() {
            return Err(HuggingFaceInferenceError::ProviderRouteMismatch);
        }
    }
    match proposal.task {
        crate::model::InferenceTask::ChatCompletion => parse_chat(object, redaction),
        crate::model::InferenceTask::TextGeneration => parse_text_generation(object, redaction),
    }
}

fn validate_optional_identity(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), HuggingFaceInferenceError> {
    if let Some(value) = object.get(key) {
        let actual = value
            .as_str()
            .ok_or(HuggingFaceInferenceError::MalformedResponse(
                "identity field must be text",
            ))?;
        if actual != expected {
            return Err(HuggingFaceInferenceError::ModelMismatch);
        }
    }
    Ok(())
}

fn reject_forbidden_fields(value: &Value) -> Result<(), HuggingFaceInferenceError> {
    match value {
        Value::Object(object) => {
            for key in object.keys() {
                if matches!(
                    key.as_str(),
                    "tool_calls"
                        | "tool_call"
                        | "tools"
                        | "tool_choice"
                        | "function_call"
                        | "function"
                        | "reasoning"
                        | "reasoning_content"
                        | "thinking"
                ) {
                    return Err(HuggingFaceInferenceError::ToolCallsForbidden);
                }
            }
            for child in object.values() {
                reject_forbidden_fields(child)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_forbidden_fields(child)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn parse_chat(
    object: &serde_json::Map<String, Value>,
    redaction: crate::model::OutputRedactionPolicy,
) -> Result<SuccessProjection, HuggingFaceInferenceError> {
    let choices = object.get("choices").and_then(Value::as_array).ok_or(
        HuggingFaceInferenceError::MalformedResponse("chat response choices are missing"),
    )?;
    if choices.len() != 1 {
        return Err(HuggingFaceInferenceError::MalformedResponse(
            "Layer-1 accepts exactly one chat choice",
        ));
    }
    let choice = choices[0]
        .as_object()
        .ok_or(HuggingFaceInferenceError::MalformedResponse(
            "chat choice is not an object",
        ))?;
    let message = choice.get("message").and_then(Value::as_object).ok_or(
        HuggingFaceInferenceError::MalformedResponse("chat message is missing"),
    )?;
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err(HuggingFaceInferenceError::MalformedResponse(
            "chat result role must be assistant",
        ));
    }
    let content = message.get("content").and_then(Value::as_str).ok_or(
        HuggingFaceInferenceError::MalformedResponse("chat result content must be text"),
    )?;
    let finish_reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .ok_or(HuggingFaceInferenceError::MalformedResponse(
            "chat finish reason is missing",
        ))
        .and_then(|reason| {
            FinishReason::parse(reason).ok_or(HuggingFaceInferenceError::MalformedResponse(
                "chat finish reason is not allowlisted",
            ))
        })?;
    let usage = parse_chat_usage(object.get("usage"))?;
    Ok(SuccessProjection {
        content: RedactedContent::from_text(content, redaction),
        usage,
        finish_reason: Some(finish_reason),
    })
}

fn parse_chat_usage(
    value: Option<&Value>,
) -> Result<Option<UsageProjection>, HuggingFaceInferenceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(HuggingFaceInferenceError::MalformedResponse(
            "usage must be an object",
        ))?;
    let prompt = required_u64(object, "prompt_tokens")?;
    let completion = required_u64(object, "completion_tokens")?;
    let total = required_u64(object, "total_tokens")?;
    UsageProjection::new(prompt, completion, total).map(Some)
}

fn parse_text_generation(
    object: &serde_json::Map<String, Value>,
    redaction: crate::model::OutputRedactionPolicy,
) -> Result<SuccessProjection, HuggingFaceInferenceError> {
    let content = object.get("generated_text").and_then(Value::as_str).ok_or(
        HuggingFaceInferenceError::MalformedResponse(
            "text-generation generated_text is missing or not text",
        ),
    )?;
    let details = object.get("details");
    let (usage, finish_reason) = if let Some(details) = details {
        let details = details
            .as_object()
            .ok_or(HuggingFaceInferenceError::MalformedResponse(
                "text-generation details must be an object",
            ))?;
        let finish_reason = details
            .get("finish_reason")
            .and_then(Value::as_str)
            .map(|reason| {
                FinishReason::parse(reason).ok_or(HuggingFaceInferenceError::MalformedResponse(
                    "text-generation finish reason is not allowlisted",
                ))
            })
            .transpose()?;
        let has_input = details.contains_key("input_length");
        let has_generated = details.contains_key("generated_tokens");
        let usage = match (has_input, has_generated) {
            (false, false) => None,
            (true, true) => Some(UsageProjection::new(
                required_u64(details, "input_length")?,
                required_u64(details, "generated_tokens")?,
                required_u64(details, "input_length")?
                    .saturating_add(required_u64(details, "generated_tokens")?),
            )?),
            _ => {
                return Err(HuggingFaceInferenceError::MalformedResponse(
                    "text-generation usage is partial",
                ));
            }
        };
        (usage, finish_reason)
    } else {
        (None, None)
    };
    Ok(SuccessProjection {
        content: RedactedContent::from_text(content, redaction),
        usage,
        finish_reason,
    })
}

fn required_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u64, HuggingFaceInferenceError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(HuggingFaceInferenceError::MalformedResponse(
            "numeric response field is missing or invalid",
        ))
}

fn failure_for_status(
    status: u16,
) -> Result<(ProviderFailureClass, bool), HuggingFaceInferenceError> {
    let result = match status {
        401 => (ProviderFailureClass::Unauthorized, false),
        403 => (ProviderFailureClass::Forbidden, false),
        404 => (ProviderFailureClass::NotFound, false),
        409 => (ProviderFailureClass::Conflict, false),
        429 => (ProviderFailureClass::RateLimited, true),
        408 | 504 => (ProviderFailureClass::Timeout, true),
        500..=599 => (ProviderFailureClass::ServerError, true),
        _ => return Err(HuggingFaceInferenceError::UnsupportedStatus(status)),
    };
    Ok(result)
}

fn error_evidence(
    mode: ProviderMode,
    recording_key: crate::model::Digest,
    proposal: &InferenceResultProposal,
    response_digest: crate::model::Digest,
    latency_ms: u64,
    class: ProviderFailureClass,
    status: Option<(u16, bool, crate::model::Digest)>,
) -> InferenceResultEvidence {
    let (http_status, retryable, error_digest) = status.map_or(
        (
            None,
            matches!(
                class,
                ProviderFailureClass::Timeout
                    | ProviderFailureClass::RateLimited
                    | ProviderFailureClass::ServerError
                    | ProviderFailureClass::TransportUnavailable
            ),
            response_digest.clone(),
        ),
        |(status, retryable, digest)| (Some(status), retryable, digest),
    );
    InferenceResultEvidence::new(
        mode,
        recording_key,
        proposal,
        response_digest,
        None,
        None,
        latency_ms,
        None,
        EvidenceDisposition::RecordedProviderError,
        Some(ProviderErrorProjection {
            class,
            http_status,
            retryable,
            error_digest,
        }),
    )
}

/// No code path in this Layer-1 provider invokes a native transport.
pub const fn native_execution_available() -> bool {
    false
}

/// Stable provider identity used in registration and diagnostics.
pub const fn provider_identity() -> &'static str {
    HUGGINGFACE_INFERENCE_PROVIDER_ID
}
