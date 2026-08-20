//! Recording-only Cohere provider boundary and response projection.

use std::fmt;

use serde_json::{Map, Value};

use crate::{
    COHERE_INFERENCE_PROVIDER_ID, digest_bytes, digest_serializable,
    model::{
        CohereInferenceError, CohereInferenceScope, ContentKind, EmbeddingProjection,
        EvidenceDisposition, FinishReason, InferencePolicy, InferenceResultEvidence,
        InferenceResultProposal, InferenceResultState, MAX_EMBEDDING_DIMENSIONS,
        MAX_IDENTIFIER_BYTES, MAX_ITEMS, ProviderErrorProjection, ProviderFailureClass,
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
    pub const fn as_str(self) -> &'static str {
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
    Http {
        status: u16,
        body: Vec<u8>,
    },
    Lifecycle {
        state: InferenceResultState,
        body: Vec<u8>,
    },
    Timeout,
    TransportUnavailable,
    BlockedEnv {
        code: BlockedEnvCode,
    },
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
            Self::Lifecycle { state, body } => formatter
                .debug_struct("Lifecycle")
                .field("state", state)
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

/// Host-provided recording envelope. It is intentionally not serializable;
/// its Debug implementation exposes only bounded metadata and digests.
#[derive(Clone)]
pub struct RecordedCohereResponse {
    recording_id: String,
    provider_id: String,
    model_id: String,
    model_revision: String,
    request_revision: Option<u64>,
    provider_digest: Option<crate::model::Digest>,
    result_revision: u64,
    latency_ms: u64,
    outcome: ProviderResponseOutcome,
}

pub type RecordedProviderResponse = RecordedCohereResponse;

impl RecordedCohereResponse {
    pub fn new(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            model_revision: model_revision.into(),
            request_revision: None,
            provider_digest: None,
            result_revision: 1,
            latency_ms,
            outcome: ProviderResponseOutcome::Http {
                status: 200,
                body: body.into(),
            },
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
            body,
            latency_ms,
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
        let mut response = Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            body,
            latency_ms,
        );
        if let ProviderResponseOutcome::Http { body, .. } = response.outcome {
            response.outcome = ProviderResponseOutcome::Http { status, body };
        }
        response
    }

    pub fn lifecycle(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        state: InferenceResultState,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        let mut response = Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            Vec::new(),
            latency_ms,
        );
        response.outcome = ProviderResponseOutcome::Lifecycle {
            state,
            body: body.into(),
        };
        response
    }

    pub fn timeout(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        let mut response = Self::new(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            Vec::new(),
            latency_ms,
        );
        response.outcome = ProviderResponseOutcome::Timeout;
        response
    }

    pub fn transport_unavailable(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        let mut response = Self::timeout(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
        );
        response.outcome = ProviderResponseOutcome::TransportUnavailable;
        response
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_revision: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        let mut response = Self::timeout(
            recording_id,
            provider_id,
            model_id,
            model_revision,
            latency_ms,
        );
        response.outcome = ProviderResponseOutcome::BlockedEnv { code };
        response
    }

    pub fn with_request_revision(mut self, request_revision: u64) -> Self {
        self.request_revision = Some(request_revision);
        self
    }

    pub fn with_provider_digest(mut self, provider_digest: crate::model::Digest) -> Self {
        self.provider_digest = Some(provider_digest);
        self
    }

    pub fn with_result_revision(mut self, result_revision: u64) -> Self {
        self.result_revision = result_revision;
        self
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

    pub fn request_revision(&self) -> Option<u64> {
        self.request_revision
    }

    pub fn provider_digest(&self) -> Option<&crate::model::Digest> {
        self.provider_digest.as_ref()
    }

    pub const fn result_revision(&self) -> u64 {
        self.result_revision
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub fn outcome(&self) -> &ProviderResponseOutcome {
        &self.outcome
    }
}

impl fmt::Debug for RecordedCohereResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedCohereResponse")
            .field("recording_key", &recording_key(&self.recording_id))
            .field("provider_id", &self.provider_id)
            .field("model_id", &self.model_id)
            .field("model_revision", &self.model_revision)
            .field("request_revision", &self.request_revision)
            .field("provider_digest", &self.provider_digest)
            .field("result_revision", &self.result_revision)
            .field("latency_ms", &self.latency_ms)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CohereProvider {
    mode: ProviderMode,
    max_response_bytes: usize,
}

impl CohereProvider {
    pub fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            max_response_bytes: DEFAULT_PROVIDER_RESPONSE_BYTES,
        }
    }

    pub fn fixture() -> Self {
        Self::new(ProviderMode::Fixture)
    }

    pub fn recording() -> Self {
        Self::new(ProviderMode::Recording)
    }

    pub fn fake() -> Self {
        Self::new(ProviderMode::Fake)
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
    ) -> Result<Self, CohereInferenceError> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(CohereInferenceError::InvalidField {
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

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn describe_model(&self, scope: &CohereInferenceScope) -> crate::model::ModelDescription {
        crate::model::ModelDescription::from_scope(scope)
    }

    pub fn record(
        &self,
        proposal: &InferenceResultProposal,
        response: &RecordedCohereResponse,
        policy: &InferencePolicy,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        validate_recording_identity(proposal, response)?;
        if response.result_revision == 0 {
            return Err(CohereInferenceError::ResultRevisionMismatch);
        }
        let recording_key = recording_key(response.recording_id());
        match &response.outcome {
            ProviderResponseOutcome::Timeout => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                digest_bytes(b"cohere-timeout"),
                response.latency_ms,
                InferenceResultState::Timeout,
                ProviderFailureClass::Timeout,
                None,
            )),
            ProviderResponseOutcome::TransportUnavailable => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                digest_bytes(b"cohere-transport-unavailable"),
                response.latency_ms,
                InferenceResultState::ProviderUnknown,
                ProviderFailureClass::TransportUnavailable,
                None,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => {
                if self.mode != ProviderMode::BlockedEnv {
                    return Err(CohereInferenceError::BlockedEnvironment(
                        "blocked-environment frame requires BLOCKED_ENV provider mode",
                    ));
                }
                let response_digest = digest_bytes(code.as_str().as_bytes());
                Ok(InferenceResultEvidence::new(
                    self.mode,
                    recording_key,
                    proposal,
                    response.result_revision,
                    response_digest.clone(),
                    None,
                    None,
                    None,
                    response.latency_ms,
                    None,
                    InferenceResultState::ProviderUnknown,
                    EvidenceDisposition::BlockedEnv,
                    Some(ProviderErrorProjection {
                        class: ProviderFailureClass::TransportUnavailable,
                        http_status: None,
                        retryable: true,
                        error_digest: response_digest,
                    }),
                ))
            }
            ProviderResponseOutcome::Lifecycle { state, body } => {
                self.record_lifecycle(proposal, response, *state, body, policy, recording_key)
            }
            ProviderResponseOutcome::Http { status, body } => {
                if body.len() > self.max_response_bytes || body.len() > policy.max_response_bytes()
                {
                    return Err(CohereInferenceError::ResponseTruncated);
                }
                let response_digest = digest_bytes(body);
                if (200..300).contains(status) {
                    if self.mode == ProviderMode::BlockedEnv {
                        return Err(CohereInferenceError::BlockedEnvironment(
                            "BLOCKED_ENV cannot assert a successful provider response",
                        ));
                    }
                    let state = state_from_body(body)?;
                    self.record_lifecycle(proposal, response, state, body, policy, recording_key)
                } else {
                    let (class, retryable, state) = failure_for_status(*status)?;
                    Ok(error_evidence(
                        self.mode,
                        recording_key,
                        proposal,
                        response.result_revision,
                        response_digest,
                        response.latency_ms,
                        state,
                        class,
                        Some((*status, retryable)),
                    ))
                }
            }
        }
    }

    fn record_lifecycle(
        &self,
        proposal: &InferenceResultProposal,
        response: &RecordedCohereResponse,
        state: InferenceResultState,
        body: &[u8],
        policy: &InferencePolicy,
        recording_key: crate::model::Digest,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        if body.len() > self.max_response_bytes || body.len() > policy.max_response_bytes() {
            return Err(CohereInferenceError::ResponseTruncated);
        }
        let response_digest = digest_bytes(body);
        match state {
            InferenceResultState::Submitted
            | InferenceResultState::Queued
            | InferenceResultState::Running
            | InferenceResultState::Expired
            | InferenceResultState::ProviderUnknown => Ok(InferenceResultEvidence::new(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                response_digest,
                None,
                None,
                None,
                response.latency_ms,
                None,
                state,
                EvidenceDisposition::RecordedProviderError,
                None,
            )),
            InferenceResultState::Failed => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                response_digest,
                response.latency_ms,
                InferenceResultState::Failed,
                ProviderFailureClass::UnexpectedStatus,
                None,
            )),
            InferenceResultState::Timeout => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                response_digest,
                response.latency_ms,
                InferenceResultState::Timeout,
                ProviderFailureClass::Timeout,
                None,
            )),
            InferenceResultState::Completed | InferenceResultState::Partial => {
                let projection = parse_success(
                    proposal,
                    body,
                    policy,
                    state == InferenceResultState::Partial,
                )?;
                Ok(InferenceResultEvidence::new(
                    self.mode,
                    recording_key,
                    proposal,
                    response.result_revision,
                    response_digest,
                    projection.content,
                    projection.embedding,
                    projection.usage,
                    response.latency_ms,
                    projection.finish_reason,
                    state,
                    if state == InferenceResultState::Partial {
                        EvidenceDisposition::RecordedPartial
                    } else {
                        EvidenceDisposition::RecordedSuccess
                    },
                    None,
                ))
            }
        }
    }
}

fn validate_recording_identity(
    proposal: &InferenceResultProposal,
    response: &RecordedCohereResponse,
) -> Result<(), CohereInferenceError> {
    proposal.verify_integrity()?;
    validate_bounded_text(response.recording_id(), "recording_id")?;
    if response.provider_id != proposal.provider_route.provider_id() {
        return Err(CohereInferenceError::ProviderRouteMismatch);
    }
    if response.model_id != proposal.model.model_id() {
        return Err(CohereInferenceError::ModelMismatch);
    }
    if response.model_revision != proposal.model.immutable_revision() {
        return Err(CohereInferenceError::ModelRevisionDrift);
    }
    if response
        .request_revision
        .is_some_and(|revision| revision != proposal.request.request_revision)
    {
        return Err(CohereInferenceError::RequestRevisionMismatch);
    }
    if response
        .provider_digest
        .as_ref()
        .is_some_and(|digest| digest != &proposal.provider_digest)
    {
        return Err(CohereInferenceError::ProviderRouteMismatch);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, field: &'static str) -> Result<(), CohereInferenceError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CohereInferenceError::InvalidField {
            field,
            reason: "must be a bounded non-empty text value",
        });
    }
    Ok(())
}

fn recording_key(recording_id: &str) -> crate::model::Digest {
    digest_serializable(&("hartevo:cohere-recording:v1", recording_id))
}

struct SuccessProjection {
    content: Option<RedactedContent>,
    embedding: Option<EmbeddingProjection>,
    usage: Option<UsageProjection>,
    finish_reason: Option<FinishReason>,
}

fn parse_success(
    proposal: &InferenceResultProposal,
    body: &[u8],
    policy: &InferencePolicy,
    allow_partial: bool,
) -> Result<SuccessProjection, CohereInferenceError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| CohereInferenceError::MalformedResponse("body is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or(CohereInferenceError::MalformedResponse(
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
            .ok_or(CohereInferenceError::MalformedResponse(
                "model revision field must be text",
            ))?;
        if revision != proposal.model.immutable_revision() {
            return Err(CohereInferenceError::ModelRevisionDrift);
        }
    }
    match proposal.task {
        crate::model::InferenceTask::Chat => parse_chat(object, allow_partial),
        crate::model::InferenceTask::Generate => parse_generate(object, allow_partial),
        crate::model::InferenceTask::Embed => parse_embeddings(object, policy),
    }
}

fn validate_optional_identity(
    object: &Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), CohereInferenceError> {
    if let Some(value) = object.get(key) {
        let actual = value
            .as_str()
            .ok_or(CohereInferenceError::MalformedResponse(
                "identity field must be text",
            ))?;
        if actual != expected {
            return Err(CohereInferenceError::ModelMismatch);
        }
    }
    Ok(())
}

fn reject_forbidden_fields(value: &Value) -> Result<(), CohereInferenceError> {
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
                        | "arguments"
                        | "tool_plan"
                        | "tool_results"
                ) {
                    return Err(CohereInferenceError::ToolCallsForbidden);
                }
                if matches!(
                    key.as_str(),
                    "file"
                        | "file_id"
                        | "file_ids"
                        | "files"
                        | "document"
                        | "documents"
                        | "attachments"
                        | "image_url"
                        | "images"
                        | "connectors"
                ) {
                    return Err(CohereInferenceError::FileAuthorityForbidden);
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
    object: &Map<String, Value>,
    allow_partial: bool,
) -> Result<SuccessProjection, CohereInferenceError> {
    let content = object
        .get("message")
        .and_then(Value::as_object)
        .and_then(|message| message.get("content"))
        .or_else(|| object.get("text"))
        .or_else(|| object.get("content"));
    let content = content
        .map(|value| redacted_text(value, ContentKind::Chat, allow_partial))
        .transpose()?;
    let finish_reason = object
        .get("finish_reason")
        .or_else(|| object.get("finishReason"))
        .and_then(Value::as_str)
        .map(|reason| {
            FinishReason::parse(reason).ok_or(CohereInferenceError::MalformedResponse(
                "chat finish reason is empty",
            ))
        })
        .transpose()?;
    if finish_reason == Some(FinishReason::ToolCalls) {
        return Err(CohereInferenceError::ToolCallsForbidden);
    }
    if !allow_partial && (content.is_none() || finish_reason.is_none()) {
        return Err(CohereInferenceError::MalformedResponse(
            "completed chat result content or finish reason is missing",
        ));
    }
    Ok(SuccessProjection {
        content,
        embedding: None,
        usage: parse_usage(object.get("usage").or_else(|| object.get("meta")))?,
        finish_reason,
    })
}

fn parse_generate(
    object: &Map<String, Value>,
    allow_partial: bool,
) -> Result<SuccessProjection, CohereInferenceError> {
    let generations = object.get("generations").and_then(Value::as_array);
    let Some(generations) = generations else {
        if allow_partial {
            return Ok(SuccessProjection {
                content: None,
                embedding: None,
                usage: parse_usage(object.get("meta").or_else(|| object.get("usage")))?,
                finish_reason: None,
            });
        }
        return Err(CohereInferenceError::MalformedResponse(
            "generate response generations are missing",
        ));
    };
    if generations.len() != 1 {
        return Err(CohereInferenceError::MalformedResponse(
            "Layer-1 accepts exactly one generation",
        ));
    }
    let generation = generations[0]
        .as_object()
        .ok_or(CohereInferenceError::MalformedResponse(
            "generation is not an object",
        ))?;
    let content = generation
        .get("text")
        .map(|value| redacted_text(value, ContentKind::Generation, allow_partial))
        .transpose()?;
    let finish_reason = generation
        .get("finish_reason")
        .or_else(|| generation.get("finishReason"))
        .and_then(Value::as_str)
        .map(|reason| {
            FinishReason::parse(reason).ok_or(CohereInferenceError::MalformedResponse(
                "generate finish reason is empty",
            ))
        })
        .transpose()?;
    if finish_reason == Some(FinishReason::ToolCalls) {
        return Err(CohereInferenceError::ToolCallsForbidden);
    }
    if !allow_partial && (content.is_none() || finish_reason.is_none()) {
        return Err(CohereInferenceError::MalformedResponse(
            "completed generation content or finish reason is missing",
        ));
    }
    Ok(SuccessProjection {
        content,
        embedding: None,
        usage: parse_usage(object.get("meta").or_else(|| object.get("usage")))?,
        finish_reason,
    })
}

fn redacted_text(
    value: &Value,
    kind: ContentKind,
    allow_partial: bool,
) -> Result<RedactedContent, CohereInferenceError> {
    match value {
        Value::String(text) => {
            if text.is_empty() && !allow_partial {
                return Err(CohereInferenceError::MalformedResponse(
                    "completed text content is empty",
                ));
            }
            RedactedContent::new(text.as_bytes(), 1, kind)
        }
        Value::Array(parts) => {
            if parts.is_empty() || parts.len() > MAX_ITEMS {
                return Err(CohereInferenceError::MalformedResponse(
                    "text content parts are outside the bounded limit",
                ));
            }
            let mut bytes = Vec::new();
            for part in parts {
                let object = part
                    .as_object()
                    .ok_or(CohereInferenceError::MalformedResponse(
                        "text content part is not an object",
                    ))?;
                let part_type = object.get("type").and_then(Value::as_str).unwrap_or("text");
                if part_type != "text" {
                    return Err(CohereInferenceError::ToolCallsForbidden);
                }
                let text = object.get("text").and_then(Value::as_str).ok_or(
                    CohereInferenceError::MalformedResponse("text content part is missing text"),
                )?;
                bytes.extend_from_slice(text.as_bytes());
            }
            if bytes.is_empty() && !allow_partial {
                return Err(CohereInferenceError::MalformedResponse(
                    "completed text content is empty",
                ));
            }
            RedactedContent::new(&bytes, parts.len(), kind)
        }
        Value::Object(object) => object
            .get("text")
            .ok_or(CohereInferenceError::MalformedResponse(
                "text content object is missing text",
            ))
            .and_then(|text| redacted_text(text, kind, allow_partial)),
        _ => Err(CohereInferenceError::MalformedResponse(
            "text content must be text or bounded text blocks",
        )),
    }
}

fn parse_embeddings(
    object: &Map<String, Value>,
    policy: &InferencePolicy,
) -> Result<SuccessProjection, CohereInferenceError> {
    let embeddings = object
        .get("embeddings")
        .ok_or(CohereInferenceError::MalformedResponse(
            "embedding values are missing",
        ))?;
    let vectors = embeddings
        .as_object()
        .and_then(|value| value.get("float").or_else(|| value.get("float32")))
        .or(Some(embeddings))
        .and_then(Value::as_array)
        .ok_or(CohereInferenceError::MalformedResponse(
            "embedding values must be a vector array",
        ))?;
    if vectors.is_empty() || vectors.len() > policy.max_items().min(MAX_ITEMS) {
        return Err(CohereInferenceError::MalformedResponse(
            "embedding item count is outside the bounded limit",
        ));
    }
    let mut dimensions = None;
    for vector in vectors {
        let vector = vector
            .as_array()
            .ok_or(CohereInferenceError::MalformedResponse(
                "embedding vector is not an array",
            ))?;
        if vector.is_empty()
            || vector.len()
                > policy
                    .max_embedding_dimensions()
                    .min(MAX_EMBEDDING_DIMENSIONS)
        {
            return Err(CohereInferenceError::MalformedResponse(
                "embedding dimensions are outside the bounded limit",
            ));
        }
        if vector.iter().any(|value| !value.is_number()) {
            return Err(CohereInferenceError::MalformedResponse(
                "embedding vector contains a non-numeric value",
            ));
        }
        if dimensions.is_some_and(|expected| expected != vector.len()) {
            return Err(CohereInferenceError::MalformedResponse(
                "embedding dimensions are inconsistent",
            ));
        }
        dimensions = Some(vector.len());
    }
    let dimensions = dimensions.ok_or(CohereInferenceError::MalformedResponse(
        "embedding dimensions are missing",
    ))?;
    Ok(SuccessProjection {
        content: None,
        embedding: Some(EmbeddingProjection {
            item_count: vectors.len(),
            dimensions,
            embedding_digest: digest_serializable(vectors),
        }),
        usage: parse_usage(object.get("meta").or_else(|| object.get("usage")))?,
        finish_reason: None,
    })
}

fn parse_usage(value: Option<&Value>) -> Result<Option<UsageProjection>, CohereInferenceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(CohereInferenceError::MalformedResponse(
            "usage metadata must be an object",
        ))?;
    let object = object
        .get("tokens")
        .or_else(|| object.get("billed_units"))
        .and_then(Value::as_object)
        .unwrap_or(object);
    let prompt = first_u64(object, &["input_tokens", "prompt_tokens"]);
    let completion = first_u64(object, &["output_tokens", "completion_tokens"]);
    let total = first_u64(object, &["total_tokens"]);
    match (prompt, completion, total) {
        (None, None, None) => Ok(None),
        (Some(prompt), Some(completion), Some(total)) => {
            UsageProjection::new(prompt, completion, total).map(Some)
        }
        (Some(prompt), Some(completion), None) => {
            UsageProjection::new(prompt, completion, prompt.saturating_add(completion)).map(Some)
        }
        _ => Err(CohereInferenceError::MalformedResponse(
            "usage input and output token fields must be paired",
        )),
    }
}

fn first_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
}

fn state_from_body(body: &[u8]) -> Result<InferenceResultState, CohereInferenceError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| CohereInferenceError::MalformedResponse("body is not valid JSON"))?;
    let Some(object) = value.as_object() else {
        return Ok(InferenceResultState::Completed);
    };
    let Some(status) = object.get("status").or_else(|| object.get("state")) else {
        return Ok(InferenceResultState::Completed);
    };
    let status = status
        .as_str()
        .ok_or(CohereInferenceError::MalformedResponse(
            "lifecycle status must be text",
        ))?
        .to_ascii_lowercase();
    Ok(match status.as_str() {
        "submitted" => InferenceResultState::Submitted,
        "queued" => InferenceResultState::Queued,
        "running" | "in_progress" => InferenceResultState::Running,
        "completed" | "complete" | "succeeded" => InferenceResultState::Completed,
        "failed" | "error" => InferenceResultState::Failed,
        "partial" | "incomplete" => InferenceResultState::Partial,
        "timeout" | "timed_out" => InferenceResultState::Timeout,
        "expired" => InferenceResultState::Expired,
        _ => InferenceResultState::ProviderUnknown,
    })
}

fn failure_for_status(
    status: u16,
) -> Result<(ProviderFailureClass, bool, InferenceResultState), CohereInferenceError> {
    let result = match status {
        400 | 413 | 422 => (
            ProviderFailureClass::InvalidRequest,
            false,
            InferenceResultState::Failed,
        ),
        401 => (
            ProviderFailureClass::Unauthorized,
            false,
            InferenceResultState::Failed,
        ),
        402 => (
            ProviderFailureClass::PaymentRequired,
            false,
            InferenceResultState::Failed,
        ),
        403 => (
            ProviderFailureClass::Forbidden,
            false,
            InferenceResultState::Failed,
        ),
        404 => (
            ProviderFailureClass::NotFound,
            false,
            InferenceResultState::Failed,
        ),
        408 | 504 => (
            ProviderFailureClass::Timeout,
            true,
            InferenceResultState::Timeout,
        ),
        409 => (
            ProviderFailureClass::Conflict,
            false,
            InferenceResultState::Failed,
        ),
        429 => (
            ProviderFailureClass::RateLimited,
            true,
            InferenceResultState::Failed,
        ),
        500..=599 => (
            ProviderFailureClass::ServerError,
            true,
            InferenceResultState::Failed,
        ),
        _ => return Err(CohereInferenceError::UnsupportedStatus(status)),
    };
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn error_evidence(
    mode: ProviderMode,
    recording_key: crate::model::Digest,
    proposal: &InferenceResultProposal,
    result_revision: u64,
    response_digest: crate::model::Digest,
    latency_ms: u64,
    state: InferenceResultState,
    class: ProviderFailureClass,
    status: Option<(u16, bool)>,
) -> InferenceResultEvidence {
    let (http_status, retryable) = status.map_or(
        (
            None,
            matches!(
                class,
                ProviderFailureClass::Timeout
                    | ProviderFailureClass::RateLimited
                    | ProviderFailureClass::ServerError
                    | ProviderFailureClass::TransportUnavailable
            ),
        ),
        |(status, retryable)| (Some(status), retryable),
    );
    InferenceResultEvidence::new(
        mode,
        recording_key,
        proposal,
        result_revision,
        response_digest.clone(),
        None,
        None,
        None,
        latency_ms,
        None,
        state,
        EvidenceDisposition::RecordedProviderError,
        Some(ProviderErrorProjection {
            class,
            http_status,
            retryable,
            error_digest: response_digest,
        }),
    )
}

/// No code path in this Layer-1 provider invokes a native transport.
pub const fn native_execution_available() -> bool {
    false
}

pub const fn provider_identity() -> &'static str {
    COHERE_INFERENCE_PROVIDER_ID
}
