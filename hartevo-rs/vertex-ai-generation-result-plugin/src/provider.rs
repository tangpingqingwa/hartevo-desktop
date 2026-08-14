//! Non-native provider seam for recorded Vertex AI response frames.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    VERTEX_AI_GENERATION_PROVIDER_ID, digest_bytes, digest_serializable,
    model::{
        CandidateSummary, FinishReason, GenerationResultEvidence, GenerationResultProposal,
        PromptFeedback, ProviderErrorProjection, ProviderFailureClass, ProviderMode, ResponseState,
        SafetyBlockReason, SafetyCategory, SafetyProbability, SafetyRating, SafetySeverity,
        UsageMetadata, VertexAiCandidate, VertexAiGenerationError, VertexAiResponse,
    },
};

pub const DEFAULT_PROVIDER_RESPONSE_BYTES: usize = crate::model::MAX_RESPONSE_BYTES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvCode {
    CredentialResolutionUnavailable,
    NativeTransportUnavailable,
    ConsentRequired,
    RegionalEndpointUnavailable,
}

impl BlockedEnvCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CredentialResolutionUnavailable => "credential_resolution_unavailable",
            Self::NativeTransportUnavailable => "native_transport_unavailable",
            Self::ConsentRequired => "consent_required",
            Self::RegionalEndpointUnavailable => "regional_endpoint_unavailable",
        }
    }
}

#[derive(Clone, Debug)]
pub enum VertexAiResponseFrame {
    Parsed(VertexAiResponse),
    Malformed,
    Oversized,
    ErrorBody,
}

#[derive(Clone, Debug)]
pub enum ProviderResponseOutcome {
    Http {
        status: u16,
        body_bytes: usize,
        response_digest: crate::model::Digest,
        frame: VertexAiResponseFrame,
    },
    Timeout,
    Cancelled,
    Expired,
    AccessLost,
    TransportUnavailable,
    BlockedEnv {
        code: BlockedEnvCode,
    },
}

/// A recording frame never retains its raw HTTP body. Successful JSON is
/// parsed immediately into typed metadata and only its digest/size is kept.
#[derive(Clone)]
pub struct RecordedVertexAiResponse {
    recording_id: String,
    provider_id: String,
    google_cloud_project_id: String,
    location: String,
    publisher: String,
    model_id: String,
    model_snapshot: String,
    latency_ms: u64,
    outcome: ProviderResponseOutcome,
}

pub type RecordedProviderResponse = RecordedVertexAiResponse;

impl fmt::Debug for RecordedVertexAiResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedVertexAiResponse")
            .field("recording_id", &self.recording_id)
            .field("provider_id", &self.provider_id)
            .field("google_cloud_project_id", &self.google_cloud_project_id)
            .field("location", &self.location)
            .field("publisher", &self.publisher)
            .field("model_id", &self.model_id)
            .field("model_snapshot", &self.model_snapshot)
            .field("latency_ms", &self.latency_ms)
            .field("outcome", &self.outcome)
            .finish()
    }
}

impl RecordedVertexAiResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
        outcome: ProviderResponseOutcome,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            google_cloud_project_id: google_cloud_project_id.into(),
            location: location.into(),
            publisher: publisher.into(),
            model_id: model_id.into(),
            model_snapshot: model_snapshot.into(),
            latency_ms,
            outcome,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn success(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        body: impl AsRef<[u8]>,
        latency_ms: u64,
    ) -> Self {
        let body = body.as_ref();
        let frame = if body.len() > DEFAULT_PROVIDER_RESPONSE_BYTES {
            VertexAiResponseFrame::Oversized
        } else {
            match VertexAiResponse::from_json(body) {
                Ok(response) => VertexAiResponseFrame::Parsed(response),
                Err(_) => VertexAiResponseFrame::Malformed,
            }
        };
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Http {
                status: 200,
                body_bytes: body.len(),
                response_digest: digest_bytes(body),
                frame,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn http_error(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        status: u16,
        body: impl AsRef<[u8]>,
        latency_ms: u64,
    ) -> Self {
        let body = body.as_ref();
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Http {
                status,
                body_bytes: body.len(),
                response_digest: digest_bytes(body),
                frame: VertexAiResponseFrame::ErrorBody,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_response(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        response: VertexAiResponse,
        latency_ms: u64,
    ) -> Self {
        let response_digest = response.response_digest();
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Http {
                status: 200,
                body_bytes: 0,
                response_digest,
                frame: VertexAiResponseFrame::Parsed(response),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn timeout(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Timeout,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancelled(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Cancelled,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn expired(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Expired,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn access_lost(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::AccessLost,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn blocked_env(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        google_cloud_project_id: impl Into<String>,
        location: impl Into<String>,
        publisher: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            google_cloud_project_id,
            location,
            publisher,
            model_id,
            model_snapshot,
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

    pub fn google_cloud_project_id(&self) -> &str {
        &self.google_cloud_project_id
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn model_snapshot(&self) -> &str {
        &self.model_snapshot
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub fn outcome(&self) -> &ProviderResponseOutcome {
        &self.outcome
    }
}

#[derive(Clone, Debug)]
pub struct VertexAiGenerationProvider {
    mode: ProviderMode,
    max_response_bytes: usize,
}

impl VertexAiGenerationProvider {
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

    pub fn loopback() -> Self {
        Self::new(ProviderMode::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderMode::BlockedEnv)
    }

    pub fn with_response_bound(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(VertexAiGenerationError::InvalidField {
                field: "max_response_bytes",
                reason: "must be positive and within the Layer-1 response ceiling",
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
        scope: &crate::model::VertexAiGenerationScope,
    ) -> crate::model::ModelDescription {
        crate::model::ModelDescription::from_scope(scope)
    }

    pub fn record(
        &self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
        redaction: crate::model::RedactionPolicy,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.record_inner(proposal, response, redaction, None)
    }

    pub fn record_scoped(
        &self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
        redaction: crate::model::RedactionPolicy,
        scope: &crate::model::VertexAiGenerationScope,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.record_inner(proposal, response, redaction, Some(scope))
    }

    fn record_inner(
        &self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
        redaction: crate::model::RedactionPolicy,
        scope: Option<&crate::model::VertexAiGenerationScope>,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        proposal.verify_integrity()?;
        validate_recording_identity(proposal, response)?;
        match &response.outcome {
            ProviderResponseOutcome::Http {
                status,
                body_bytes,
                response_digest,
                frame,
            } => {
                if *body_bytes > self.max_response_bytes {
                    return Err(VertexAiGenerationError::ResponseTooLarge);
                }
                if (200..300).contains(status) {
                    if self.mode == ProviderMode::BlockedEnv {
                        return Err(VertexAiGenerationError::BlockedEnvironment(
                            "BLOCKED_ENV cannot assert a successful provider response",
                        ));
                    }
                    let VertexAiResponseFrame::Parsed(parsed) = frame else {
                        return Err(VertexAiGenerationError::MalformedResponse(
                            "successful response frame is not a complete typed response",
                        ));
                    };
                    validate_response(scope, proposal, parsed)?;
                    let candidates = parsed
                        .candidates
                        .iter()
                        .map(CandidateSummary::from)
                        .collect::<Vec<_>>();
                    Ok(GenerationResultEvidence::new(
                        self.mode,
                        proposal,
                        Some(parsed.response_id.clone()),
                        Some(parsed.model_version.clone()),
                        response_digest.clone(),
                        parsed.output_digest(),
                        candidates,
                        parsed.prompt_feedback.clone(),
                        parsed.usage_metadata.clone(),
                        parsed.state(),
                        None,
                        redaction,
                    ))
                } else {
                    let (state, class, retryable) = failure_for_status(*status)?;
                    Ok(error_evidence(
                        self.mode,
                        proposal,
                        response_digest.clone(),
                        state,
                        class,
                        retryable,
                        Some(*status),
                        redaction,
                    ))
                }
            }
            ProviderResponseOutcome::Timeout => Ok(error_evidence(
                self.mode,
                proposal,
                digest_bytes(b"vertex-ai-timeout"),
                ResponseState::Expired,
                ProviderFailureClass::Timeout,
                true,
                None,
                redaction,
            )),
            ProviderResponseOutcome::Cancelled => Ok(error_evidence(
                self.mode,
                proposal,
                digest_bytes(b"vertex-ai-cancelled"),
                ResponseState::Cancelled,
                ProviderFailureClass::Cancelled,
                false,
                None,
                redaction,
            )),
            ProviderResponseOutcome::Expired => Ok(error_evidence(
                self.mode,
                proposal,
                digest_bytes(b"vertex-ai-expired"),
                ResponseState::Expired,
                ProviderFailureClass::Expired,
                true,
                None,
                redaction,
            )),
            ProviderResponseOutcome::AccessLost => Ok(error_evidence(
                self.mode,
                proposal,
                digest_bytes(b"vertex-ai-access-lost"),
                ResponseState::AccessLost,
                ProviderFailureClass::Unauthorized,
                false,
                None,
                redaction,
            )),
            ProviderResponseOutcome::TransportUnavailable => Ok(error_evidence(
                self.mode,
                proposal,
                digest_bytes(b"vertex-ai-transport-unavailable"),
                ResponseState::ProviderUnknown,
                ProviderFailureClass::TransportUnavailable,
                true,
                None,
                redaction,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => {
                if self.mode != ProviderMode::BlockedEnv {
                    return Err(VertexAiGenerationError::BlockedEnvironment(
                        "BLOCKED_ENV frame requires BLOCKED_ENV provider mode",
                    ));
                }
                let response_digest = digest_serializable(&("vertex-ai-blocked-env/v1", code));
                Ok(error_evidence(
                    self.mode,
                    proposal,
                    response_digest,
                    ResponseState::ProviderUnknown,
                    ProviderFailureClass::TransportUnavailable,
                    true,
                    None,
                    redaction,
                ))
            }
        }
    }
}

fn validate_recording_identity(
    proposal: &GenerationResultProposal,
    response: &RecordedVertexAiResponse,
) -> Result<(), VertexAiGenerationError> {
    if response.recording_id.trim().is_empty()
        || response.recording_id.len() > crate::model::MAX_IDENTIFIER_BYTES
        || response.recording_id.chars().any(char::is_control)
    {
        return Err(VertexAiGenerationError::InvalidField {
            field: "recording_id",
            reason: "must be a bounded non-empty identifier",
        });
    }
    if response.provider_id != VERTEX_AI_GENERATION_PROVIDER_ID {
        return Err(VertexAiGenerationError::ProviderRouteMismatch);
    }
    if response.google_cloud_project_id != proposal.google_cloud_project.project_id() {
        return Err(VertexAiGenerationError::ProjectMismatch);
    }
    if response.location != proposal.location.as_str() {
        return Err(VertexAiGenerationError::LocationMismatch);
    }
    if response.publisher != proposal.publisher.as_str() {
        return Err(VertexAiGenerationError::PublisherMismatch);
    }
    if response.model_id != proposal.model.model_id() {
        return Err(VertexAiGenerationError::ModelMismatch);
    }
    if response.model_snapshot != proposal.model.immutable_snapshot() {
        return Err(VertexAiGenerationError::ModelSnapshotDrift);
    }
    Ok(())
}

fn validate_response(
    scope: Option<&crate::model::VertexAiGenerationScope>,
    proposal: &GenerationResultProposal,
    response: &VertexAiResponse,
) -> Result<(), VertexAiGenerationError> {
    if response.model_version != proposal.model.expected_model_version() {
        return Err(VertexAiGenerationError::ModelSnapshotDrift);
    }
    let max_candidates = scope.map_or(crate::model::MAX_CANDIDATES, |value| {
        value.response().max_candidates()
    });
    let max_output_bytes = scope.map_or(crate::model::MAX_OUTPUT_BYTES, |value| {
        value.response().max_output_bytes()
    });
    let max_output_tokens = scope.map_or(crate::model::MAX_OUTPUT_TOKENS, |value| {
        value.response().max_output_tokens()
    });
    if response.candidates.len() > max_candidates {
        return Err(VertexAiGenerationError::ResponseCandidateCountExceeded);
    }
    let output_bytes = response
        .candidates
        .iter()
        .map(|candidate| candidate.content_byte_length)
        .sum::<usize>();
    if output_bytes > max_output_bytes {
        return Err(VertexAiGenerationError::ResponseContentTooLarge);
    }
    if response
        .usage_metadata
        .as_ref()
        .is_some_and(|usage| usage.candidates_token_count > max_output_tokens as u64)
    {
        return Err(VertexAiGenerationError::OutputTokenBudgetExceeded);
    }
    if proposal.request.max_output_tokens > max_output_tokens
        || proposal.request.candidate_count > max_candidates
    {
        return Err(VertexAiGenerationError::ScopeMismatch(
            "proposal exceeds the response policy",
        ));
    }
    Ok(())
}

fn failure_for_status(
    status: u16,
) -> Result<(ResponseState, ProviderFailureClass, bool), VertexAiGenerationError> {
    let result = match status {
        400 => (
            ResponseState::Failed,
            ProviderFailureClass::InvalidRequest,
            false,
        ),
        401 => (
            ResponseState::AccessLost,
            ProviderFailureClass::Unauthorized,
            false,
        ),
        403 => (
            ResponseState::AccessLost,
            ProviderFailureClass::Forbidden,
            false,
        ),
        404 => (
            ResponseState::ProviderUnknown,
            ProviderFailureClass::NotFound,
            false,
        ),
        408 | 504 => (ResponseState::Expired, ProviderFailureClass::Timeout, true),
        409 => (ResponseState::Failed, ProviderFailureClass::Conflict, false),
        429 => (
            ResponseState::RateLimited,
            ProviderFailureClass::RateLimited,
            true,
        ),
        500..=599 => (
            ResponseState::Failed,
            ProviderFailureClass::ServerError,
            true,
        ),
        _ => return Err(VertexAiGenerationError::UnsupportedStatus(status)),
    };
    Ok(result)
}

fn error_evidence(
    mode: ProviderMode,
    proposal: &GenerationResultProposal,
    response_digest: crate::model::Digest,
    state: ResponseState,
    class: ProviderFailureClass,
    retryable: bool,
    status: Option<u16>,
    redaction: crate::model::RedactionPolicy,
) -> GenerationResultEvidence {
    GenerationResultEvidence::new(
        mode,
        proposal,
        None,
        None,
        response_digest.clone(),
        None,
        Vec::new(),
        None,
        None,
        state,
        Some(ProviderErrorProjection {
            class,
            http_status: status,
            retryable,
            error_digest: response_digest,
        }),
        redaction,
    )
}

impl VertexAiResponse {
    /// Parse a bounded GenerateContent response into metadata only. All
    /// candidate text is hashed and discarded before this method returns.
    pub fn from_json(body: impl AsRef<[u8]>) -> Result<Self, VertexAiGenerationError> {
        let body = body.as_ref();
        let value: Value = serde_json::from_slice(body)
            .map_err(|_| VertexAiGenerationError::MalformedResponse("body is not valid JSON"))?;
        reject_forbidden_fields(&value)?;
        let object = value
            .as_object()
            .ok_or(VertexAiGenerationError::MalformedResponse(
                "response must be a JSON object",
            ))?;
        let response_id = required_string(object, "responseId")?;
        let model_version = required_string(object, "modelVersion")?;
        let prompt_feedback = object
            .get("promptFeedback")
            .map(parse_prompt_feedback)
            .transpose()?;
        let candidates = object
            .get("candidates")
            .map(parse_candidates)
            .transpose()?
            .unwrap_or_default();
        let usage_metadata = object
            .get("usageMetadata")
            .map(parse_usage_metadata)
            .transpose()?;
        VertexAiResponse::new(
            response_id,
            model_version,
            candidates,
            prompt_feedback,
            usage_metadata,
        )
    }
}

fn reject_forbidden_fields(value: &Value) -> Result<(), VertexAiGenerationError> {
    match value {
        Value::Object(object) => {
            for key in object.keys() {
                if matches!(
                    key.as_str(),
                    "tools"
                        | "toolConfig"
                        | "functionCall"
                        | "functionResponse"
                        | "toolCall"
                        | "toolUse"
                        | "toolArguments"
                ) {
                    return Err(VertexAiGenerationError::ToolCallsForbidden);
                }
                if matches!(
                    key.as_str(),
                    "groundingMetadata"
                        | "groundingChunks"
                        | "groundingSupports"
                        | "searchEntryPoint"
                        | "googleSearchRetrieval"
                        | "retrieval"
                ) {
                    return Err(VertexAiGenerationError::GroundingForbidden);
                }
                if matches!(
                    key.as_str(),
                    "thought" | "thoughtSignature" | "thinking" | "reasoning" | "reasoningContent"
                ) {
                    return Err(VertexAiGenerationError::MalformedResponse(
                        "hidden reasoning is forbidden",
                    ));
                }
                if matches!(key.as_str(), "inlineData" | "fileData" | "fileBytes") {
                    return Err(VertexAiGenerationError::MalformedResponse(
                        "raw file bytes are forbidden",
                    ));
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

fn required_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<String, VertexAiGenerationError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "required response identity is missing or not text",
        ))
}

fn parse_candidates(value: &Value) -> Result<Vec<VertexAiCandidate>, VertexAiGenerationError> {
    let values = value
        .as_array()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "candidates must be an array",
        ))?;
    if values.len() > crate::model::MAX_CANDIDATES {
        return Err(VertexAiGenerationError::ResponseCandidateCountExceeded);
    }
    values
        .iter()
        .enumerate()
        .map(|(position, value)| parse_candidate(position, value))
        .collect()
}

fn parse_candidate(
    position: usize,
    value: &Value,
) -> Result<VertexAiCandidate, VertexAiGenerationError> {
    let object = value
        .as_object()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "candidate must be an object",
        ))?;
    let index = object
        .get("index")
        .and_then(Value::as_u64)
        .unwrap_or(position as u64);
    let index = u32::try_from(index).map_err(|_| {
        VertexAiGenerationError::MalformedResponse("candidate index is out of range")
    })?;
    let content = object.get("content").and_then(Value::as_object).ok_or(
        VertexAiGenerationError::MalformedResponse("candidate content is missing"),
    )?;
    if let Some(role) = content.get("role")
        && role.as_str() != Some("model")
    {
        return Err(VertexAiGenerationError::MalformedResponse(
            "candidate role must be model",
        ));
    }
    let parts = content.get("parts").and_then(Value::as_array).ok_or(
        VertexAiGenerationError::MalformedResponse("candidate content parts are missing"),
    )?;
    if parts.is_empty() {
        return Err(VertexAiGenerationError::MalformedResponse(
            "candidate content parts are empty",
        ));
    }
    let mut content_bytes = 0_usize;
    let mut digest_material = Vec::new();
    for part in parts {
        let part_object = part
            .as_object()
            .ok_or(VertexAiGenerationError::MalformedResponse(
                "candidate content part is not an object",
            ))?;
        let text = part_object.get("text").and_then(Value::as_str).ok_or(
            VertexAiGenerationError::MalformedResponse("candidate content must be text-only"),
        )?;
        if text.chars().any(char::is_control) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "candidate content contains control characters",
            ));
        }
        content_bytes = content_bytes.saturating_add(text.len());
        digest_material.extend_from_slice(&(text.len() as u64).to_be_bytes());
        digest_material.extend_from_slice(text.as_bytes());
    }
    let finish_reason = object
        .get("finishReason")
        .and_then(Value::as_str)
        .map(parse_finish_reason)
        .transpose()?
        .unwrap_or(FinishReason::Unspecified);
    let safety_ratings = object
        .get("safetyRatings")
        .map(parse_safety_ratings)
        .transpose()?
        .unwrap_or_default();
    VertexAiCandidate::new(
        index,
        digest_bytes(&digest_material),
        content_bytes,
        finish_reason,
        safety_ratings,
    )
}

fn parse_finish_reason(value: &str) -> Result<FinishReason, VertexAiGenerationError> {
    match value {
        "STOP" | "stop" => Ok(FinishReason::Stop),
        "MAX_TOKENS" | "max_tokens" => Ok(FinishReason::MaxTokens),
        "SAFETY" | "safety" => Ok(FinishReason::Safety),
        "RECITATION" | "recitation" => Ok(FinishReason::Recitation),
        "OTHER" | "other" => Ok(FinishReason::Other),
        "FINISH_REASON_UNSPECIFIED" | "unspecified" => Ok(FinishReason::Unspecified),
        _ => Err(VertexAiGenerationError::MalformedResponse(
            "finish reason is not allowlisted",
        )),
    }
}

fn parse_prompt_feedback(value: &Value) -> Result<PromptFeedback, VertexAiGenerationError> {
    let object = value
        .as_object()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "prompt feedback must be an object",
        ))?;
    let block_reason = object
        .get("blockReason")
        .map(|value| {
            value
                .as_str()
                .ok_or(VertexAiGenerationError::MalformedResponse(
                    "prompt block reason must be text",
                ))
                .and_then(parse_block_reason)
        })
        .transpose()?;
    let safety_ratings = object
        .get("safetyRatings")
        .map(parse_safety_ratings)
        .transpose()?
        .unwrap_or_default();
    PromptFeedback::new(block_reason, safety_ratings)
}

fn parse_block_reason(value: &str) -> Result<SafetyBlockReason, VertexAiGenerationError> {
    match value {
        "SAFETY" | "safety" => Ok(SafetyBlockReason::Safety),
        "PROHIBITED_CONTENT" | "prohibited_content" => Ok(SafetyBlockReason::ProhibitedContent),
        "SPII" | "spii" => Ok(SafetyBlockReason::Spii),
        "BLOCKLIST" | "blocklist" => Ok(SafetyBlockReason::Blocklist),
        "BLOCK_REASON_UNSPECIFIED" | "unspecified" => Ok(SafetyBlockReason::Unspecified),
        "OTHER" | "other" => Ok(SafetyBlockReason::Other),
        _ => Err(VertexAiGenerationError::MalformedResponse(
            "prompt block reason is not allowlisted",
        )),
    }
}

fn parse_safety_ratings(value: &Value) -> Result<Vec<SafetyRating>, VertexAiGenerationError> {
    let values = value
        .as_array()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "safety ratings must be an array",
        ))?;
    if values.len() > crate::model::MAX_SAFETY_RATINGS {
        return Err(VertexAiGenerationError::MalformedResponse(
            "too many safety ratings",
        ));
    }
    values.iter().map(parse_safety_rating).collect()
}

fn parse_safety_rating(value: &Value) -> Result<SafetyRating, VertexAiGenerationError> {
    let object = value
        .as_object()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "safety rating must be an object",
        ))?;
    let category = match required_string(object, "category")?.as_str() {
        "HARM_CATEGORY_HARASSMENT" => SafetyCategory::Harassment,
        "HARM_CATEGORY_HATE_SPEECH" => SafetyCategory::HateSpeech,
        "HARM_CATEGORY_SEXUALLY_EXPLICIT" => SafetyCategory::SexuallyExplicit,
        "HARM_CATEGORY_DANGEROUS_CONTENT" => SafetyCategory::DangerousContent,
        "HARM_CATEGORY_CIVIC_INTEGRITY" => SafetyCategory::CivicIntegrity,
        _ => {
            return Err(VertexAiGenerationError::MalformedResponse(
                "safety category is not allowlisted",
            ));
        }
    };
    let probability = parse_probability(required_string(object, "probability")?.as_str())?;
    let severity = object
        .get("severity")
        .map(|value| {
            value
                .as_str()
                .ok_or(VertexAiGenerationError::MalformedResponse(
                    "safety severity must be text",
                ))
                .and_then(parse_severity)
        })
        .transpose()?
        .unwrap_or(SafetySeverity::Unspecified);
    let blocked = object
        .get("blocked")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(SafetyRating::new(category, probability, severity, blocked))
}

fn parse_probability(value: &str) -> Result<SafetyProbability, VertexAiGenerationError> {
    match value {
        "NEGLIGIBLE" | "negligible" => Ok(SafetyProbability::Negligible),
        "LOW" | "low" => Ok(SafetyProbability::Low),
        "MEDIUM" | "medium" => Ok(SafetyProbability::Medium),
        "HIGH" | "high" => Ok(SafetyProbability::High),
        "PROBABILITY_UNSPECIFIED" | "unspecified" => Ok(SafetyProbability::Unspecified),
        _ => Err(VertexAiGenerationError::MalformedResponse(
            "safety probability is not allowlisted",
        )),
    }
}

fn parse_severity(value: &str) -> Result<SafetySeverity, VertexAiGenerationError> {
    match value {
        "NEGLIGIBLE" | "negligible" => Ok(SafetySeverity::Negligible),
        "LOW" | "low" => Ok(SafetySeverity::Low),
        "MEDIUM" | "medium" => Ok(SafetySeverity::Medium),
        "HIGH" | "high" => Ok(SafetySeverity::High),
        "SEVERITY_UNSPECIFIED" | "unspecified" => Ok(SafetySeverity::Unspecified),
        _ => Err(VertexAiGenerationError::MalformedResponse(
            "safety severity is not allowlisted",
        )),
    }
}

fn parse_usage_metadata(value: &Value) -> Result<UsageMetadata, VertexAiGenerationError> {
    let object = value
        .as_object()
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "usage metadata must be an object",
        ))?;
    let prompt = required_u64(object, "promptTokenCount")?;
    let candidates = required_u64(object, "candidatesTokenCount")?;
    let total = required_u64(object, "totalTokenCount")?;
    let cached = optional_u64(object, "cachedContentTokenCount")?;
    let thoughts = optional_u64(object, "thoughtsTokenCount")?;
    UsageMetadata::new(prompt, candidates, total, cached, thoughts)
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, VertexAiGenerationError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(VertexAiGenerationError::MalformedResponse(
            "numeric response field is missing or invalid",
        ))
}

fn optional_u64(
    object: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, VertexAiGenerationError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or(VertexAiGenerationError::MalformedResponse(
                    "optional numeric response field is invalid",
                ))
        })
        .transpose()
}

pub const fn native_execution_available() -> bool {
    false
}

pub const fn provider_identity() -> &'static str {
    VERTEX_AI_GENERATION_PROVIDER_ID
}
