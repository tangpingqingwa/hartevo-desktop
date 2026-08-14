//! Recording-only provider boundary and Anthropic response projection.

use std::fmt;

use serde_json::Value;

use crate::{
    AnthropicMessageResultError, Result,
    model::{
        AnthropicMessageResultEvidence, AnthropicMessageResultProposal, AnthropicScope,
        ContentBlockKind, ContentBlockProjection, Digest, Layer1Authority, MessagePolicy,
        ModelVersion, ProviderDefinition, ProviderErrorClass, ProviderErrorProjection,
        ProviderProvenance, RefusalCategory, RefusalProjection, ResultStatus, StopReason,
        UsageProjection,
    },
};

pub const DEFAULT_PROVIDER_RESPONSE_BYTES: usize = crate::MAX_RESPONSE_BYTES;

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

/// A borrowed response frame. The service consumes the body immediately and
/// only retains its digest and bounded projections.
#[derive(Clone)]
pub enum ProviderResponseOutcome<'a> {
    Http {
        status: u16,
        body: &'a [u8],
        provider_request_id: Option<&'a str>,
        retry_after_seconds: Option<u64>,
    },
    Timeout,
    TransportUnavailable,
    BlockedEnv {
        code: BlockedEnvCode,
    },
}

impl fmt::Debug for ProviderResponseOutcome<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http {
                status,
                body,
                provider_request_id,
                retry_after_seconds,
            } => formatter
                .debug_struct("Http")
                .field("status", status)
                .field("response_bytes", &body.len())
                .field("response_digest", &Digest::from_bytes(body))
                .field(
                    "provider_request_id_present",
                    &provider_request_id.is_some(),
                )
                .field("retry_after_seconds", retry_after_seconds)
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

/// Provider recording envelope. It intentionally does not implement
/// Serialize, and its Debug output excludes response bytes and identifiers.
#[derive(Clone)]
pub struct RecordedAnthropicResponse<'a> {
    recording_id: String,
    latency_ms: u64,
    provenance: ProviderProvenance,
    outcome: ProviderResponseOutcome<'a>,
}

impl<'a> RecordedAnthropicResponse<'a> {
    pub fn new(
        recording_id: impl Into<String>,
        latency_ms: u64,
        outcome: ProviderResponseOutcome<'a>,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            latency_ms,
            provenance: ProviderProvenance::Recording,
            outcome,
        }
    }

    pub fn success(recording_id: impl Into<String>, body: &'a [u8], latency_ms: u64) -> Self {
        Self::new(
            recording_id,
            latency_ms,
            ProviderResponseOutcome::Http {
                status: 200,
                body,
                provider_request_id: None,
                retry_after_seconds: None,
            },
        )
    }

    pub fn http(
        recording_id: impl Into<String>,
        status: u16,
        body: &'a [u8],
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            latency_ms,
            ProviderResponseOutcome::Http {
                status,
                body,
                provider_request_id: None,
                retry_after_seconds: None,
            },
        )
    }

    pub fn http_error(
        recording_id: impl Into<String>,
        status: u16,
        body: &'a [u8],
        latency_ms: u64,
    ) -> Self {
        Self::http(recording_id, status, body, latency_ms)
    }

    pub fn timeout(recording_id: impl Into<String>, latency_ms: u64) -> Self {
        Self::new(recording_id, latency_ms, ProviderResponseOutcome::Timeout)
    }

    pub fn transport_unavailable(recording_id: impl Into<String>, latency_ms: u64) -> Self {
        Self::new(
            recording_id,
            latency_ms,
            ProviderResponseOutcome::TransportUnavailable,
        )
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            latency_ms,
            ProviderResponseOutcome::BlockedEnv { code },
        )
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    #[must_use]
    pub fn with_provider_request_id(mut self, provider_request_id: &'a str) -> Self {
        if let ProviderResponseOutcome::Http {
            provider_request_id: current,
            ..
        } = &mut self.outcome
        {
            *current = Some(provider_request_id);
        }
        self
    }

    #[must_use]
    pub fn with_retry_after(mut self, retry_after_seconds: u64) -> Self {
        if let ProviderResponseOutcome::Http {
            retry_after_seconds: current,
            ..
        } = &mut self.outcome
        {
            *current = Some(retry_after_seconds);
        }
        self
    }

    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn outcome(&self) -> &ProviderResponseOutcome<'a> {
        &self.outcome
    }
}

impl fmt::Debug for RecordedAnthropicResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedAnthropicResponse")
            .field(
                "recording_id_digest",
                &Digest::from_text(&self.recording_id),
            )
            .field("latency_ms", &self.latency_ms)
            .field("provenance", &self.provenance)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct AnthropicProvider {
    mode: ProviderProvenance,
    max_response_bytes: usize,
}

impl AnthropicProvider {
    pub fn new(mode: ProviderProvenance) -> Self {
        Self {
            mode,
            max_response_bytes: DEFAULT_PROVIDER_RESPONSE_BYTES,
        }
    }

    pub fn fixture() -> Self {
        Self::new(ProviderProvenance::Fixture)
    }

    pub fn fake() -> Self {
        Self::new(ProviderProvenance::Fake)
    }

    pub fn recording() -> Self {
        Self::new(ProviderProvenance::Recording)
    }

    pub fn loopback() -> Self {
        Self::new(ProviderProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderProvenance::BlockedEnv)
    }

    pub fn with_response_bound(mut self, max_response_bytes: usize) -> Result<Self> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "max_response_bytes",
                reason: "must stay within the Layer-1 response bound",
            });
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    pub const fn mode(&self) -> ProviderProvenance {
        self.mode
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub fn definition(&self, scope: &AnthropicScope) -> ProviderDefinition {
        ProviderDefinition::for_scope(scope)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn record(
        &self,
        proposal: &AnthropicMessageResultProposal,
        response: &RecordedAnthropicResponse<'_>,
        policy: &MessagePolicy,
    ) -> Result<AnthropicMessageResultEvidence> {
        if response.latency_ms > crate::MAX_LATENCY_MS {
            return Err(AnthropicMessageResultError::LatencyInvalid);
        }
        let recording_id_digest = Digest::from_text(response.recording_id());
        match response.outcome() {
            ProviderResponseOutcome::Timeout => Ok(failure_evidence(
                proposal,
                recording_id_digest,
                response.latency_ms,
                response.provenance(),
                None,
                ProviderErrorClass::Timeout,
                None,
                0,
                None,
                None,
            )),
            ProviderResponseOutcome::TransportUnavailable => Ok(failure_evidence(
                proposal,
                recording_id_digest,
                response.latency_ms,
                response.provenance(),
                None,
                ProviderErrorClass::TransportUnavailable,
                None,
                0,
                None,
                None,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => Ok(failure_evidence(
                proposal,
                recording_id_digest,
                response.latency_ms,
                response.provenance(),
                None,
                ProviderErrorClass::BlockedEnv,
                None,
                0,
                None,
                Some(Digest::from_text(code.as_str())),
            )),
            ProviderResponseOutcome::Http {
                status,
                body,
                provider_request_id,
                retry_after_seconds,
            } => {
                let response_digest = Digest::from_bytes(body);
                if body.len() > policy.max_response_bytes || body.len() > self.max_response_bytes {
                    return Ok(failure_evidence(
                        proposal,
                        recording_id_digest,
                        response.latency_ms,
                        response.provenance(),
                        Some(response_digest),
                        ProviderErrorClass::ResponseTooLarge,
                        Some(*status),
                        body.len(),
                        None,
                        None,
                    ));
                }
                if !(200..300).contains(status) {
                    let (class, status_projection) = error_class_for_status(*status);
                    return Ok(failure_evidence(
                        proposal,
                        recording_id_digest,
                        response.latency_ms,
                        response.provenance(),
                        Some(response_digest),
                        class,
                        status_projection,
                        body.len(),
                        *retry_after_seconds,
                        None,
                    ));
                }
                match parse_success(
                    proposal,
                    recording_id_digest.clone(),
                    response.provenance(),
                    response.latency_ms,
                    *provider_request_id,
                    body,
                    response_digest.clone(),
                    policy,
                ) {
                    Ok(evidence) => Ok(evidence),
                    Err(error @ AnthropicMessageResultError::ModelVersionDrift) => Err(error),
                    Err(error) => Ok(malformed_evidence(
                        proposal,
                        recording_id_digest,
                        response.latency_ms,
                        response.provenance(),
                        response_digest,
                        body.len(),
                        &error,
                    )),
                }
            }
        }
    }
}

fn error_class_for_status(status: u16) -> (ProviderErrorClass, Option<u16>) {
    match status {
        400 => (ProviderErrorClass::BadRequest, Some(status)),
        401 => (ProviderErrorClass::Unauthorized, Some(status)),
        403 => (ProviderErrorClass::Forbidden, Some(status)),
        404 => (ProviderErrorClass::NotFound, Some(status)),
        409 => (ProviderErrorClass::Conflict, Some(status)),
        429 => (ProviderErrorClass::RateLimited, Some(status)),
        500..=599 => (ProviderErrorClass::ServerError, Some(status)),
        _ => (ProviderErrorClass::ProviderUnknown, Some(status)),
    }
}

fn base_evidence(
    proposal: &AnthropicMessageResultProposal,
    recording_id_digest: Digest,
    latency_ms: u64,
    provenance: ProviderProvenance,
    response_digest: Digest,
    response_bytes: usize,
) -> AnthropicMessageResultEvidence {
    AnthropicMessageResultEvidence {
        request_id: proposal.request_id.clone(),
        request_digest: proposal.request_digest.clone(),
        proposal_digest: proposal.proposal_digest.clone(),
        registration_digest: proposal.registration_digest.clone(),
        scope: proposal.scope.clone(),
        provider_digest: proposal.provider_digest.clone(),
        api_digest: proposal.api_digest.clone(),
        model_digest: proposal.model_digest.clone(),
        permission_digest: proposal.permission_digest.clone(),
        scope_digest: proposal.scope_digest.clone(),
        revision_digest: proposal.revision_digest.clone(),
        recording_id_digest,
        response_id_digest: None,
        response_digest,
        response_bytes,
        response_model: None,
        status: ResultStatus::ProviderError,
        stop_reason: None,
        usage: None,
        latency_ms,
        refusal: None,
        citations: Vec::new(),
        content_blocks: Vec::new(),
        content_digest: Digest::from_text("empty-anthropic-content"),
        provider_error: None,
        provenance,
        authority: Layer1Authority::layer_one(),
        evidence_digest: Digest::pending(),
    }
}

fn finish_evidence(mut evidence: AnthropicMessageResultEvidence) -> AnthropicMessageResultEvidence {
    evidence.evidence_digest = evidence.computed_digest();
    evidence
}

#[allow(clippy::too_many_arguments)]
fn failure_evidence(
    proposal: &AnthropicMessageResultProposal,
    recording_id_digest: Digest,
    latency_ms: u64,
    provenance: ProviderProvenance,
    response_digest: Option<Digest>,
    class: ProviderErrorClass,
    http_status: Option<u16>,
    response_bytes: usize,
    retry_after_seconds: Option<u64>,
    code_digest: Option<Digest>,
) -> AnthropicMessageResultEvidence {
    let response_digest = response_digest.unwrap_or_else(|| {
        Digest::from_serializable(&(class, http_status, &retry_after_seconds, &code_digest))
    });
    let status = match class {
        ProviderErrorClass::BlockedEnv => ResultStatus::BlockedEnv,
        ProviderErrorClass::ProviderUnknown => ResultStatus::ProviderUnknown,
        _ => ResultStatus::ProviderError,
    };
    finish_evidence({
        let mut evidence = base_evidence(
            proposal,
            recording_id_digest,
            latency_ms,
            provenance,
            response_digest.clone(),
            response_bytes,
        );
        evidence.status = status;
        evidence.content_digest = response_digest.clone();
        evidence.provider_error = Some(ProviderErrorProjection {
            class,
            http_status,
            retry_after_seconds,
            response_body_digest: if class == ProviderErrorClass::BlockedEnv {
                code_digest
            } else {
                Some(response_digest)
            },
        });
        evidence
    })
}

fn malformed_evidence(
    proposal: &AnthropicMessageResultProposal,
    recording_id_digest: Digest,
    latency_ms: u64,
    provenance: ProviderProvenance,
    response_digest: Digest,
    response_bytes: usize,
    error: &AnthropicMessageResultError,
) -> AnthropicMessageResultEvidence {
    let class = match error {
        AnthropicMessageResultError::PartialResponse(_) => ProviderErrorClass::PartialResponse,
        _ => ProviderErrorClass::MalformedResponse,
    };
    let mut evidence = base_evidence(
        proposal,
        recording_id_digest,
        latency_ms,
        provenance,
        response_digest.clone(),
        response_bytes,
    );
    evidence.status = ResultStatus::Partial;
    evidence.content_digest = response_digest.clone();
    evidence.provider_error = Some(ProviderErrorProjection {
        class,
        http_status: None,
        retry_after_seconds: None,
        response_body_digest: Some(response_digest),
    });
    finish_evidence(evidence)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn parse_success(
    proposal: &AnthropicMessageResultProposal,
    recording_id_digest: Digest,
    provenance: ProviderProvenance,
    latency_ms: u64,
    provider_request_id: Option<&str>,
    body: &[u8],
    response_digest: Digest,
    policy: &MessagePolicy,
) -> Result<AnthropicMessageResultEvidence> {
    let document: Value = serde_json::from_slice(body)
        .map_err(|_| AnthropicMessageResultError::MalformedResponse("JSON"))?;
    let object = document
        .as_object()
        .ok_or(AnthropicMessageResultError::MalformedResponse(
            "response root is not an object",
        ))?;
    let response_model_id = object.get("model").and_then(Value::as_str).ok_or(
        AnthropicMessageResultError::PartialResponse("response model is missing"),
    )?;
    if response_model_id != proposal.model.model_id {
        return Err(AnthropicMessageResultError::ModelVersionDrift);
    }
    let stop_reason_text = object.get("stop_reason").and_then(Value::as_str).ok_or(
        AnthropicMessageResultError::PartialResponse("stop_reason is missing"),
    )?;
    let stop_reason = stop_reason_from_text(stop_reason_text);
    let usage_value = object
        .get("usage")
        .ok_or(AnthropicMessageResultError::PartialResponse(
            "usage is missing",
        ))?;
    let usage_object =
        usage_value
            .as_object()
            .ok_or(AnthropicMessageResultError::MalformedResponse(
                "usage is not an object",
            ))?;
    let usage = UsageProjection::new(
        required_u64(usage_object, "input_tokens")?,
        required_u64(usage_object, "output_tokens")?,
        optional_u64(usage_object, "cache_creation_input_tokens")?,
        optional_u64(usage_object, "cache_read_input_tokens")?,
    )?;

    let content = object.get("content").and_then(Value::as_array).ok_or(
        AnthropicMessageResultError::PartialResponse("content is missing or not an array"),
    )?;
    if content.is_empty() {
        return Err(AnthropicMessageResultError::PartialResponse(
            "content is empty",
        ));
    }
    if content.len() > policy.max_content_blocks {
        return Err(AnthropicMessageResultError::PartialResponse(
            "content block bound exceeded",
        ));
    }
    let mut blocks = Vec::with_capacity(content.len());
    let mut citations = Vec::new();
    let mut refusal = None;
    for block in content {
        let block_object =
            block
                .as_object()
                .ok_or(AnthropicMessageResultError::MalformedResponse(
                    "content block is not an object",
                ))?;
        let block_type = block_object.get("type").and_then(Value::as_str).ok_or(
            AnthropicMessageResultError::PartialResponse("content block type is missing"),
        )?;
        let projection = match block_type {
            "text" => {
                let text = block_object.get("text").and_then(Value::as_str).ok_or(
                    AnthropicMessageResultError::PartialResponse("text content is missing"),
                )?;
                let block_citations = block_object
                    .get("citations")
                    .and_then(Value::as_array)
                    .map_or(Ok(Vec::new()), |values| {
                        values
                            .iter()
                            .map(crate::model::CitationMetadata::from_json)
                            .collect::<Result<Vec<_>>>()
                    })?;
                if citations.len() + block_citations.len() > policy.max_citations {
                    return Err(AnthropicMessageResultError::PartialResponse(
                        "citation bound exceeded",
                    ));
                }
                citations.extend(block_citations);
                ContentBlockProjection {
                    kind: ContentBlockKind::Text,
                    content_digest: Digest::from_text(text),
                    content_bytes: text.len(),
                    citation_count: block_object
                        .get("citations")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                }
            }
            "tool_use" | "server_tool_use" => ContentBlockProjection {
                kind: ContentBlockKind::ToolUse,
                content_digest: Digest::from_serializable(block),
                content_bytes: serde_json::to_vec(block).map_or(0, |bytes| bytes.len()),
                citation_count: 0,
            },
            "thinking" | "redacted_thinking" => ContentBlockProjection {
                kind: ContentBlockKind::ThinkingRedacted,
                content_digest: Digest::from_serializable(block),
                content_bytes: serde_json::to_vec(block).map_or(0, |bytes| bytes.len()),
                citation_count: 0,
            },
            "refusal" => {
                let reason_digest = block_object
                    .get("reason")
                    .or_else(|| block_object.get("text"))
                    .and_then(Value::as_str)
                    .map(Digest::from_text);
                refusal = Some(RefusalProjection {
                    category: RefusalCategory::Provider,
                    reason_digest,
                });
                ContentBlockProjection {
                    kind: ContentBlockKind::Refusal,
                    content_digest: Digest::from_serializable(block),
                    content_bytes: serde_json::to_vec(block).map_or(0, |bytes| bytes.len()),
                    citation_count: 0,
                }
            }
            _ => ContentBlockProjection {
                kind: ContentBlockKind::ProviderUnknown,
                content_digest: Digest::from_serializable(block),
                content_bytes: serde_json::to_vec(block).map_or(0, |bytes| bytes.len()),
                citation_count: 0,
            },
        };
        blocks.push(projection);
    }
    if stop_reason == StopReason::Refusal && refusal.is_none() {
        refusal = Some(RefusalProjection {
            category: RefusalCategory::Provider,
            reason_digest: object
                .get("refusal")
                .and_then(Value::as_str)
                .map(Digest::from_text),
        });
    }
    let status = match stop_reason {
        StopReason::EndTurn | StopReason::MaxTokens | StopReason::StopSequence => {
            ResultStatus::Complete
        }
        StopReason::ToolUse => ResultStatus::ToolUse,
        StopReason::Refusal => ResultStatus::Refused,
        StopReason::ProviderUnknown => ResultStatus::ProviderUnknown,
    };
    let response_model = ModelVersion {
        model_id: response_model_id.to_owned(),
        immutable_version: proposal.model.immutable_version.clone(),
    };
    let response_id_digest = object
        .get("id")
        .and_then(Value::as_str)
        .map(Digest::from_text)
        .or_else(|| provider_request_id.map(Digest::from_text));
    let content_digest = Digest::from_serializable(&(&blocks, &citations, &stop_reason, &usage));
    let mut evidence = base_evidence(
        proposal,
        recording_id_digest,
        latency_ms,
        provenance,
        response_digest,
        body.len(),
    );
    evidence.response_id_digest = response_id_digest;
    evidence.response_model = Some(response_model);
    evidence.status = status;
    evidence.stop_reason = Some(stop_reason);
    evidence.usage = Some(usage);
    evidence.refusal = refusal;
    evidence.citations = citations;
    evidence.content_blocks = blocks;
    evidence.content_digest = content_digest;
    Ok(finish_evidence(evidence))
}

fn stop_reason_from_text(value: &str) -> StopReason {
    match value {
        "end_turn" => StopReason::EndTurn,
        "max_tokens" => StopReason::MaxTokens,
        "tool_use" => StopReason::ToolUse,
        "stop_sequence" => StopReason::StopSequence,
        "refusal" => StopReason::Refusal,
        _ => StopReason::ProviderUnknown,
    }
}

fn required_u64(object: &serde_json::Map<String, Value>, key: &'static str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(AnthropicMessageResultError::MalformedResponse(key))
}

fn optional_u64(object: &serde_json::Map<String, Value>, key: &'static str) -> Result<Option<u64>> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(AnthropicMessageResultError::MalformedResponse(key)),
    }
}
