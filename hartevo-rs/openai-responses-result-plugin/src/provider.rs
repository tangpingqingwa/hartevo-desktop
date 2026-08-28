//! Non-native recording, fixture, loopback, and `BLOCKED_ENV` provider seam.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    digest_bytes, digest_serializable,
    model::{
        BlockedEnvCode, Digest, EvidenceDisposition, ModelSnapshot, OpenAIResponsesProposal,
        OpenAIResponsesResultError, OpenAIResponsesResultEvidence, OpenAIResponsesScope,
        OutputRetentionMode, OutputRetentionPolicy, OutputSummary, ProviderFailureClass,
        ProviderMode, RedactionMetadata, ResponseErrorMetadata, ResponseId, ResponseStatus,
        ResponseUsage, StructuredOutputSchema,
    },
};

pub const DEFAULT_PROVIDER_RESPONSE_BYTES: usize = crate::model::MAX_OUTPUT_BYTES;

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

/// A borrowed-host response frame. It is deliberately non-serializable and
/// its body is consumed only long enough to create redacted evidence.
#[derive(Clone)]
pub struct RecordedResponseFrame {
    recording_id: String,
    provider_id: String,
    model_id: String,
    model_snapshot: String,
    latency_ms: u64,
    cost_micros: Option<u64>,
    outcome: ProviderResponseOutcome,
}

impl RecordedResponseFrame {
    pub fn new(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
        outcome: ProviderResponseOutcome,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            model_snapshot: model_snapshot.into(),
            latency_ms,
            cost_micros: None,
            outcome,
        }
    }

    pub fn success(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Http {
                status: 200,
                body: body.into(),
            },
        )
    }

    pub fn http(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        status: u16,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_snapshot,
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
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::Timeout,
        )
    }

    pub fn transport_unavailable(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::TransportUnavailable,
        )
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        model_snapshot: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        Self::new(
            recording_id,
            provider_id,
            model_id,
            model_snapshot,
            latency_ms,
            ProviderResponseOutcome::BlockedEnv { code },
        )
    }

    #[must_use]
    pub fn with_cost_micros(mut self, cost_micros: u64) -> Self {
        self.cost_micros = Some(cost_micros);
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

    pub fn model_snapshot(&self) -> &str {
        &self.model_snapshot
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub const fn cost_micros(&self) -> Option<u64> {
        self.cost_micros
    }

    pub fn outcome(&self) -> &ProviderResponseOutcome {
        &self.outcome
    }
}

impl fmt::Debug for RecordedResponseFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedResponseFrame")
            .field("recording_key", &recording_key(&self.recording_id))
            .field("provider_id", &self.provider_id)
            .field("model_id", &self.model_id)
            .field("model_snapshot", &self.model_snapshot)
            .field("latency_ms", &self.latency_ms)
            .field("cost_micros", &self.cost_micros)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelDescription {
    pub provider_id: String,
    pub model_id: String,
    pub immutable_snapshot: String,
    pub provider_digest: Digest,
    pub model_snapshot_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl ModelDescription {
    fn from_scope(scope: &OpenAIResponsesScope) -> Self {
        Self {
            provider_id: scope.provider().provider_id().to_owned(),
            model_id: scope.model().model_id().to_owned(),
            immutable_snapshot: scope.model().immutable_snapshot().to_owned(),
            provider_digest: scope.provider_digest(),
            model_snapshot_digest: scope.model_digest(),
            connected: false,
            native: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpenAIResponsesProvider {
    mode: ProviderMode,
    max_response_bytes: usize,
}

impl OpenAIResponsesProvider {
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
    ) -> Result<Self, OpenAIResponsesResultError> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "max_response_bytes",
                reason: "must be a positive bounded response size",
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

    pub fn describe_model(&self, scope: &OpenAIResponsesScope) -> ModelDescription {
        ModelDescription::from_scope(scope)
    }

    #[allow(clippy::too_many_lines)]
    pub fn record(
        &self,
        scope: &OpenAIResponsesScope,
        proposal: &OpenAIResponsesProposal,
        frame: &RecordedResponseFrame,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        proposal.verify_integrity()?;
        validate_proposal_scope(scope, proposal)?;
        validate_frame_identity(scope, frame)?;
        if frame.latency_ms > scope.input_policy().max_latency_ms() {
            return Err(OpenAIResponsesResultError::LatencyCeilingExceeded);
        }
        if frame
            .cost_micros
            .is_some_and(|cost| cost > scope.input_policy().max_cost_micros())
        {
            return Err(OpenAIResponsesResultError::CostCeilingExceeded);
        }
        if self.mode == ProviderMode::BlockedEnv
            && !matches!(frame.outcome, ProviderResponseOutcome::BlockedEnv { .. })
        {
            return Err(OpenAIResponsesResultError::BlockedEnvironment(
                "BLOCKED_ENV cannot assert a provider response",
            ));
        }
        if self.mode != ProviderMode::BlockedEnv
            && matches!(frame.outcome, ProviderResponseOutcome::BlockedEnv { .. })
        {
            return Err(OpenAIResponsesResultError::BlockedEnvironment(
                "BLOCKED_ENV frames require BLOCKED_ENV provider mode",
            ));
        }

        let recording_digest = recording_key(frame.recording_id());
        match &frame.outcome {
            ProviderResponseOutcome::Timeout => Ok(error_evidence(
                scope,
                proposal,
                None,
                ResponseStatus::ProviderUnknown,
                frame,
                digest_bytes(b"timeout"),
                recording_digest,
                ProviderFailureClass::Timeout,
                None,
                true,
                EvidenceDisposition::RecordedProviderError,
                self.mode,
            )),
            ProviderResponseOutcome::TransportUnavailable => Ok(error_evidence(
                scope,
                proposal,
                None,
                ResponseStatus::ProviderUnknown,
                frame,
                digest_bytes(b"transport-unavailable"),
                recording_digest,
                ProviderFailureClass::TransportUnavailable,
                None,
                true,
                EvidenceDisposition::RecordedProviderError,
                self.mode,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => Ok(error_evidence(
                scope,
                proposal,
                None,
                ResponseStatus::ProviderUnknown,
                frame,
                digest_bytes(code.as_str().as_bytes()),
                recording_digest,
                ProviderFailureClass::TransportUnavailable,
                None,
                true,
                EvidenceDisposition::BlockedEnv,
                self.mode,
            )),
            ProviderResponseOutcome::Http { status, body } => {
                if body.len() > self.max_response_bytes
                    || body.len() > scope.input_policy().max_output_bytes()
                {
                    return Err(OpenAIResponsesResultError::ResponseTruncated);
                }
                let response_digest = digest_bytes(body);
                if (200..300).contains(status) {
                    parse_success(
                        scope,
                        proposal,
                        frame,
                        body,
                        response_digest,
                        recording_digest,
                        self.mode,
                    )
                } else {
                    parse_http_error(
                        scope,
                        proposal,
                        frame,
                        *status,
                        body,
                        response_digest,
                        recording_digest,
                        self.mode,
                    )
                }
            }
        }
    }

    /// Native credentials, HTTPS transport, and independent provider readback
    /// are intentionally Layer-2 seams.
    pub fn execute_native(
        &self,
        _scope: &OpenAIResponsesScope,
        _proposal: &OpenAIResponsesProposal,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        Err(OpenAIResponsesResultError::NativeExecutionUnavailable)
    }
}

fn validate_frame_identity(
    scope: &OpenAIResponsesScope,
    frame: &RecordedResponseFrame,
) -> Result<(), OpenAIResponsesResultError> {
    if frame.recording_id.trim().is_empty()
        || frame.recording_id.len() > crate::model::MAX_IDENTIFIER_BYTES
        || frame
            .recording_id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(OpenAIResponsesResultError::InvalidField {
            field: "recording_id",
            reason: "must be a bounded non-empty identifier",
        });
    }
    if frame.provider_id != scope.provider().provider_id() {
        return Err(OpenAIResponsesResultError::ProviderIdentityMismatch);
    }
    if frame.model_id != scope.model().model_id()
        || frame.model_snapshot != scope.model().immutable_snapshot()
    {
        return Err(OpenAIResponsesResultError::ModelSnapshotMismatch);
    }
    Ok(())
}

fn validate_proposal_scope(
    scope: &OpenAIResponsesScope,
    proposal: &OpenAIResponsesProposal,
) -> Result<(), OpenAIResponsesResultError> {
    if proposal.provider_digest != scope.provider_digest()
        || proposal.organization_digest != scope.organization_digest()
        || proposal.project_digest != scope.project_digest()
        || proposal.model_snapshot_digest != scope.model_digest()
        || proposal.input_policy_digest != scope.input_policy_digest()
        || proposal.structured_schema_digest != scope.structured_schema_digest()
        || proposal.tool_policy_digest != scope.tool_policy_digest()
        || proposal.mission_digest != scope.mission_digest()
        || proposal.work_product_digest != scope.work_product_digest()
        || proposal.consent_digest != scope.consent_digest()
        || proposal.scope_digest != scope.digest()
    {
        return Err(OpenAIResponsesResultError::ScopeMismatch(
            "provider proposal is not bound to the supplied scope",
        ));
    }
    Ok(())
}

fn recording_key(recording_id: &str) -> Digest {
    digest_serializable(&("hartevo:openai-responses-recording:v1", recording_id))
}

fn parse_success(
    scope: &OpenAIResponsesScope,
    proposal: &OpenAIResponsesProposal,
    frame: &RecordedResponseFrame,
    body: &[u8],
    response_digest: Digest,
    recording_digest: Digest,
    mode: ProviderMode,
) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| OpenAIResponsesResultError::MalformedResponse("body is not valid JSON"))?;
    reject_forbidden_fields(&value)?;
    let object = value
        .as_object()
        .ok_or(OpenAIResponsesResultError::MalformedResponse(
            "response must be a JSON object",
        ))?;
    let response_id = parse_response_id(object)?;
    validate_response_model(scope.model(), object)?;
    let status_value = object.get("status").and_then(Value::as_str).ok_or(
        OpenAIResponsesResultError::MalformedResponse("response status is missing"),
    )?;
    let status = ResponseStatus::from_provider_status(status_value)
        .unwrap_or(ResponseStatus::ProviderUnknown);
    let usage = parse_usage(object.get("usage"))?;
    validate_usage(scope, usage)?;
    let output = if status == ResponseStatus::Completed {
        Some(parse_output(
            object,
            scope.structured_output_schema(),
            scope.input_policy().output_retention(),
            scope.input_policy().max_output_bytes(),
        )?)
    } else {
        None
    };
    let error = response_error_metadata(object, status, status_value, &response_digest);
    let disposition = if status == ResponseStatus::Completed {
        EvidenceDisposition::RecordedSuccess
    } else if error.is_some() {
        EvidenceDisposition::RecordedProviderError
    } else {
        EvidenceDisposition::RecordedStatus
    };
    Ok(OpenAIResponsesResultEvidence::new(
        proposal,
        Some(response_id),
        status,
        usage,
        frame.latency_ms,
        frame.cost_micros,
        output,
        error,
        disposition,
        mode,
        response_digest,
        recording_digest,
        RedactionMetadata::for_policy(scope.input_policy().output_retention()),
    ))
}

fn response_error_metadata(
    object: &Map<String, Value>,
    status: ResponseStatus,
    status_value: &str,
    response_digest: &Digest,
) -> Option<ResponseErrorMetadata> {
    let (class, retryable) = match status {
        ResponseStatus::Incomplete => (ProviderFailureClass::ProviderUnknown, true),
        ResponseStatus::RateLimited => (ProviderFailureClass::RateLimited, true),
        ResponseStatus::AccessLost => (ProviderFailureClass::Unauthorized, false),
        ResponseStatus::Failed | ResponseStatus::ProviderUnknown => {
            (ProviderFailureClass::ProviderUnknown, false)
        }
        ResponseStatus::Queued
        | ResponseStatus::Running
        | ResponseStatus::Completed
        | ResponseStatus::Cancelled
        | ResponseStatus::Expired => return None,
    };
    let code_digest = object
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("incomplete_details")
                .and_then(Value::as_object)
                .and_then(|details| details.get("reason"))
                .and_then(Value::as_str)
        })
        .map(|code| digest_bytes(code.as_bytes()))
        .or_else(|| {
            if status == ResponseStatus::ProviderUnknown {
                Some(digest_bytes(status_value.as_bytes()))
            } else {
                None
            }
        });
    Some(ResponseErrorMetadata {
        class,
        http_status: None,
        retryable,
        error_digest: response_digest.clone(),
        code_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn parse_http_error(
    scope: &OpenAIResponsesScope,
    proposal: &OpenAIResponsesProposal,
    frame: &RecordedResponseFrame,
    status: u16,
    body: &[u8],
    response_digest: Digest,
    recording_digest: Digest,
    mode: ProviderMode,
) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    if let Some(value) = parsed.as_ref() {
        reject_forbidden_fields(value)?;
    }
    let response_id = parsed
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|object| parse_response_id(object).ok());
    let (response_status, class, retryable) = match status {
        400 => (
            ResponseStatus::Failed,
            ProviderFailureClass::BadRequest,
            false,
        ),
        401 => (
            ResponseStatus::AccessLost,
            ProviderFailureClass::Unauthorized,
            false,
        ),
        403 => (
            ResponseStatus::AccessLost,
            ProviderFailureClass::Forbidden,
            false,
        ),
        404 => (
            ResponseStatus::Failed,
            ProviderFailureClass::NotFound,
            false,
        ),
        408 | 504 => (
            ResponseStatus::ProviderUnknown,
            ProviderFailureClass::Timeout,
            true,
        ),
        409 => (
            ResponseStatus::Failed,
            ProviderFailureClass::Conflict,
            false,
        ),
        429 => (
            ResponseStatus::RateLimited,
            ProviderFailureClass::RateLimited,
            true,
        ),
        500..=599 => (
            ResponseStatus::Failed,
            ProviderFailureClass::ServerError,
            true,
        ),
        _ => (
            ResponseStatus::ProviderUnknown,
            ProviderFailureClass::ProviderUnknown,
            false,
        ),
    };
    let (error_digest, code_digest) = parsed.as_ref().and_then(Value::as_object).map_or(
        (response_digest.clone(), None),
        |object| {
            let code_digest = object
                .get("error")
                .and_then(Value::as_object)
                .and_then(|error| error.get("code"))
                .and_then(Value::as_str)
                .map(|code| digest_bytes(code.as_bytes()));
            (response_digest.clone(), code_digest)
        },
    );
    Ok(OpenAIResponsesResultEvidence::new(
        proposal,
        response_id,
        response_status,
        None,
        frame.latency_ms,
        frame.cost_micros,
        None,
        Some(ResponseErrorMetadata {
            class,
            http_status: Some(status),
            retryable,
            error_digest,
            code_digest,
        }),
        EvidenceDisposition::RecordedProviderError,
        mode,
        response_digest,
        recording_digest,
        RedactionMetadata::for_policy(scope.input_policy().output_retention()),
    ))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn error_evidence(
    scope: &OpenAIResponsesScope,
    proposal: &OpenAIResponsesProposal,
    response_id: Option<ResponseId>,
    status: ResponseStatus,
    frame: &RecordedResponseFrame,
    response_digest: Digest,
    recording_digest: Digest,
    class: ProviderFailureClass,
    http_status: Option<u16>,
    retryable: bool,
    disposition: EvidenceDisposition,
    mode: ProviderMode,
) -> OpenAIResponsesResultEvidence {
    OpenAIResponsesResultEvidence::new(
        proposal,
        response_id,
        status,
        None,
        frame.latency_ms,
        frame.cost_micros,
        None,
        Some(ResponseErrorMetadata {
            class,
            http_status,
            retryable,
            error_digest: response_digest.clone(),
            code_digest: None,
        }),
        disposition,
        mode,
        response_digest,
        recording_digest,
        RedactionMetadata::for_policy(scope.input_policy().output_retention()),
    )
}

fn parse_response_id(
    object: &Map<String, Value>,
) -> Result<ResponseId, OpenAIResponsesResultError> {
    let value = object.get("id").and_then(Value::as_str).ok_or(
        OpenAIResponsesResultError::MalformedResponse("response id is missing or not text"),
    )?;
    ResponseId::new(value)
}

fn validate_response_model(
    model: &ModelSnapshot,
    object: &Map<String, Value>,
) -> Result<(), OpenAIResponsesResultError> {
    let api_model = object.get("model").and_then(Value::as_str).ok_or(
        OpenAIResponsesResultError::MalformedResponse(
            "response model snapshot is missing or not text",
        ),
    )?;
    if !model.matches_api_model(api_model) {
        return Err(OpenAIResponsesResultError::ModelSnapshotMismatch);
    }
    if let Some(snapshot) = object.get("model_snapshot") {
        let snapshot = snapshot
            .as_str()
            .ok_or(OpenAIResponsesResultError::MalformedResponse(
                "model_snapshot must be text",
            ))?;
        if snapshot != model.immutable_snapshot() {
            return Err(OpenAIResponsesResultError::ModelSnapshotMismatch);
        }
    }
    Ok(())
}

fn parse_usage(value: Option<&Value>) -> Result<Option<ResponseUsage>, OpenAIResponsesResultError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(OpenAIResponsesResultError::MalformedResponse(
            "usage must be an object",
        ))?;
    let input_tokens = required_u64(object, "input_tokens")?;
    let output_tokens = required_u64(object, "output_tokens")?;
    let total_tokens = required_u64(object, "total_tokens")?;
    let usage = ResponseUsage::new(
        input_tokens,
        output_tokens,
        object
            .get("input_tokens_details")
            .and_then(Value::as_object)
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64),
    )?;
    if total_tokens != usage.total_tokens {
        return Err(OpenAIResponsesResultError::MalformedResponse(
            "usage total_tokens does not equal input_tokens plus output_tokens",
        ));
    }
    Ok(Some(usage))
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, OpenAIResponsesResultError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(OpenAIResponsesResultError::MalformedResponse(
            "usage numeric field is missing or invalid",
        ))
}

fn validate_usage(
    scope: &OpenAIResponsesScope,
    usage: Option<ResponseUsage>,
) -> Result<(), OpenAIResponsesResultError> {
    if let Some(usage) = usage {
        if usage.input_tokens > scope.input_policy().max_input_tokens() {
            return Err(OpenAIResponsesResultError::InputTokenCeilingExceeded);
        }
        if usage.output_tokens > scope.input_policy().max_output_tokens() {
            return Err(OpenAIResponsesResultError::OutputTokenCeilingExceeded);
        }
    }
    Ok(())
}

fn parse_output(
    object: &Map<String, Value>,
    schema: Option<&StructuredOutputSchema>,
    retention: OutputRetentionPolicy,
    max_output_bytes: usize,
) -> Result<OutputSummary, OpenAIResponsesResultError> {
    let text = extract_output_text(object)?;
    if text.len() > max_output_bytes {
        return Err(OpenAIResponsesResultError::OutputTooLarge);
    }
    let content_digest = digest_bytes(text.as_bytes());
    let structured_output_digest = if let Some(schema) = schema {
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| OpenAIResponsesResultError::StructuredOutputInvalid)?;
        if !matches_schema(&value, schema.schema()) {
            return Err(OpenAIResponsesResultError::StructuredOutputInvalid);
        }
        Some(content_digest.clone())
    } else {
        None
    };
    let (preview, preview_truncated, retained_bytes) = match retention.mode() {
        OutputRetentionMode::DigestOnly => (None, false, 0),
        OutputRetentionMode::BoundedPrefix => {
            let preview: String = text.chars().take(retention.preview_chars()).collect();
            let truncated = text.chars().count() > retention.preview_chars();
            let bytes = preview.len();
            (Some(preview), truncated, bytes)
        }
    };
    Ok(OutputSummary {
        content_digest,
        structured_output_digest,
        preview,
        preview_truncated,
        retained_bytes,
    })
}

fn extract_output_text(object: &Map<String, Value>) -> Result<String, OpenAIResponsesResultError> {
    if let Some(output_text) = object.get("output_text") {
        return output_text.as_str().map(ToOwned::to_owned).ok_or(
            OpenAIResponsesResultError::MalformedResponse("output_text must be text"),
        );
    }
    let output = object.get("output").and_then(Value::as_array).ok_or(
        OpenAIResponsesResultError::MalformedResponse("completed response output is missing"),
    )?;
    let mut text = String::new();
    for item in output {
        let item = item
            .as_object()
            .ok_or(OpenAIResponsesResultError::MalformedResponse(
                "response output item must be an object",
            ))?;
        if matches!(
            item.get("type").and_then(Value::as_str),
            Some("reasoning" | "function_call" | "web_search_call")
        ) {
            return Err(OpenAIResponsesResultError::ToolPolicyViolation);
        }
        let Some(content) = item.get("content").and_then(Value::as_array) else {
            continue;
        };
        for part in content {
            let part = part
                .as_object()
                .ok_or(OpenAIResponsesResultError::MalformedResponse(
                    "response content part must be an object",
                ))?;
            if part.get("type").and_then(Value::as_str) == Some("output_text") {
                let value = part.get("text").and_then(Value::as_str).ok_or(
                    OpenAIResponsesResultError::MalformedResponse(
                        "output_text content must be text",
                    ),
                )?;
                text.push_str(value);
            }
        }
    }
    if text.is_empty() {
        return Err(OpenAIResponsesResultError::MalformedResponse(
            "completed response has no allowlisted output text",
        ));
    }
    Ok(text)
}

fn reject_forbidden_fields(value: &Value) -> Result<(), OpenAIResponsesResultError> {
    match value {
        Value::Object(object) => {
            for key in object.keys() {
                if matches!(
                    key.as_str(),
                    "reasoning"
                        | "reasoning_content"
                        | "thinking"
                        | "tool_calls"
                        | "tool_call"
                        | "function_call"
                        | "function"
                        | "arguments"
                        | "web_search_call"
                ) {
                    return Err(OpenAIResponsesResultError::ToolPolicyViolation);
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

fn matches_schema(value: &Value, schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    if let Some(enum_values) = object.get("enum").and_then(Value::as_array)
        && !enum_values.iter().any(|candidate| candidate == value)
    {
        return false;
    }
    if let Some(kind) = object.get("type").and_then(Value::as_str) {
        let type_matches = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => false,
        };
        if !type_matches {
            return false;
        }
    }
    if let Some(object_value) = value.as_object() {
        let Some(properties) = object.get("properties").and_then(Value::as_object) else {
            return true;
        };
        if object.get("additionalProperties").and_then(Value::as_bool) == Some(false)
            && object_value.keys().any(|key| !properties.contains_key(key))
        {
            return false;
        }
        if let Some(required) = object.get("required").and_then(Value::as_array)
            && required.iter().any(|key| {
                key.as_str()
                    .is_none_or(|key| !object_value.contains_key(key))
            })
        {
            return false;
        }
        if properties.iter().any(|(key, property_schema)| {
            object_value
                .get(key)
                .is_some_and(|candidate| !matches_schema(candidate, property_schema))
        }) {
            return false;
        }
    }
    if let Some(array_value) = value.as_array()
        && let Some(items) = object.get("items")
        && array_value
            .iter()
            .any(|candidate| !matches_schema(candidate, items))
    {
        return false;
    }
    true
}
