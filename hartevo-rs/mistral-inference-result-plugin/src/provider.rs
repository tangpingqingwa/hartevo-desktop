//! Recording-only Mistral provider boundary and response projection.

use std::fmt;

use serde_json::Value;

use crate::{
    MISTRAL_INFERENCE_PROVIDER_ID, digest_bytes, digest_serializable,
    model::{
        ClassificationProjection, ContentKind, EmbeddingProjection, EvidenceDisposition,
        FinishReason, InferencePolicy, InferenceResultEvidence, InferenceResultProposal,
        InferenceResultState, MAX_CLASSIFICATION_RESULTS, MAX_IDENTIFIER_BYTES, MAX_ITEMS,
        MAX_MODEL_LIST_ITEMS, MistralInferenceError, ModelDescription, ModelListEvidence,
        ModelListItem, ProviderErrorProjection, ProviderFailureClass, ProviderMode,
        RedactedContent, UsageProjection,
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
    pub(crate) fn as_str(self) -> &'static str {
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

/// Borrowed-host recording envelope. It is intentionally not serializable;
/// its Debug implementation exposes only bounded metadata and digests.
#[derive(Clone)]
pub struct RecordedMistralResponse {
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

pub type RecordedProviderResponse = RecordedMistralResponse;

impl RecordedMistralResponse {
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
        response.outcome = ProviderResponseOutcome::Http {
            status,
            body: match response.outcome {
                ProviderResponseOutcome::Http { body, .. } => body,
                _ => unreachable!("new creates an HTTP response"),
            },
        };
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

impl fmt::Debug for RecordedMistralResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordedMistralResponse")
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

/// A separate model-list recording envelope prevents an inference response
/// from being mistaken for a model catalog observation.
#[derive(Clone)]
pub struct MistralModelListResponse {
    recording_id: String,
    provider_id: String,
    result_revision: u64,
    latency_ms: u64,
    outcome: ProviderResponseOutcome,
}

impl MistralModelListResponse {
    pub fn success(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            result_revision: 1,
            latency_ms,
            outcome: ProviderResponseOutcome::Http {
                status: 200,
                body: body.into(),
            },
        }
    }

    pub fn http_error(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        status: u16,
        body: impl Into<Vec<u8>>,
        latency_ms: u64,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            result_revision: 1,
            latency_ms,
            outcome: ProviderResponseOutcome::Http {
                status,
                body: body.into(),
            },
        }
    }

    pub fn blocked_env(
        recording_id: impl Into<String>,
        provider_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Self {
        Self {
            recording_id: recording_id.into(),
            provider_id: provider_id.into(),
            result_revision: 1,
            latency_ms,
            outcome: ProviderResponseOutcome::BlockedEnv { code },
        }
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

impl fmt::Debug for MistralModelListResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MistralModelListResponse")
            .field("recording_key", &recording_key(&self.recording_id))
            .field("provider_id", &self.provider_id)
            .field("result_revision", &self.result_revision)
            .field("latency_ms", &self.latency_ms)
            .field("outcome", &self.outcome)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct MistralProvider {
    mode: ProviderMode,
    max_response_bytes: usize,
    max_model_list_items: usize,
}

impl MistralProvider {
    pub fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            max_response_bytes: DEFAULT_PROVIDER_RESPONSE_BYTES,
            max_model_list_items: MAX_MODEL_LIST_ITEMS,
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
    ) -> Result<Self, MistralInferenceError> {
        if max_response_bytes == 0 || max_response_bytes > DEFAULT_PROVIDER_RESPONSE_BYTES {
            return Err(MistralInferenceError::InvalidField {
                field: "max_response_bytes",
                reason: "must be a positive Layer-1 response bound",
            });
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    pub fn with_model_list_bound(
        mut self,
        max_model_list_items: usize,
    ) -> Result<Self, MistralInferenceError> {
        if max_model_list_items == 0 || max_model_list_items > MAX_MODEL_LIST_ITEMS {
            return Err(MistralInferenceError::InvalidField {
                field: "max_model_list_items",
                reason: "must be within the bounded model-list limit",
            });
        }
        self.max_model_list_items = max_model_list_items;
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

    pub fn describe_model(&self, scope: &crate::model::MistralInferenceScope) -> ModelDescription {
        ModelDescription::from_scope(scope)
    }

    pub fn record(
        &self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
        policy: &InferencePolicy,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        validate_recording_identity(proposal, response)?;
        if response.result_revision == 0 {
            return Err(MistralInferenceError::ResultRevisionMismatch);
        }
        let recording_key = recording_key(response.recording_id());
        match &response.outcome {
            ProviderResponseOutcome::Timeout => Ok(error_evidence(
                self.mode,
                recording_key,
                proposal,
                response.result_revision,
                digest_bytes(b"mistral-timeout"),
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
                digest_bytes(b"mistral-transport-unavailable"),
                response.latency_ms,
                InferenceResultState::ProviderUnknown,
                ProviderFailureClass::TransportUnavailable,
                None,
            )),
            ProviderResponseOutcome::BlockedEnv { code } => {
                if self.mode != ProviderMode::BlockedEnv {
                    return Err(MistralInferenceError::BlockedEnvironment(
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
                    return Err(MistralInferenceError::ResponseTruncated);
                }
                let response_digest = digest_bytes(body);
                if (200..300).contains(status) {
                    if self.mode == ProviderMode::BlockedEnv {
                        return Err(MistralInferenceError::BlockedEnvironment(
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
        response: &RecordedMistralResponse,
        state: InferenceResultState,
        body: &[u8],
        policy: &InferencePolicy,
        recording_key: crate::model::Digest,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        if body.len() > self.max_response_bytes || body.len() > policy.max_response_bytes() {
            return Err(MistralInferenceError::ResponseTruncated);
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
                    projection.classification,
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

    pub fn record_model_list(
        &self,
        response: &MistralModelListResponse,
        expected_model_id: &str,
        policy: &InferencePolicy,
    ) -> Result<ModelListEvidence, MistralInferenceError> {
        validate_model_list_identity(response)?;
        if response.result_revision == 0 {
            return Err(MistralInferenceError::ResultRevisionMismatch);
        }
        let (status, body) = match &response.outcome {
            ProviderResponseOutcome::Http { status, body } => (*status, body.as_slice()),
            ProviderResponseOutcome::BlockedEnv { code } => {
                if self.mode != ProviderMode::BlockedEnv {
                    return Err(MistralInferenceError::BlockedEnvironment(
                        "blocked-environment frame requires BLOCKED_ENV provider mode",
                    ));
                }
                return Err(MistralInferenceError::BlockedEnvironment(code.as_str()));
            }
            ProviderResponseOutcome::Timeout | ProviderResponseOutcome::TransportUnavailable => {
                return Err(MistralInferenceError::ProviderFailure(
                    ProviderFailureClass::TransportUnavailable,
                ));
            }
            ProviderResponseOutcome::Lifecycle { .. } => {
                return Err(MistralInferenceError::MalformedResponse(
                    "model-list does not accept inference lifecycle frames",
                ));
            }
        };
        if body.len() > self.max_response_bytes || body.len() > policy.max_response_bytes() {
            return Err(MistralInferenceError::ResponseTruncated);
        }
        if !(200..300).contains(&status) {
            let (class, _, _) = failure_for_status(status)?;
            return Err(MistralInferenceError::ProviderFailure(class));
        }
        if self.mode == ProviderMode::BlockedEnv {
            return Err(MistralInferenceError::BlockedEnvironment(
                "BLOCKED_ENV cannot assert a successful model list",
            ));
        }
        let value: Value = serde_json::from_slice(body).map_err(|_| {
            MistralInferenceError::MalformedResponse("model list is not valid JSON")
        })?;
        let object = value
            .as_object()
            .ok_or(MistralInferenceError::MalformedResponse(
                "model list must be a JSON object",
            ))?;
        reject_forbidden_fields(&value)?;
        let data = object.get("data").and_then(Value::as_array).ok_or(
            MistralInferenceError::MalformedResponse("model list data is missing"),
        )?;
        let max_items = policy.max_model_list_items().min(self.max_model_list_items);
        if data.is_empty() || data.len() > max_items {
            return Err(MistralInferenceError::MalformedResponse(
                "model list item count is outside the bounded limit",
            ));
        }
        let mut models = Vec::with_capacity(data.len());
        for item in data {
            let item = item
                .as_object()
                .ok_or(MistralInferenceError::MalformedResponse(
                    "model list item is not an object",
                ))?;
            let model_id = item.get("id").and_then(Value::as_str).ok_or(
                MistralInferenceError::MalformedResponse("model list item id is missing"),
            )?;
            validate_bounded_text(model_id, "model_list.model_id")?;
            let model_type = item
                .get("object")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let capabilities = item
                .get("capabilities")
                .or_else(|| item.get("owned_by"))
                .unwrap_or(&Value::Null);
            models.push(ModelListItem {
                model_id: model_id.to_owned(),
                model_type,
                capabilities_digest: digest_serializable(capabilities),
            });
        }
        let pinned_model_allowlisted = models
            .iter()
            .any(|model| model.model_id == expected_model_id);
        Ok(ModelListEvidence::new(
            self.mode,
            recording_key(response.recording_id()),
            digest_bytes(body),
            response.result_revision,
            models,
            pinned_model_allowlisted,
        ))
    }
}

fn validate_recording_identity(
    proposal: &InferenceResultProposal,
    response: &RecordedMistralResponse,
) -> Result<(), MistralInferenceError> {
    proposal.verify_integrity()?;
    validate_bounded_text(response.recording_id(), "recording_id")?;
    if response.provider_id != proposal.provider_route.provider_id() {
        return Err(MistralInferenceError::ProviderRouteMismatch);
    }
    if response.model_id != proposal.model.model_id() {
        return Err(MistralInferenceError::ModelMismatch);
    }
    if response.model_revision != proposal.model.immutable_revision() {
        return Err(MistralInferenceError::ModelRevisionDrift);
    }
    if response
        .request_revision
        .is_some_and(|revision| revision != proposal.request.request_revision)
    {
        return Err(MistralInferenceError::RequestRevisionMismatch);
    }
    if response
        .provider_digest
        .as_ref()
        .is_some_and(|digest| digest != &proposal.provider_digest)
    {
        return Err(MistralInferenceError::ProviderRouteMismatch);
    }
    Ok(())
}

fn validate_model_list_identity(
    response: &MistralModelListResponse,
) -> Result<(), MistralInferenceError> {
    validate_bounded_text(response.recording_id(), "recording_id")?;
    if response.provider_id != "mistral" {
        return Err(MistralInferenceError::ProviderRouteMismatch);
    }
    Ok(())
}

fn validate_bounded_text(value: &str, field: &'static str) -> Result<(), MistralInferenceError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(MistralInferenceError::InvalidField {
            field,
            reason: "must be a bounded non-empty text value",
        });
    }
    Ok(())
}

fn recording_key(recording_id: &str) -> crate::model::Digest {
    digest_serializable(&("hartevo:mistral-recording:v1", recording_id))
}

struct SuccessProjection {
    content: Option<RedactedContent>,
    embedding: Option<EmbeddingProjection>,
    classification: Option<ClassificationProjection>,
    usage: Option<UsageProjection>,
    finish_reason: Option<FinishReason>,
}

fn parse_success(
    proposal: &InferenceResultProposal,
    body: &[u8],
    policy: &InferencePolicy,
    allow_partial: bool,
) -> Result<SuccessProjection, MistralInferenceError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| MistralInferenceError::MalformedResponse("body is not valid JSON"))?;
    let object = value
        .as_object()
        .ok_or(MistralInferenceError::MalformedResponse(
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
            .ok_or(MistralInferenceError::MalformedResponse(
                "model revision field must be text",
            ))?;
        if revision != proposal.model.immutable_revision() {
            return Err(MistralInferenceError::ModelRevisionDrift);
        }
    }
    match proposal.task {
        crate::model::InferenceTask::ChatCompletion => parse_chat(object, allow_partial),
        crate::model::InferenceTask::Embedding => parse_embeddings(object, policy),
        crate::model::InferenceTask::Classification => parse_classification(object, policy),
    }
}

fn validate_optional_identity(
    object: &serde_json::Map<String, Value>,
    key: &str,
    expected: &str,
) -> Result<(), MistralInferenceError> {
    if let Some(value) = object.get(key) {
        let actual = value
            .as_str()
            .ok_or(MistralInferenceError::MalformedResponse(
                "identity field must be text",
            ))?;
        if actual != expected {
            return Err(MistralInferenceError::ModelMismatch);
        }
    }
    Ok(())
}

fn reject_forbidden_fields(value: &Value) -> Result<(), MistralInferenceError> {
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
                ) {
                    return Err(MistralInferenceError::ToolCallsForbidden);
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
                ) {
                    return Err(MistralInferenceError::FileAuthorityForbidden);
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
    allow_partial: bool,
) -> Result<SuccessProjection, MistralInferenceError> {
    let choices = object.get("choices").and_then(Value::as_array).ok_or(
        MistralInferenceError::MalformedResponse("chat response choices are missing"),
    )?;
    if choices.len() != 1 {
        return Err(MistralInferenceError::MalformedResponse(
            "Layer-1 accepts exactly one chat choice",
        ));
    }
    let choice = choices[0]
        .as_object()
        .ok_or(MistralInferenceError::MalformedResponse(
            "chat choice is not an object",
        ))?;
    let message = choice.get("message").and_then(Value::as_object);
    let Some(message) = message else {
        if allow_partial {
            return Ok(SuccessProjection {
                content: None,
                embedding: None,
                classification: None,
                usage: parse_chat_usage(object.get("usage"))?,
                finish_reason: None,
            });
        }
        return Err(MistralInferenceError::MalformedResponse(
            "chat message is missing",
        ));
    };
    if message.get("role").and_then(Value::as_str) != Some("assistant") {
        return Err(MistralInferenceError::MalformedResponse(
            "chat result role must be assistant",
        ));
    }
    let content = message.get("content").and_then(Value::as_str);
    let finish_reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .map(|reason| {
            FinishReason::parse(reason).ok_or(MistralInferenceError::MalformedResponse(
                "chat finish reason is empty",
            ))
        })
        .transpose()?;
    if finish_reason == Some(FinishReason::ToolCalls) {
        return Err(MistralInferenceError::ToolCallsForbidden);
    }
    if !allow_partial && (content.is_none() || finish_reason.is_none()) {
        return Err(MistralInferenceError::MalformedResponse(
            "completed chat result content or finish reason is missing",
        ));
    }
    let redacted = content
        .map(|content| RedactedContent::new(content.as_bytes(), 1, ContentKind::Completion))
        .transpose()?;
    Ok(SuccessProjection {
        content: redacted,
        embedding: None,
        classification: None,
        usage: parse_chat_usage(object.get("usage"))?,
        finish_reason,
    })
}

fn parse_chat_usage(
    value: Option<&Value>,
) -> Result<Option<UsageProjection>, MistralInferenceError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or(MistralInferenceError::MalformedResponse(
            "usage must be an object",
        ))?;
    let prompt = required_u64(object, "prompt_tokens")?;
    let completion = required_u64(object, "completion_tokens")?;
    let total = required_u64(object, "total_tokens")?;
    UsageProjection::new(prompt, completion, total).map(Some)
}

fn parse_embeddings(
    object: &serde_json::Map<String, Value>,
    policy: &InferencePolicy,
) -> Result<SuccessProjection, MistralInferenceError> {
    let data = object.get("data").and_then(Value::as_array).ok_or(
        MistralInferenceError::MalformedResponse("embedding data is missing"),
    )?;
    if data.is_empty() || data.len() > policy.max_items().min(MAX_ITEMS) {
        return Err(MistralInferenceError::MalformedResponse(
            "embedding item count is outside the bounded limit",
        ));
    }
    let mut dimensions = None;
    for item in data {
        let item = item
            .as_object()
            .ok_or(MistralInferenceError::MalformedResponse(
                "embedding item is not an object",
            ))?;
        let vector = item
            .get("embedding")
            .ok_or(MistralInferenceError::MalformedResponse(
                "embedding vector is missing",
            ))?;
        let vector = vector
            .as_array()
            .ok_or(MistralInferenceError::MalformedResponse(
                "embedding vector must be an array",
            ))?;
        if vector.is_empty() || vector.len() > policy.max_embedding_dimensions() {
            return Err(MistralInferenceError::MalformedResponse(
                "embedding dimensions are outside the bounded limit",
            ));
        }
        if vector.iter().any(|value| !value.is_number()) {
            return Err(MistralInferenceError::MalformedResponse(
                "embedding vector contains a non-numeric value",
            ));
        }
        if dimensions.is_some_and(|expected| expected != vector.len()) {
            return Err(MistralInferenceError::MalformedResponse(
                "embedding dimensions are inconsistent",
            ));
        }
        dimensions = Some(vector.len());
    }
    let dimensions = dimensions.ok_or(MistralInferenceError::MalformedResponse(
        "embedding dimensions are missing",
    ))?;
    Ok(SuccessProjection {
        content: None,
        embedding: Some(EmbeddingProjection {
            item_count: data.len(),
            dimensions,
            embedding_digest: digest_serializable(data),
        }),
        classification: None,
        usage: parse_chat_usage(object.get("usage"))?,
        finish_reason: None,
    })
}

fn parse_classification(
    object: &serde_json::Map<String, Value>,
    policy: &InferencePolicy,
) -> Result<SuccessProjection, MistralInferenceError> {
    let results = object.get("results").and_then(Value::as_array).ok_or(
        MistralInferenceError::MalformedResponse("classification results are missing"),
    )?;
    if results.is_empty()
        || results.len()
            > policy
                .max_classification_results()
                .min(MAX_CLASSIFICATION_RESULTS)
    {
        return Err(MistralInferenceError::MalformedResponse(
            "classification result count is outside the bounded limit",
        ));
    }
    let mut flagged_count = 0;
    for result in results {
        let result = result
            .as_object()
            .ok_or(MistralInferenceError::MalformedResponse(
                "classification result is not an object",
            ))?;
        if let Some(categories) = result.get("categories").and_then(Value::as_object) {
            flagged_count += categories
                .values()
                .filter(|value| value.as_bool() == Some(true))
                .count();
        }
        if result.get("categories").is_none() && result.get("category_scores").is_none() {
            return Err(MistralInferenceError::MalformedResponse(
                "classification result metadata is missing",
            ));
        }
    }
    Ok(SuccessProjection {
        content: None,
        embedding: None,
        classification: Some(ClassificationProjection {
            result_count: results.len(),
            flagged_count,
            metadata_digest: digest_serializable(results),
        }),
        usage: None,
        finish_reason: None,
    })
}

fn required_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u64, MistralInferenceError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(MistralInferenceError::MalformedResponse(
            "numeric response field is missing or invalid",
        ))
}

fn state_from_body(body: &[u8]) -> Result<InferenceResultState, MistralInferenceError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| MistralInferenceError::MalformedResponse("body is not valid JSON"))?;
    let Some(object) = value.as_object() else {
        return Ok(InferenceResultState::Completed);
    };
    let Some(status) = object.get("status").or_else(|| object.get("state")) else {
        return Ok(InferenceResultState::Completed);
    };
    let status = status
        .as_str()
        .ok_or(MistralInferenceError::MalformedResponse(
            "lifecycle status must be text",
        ))?;
    Ok(match status {
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
) -> Result<(ProviderFailureClass, bool, InferenceResultState), MistralInferenceError> {
    let result = match status {
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
        413 | 422 => (
            ProviderFailureClass::InvalidRequest,
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
        _ => return Err(MistralInferenceError::UnsupportedStatus(status)),
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
    MISTRAL_INFERENCE_PROVIDER_ID
}
