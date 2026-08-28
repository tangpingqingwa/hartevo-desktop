//! Typed, bounded contract values for the direct `OpenAI` Responses result seam.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    OPENAI_RESPONSES_RESULT_CONTRACT_JSON, OPENAI_RESPONSES_RESULT_CONTRACT_VERSION,
    OPENAI_RESPONSES_RESULT_PLUGIN_VERSION, OPENAI_RESPONSES_RESULT_PROVIDER_ID,
    OPENAI_RESPONSES_RESULT_SCHEMA_VERSION, digest_bytes, digest_serializable,
};

pub const DEFAULT_OPENAI_RESPONSES_API_HOST: &str = "https://api.openai.com";
pub const DEFAULT_OPENAI_RESPONSES_ENDPOINT: &str = "/v1/responses";
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REFERENCE_BYTES: usize = 256;
pub const MAX_MODEL_BYTES: usize = 128;
pub const MAX_POLICY_REVISION_BYTES: usize = 128;
pub const MAX_SCHEMA_BYTES: usize = 128 * 1024;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_INPUT_ITEMS: usize = 64;
pub const MAX_IMAGE_REFERENCES: usize = 16;
pub const MAX_FILE_REFERENCES: usize = 16;
pub const MAX_OUTPUT_TOKENS: u64 = 32_768;
pub const MAX_INPUT_TOKENS: u64 = 1_000_000;
pub const MAX_LATENCY_MS: u64 = 10 * 60 * 1_000;
pub const MAX_COST_MICROS: u64 = 10_000_000;
pub const MAX_PREVIEW_CHARS: usize = 1_024;

/// Every error is a safe projection and contains no provider body or secret.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpenAIResponsesResultError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("scope mismatch: {0}")]
    ScopeMismatch(&'static str),
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration binding is stale or tampered")]
    RegistrationTampered,
    #[error("proposal digest does not match its immutable contents")]
    ProposalTampered,
    #[error("response evidence digest does not match its immutable contents")]
    EvidenceTampered,
    #[error("request is not bound to the pinned model snapshot")]
    ModelSnapshotMismatch,
    #[error("request is not bound to the pinned project")]
    ProjectMismatch,
    #[error("request is not bound to the pinned Mission")]
    MissionMismatch,
    #[error("request is not bound to the pinned Work Product")]
    WorkProductMismatch,
    #[error("input policy binding drifted")]
    InputPolicyDrift,
    #[error("structured output schema binding drifted")]
    StructuredSchemaMismatch,
    #[error("tool policy violation; Layer-1 tools are disabled")]
    ToolPolicyViolation,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("consent binding drifted")]
    ConsentDrift,
    #[error("input exceeds the configured byte bound")]
    InputTooLarge,
    #[error("input item count exceeds the configured bound")]
    InputItemCountExceeded,
    #[error("text input exceeds the configured bound")]
    TextInputTooLarge,
    #[error("image-reference count exceeds the configured bound")]
    ImageReferenceCountExceeded,
    #[error("file-reference count exceeds the configured bound")]
    FileReferenceCountExceeded,
    #[error("file reference is not declared by the input policy")]
    UndeclaredFileReference,
    #[error("input kind is not allowed by the input policy")]
    InputKindForbidden,
    #[error("input token ceiling exceeds the configured bound")]
    InputTokenCeilingExceeded,
    #[error("output token ceiling exceeds the configured bound")]
    OutputTokenCeilingExceeded,
    #[error("latency ceiling exceeds the configured bound")]
    LatencyCeilingExceeded,
    #[error("cost ceiling exceeds the configured bound")]
    CostCeilingExceeded,
    #[error("output exceeds the configured byte bound")]
    OutputTooLarge,
    #[error("response body is truncated")]
    ResponseTruncated,
    #[error("provider response is malformed or partial: {0}")]
    MalformedResponse(&'static str),
    #[error("structured output does not satisfy the pinned strict JSON schema")]
    StructuredOutputInvalid,
    #[error("provider returned an unsupported HTTP status: {0}")]
    UnsupportedHttpStatus(u16),
    #[error("provider frame identity does not match the proposal")]
    ProviderIdentityMismatch,
    #[error("provider response is unavailable in BLOCKED_ENV: {0}")]
    BlockedEnvironment(&'static str),
    #[error("a provider recording was replayed")]
    ReplayDetected,
    #[error("native provider execution is a Layer-2 gap")]
    NativeExecutionUnavailable,
}

/// SHA-256 digest used to fence externally meaningful values.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        digest_bytes(bytes.as_ref())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    pub(crate) fn from_hex(bytes: impl AsRef<[u8]>) -> Self {
        Self(crate::hex_encode(bytes))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

/// Opaque host-owned secret binding.
///
/// The opaque handle is hashed at construction and is never retained,
/// serialized, or displayed. Native credential resolution is intentionally
/// outside this crate.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: SecretKind,
    revision: u64,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, OpenAIResponsesResultError> {
        Self::with_kind(opaque_reference, SecretKind::ApiKey, revision)
    }

    pub fn with_kind(
        opaque_reference: impl AsRef<str>,
        kind: SecretKind,
        revision: u64,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }
        if revision == 0 {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "secret_reference_revision",
                reason: "must be non-zero",
            });
        }
        let mut material = b"hartevo:openai-responses-secret-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        material.push(match kind {
            SecretKind::ApiKey => 0,
        });
        Ok(Self {
            reference_digest: digest_bytes(&material),
            kind,
            revision,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAIResponsesPermission {
    ResponsesCreate,
}

/// Organization permission and its opaque host-owned credential reference.
#[derive(Clone, Eq, PartialEq)]
pub struct PermissionScope {
    permission: OpenAIResponsesPermission,
    secret_reference: SecretReference,
}

impl PermissionScope {
    pub fn new(permission: OpenAIResponsesPermission, secret_reference: SecretReference) -> Self {
        Self {
            permission,
            secret_reference,
        }
    }

    pub const fn permission(&self) -> OpenAIResponsesPermission {
        self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.permission,
            self.secret_reference.reference_digest(),
            self.secret_reference.revision(),
        ))
    }
}

impl fmt::Debug for PermissionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PermissionScope")
            .field("permission", &self.permission)
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrganizationScope {
    id: String,
    revision: u64,
}

impl OrganizationScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAIResponsesResultError> {
        let id = bounded_scope_id("organization_id", id.into())?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: u64,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAIResponsesResultError> {
        let id = bounded_scope_id("project_id", id.into())?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: String,
    revision: u64,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAIResponsesResultError> {
        let id = bounded_scope_id("mission_id", id.into())?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: String,
    revision: u64,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAIResponsesResultError> {
        let id = bounded_scope_id("work_product_id", id.into())?;
        Ok(Self { id, revision })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

fn bounded_scope_id(field: &'static str, id: String) -> Result<String, OpenAIResponsesResultError> {
    if id.trim().is_empty() || id.len() > MAX_IDENTIFIER_BYTES || id.chars().any(char::is_control) {
        return Err(OpenAIResponsesResultError::InvalidField {
            field,
            reason: "must be a bounded non-empty scope identifier",
        });
    }
    Ok(id)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAIResponsesProviderScope {
    provider_id: String,
    api_host: String,
    endpoint: String,
}

impl OpenAIResponsesProviderScope {
    pub fn new(
        provider_id: impl Into<String>,
        api_host: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let provider_id = provider_id.into();
        let api_host = api_host.into().trim_end_matches('/').to_owned();
        let endpoint = endpoint.into();
        if provider_id != OPENAI_RESPONSES_RESULT_PROVIDER_ID {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "provider_id",
                reason: "must be the explicit OpenAI Responses provider",
            });
        }
        if api_host != DEFAULT_OPENAI_RESPONSES_API_HOST
            || api_host.contains('?')
            || api_host.contains('#')
            || api_host.chars().any(char::is_whitespace)
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "api_host",
                reason: "must be the fixed HTTPS OpenAI API host",
            });
        }
        if endpoint != DEFAULT_OPENAI_RESPONSES_ENDPOINT {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "endpoint",
                reason: "must be the direct Responses endpoint",
            });
        }
        Ok(Self {
            provider_id,
            api_host,
            endpoint,
        })
    }

    pub fn openai() -> Self {
        Self {
            provider_id: OPENAI_RESPONSES_RESULT_PROVIDER_ID.to_owned(),
            api_host: DEFAULT_OPENAI_RESPONSES_API_HOST.to_owned(),
            endpoint: DEFAULT_OPENAI_RESPONSES_ENDPOINT.to_owned(),
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn api_host(&self) -> &str {
        &self.api_host
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelSnapshot {
    model_id: String,
    immutable_snapshot: String,
}

impl ModelSnapshot {
    pub fn new(
        model_id: impl Into<String>,
        immutable_snapshot: impl Into<String>,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let model_id = model_id.into();
        let immutable_snapshot = immutable_snapshot.into();
        validate_model_part("model_id", &model_id)?;
        validate_model_part("immutable_model_snapshot", &immutable_snapshot)?;
        if matches!(
            immutable_snapshot.as_str(),
            "latest" | "default" | "auto" | "main" | "master"
        ) {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "immutable_model_snapshot",
                reason: "must be pinned and cannot be a floating alias",
            });
        }
        Ok(Self {
            model_id,
            immutable_snapshot,
        })
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn immutable_snapshot(&self) -> &str {
        &self.immutable_snapshot
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub(crate) fn matches_api_model(&self, value: &str) -> bool {
        value == self.immutable_snapshot
            || (self.model_id == self.immutable_snapshot && value == self.model_id)
    }
}

fn validate_model_part(field: &'static str, value: &str) -> Result<(), OpenAIResponsesResultError> {
    if value.trim().is_empty()
        || value.len() > MAX_MODEL_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(OpenAIResponsesResultError::InvalidField {
            field,
            reason: "must be a bounded non-empty model value without whitespace",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRetentionMode {
    DigestOnly,
    BoundedPrefix,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputRetentionPolicy {
    mode: OutputRetentionMode,
    preview_chars: usize,
}

impl OutputRetentionPolicy {
    pub const fn digest_only() -> Self {
        Self {
            mode: OutputRetentionMode::DigestOnly,
            preview_chars: 0,
        }
    }

    pub fn bounded_prefix(preview_chars: usize) -> Result<Self, OpenAIResponsesResultError> {
        if preview_chars == 0 || preview_chars > MAX_PREVIEW_CHARS {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "output_retention_policy",
                reason: "prefix preview must be bounded and non-zero",
            });
        }
        Ok(Self {
            mode: OutputRetentionMode::BoundedPrefix,
            preview_chars,
        })
    }

    pub const fn mode(self) -> OutputRetentionMode {
        self.mode
    }

    pub const fn preview_chars(self) -> usize {
        self.preview_chars
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputPolicy {
    revision: String,
    max_input_bytes: usize,
    max_text_bytes: usize,
    max_items: usize,
    max_image_references: usize,
    max_file_references: usize,
    max_output_bytes: usize,
    max_input_tokens: u64,
    max_output_tokens: u64,
    max_latency_ms: u64,
    max_cost_micros: u64,
    output_retention: OutputRetentionPolicy,
    declared_file_references: BTreeSet<Digest>,
}

impl InputPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: impl Into<String>,
        max_input_bytes: usize,
        max_output_bytes: usize,
        max_input_tokens: u64,
        max_output_tokens: u64,
        max_latency_ms: u64,
        max_cost_micros: u64,
        output_retention: OutputRetentionPolicy,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let revision = revision.into();
        if revision.trim().is_empty()
            || revision.len() > MAX_POLICY_REVISION_BYTES
            || revision
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_policy_revision",
                reason: "must be a bounded non-empty revision",
            });
        }
        if max_input_bytes == 0
            || max_input_bytes > MAX_INPUT_BYTES
            || max_output_bytes == 0
            || max_output_bytes > MAX_OUTPUT_BYTES
            || max_input_tokens == 0
            || max_input_tokens > MAX_INPUT_TOKENS
            || max_output_tokens == 0
            || max_output_tokens > MAX_OUTPUT_TOKENS
            || max_latency_ms == 0
            || max_latency_ms > MAX_LATENCY_MS
            || max_cost_micros == 0
            || max_cost_micros > MAX_COST_MICROS
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_policy",
                reason: "one or more ceilings are outside the Layer-1 bounds",
            });
        }
        Ok(Self {
            revision,
            max_text_bytes: max_input_bytes.min(MAX_TEXT_BYTES),
            max_items: MAX_INPUT_ITEMS,
            max_image_references: MAX_IMAGE_REFERENCES,
            max_file_references: MAX_FILE_REFERENCES,
            max_input_bytes,
            max_output_bytes,
            max_input_tokens,
            max_output_tokens,
            max_latency_ms,
            max_cost_micros,
            output_retention,
            declared_file_references: BTreeSet::new(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), OpenAIResponsesResultError> {
        if self.revision.trim().is_empty()
            || self.revision.len() > MAX_POLICY_REVISION_BYTES
            || self
                .revision
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_INPUT_BYTES
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_OUTPUT_BYTES
            || self.max_input_tokens == 0
            || self.max_input_tokens > MAX_INPUT_TOKENS
            || self.max_output_tokens == 0
            || self.max_output_tokens > MAX_OUTPUT_TOKENS
            || self.max_latency_ms == 0
            || self.max_latency_ms > MAX_LATENCY_MS
            || self.max_cost_micros == 0
            || self.max_cost_micros > MAX_COST_MICROS
            || self.max_text_bytes == 0
            || self.max_text_bytes > self.max_input_bytes
            || self.max_text_bytes > MAX_TEXT_BYTES
            || self.max_items == 0
            || self.max_items > MAX_INPUT_ITEMS
            || self.max_image_references > MAX_IMAGE_REFERENCES
            || self.max_file_references > MAX_FILE_REFERENCES
            || (self.output_retention.mode() == OutputRetentionMode::DigestOnly
                && self.output_retention.preview_chars() != 0)
            || (self.output_retention.mode() == OutputRetentionMode::BoundedPrefix
                && (self.output_retention.preview_chars() == 0
                    || self.output_retention.preview_chars() > MAX_PREVIEW_CHARS))
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_policy",
                reason: "one or more policy values are outside the Layer-1 bounds",
            });
        }
        Ok(())
    }

    pub fn conservative(revision: impl Into<String>) -> Result<Self, OpenAIResponsesResultError> {
        Self::new(
            revision,
            256 * 1024,
            512 * 1024,
            32_768,
            8_192,
            120_000,
            1_000_000,
            OutputRetentionPolicy::digest_only(),
        )
    }

    pub fn with_item_bounds(
        mut self,
        max_text_bytes: usize,
        max_items: usize,
        max_image_references: usize,
        max_file_references: usize,
    ) -> Result<Self, OpenAIResponsesResultError> {
        if max_text_bytes == 0
            || max_text_bytes > self.max_input_bytes
            || max_text_bytes > MAX_TEXT_BYTES
            || max_items == 0
            || max_items > MAX_INPUT_ITEMS
            || max_image_references > MAX_IMAGE_REFERENCES
            || max_file_references > MAX_FILE_REFERENCES
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_policy_item_bounds",
                reason: "item bounds exceed the Layer-1 limits",
            });
        }
        self.max_text_bytes = max_text_bytes;
        self.max_items = max_items;
        self.max_image_references = max_image_references;
        self.max_file_references = max_file_references;
        Ok(self)
    }

    #[must_use]
    pub fn with_declared_file_reference(mut self, reference: &FileReference) -> Self {
        self.declared_file_references
            .insert(reference.reference_digest().clone());
        self
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub const fn max_text_bytes(&self) -> usize {
        self.max_text_bytes
    }

    pub const fn max_items(&self) -> usize {
        self.max_items
    }

    pub const fn max_image_references(&self) -> usize {
        self.max_image_references
    }

    pub const fn max_file_references(&self) -> usize {
        self.max_file_references
    }

    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub const fn max_input_tokens(&self) -> u64 {
        self.max_input_tokens
    }

    pub const fn max_output_tokens(&self) -> u64 {
        self.max_output_tokens
    }

    pub const fn max_latency_ms(&self) -> u64 {
        self.max_latency_ms
    }

    pub const fn max_cost_micros(&self) -> u64 {
        self.max_cost_micros
    }

    pub const fn output_retention(&self) -> OutputRetentionPolicy {
        self.output_retention
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub(crate) fn is_file_declared(&self, reference: &FileReference) -> bool {
        self.declared_file_references
            .contains(reference.reference_digest())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StructuredOutputSchema {
    name: String,
    schema: Value,
    schema_digest: Digest,
}

impl StructuredOutputSchema {
    pub fn new(
        name: impl Into<String>,
        schema: Value,
        strict: bool,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let name = name.into();
        if name.trim().is_empty()
            || name.len() > MAX_IDENTIFIER_BYTES
            || name
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "structured_output_schema.name",
                reason: "must be a bounded non-empty name",
            });
        }
        if !strict {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "structured_output_schema.strict",
                reason: "Layer-1 accepts only strict JSON schemas",
            });
        }
        let encoded =
            serde_json::to_vec(&schema).map_err(|_| OpenAIResponsesResultError::InvalidField {
                field: "structured_output_schema",
                reason: "schema must be JSON serializable",
            })?;
        if encoded.is_empty() || encoded.len() > MAX_SCHEMA_BYTES {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "structured_output_schema",
                reason: "schema exceeds the bounded JSON-schema size",
            });
        }
        validate_strict_schema(&schema)?;
        let schema_digest = digest_bytes(&encoded);
        Ok(Self {
            name,
            schema,
            schema_digest,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub const fn strict(&self) -> bool {
        true
    }

    pub fn schema(&self) -> &Value {
        &self.schema
    }
}

impl fmt::Debug for StructuredOutputSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructuredOutputSchema")
            .field("name", &self.name)
            .field("strict", &true)
            .field(
                "schema_bytes",
                &serde_json::to_vec(&self.schema).map_or(0, |bytes| bytes.len()),
            )
            .field("schema_digest", &self.schema_digest)
            .finish()
    }
}

fn validate_strict_schema(schema: &Value) -> Result<(), OpenAIResponsesResultError> {
    let object = schema
        .as_object()
        .ok_or(OpenAIResponsesResultError::InvalidField {
            field: "structured_output_schema",
            reason: "root must be a JSON object schema",
        })?;
    if object.get("type").and_then(Value::as_str) != Some("object") {
        return Err(OpenAIResponsesResultError::InvalidField {
            field: "structured_output_schema.type",
            reason: "strict Layer-1 schemas must have an object root",
        });
    }
    validate_schema_node(schema)
}

fn validate_schema_node(value: &Value) -> Result<(), OpenAIResponsesResultError> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if object.get("type").and_then(Value::as_str) == Some("object")
        && object.contains_key("properties")
        && object.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(OpenAIResponsesResultError::InvalidField {
            field: "structured_output_schema.additionalProperties",
            reason: "strict object schemas must set additionalProperties to false",
        });
    }
    for child in object.values() {
        match child {
            Value::Object(_) => validate_schema_node(child)?,
            Value::Array(values) => {
                for value in values {
                    validate_schema_node(value)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPolicyMode {
    Disabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolPolicy {
    mode: ToolPolicyMode,
    web_search: bool,
    max_tools: u8,
}

impl ToolPolicy {
    pub const fn disabled() -> Self {
        Self {
            mode: ToolPolicyMode::Disabled,
            web_search: false,
            max_tools: 0,
        }
    }

    pub fn with_tools(
        _max_tools: u8,
        _web_search: bool,
    ) -> Result<Self, OpenAIResponsesResultError> {
        Err(OpenAIResponsesResultError::ToolPolicyViolation)
    }

    pub const fn mode(self) -> ToolPolicyMode {
        self.mode
    }

    pub const fn tools_enabled(self) -> bool {
        self.max_tools != 0
    }

    pub const fn web_search_enabled(self) -> bool {
        self.web_search
    }

    pub fn digest(self) -> Digest {
        digest_serializable(&self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    id: String,
    revision: u64,
    output_retention: OutputRetentionPolicy,
    allow_content_digest: bool,
    allow_bounded_preview: bool,
}

impl ConsentScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        output_retention: OutputRetentionPolicy,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let id = bounded_scope_id("consent_id", id.into())?;
        Ok(Self {
            id,
            revision,
            output_retention,
            allow_content_digest: true,
            allow_bounded_preview: output_retention.mode() == OutputRetentionMode::BoundedPrefix,
        })
    }

    pub fn digest_only(
        id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, OpenAIResponsesResultError> {
        Self::new(id, revision, OutputRetentionPolicy::digest_only())
    }

    pub fn bounded_prefix(
        id: impl Into<String>,
        revision: u64,
        preview_chars: usize,
    ) -> Result<Self, OpenAIResponsesResultError> {
        Self::new(
            id,
            revision,
            OutputRetentionPolicy::bounded_prefix(preview_chars)?,
        )
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn output_retention(&self) -> OutputRetentionPolicy {
        self.output_retention
    }

    pub const fn allow_content_digest(&self) -> bool {
        self.allow_content_digest
    }

    pub const fn allow_bounded_preview(&self) -> bool {
        self.allow_bounded_preview
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpenAIResponsesScope {
    provider: OpenAIResponsesProviderScope,
    organization: OrganizationScope,
    project: ProjectScope,
    permission: PermissionScope,
    model: ModelSnapshot,
    input_policy: InputPolicy,
    structured_output_schema: Option<StructuredOutputSchema>,
    tool_policy: ToolPolicy,
    mission: MissionScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
}

impl OpenAIResponsesScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: OpenAIResponsesProviderScope,
        organization: OrganizationScope,
        project: ProjectScope,
        permission: PermissionScope,
        model: ModelSnapshot,
        input_policy: InputPolicy,
        structured_output_schema: Option<StructuredOutputSchema>,
        tool_policy: ToolPolicy,
        mission: MissionScope,
        work_product: WorkProductScope,
        consent: ConsentScope,
    ) -> Result<Self, OpenAIResponsesResultError> {
        input_policy.validate()?;
        if tool_policy.tools_enabled() || tool_policy.web_search_enabled() {
            return Err(OpenAIResponsesResultError::ToolPolicyViolation);
        }
        if input_policy.output_retention() != consent.output_retention()
            || !consent.allow_content_digest()
            || (input_policy.output_retention().mode() == OutputRetentionMode::BoundedPrefix
                && !consent.allow_bounded_preview())
        {
            return Err(OpenAIResponsesResultError::ConsentDrift);
        }
        Ok(Self {
            provider,
            organization,
            project,
            permission,
            model,
            input_policy,
            structured_output_schema,
            tool_policy,
            mission,
            work_product,
            consent,
        })
    }

    pub fn provider(&self) -> &OpenAIResponsesProviderScope {
        &self.provider
    }

    pub fn organization(&self) -> &OrganizationScope {
        &self.organization
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn model(&self) -> &ModelSnapshot {
        &self.model
    }

    pub fn input_policy(&self) -> &InputPolicy {
        &self.input_policy
    }

    pub fn structured_output_schema(&self) -> Option<&StructuredOutputSchema> {
        self.structured_output_schema.as_ref()
    }

    pub const fn tool_policy(&self) -> ToolPolicy {
        self.tool_policy
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn provider_digest(&self) -> Digest {
        self.provider.digest()
    }

    pub fn organization_digest(&self) -> Digest {
        self.organization.digest()
    }

    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn model_digest(&self) -> Digest {
        self.model.digest()
    }

    pub fn input_policy_digest(&self) -> Digest {
        self.input_policy.digest()
    }

    pub fn structured_schema_digest(&self) -> Option<Digest> {
        self.structured_output_schema
            .as_ref()
            .map(|schema| schema.schema_digest().clone())
    }

    pub fn tool_policy_digest(&self) -> Digest {
        self.tool_policy.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&ScopeDigestMaterial {
            provider: &self.provider,
            organization: &self.organization,
            project: &self.project,
            permission_digest: self.permission.digest(),
            model: &self.model,
            input_policy: &self.input_policy,
            structured_schema_digest: self.structured_schema_digest(),
            tool_policy: self.tool_policy,
            mission: &self.mission,
            work_product: &self.work_product,
            consent: &self.consent,
        })
    }
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    provider: &'a OpenAIResponsesProviderScope,
    organization: &'a OrganizationScope,
    project: &'a ProjectScope,
    permission_digest: Digest,
    model: &'a ModelSnapshot,
    input_policy: &'a InputPolicy,
    structured_schema_digest: Option<Digest>,
    tool_policy: ToolPolicy,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    consent: &'a ConsentScope,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSnapshot<'a> {
    provider: &'a OpenAIResponsesProviderScope,
    organization: &'a OrganizationScope,
    project: &'a ProjectScope,
    permission: OpenAIResponsesPermission,
    secret_reference_digest: &'a Digest,
    model: &'a ModelSnapshot,
    input_policy: &'a InputPolicy,
    structured_schema_digest: Option<Digest>,
    tool_policy: ToolPolicy,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    consent: &'a ConsentScope,
}

impl Serialize for OpenAIResponsesScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ScopeSnapshot {
            provider: &self.provider,
            organization: &self.organization,
            project: &self.project,
            permission: self.permission.permission,
            secret_reference_digest: self.permission.secret_reference.reference_digest(),
            model: &self.model,
            input_policy: &self.input_policy,
            structured_schema_digest: self.structured_schema_digest(),
            tool_policy: self.tool_policy,
            mission: &self.mission,
            work_product: &self.work_product,
            consent: &self.consent,
        }
        .serialize(serializer)
    }
}

impl fmt::Debug for OpenAIResponsesScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAIResponsesScope")
            .field("provider", &self.provider)
            .field("organization", &self.organization)
            .field("project", &self.project)
            .field("permission", &self.permission)
            .field("model", &self.model)
            .field("input_policy", &self.input_policy)
            .field("structured_output_schema", &self.structured_output_schema)
            .field("tool_policy", &self.tool_policy)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("consent", &self.consent)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Text,
    Multimodal,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ImageReference {
    reference_digest: Digest,
    media_type: String,
}

impl ImageReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        media_type: impl Into<String>,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let opaque_reference = opaque_reference.as_ref();
        let media_type = media_type.into();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || opaque_reference.starts_with("data:")
            || opaque_reference.starts_with("file:")
            || !(opaque_reference.starts_with("https://")
                || opaque_reference.starts_with("image-")
                || opaque_reference.starts_with("ref:"))
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "image_reference",
                reason: "must be a bounded HTTPS or opaque image reference, never bytes",
            });
        }
        if !matches!(
            media_type.as_str(),
            "image/png" | "image/jpeg" | "image/webp" | "image/gif"
        ) {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "image_media_type",
                reason: "must be an allowlisted image media type",
            });
        }
        let reference_digest = digest_bytes(opaque_reference.as_bytes());
        Ok(Self {
            reference_digest,
            media_type,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}

impl fmt::Debug for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageReference")
            .field("reference_digest", &self.reference_digest)
            .field("media_type", &self.media_type)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct FileReference {
    reference_digest: Digest,
}

impl FileReference {
    pub fn new(opaque_reference: impl AsRef<str>) -> Result<Self, OpenAIResponsesResultError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || opaque_reference.starts_with("data:")
            || opaque_reference.starts_with('/')
            || opaque_reference.starts_with("file:")
            || !(opaque_reference.starts_with("file-")
                || opaque_reference.starts_with("file_ref:")
                || opaque_reference.starts_with("ref:"))
        {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "file_reference",
                reason: "must be a bounded declared opaque file reference, never a path or bytes",
            });
        }
        Ok(Self {
            reference_digest: digest_bytes(opaque_reference.as_bytes()),
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }
}

impl fmt::Debug for FileReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileReference")
            .field("reference_digest", &self.reference_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ResponsesInputItem {
    Text(String),
    ImageReference(ImageReference),
    FileReference(FileReference),
}

impl ResponsesInputItem {
    pub fn text(value: impl Into<String>) -> Result<Self, OpenAIResponsesResultError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_text",
                reason: "must be non-empty and free of control characters",
            });
        }
        Ok(Self::Text(value))
    }

    pub fn image_reference(reference: ImageReference) -> Self {
        Self::ImageReference(reference)
    }

    pub fn file_reference(reference: FileReference) -> Self {
        Self::FileReference(reference)
    }
}

impl fmt::Debug for ResponsesInputItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(value) => formatter
                .debug_struct("ResponsesInputItem::Text")
                .field("bytes", &value.len())
                .field("digest", &digest_bytes(value.as_bytes()))
                .finish(),
            Self::ImageReference(reference) => formatter
                .debug_tuple("ResponsesInputItem::ImageReference")
                .field(reference)
                .finish(),
            Self::FileReference(reference) => formatter
                .debug_tuple("ResponsesInputItem::FileReference")
                .field(reference)
                .finish(),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum ResponsesInput {
    Text(String),
    Items(Vec<ResponsesInputItem>),
}

impl ResponsesInput {
    pub fn text(value: impl Into<String>) -> Result<Self, OpenAIResponsesResultError> {
        Ok(Self::Text(match ResponsesInputItem::text(value)? {
            ResponsesInputItem::Text(value) => value,
            ResponsesInputItem::ImageReference(_) | ResponsesInputItem::FileReference(_) => {
                unreachable!("text constructor only creates text")
            }
        }))
    }

    pub fn items(items: Vec<ResponsesInputItem>) -> Result<Self, OpenAIResponsesResultError> {
        if items.is_empty() {
            return Err(OpenAIResponsesResultError::InvalidField {
                field: "input_items",
                reason: "must contain at least one bounded input item",
            });
        }
        Ok(Self::Items(items))
    }

    pub fn kind(&self) -> InputKind {
        match self {
            Self::Text(_) => InputKind::Text,
            Self::Items(_) => InputKind::Multimodal,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), OpenAIResponsesResultError> {
        match self {
            Self::Text(value) => validate_input_text(value),
            Self::Items(items) => {
                if items.is_empty() {
                    return Err(OpenAIResponsesResultError::InvalidField {
                        field: "input_items",
                        reason: "must contain at least one bounded input item",
                    });
                }
                for item in items {
                    if let ResponsesInputItem::Text(value) = item {
                        validate_input_text(value)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub(crate) fn item_count(&self) -> usize {
        match self {
            Self::Text(_) => 1,
            Self::Items(items) => items.len(),
        }
    }

    pub(crate) fn text_bytes(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Items(items) => items
                .iter()
                .map(|item| match item {
                    ResponsesInputItem::Text(value) => value.len(),
                    ResponsesInputItem::ImageReference(reference) => reference.media_type.len(),
                    ResponsesInputItem::FileReference(_) => 0,
                })
                .sum(),
        }
    }

    pub(crate) fn byte_len(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Items(items) => items
                .iter()
                .map(|item| match item {
                    ResponsesInputItem::Text(value) => value.len(),
                    ResponsesInputItem::ImageReference(reference) => {
                        reference.reference_digest.as_str().len() + reference.media_type.len()
                    }
                    ResponsesInputItem::FileReference(reference) => {
                        reference.reference_digest.as_str().len()
                    }
                })
                .sum(),
        }
    }

    pub(crate) fn image_count(&self) -> usize {
        match self {
            Self::Text(_) => 0,
            Self::Items(items) => items
                .iter()
                .filter(|item| matches!(item, ResponsesInputItem::ImageReference(_)))
                .count(),
        }
    }

    pub(crate) fn file_count(&self) -> usize {
        match self {
            Self::Text(_) => 0,
            Self::Items(items) => items
                .iter()
                .filter(|item| matches!(item, ResponsesInputItem::FileReference(_)))
                .count(),
        }
    }

    pub(crate) fn undeclared_file(&self, policy: &InputPolicy) -> bool {
        match self {
            Self::Text(_) => false,
            Self::Items(items) => items.iter().any(|item| match item {
                ResponsesInputItem::FileReference(reference) => !policy.is_file_declared(reference),
                ResponsesInputItem::Text(_) | ResponsesInputItem::ImageReference(_) => false,
            }),
        }
    }

    pub(crate) fn digest(&self) -> Digest {
        match self {
            Self::Text(value) => digest_serializable(&("text", digest_bytes(value.as_bytes()))),
            Self::Items(items) => {
                let descriptors: Vec<_> = items
                    .iter()
                    .map(|item| match item {
                        ResponsesInputItem::Text(value) => {
                            ("text", digest_bytes(value.as_bytes()), None::<Digest>)
                        }
                        ResponsesInputItem::ImageReference(reference) => (
                            "image_reference",
                            reference.reference_digest.clone(),
                            Some(digest_bytes(reference.media_type.as_bytes())),
                        ),
                        ResponsesInputItem::FileReference(reference) => {
                            ("file_reference", reference.reference_digest.clone(), None)
                        }
                    })
                    .collect();
                digest_serializable(&("items", descriptors))
            }
        }
    }
}

fn validate_input_text(value: &str) -> Result<(), OpenAIResponsesResultError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OpenAIResponsesResultError::InvalidField {
            field: "input_text",
            reason: "must be non-empty and free of control characters",
        });
    }
    Ok(())
}

impl fmt::Debug for ResponsesInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponsesInput")
            .field("kind", &self.kind())
            .field("item_count", &self.item_count())
            .field("bytes", &self.byte_len())
            .field("input_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, OpenAIResponsesResultError> {
        Ok(Self(bounded_identifier("request_id", value.into())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseId(String);

impl ResponseId {
    pub fn new(value: impl Into<String>) -> Result<Self, OpenAIResponsesResultError> {
        Ok(Self(bounded_identifier("response_id", value.into())?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn bounded_identifier(
    field: &'static str,
    value: String,
) -> Result<String, OpenAIResponsesResultError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(OpenAIResponsesResultError::InvalidField {
            field,
            reason: "must be a bounded non-empty identifier",
        });
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAIResponsesRequest {
    request_id: RequestId,
    input: ResponsesInput,
    structured_output_schema: Option<StructuredOutputSchema>,
    tool_policy: ToolPolicy,
}

impl OpenAIResponsesRequest {
    pub fn new(request_id: RequestId, input: ResponsesInput) -> Self {
        Self {
            request_id,
            input,
            structured_output_schema: None,
            tool_policy: ToolPolicy::disabled(),
        }
    }

    #[must_use]
    pub fn with_structured_output_schema(mut self, schema: StructuredOutputSchema) -> Self {
        self.structured_output_schema = Some(schema);
        self
    }

    pub fn with_tool_policy(
        mut self,
        policy: ToolPolicy,
    ) -> Result<Self, OpenAIResponsesResultError> {
        if policy.tools_enabled() || policy.web_search_enabled() {
            return Err(OpenAIResponsesResultError::ToolPolicyViolation);
        }
        self.tool_policy = policy;
        Ok(self)
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn input(&self) -> &ResponsesInput {
        &self.input
    }

    pub fn structured_output_schema(&self) -> Option<&StructuredOutputSchema> {
        self.structured_output_schema.as_ref()
    }

    pub const fn tool_policy(&self) -> ToolPolicy {
        self.tool_policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputDescriptor {
    kind: InputKind,
    item_count: usize,
    input_bytes: usize,
    text_bytes: usize,
    image_references: usize,
    file_references: usize,
    input_digest: Digest,
}

impl InputDescriptor {
    pub(crate) fn from_input(input: &ResponsesInput) -> Self {
        Self {
            kind: input.kind(),
            item_count: input.item_count(),
            input_bytes: input.byte_len(),
            text_bytes: input.text_bytes(),
            image_references: input.image_count(),
            file_references: input.file_count(),
            input_digest: input.digest(),
        }
    }

    pub const fn kind(&self) -> InputKind {
        self.kind
    }

    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub const fn text_bytes(&self) -> usize {
        self.text_bytes
    }

    pub const fn image_references(&self) -> usize {
        self.image_references
    }

    pub const fn file_references(&self) -> usize {
        self.file_references
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAIResponsesProposal {
    pub request_id: RequestIdProjection,
    pub input: InputDescriptor,
    pub structured_schema_digest: Option<Digest>,
    pub tool_policy_digest: Digest,
    pub provider_digest: Digest,
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub model_snapshot_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub input_policy_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RequestIdProjection(String);

impl RequestIdProjection {
    pub(crate) fn from_id(id: &RequestId) -> Self {
        Self(id.0.clone())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl OpenAIResponsesProposal {
    pub(crate) fn new(
        scope: &OpenAIResponsesScope,
        registration: &PluginRegistration,
        request: &OpenAIResponsesRequest,
    ) -> Self {
        let input = InputDescriptor::from_input(request.input());
        let structured_schema_digest = request
            .structured_output_schema()
            .map(|schema| schema.schema_digest().clone());
        let mut proposal = Self {
            request_id: RequestIdProjection::from_id(request.request_id()),
            input,
            structured_schema_digest,
            tool_policy_digest: request.tool_policy().digest(),
            provider_digest: scope.provider_digest(),
            organization_digest: scope.organization_digest(),
            project_digest: scope.project_digest(),
            model_snapshot_digest: scope.model_digest(),
            mission_digest: scope.mission_digest(),
            work_product_digest: scope.work_product_digest(),
            consent_digest: scope.consent_digest(),
            input_policy_digest: scope.input_policy_digest(),
            scope_digest: scope.digest(),
            registration_digest: registration.registration_digest().clone(),
            proposal_digest: Digest::sha256([]),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&ProposalDigestMaterial {
            request_id: &self.request_id,
            input: &self.input,
            structured_schema_digest: &self.structured_schema_digest,
            tool_policy_digest: &self.tool_policy_digest,
            provider_digest: &self.provider_digest,
            organization_digest: &self.organization_digest,
            project_digest: &self.project_digest,
            model_snapshot_digest: &self.model_snapshot_digest,
            mission_digest: &self.mission_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            input_policy_digest: &self.input_policy_digest,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), OpenAIResponsesResultError> {
        if self.proposal_digest != self.compute_digest() {
            return Err(OpenAIResponsesResultError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ProposalDigestMaterial<'a> {
    request_id: &'a RequestIdProjection,
    input: &'a InputDescriptor,
    structured_schema_digest: &'a Option<Digest>,
    tool_policy_digest: &'a Digest,
    provider_digest: &'a Digest,
    organization_digest: &'a Digest,
    project_digest: &'a Digest,
    model_snapshot_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    input_policy_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderMode {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedEnvCode {
    NativeCredentialResolutionUnavailable,
    NativeTransportUnavailable,
    ProviderReadBackUnavailable,
    NativeLayer2Required,
}

impl BlockedEnvCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeCredentialResolutionUnavailable => {
                "native_credential_resolution_unavailable"
            }
            Self::NativeTransportUnavailable => "native_transport_unavailable",
            Self::ProviderReadBackUnavailable => "provider_read_back_unavailable",
            Self::NativeLayer2Required => "native_layer2_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Queued,
    Running,
    Completed,
    Incomplete,
    Failed,
    Cancelled,
    Expired,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

impl ResponseStatus {
    pub(crate) fn from_provider_status(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "in_progress" | "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "incomplete" => Some(Self::Incomplete),
            "failed" => Some(Self::Failed),
            "cancelled" | "canceled" => Some(Self::Cancelled),
            "expired" => Some(Self::Expired),
            "rate_limited" => Some(Self::RateLimited),
            "access_lost" => Some(Self::AccessLost),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
    TransportUnavailable,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseErrorMetadata {
    pub class: ProviderFailureClass,
    pub http_status: Option<u16>,
    pub retryable: bool,
    pub error_digest: Digest,
    pub code_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cached_input_tokens: Option<u64>,
}

impl ResponseUsage {
    pub fn new(
        input_tokens: u64,
        output_tokens: u64,
        cached_input_tokens: Option<u64>,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let total_tokens = input_tokens.checked_add(output_tokens).ok_or(
            OpenAIResponsesResultError::MalformedResponse("usage token count overflowed"),
        )?;
        if let Some(cached) = cached_input_tokens
            && cached > input_tokens
        {
            return Err(OpenAIResponsesResultError::MalformedResponse(
                "cached input tokens exceed input tokens",
            ));
        }
        Ok(Self {
            input_tokens,
            output_tokens,
            total_tokens,
            cached_input_tokens,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputSummary {
    pub content_digest: Digest,
    pub structured_output_digest: Option<Digest>,
    pub preview: Option<String>,
    pub preview_truncated: bool,
    pub retained_bytes: usize,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionMetadata {
    pub mode: OutputRetentionMode,
    pub raw_content_retained: bool,
    pub hidden_reasoning_retained: bool,
    pub tool_arguments_retained: bool,
    pub citations_retained: bool,
}

impl RedactionMetadata {
    pub const fn for_policy(policy: OutputRetentionPolicy) -> Self {
        Self {
            mode: policy.mode,
            raw_content_retained: false,
            hidden_reasoning_retained: false,
            tool_arguments_retained: false,
            citations_retained: false,
        }
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityClaims {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub durable_provider_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_truth: bool,
    pub kernel_verification: bool,
    pub kernel_outcome_adoption: bool,
    pub tool_execution: bool,
    pub web_search: bool,
}

impl AuthorityClaims {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            external_writes: false,
            durable_provider_receipt: false,
            independent_read_back: false,
            kernel_truth: false,
            kernel_verification: false,
            kernel_outcome_adoption: false,
            tool_execution: false,
            web_search: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    RecordedSuccess,
    RecordedStatus,
    RecordedProviderError,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAIResponsesResultEvidence {
    pub response_id: Option<ResponseIdProjection>,
    pub request_id: RequestIdProjection,
    pub status: ResponseStatus,
    pub usage: Option<ResponseUsage>,
    pub latency_ms: u64,
    pub cost_micros: Option<u64>,
    pub output: Option<OutputSummary>,
    pub error: Option<ResponseErrorMetadata>,
    pub disposition: EvidenceDisposition,
    pub provenance: ProviderMode,
    pub response_digest: Digest,
    pub recording_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub organization_digest: Digest,
    pub project_digest: Digest,
    pub model_snapshot_digest: Digest,
    pub input_policy_digest: Digest,
    pub structured_schema_digest: Option<Digest>,
    pub tool_policy_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub redaction: RedactionMetadata,
    pub authority: AuthorityClaims,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResponseIdProjection(String);

impl ResponseIdProjection {
    pub(crate) fn from_id(id: &ResponseId) -> Self {
        Self(id.0.clone())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl OpenAIResponsesResultEvidence {
    #[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
    pub(crate) fn new(
        proposal: &OpenAIResponsesProposal,
        response_id: Option<ResponseId>,
        status: ResponseStatus,
        usage: Option<ResponseUsage>,
        latency_ms: u64,
        cost_micros: Option<u64>,
        output: Option<OutputSummary>,
        error: Option<ResponseErrorMetadata>,
        disposition: EvidenceDisposition,
        provenance: ProviderMode,
        response_digest: Digest,
        recording_digest: Digest,
        redaction: RedactionMetadata,
    ) -> Self {
        let mut evidence = Self {
            response_id: response_id.as_ref().map(ResponseIdProjection::from_id),
            request_id: proposal.request_id.clone(),
            status,
            usage,
            latency_ms,
            cost_micros,
            output,
            error,
            disposition,
            provenance,
            response_digest,
            recording_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            organization_digest: proposal.organization_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            model_snapshot_digest: proposal.model_snapshot_digest.clone(),
            input_policy_digest: proposal.input_policy_digest.clone(),
            structured_schema_digest: proposal.structured_schema_digest.clone(),
            tool_policy_digest: proposal.tool_policy_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            redaction,
            authority: AuthorityClaims::layer_one(),
            evidence_digest: Digest::sha256([]),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&EvidenceDigestMaterial {
            response_id: &self.response_id,
            request_id: &self.request_id,
            status: self.status,
            usage: &self.usage,
            latency_ms: self.latency_ms,
            cost_micros: self.cost_micros,
            output: &self.output,
            error: &self.error,
            disposition: self.disposition,
            provenance: self.provenance,
            response_digest: &self.response_digest,
            recording_digest: &self.recording_digest,
            proposal_digest: &self.proposal_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            organization_digest: &self.organization_digest,
            project_digest: &self.project_digest,
            model_snapshot_digest: &self.model_snapshot_digest,
            input_policy_digest: &self.input_policy_digest,
            structured_schema_digest: &self.structured_schema_digest,
            tool_policy_digest: &self.tool_policy_digest,
            mission_digest: &self.mission_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            scope_digest: &self.scope_digest,
            redaction: self.redaction,
            authority: self.authority,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), OpenAIResponsesResultError> {
        if self.evidence_digest != self.compute_digest() {
            return Err(OpenAIResponsesResultError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct EvidenceDigestMaterial<'a> {
    response_id: &'a Option<ResponseIdProjection>,
    request_id: &'a RequestIdProjection,
    status: ResponseStatus,
    usage: &'a Option<ResponseUsage>,
    latency_ms: u64,
    cost_micros: Option<u64>,
    output: &'a Option<OutputSummary>,
    error: &'a Option<ResponseErrorMetadata>,
    disposition: EvidenceDisposition,
    provenance: ProviderMode,
    response_digest: &'a Digest,
    recording_digest: &'a Digest,
    proposal_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    organization_digest: &'a Digest,
    project_digest: &'a Digest,
    model_snapshot_digest: &'a Digest,
    input_policy_digest: &'a Digest,
    structured_schema_digest: &'a Option<Digest>,
    tool_policy_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    scope_digest: &'a Digest,
    redaction: RedactionMetadata,
    authority: AuthorityClaims,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeDrift,
    PermissionDrift,
    PolicyDrift,
    ConsentWithdrawn,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum RegistrationStatus {
    Active,
    Revoked {
        revision: u64,
        reason: RevocationReason,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    registration_digest: Digest,
    revision: u64,
    reason: RevocationReason,
}

impl Revocation {
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn reason(&self) -> &RevocationReason {
        &self.reason
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginRegistration {
    plugin_version: String,
    contract_version: String,
    version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    organization_digest: Digest,
    project_digest: Digest,
    model_snapshot_digest: Digest,
    input_policy_digest: Digest,
    structured_schema_digest: Option<Digest>,
    tool_policy_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    consent_digest: Digest,
    registration_digest: Digest,
    revocation_revision: u64,
    status: RegistrationStatus,
}

impl PluginRegistration {
    pub(crate) fn new(scope: &OpenAIResponsesScope) -> Self {
        let version_digest = digest_serializable(&(
            OPENAI_RESPONSES_RESULT_SCHEMA_VERSION,
            OPENAI_RESPONSES_RESULT_PLUGIN_VERSION,
            OPENAI_RESPONSES_RESULT_CONTRACT_VERSION,
        ));
        let contract_digest = digest_bytes(OPENAI_RESPONSES_RESULT_CONTRACT_JSON.as_bytes());
        let mut registration = Self {
            plugin_version: OPENAI_RESPONSES_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: OPENAI_RESPONSES_RESULT_CONTRACT_VERSION.to_owned(),
            version_digest,
            contract_digest,
            provider_digest: scope.provider_digest(),
            organization_digest: scope.organization_digest(),
            project_digest: scope.project_digest(),
            model_snapshot_digest: scope.model_digest(),
            input_policy_digest: scope.input_policy_digest(),
            structured_schema_digest: scope.structured_schema_digest(),
            tool_policy_digest: scope.tool_policy_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent_digest(),
            registration_digest: Digest::sha256([]),
            revocation_revision: 0,
            status: RegistrationStatus::Active,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&RegistrationDigestMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            organization_digest: &self.organization_digest,
            project_digest: &self.project_digest,
            model_snapshot_digest: &self.model_snapshot_digest,
            input_policy_digest: &self.input_policy_digest,
            structured_schema_digest: &self.structured_schema_digest,
            tool_policy_digest: &self.tool_policy_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            consent_digest: &self.consent_digest,
            revocation_revision: self.revocation_revision,
            status: &self.status,
        })
    }

    pub fn validate_against(
        &self,
        scope: &OpenAIResponsesScope,
    ) -> Result<(), OpenAIResponsesResultError> {
        if !matches!(self.status, RegistrationStatus::Active) {
            return Err(OpenAIResponsesResultError::RegistrationRevoked);
        }
        if self.registration_digest != self.compute_digest() {
            return Err(OpenAIResponsesResultError::RegistrationTampered);
        }
        if self.plugin_version != OPENAI_RESPONSES_RESULT_PLUGIN_VERSION
            || self.contract_version != OPENAI_RESPONSES_RESULT_CONTRACT_VERSION
            || self.version_digest
                != digest_serializable(&(
                    OPENAI_RESPONSES_RESULT_SCHEMA_VERSION,
                    OPENAI_RESPONSES_RESULT_PLUGIN_VERSION,
                    OPENAI_RESPONSES_RESULT_CONTRACT_VERSION,
                ))
            || self.contract_digest
                != digest_bytes(OPENAI_RESPONSES_RESULT_CONTRACT_JSON.as_bytes())
            || self.provider_digest != scope.provider_digest()
            || self.organization_digest != scope.organization_digest()
            || self.project_digest != scope.project_digest()
            || self.model_snapshot_digest != scope.model_digest()
            || self.input_policy_digest != scope.input_policy_digest()
            || self.structured_schema_digest != scope.structured_schema_digest()
            || self.tool_policy_digest != scope.tool_policy_digest()
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.consent_digest != scope.consent_digest()
        {
            return Err(OpenAIResponsesResultError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn organization_digest(&self) -> &Digest {
        &self.organization_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn model_snapshot_digest(&self) -> &Digest {
        &self.model_snapshot_digest
    }

    pub fn input_policy_digest(&self) -> &Digest {
        &self.input_policy_digest
    }

    pub fn structured_schema_digest(&self) -> Option<&Digest> {
        self.structured_schema_digest.as_ref()
    }

    pub fn tool_policy_digest(&self) -> &Digest {
        &self.tool_policy_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn revocation_revision(&self) -> u64 {
        self.revocation_revision
    }

    pub fn status(&self) -> &RegistrationStatus {
        &self.status
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub(crate) fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, OpenAIResponsesResultError> {
        if !self.is_active() {
            return Err(OpenAIResponsesResultError::RegistrationRevoked);
        }
        self.revocation_revision = self.revocation_revision.saturating_add(1);
        self.status = RegistrationStatus::Revoked {
            revision: self.revocation_revision,
            reason: reason.clone(),
        };
        self.registration_digest = self.compute_digest();
        Ok(Revocation {
            registration_digest: self.registration_digest.clone(),
            revision: self.revocation_revision,
            reason,
        })
    }

    pub(crate) fn restore(&mut self) {
        if self.is_active() {
            return;
        }
        self.revocation_revision = self.revocation_revision.saturating_add(1);
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.compute_digest();
    }
}

#[derive(Serialize)]
struct RegistrationDigestMaterial<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    organization_digest: &'a Digest,
    project_digest: &'a Digest,
    model_snapshot_digest: &'a Digest,
    input_policy_digest: &'a Digest,
    structured_schema_digest: &'a Option<Digest>,
    tool_policy_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    consent_digest: &'a Digest,
    revocation_revision: u64,
    status: &'a RegistrationStatus,
}

pub type OpenAIOrganizationScope = OrganizationScope;
pub type OpenAIProjectScope = ProjectScope;
pub type OpenAIMissionScope = MissionScope;
pub type OpenAIWorkProductScope = WorkProductScope;
pub type OpenAIInputPolicy = InputPolicy;
pub type OpenAIStructuredOutputSchema = StructuredOutputSchema;
pub type OpenAIToolPolicy = ToolPolicy;
pub type OpenAIConsentScope = ConsentScope;
pub type OpenAIResponseScope = OpenAIResponsesScope;
pub type ResponseScope = OpenAIResponsesScope;
pub type Response = OpenAIResponsesResultEvidence;
pub type OpenAIResponse = OpenAIResponsesResultEvidence;
pub type ResponseRequest = OpenAIResponsesRequest;
pub type ResponseProposal = OpenAIResponsesProposal;
pub type ResponseEvidence = OpenAIResponsesResultEvidence;
pub type OpenAIResponseStatus = ResponseStatus;
pub type OpenAIResponseUsage = ResponseUsage;
pub type OpenAIResponseErrorMetadata = ResponseErrorMetadata;
pub type OpenAIResponseId = ResponseId;
pub type OpenAIRequestId = RequestId;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_reference_is_opaque_in_debug() {
        let secret = SecretReference::new("super-secret-api-key", 1).expect("secret");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("super-secret-api-key"));
        assert!(debug.contains("reference_digest"));
    }

    #[test]
    fn strict_schema_requires_object_and_additional_properties_false() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
            "additionalProperties": false
        });
        let accepted = StructuredOutputSchema::new("answer", schema, true);
        assert!(accepted.is_ok());
        let rejected = StructuredOutputSchema::new(
            "answer",
            serde_json::json!({"type": "object", "properties": {}}),
            true,
        );
        assert!(rejected.is_err());
    }
}
