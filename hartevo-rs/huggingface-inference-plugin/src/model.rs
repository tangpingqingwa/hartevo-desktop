//! Typed, serializable contract models for the Hugging Face result seam.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    HUGGINGFACE_INFERENCE_CONTRACT_JSON, HUGGINGFACE_INFERENCE_CONTRACT_VERSION,
    HUGGINGFACE_INFERENCE_PLUGIN_VERSION, HUGGINGFACE_INFERENCE_PROVIDER_ID,
    HUGGINGFACE_INFERENCE_SCHEMA_VERSION, HUGGINGFACE_INFERENCE_SERVICE_ID, digest_bytes,
    digest_serializable,
};

pub const DEFAULT_HUGGINGFACE_API_HOST: &str = "https://router.huggingface.co";
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MODEL_REVISION_BYTES: usize = 128;
pub const MAX_POLICY_REVISION_BYTES: usize = 128;
pub const MAX_PROJECT_SCOPE_BYTES: usize = 128;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_MESSAGES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
pub const MAX_NEW_TOKENS: u32 = 4096;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PREVIEW_CHARS: usize = 1024;

/// All provider errors are projections.  They never contain provider body
/// text, authorization material, or a raw error message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
    TransportUnavailable,
    UnexpectedStatus,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HuggingFaceInferenceError {
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
    #[error("result evidence digest does not match its immutable contents")]
    EvidenceTampered,
    #[error("model revision drifted from the pinned immutable revision")]
    ModelRevisionDrift,
    #[error("provider route mismatch; silent failover is refused")]
    ProviderRouteMismatch,
    #[error("model identity mismatch")]
    ModelMismatch,
    #[error("task mismatch")]
    TaskMismatch,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("policy binding drifted")]
    PolicyDrift,
    #[error("input exceeds the configured byte bound")]
    InputTooLarge,
    #[error("message count exceeds the configured bound")]
    MessageCountExceeded,
    #[error("message exceeds the configured byte bound")]
    MessageTooLarge,
    #[error("generation budget exceeds the configured bound")]
    GenerationBudgetExceeded,
    #[error("tool calls are not allowed by the Layer-1 contract")]
    ToolCallsForbidden,
    #[error("streaming is not allowed by the Layer-1 contract")]
    StreamingForbidden,
    #[error("provider response is truncated")]
    ResponseTruncated,
    #[error("provider response is malformed or partial: {0}")]
    MalformedResponse(&'static str),
    #[error("provider returned an unsupported status: {0}")]
    UnsupportedStatus(u16),
    #[error("provider response is unavailable in BLOCKED_ENV: {0}")]
    BlockedEnvironment(&'static str),
    #[error("a provider recording was replayed")]
    ReplayDetected,
    #[error("native provider execution is a Layer-2 gap")]
    NativeExecutionUnavailable,
    #[error("provider failure: {0:?}")]
    ProviderFailure(ProviderFailureClass),
}

/// SHA-256 digest used to fence every externally meaningful binding.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        crate::digest_bytes(bytes.as_ref())
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
    HfToken,
    OAuth,
}

/// Opaque host-owned secret binding.  The constructor hashes the opaque
/// handle and discards it; no token or OAuth bytes are retained or serialized.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: SecretKind,
    revision: u64,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        kind: SecretKind,
        revision: u64,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }

        let mut material = b"hartevo:huggingface-secret-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        material.push(match kind {
            SecretKind::HfToken => 0,
            SecretKind::OAuth => 1,
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
pub enum InferencePermission {
    InferenceProviders,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct HuggingFaceApiHost(String);

impl HuggingFaceApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self, HuggingFaceInferenceError> {
        let value = value.into().trim_end_matches('/').to_owned();
        let valid_router = value == DEFAULT_HUGGINGFACE_API_HOST
            || value.starts_with("https://router.huggingface.co/");
        if !valid_router
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_whitespace)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "api_host",
                reason: "must be an HTTPS Hugging Face router host without query or fragment",
            });
        }
        Ok(Self(value))
    }

    pub fn router() -> Self {
        Self(DEFAULT_HUGGINGFACE_API_HOST.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HuggingFaceApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HuggingFaceApiHost")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelRevision {
    model_id: String,
    immutable_revision: String,
}

impl ModelRevision {
    pub fn new(
        model_id: impl Into<String>,
        immutable_revision: impl Into<String>,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let model_id = model_id.into();
        let immutable_revision = immutable_revision.into();
        if model_id.trim().is_empty()
            || model_id.len() > MAX_IDENTIFIER_BYTES
            || model_id.matches('/').count() != 1
            || model_id.contains(':')
            || model_id.chars().any(char::is_whitespace)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "model_id",
                reason: "must be a bounded org/model id without a routing suffix",
            });
        }
        if immutable_revision.trim().is_empty()
            || immutable_revision.len() > MAX_MODEL_REVISION_BYTES
            || immutable_revision.chars().any(char::is_whitespace)
            || matches!(
                immutable_revision.as_str(),
                "main" | "master" | "latest" | "default"
            )
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "immutable_model_revision",
                reason: "must be a bounded pinned revision, not a floating alias",
            });
        }
        Ok(Self {
            model_id,
            immutable_revision,
        })
    }

    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn immutable_revision(&self) -> &str {
        &self.immutable_revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

impl fmt::Debug for ModelRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelRevision")
            .field("model_id", &self.model_id)
            .field("immutable_revision", &self.immutable_revision)
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceTask {
    ChatCompletion,
    TextGeneration,
}

impl InferenceTask {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChatCompletion => "chat_completion",
            Self::TextGeneration => "text_generation",
        }
    }

    pub fn digest(self) -> Digest {
        digest_serializable(&self)
    }
}

const ALLOWED_PROVIDER_IDS: &[&str] = &[
    "baseten",
    "cerebras",
    "cohere",
    "deepinfra",
    "fal-ai",
    "featherless-ai",
    "fireworks-ai",
    "groq",
    "hf-inference",
    "novita",
    "nscale",
    "openai",
    "ovhcloud",
    "publicai",
    "replicate",
    "scaleway",
    "together",
    "wavespeed",
    "zai-org",
];

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRoute {
    provider_id: String,
    api_host: HuggingFaceApiHost,
}

impl ProviderRoute {
    pub fn new(provider_id: impl Into<String>) -> Result<Self, HuggingFaceInferenceError> {
        Self::with_host(provider_id, HuggingFaceApiHost::router())
    }

    pub fn with_host(
        provider_id: impl Into<String>,
        api_host: HuggingFaceApiHost,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let provider_id = provider_id.into();
        if !ALLOWED_PROVIDER_IDS.contains(&provider_id.as_str()) {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "provider_route",
                reason: "must be one explicit allowlisted Inference Provider and cannot be auto",
            });
        }
        Ok(Self {
            provider_id,
            api_host,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn api_host(&self) -> &HuggingFaceApiHost {
        &self.api_host
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

impl fmt::Debug for ProviderRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRoute")
            .field("provider_id", &self.provider_id)
            .field("api_host", &self.api_host)
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountScope {
    account_id: String,
    organization: Option<String>,
    permission: InferencePermission,
    secret_reference: SecretReference,
}

impl AccountScope {
    pub fn new(
        account_id: impl Into<String>,
        permission: InferencePermission,
        secret_reference: SecretReference,
    ) -> Result<Self, HuggingFaceInferenceError> {
        Self::with_organization(account_id, None::<String>, permission, secret_reference)
    }

    pub fn with_organization(
        account_id: impl Into<String>,
        organization: Option<impl Into<String>>,
        permission: InferencePermission,
        secret_reference: SecretReference,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let account_id = account_id.into();
        let organization = organization.map(Into::into);
        if account_id.trim().is_empty()
            || account_id.len() > MAX_IDENTIFIER_BYTES
            || account_id.chars().any(char::is_whitespace)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "account_id",
                reason: "must be a bounded non-empty account identifier",
            });
        }
        if organization
            .as_deref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > MAX_IDENTIFIER_BYTES)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "organization",
                reason: "must be empty or a bounded organization identifier",
            });
        }
        Ok(Self {
            account_id,
            organization,
            permission,
            secret_reference,
        })
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn organization(&self) -> Option<&str> {
        self.organization.as_deref()
    }

    pub const fn permission(&self) -> InferencePermission {
        self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn permission_digest(&self) -> Digest {
        digest_serializable(&PermissionBinding {
            permission: self.permission,
            secret_reference_digest: self.secret_reference.reference_digest(),
        })
    }
}

impl fmt::Debug for AccountScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountScope")
            .field("account_id", &self.account_id)
            .field("organization", &self.organization)
            .field("permission", &self.permission)
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.permission_digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: u64,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, HuggingFaceInferenceError> {
        scoped_id("project_id", id, revision)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: String,
    revision: u64,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, HuggingFaceInferenceError> {
        scoped_id("mission_id", id, revision)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: String,
    revision: u64,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, HuggingFaceInferenceError> {
        scoped_id("work_product_id", id, revision)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

fn scoped_id<T>(
    field: &'static str,
    id: impl Into<String>,
    revision: u64,
) -> Result<T, HuggingFaceInferenceError>
where
    T: From<ScopedId>,
{
    let id = id.into();
    if id.trim().is_empty()
        || id.len() > MAX_PROJECT_SCOPE_BYTES
        || id.chars().any(char::is_control)
    {
        return Err(HuggingFaceInferenceError::InvalidField {
            field,
            reason: "must be a bounded non-empty scope identifier",
        });
    }
    Ok(T::from(ScopedId { id, revision }))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopedId {
    id: String,
    revision: u64,
}

impl From<ScopedId> for ProjectScope {
    fn from(value: ScopedId) -> Self {
        Self {
            id: value.id,
            revision: value.revision,
        }
    }
}

impl From<ScopedId> for MissionScope {
    fn from(value: ScopedId) -> Self {
        Self {
            id: value.id,
            revision: value.revision,
        }
    }
}

impl From<ScopedId> for WorkProductScope {
    fn from(value: ScopedId) -> Self {
        Self {
            id: value.id,
            revision: value.revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRedactionMode {
    DigestOnly,
    Prefix,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputRedactionPolicy {
    mode: OutputRedactionMode,
    preview_chars: usize,
}

impl OutputRedactionPolicy {
    pub const fn digest_only() -> Self {
        Self {
            mode: OutputRedactionMode::DigestOnly,
            preview_chars: 0,
        }
    }

    pub fn prefix(preview_chars: usize) -> Result<Self, HuggingFaceInferenceError> {
        if preview_chars == 0 || preview_chars > MAX_PREVIEW_CHARS {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "output_redaction_policy",
                reason: "prefix preview must be bounded and non-zero",
            });
        }
        Ok(Self {
            mode: OutputRedactionMode::Prefix,
            preview_chars,
        })
    }

    pub const fn mode(self) -> OutputRedactionMode {
        self.mode
    }

    pub const fn preview_chars(self) -> usize {
        self.preview_chars
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferencePolicy {
    revision: String,
    max_input_bytes: usize,
    max_messages: usize,
    max_message_bytes: usize,
    max_new_tokens: u32,
    output_redaction: OutputRedactionPolicy,
}

impl InferencePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: impl Into<String>,
        max_input_bytes: usize,
        max_messages: usize,
        max_message_bytes: usize,
        max_new_tokens: u32,
        output_redaction: OutputRedactionPolicy,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let revision = revision.into();
        if revision.trim().is_empty()
            || revision.len() > MAX_POLICY_REVISION_BYTES
            || revision.chars().any(char::is_whitespace)
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "policy_revision",
                reason: "must be a bounded non-empty revision",
            });
        }
        if max_input_bytes == 0
            || max_input_bytes > MAX_INPUT_BYTES
            || max_messages == 0
            || max_messages > MAX_MESSAGES
            || max_message_bytes == 0
            || max_message_bytes > MAX_MESSAGE_BYTES
            || max_new_tokens == 0
            || max_new_tokens > MAX_NEW_TOKENS
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "input_policy",
                reason: "one or more bounds are outside the Layer-1 limits",
            });
        }
        Ok(Self {
            revision,
            max_input_bytes,
            max_messages,
            max_message_bytes,
            max_new_tokens,
            output_redaction,
        })
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub const fn max_messages(&self) -> usize {
        self.max_messages
    }

    pub const fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    pub const fn max_new_tokens(&self) -> u32 {
        self.max_new_tokens
    }

    pub const fn output_redaction(&self) -> OutputRedactionPolicy {
        self.output_redaction
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HuggingFaceInferenceScope {
    api_host: HuggingFaceApiHost,
    account: AccountScope,
    model: ModelRevision,
    task: InferenceTask,
    provider_route: ProviderRoute,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    policy: InferencePolicy,
}

impl HuggingFaceInferenceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_host: HuggingFaceApiHost,
        account: AccountScope,
        model: ModelRevision,
        task: InferenceTask,
        provider_route: ProviderRoute,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        policy: InferencePolicy,
    ) -> Result<Self, HuggingFaceInferenceError> {
        if provider_route.api_host() != &api_host {
            return Err(HuggingFaceInferenceError::ScopeMismatch(
                "provider route host differs from the scoped API host",
            ));
        }
        Ok(Self {
            api_host,
            account,
            model,
            task,
            provider_route,
            project,
            mission,
            work_product,
            policy,
        })
    }

    pub fn api_host(&self) -> &HuggingFaceApiHost {
        &self.api_host
    }

    pub fn account(&self) -> &AccountScope {
        &self.account
    }

    pub fn model(&self) -> &ModelRevision {
        &self.model
    }

    pub const fn task(&self) -> InferenceTask {
        self.task
    }

    pub fn provider_route(&self) -> &ProviderRoute {
        &self.provider_route
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn policy(&self) -> &InferencePolicy {
        &self.policy
    }

    pub fn model_digest(&self) -> Digest {
        self.model.digest()
    }

    pub fn provider_digest(&self) -> Digest {
        self.provider_route.digest()
    }

    pub fn task_digest(&self) -> Digest {
        self.task.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.account.permission_digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&ScopeDigestMaterial {
            api_host: &self.api_host,
            account: &self.account,
            model: &self.model,
            task: self.task,
            provider_route: &self.provider_route,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            policy: &self.policy,
        })
    }
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    api_host: &'a HuggingFaceApiHost,
    account: &'a AccountScope,
    model: &'a ModelRevision,
    task: InferenceTask,
    provider_route: &'a ProviderRoute,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    policy: &'a InferencePolicy,
}

#[derive(Serialize)]
struct PermissionBinding<'a> {
    permission: InferencePermission,
    secret_reference_digest: &'a Digest,
}

impl fmt::Debug for HuggingFaceInferenceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HuggingFaceInferenceScope")
            .field("api_host", &self.api_host)
            .field("account", &self.account)
            .field("model", &self.model)
            .field("task", &self.task)
            .field("provider_route", &self.provider_route)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("policy_revision", &self.policy.revision)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeDrift,
    PermissionDrift,
    PolicyDrift,
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
    model_digest: Digest,
    task_digest: Digest,
    scope_digest: Digest,
    permission_digest: Digest,
    registration_digest: Digest,
    revocation_revision: u64,
    status: RegistrationStatus,
}

impl PluginRegistration {
    pub(crate) fn new(scope: &HuggingFaceInferenceScope) -> Self {
        let version_digest = digest_serializable(&(
            HUGGINGFACE_INFERENCE_PLUGIN_VERSION,
            HUGGINGFACE_INFERENCE_CONTRACT_VERSION,
        ));
        let contract_digest = digest_bytes(HUGGINGFACE_INFERENCE_CONTRACT_JSON.as_bytes());
        let provider_digest = scope.provider_digest();
        let model_digest = scope.model_digest();
        let task_digest = scope.task_digest();
        let scope_digest = scope.digest();
        let permission_digest = scope.permission_digest();
        let registration_digest = digest_serializable(&RegistrationMaterial {
            plugin_version: HUGGINGFACE_INFERENCE_PLUGIN_VERSION,
            contract_version: HUGGINGFACE_INFERENCE_CONTRACT_VERSION,
            version_digest: &version_digest,
            contract_digest: &contract_digest,
            provider_digest: &provider_digest,
            model_digest: &model_digest,
            task_digest: &task_digest,
            scope_digest: &scope_digest,
            permission_digest: &permission_digest,
        });
        Self {
            plugin_version: HUGGINGFACE_INFERENCE_PLUGIN_VERSION.to_owned(),
            contract_version: HUGGINGFACE_INFERENCE_CONTRACT_VERSION.to_owned(),
            version_digest,
            contract_digest,
            provider_digest,
            model_digest,
            task_digest,
            scope_digest,
            permission_digest,
            registration_digest,
            revocation_revision: 0,
            status: RegistrationStatus::Active,
        }
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
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

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn task_digest(&self) -> &Digest {
        &self.task_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
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

    pub(crate) fn validate_against(
        &self,
        scope: &HuggingFaceInferenceScope,
    ) -> Result<(), HuggingFaceInferenceError> {
        if self.version_digest
            != digest_serializable(&(self.plugin_version.as_str(), self.contract_version.as_str()))
            || self.contract_digest != digest_bytes(HUGGINGFACE_INFERENCE_CONTRACT_JSON.as_bytes())
            || self.provider_digest != scope.provider_digest()
            || self.model_digest != scope.model_digest()
            || self.task_digest != scope.task_digest()
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest()
            || self.registration_digest
                != digest_serializable(&RegistrationMaterial {
                    plugin_version: &self.plugin_version,
                    contract_version: &self.contract_version,
                    version_digest: &self.version_digest,
                    contract_digest: &self.contract_digest,
                    provider_digest: &self.provider_digest,
                    model_digest: &self.model_digest,
                    task_digest: &self.task_digest,
                    scope_digest: &self.scope_digest,
                    permission_digest: &self.permission_digest,
                })
        {
            return Err(HuggingFaceInferenceError::RegistrationTampered);
        }
        if !self.is_active() {
            return Err(HuggingFaceInferenceError::RegistrationRevoked);
        }
        Ok(())
    }

    pub(crate) fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, HuggingFaceInferenceError> {
        if self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                HuggingFaceInferenceError::InvalidField {
                    field: "revocation_revision",
                    reason: "revision overflow",
                },
            )?;
            self.status = RegistrationStatus::Revoked {
                revision: self.revocation_revision,
                reason: reason.clone(),
            };
        }
        Ok(Revocation {
            registration_digest: self.registration_digest.clone(),
            revision: self.revocation_revision,
            reason,
        })
    }

    pub(crate) fn restore(&mut self) -> Result<(), HuggingFaceInferenceError> {
        if !self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                HuggingFaceInferenceError::InvalidField {
                    field: "revocation_revision",
                    reason: "revision overflow",
                },
            )?;
            self.status = RegistrationStatus::Active;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct RegistrationMaterial<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    model_digest: &'a Digest,
    task_digest: &'a Digest,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    ChatMessages,
    Text,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestOptions {
    stream: bool,
    tool_calls: bool,
}

impl RequestOptions {
    pub const fn bounded() -> Self {
        Self {
            stream: false,
            tool_calls: false,
        }
    }

    pub const fn new(stream: bool, tool_calls: bool) -> Self {
        Self { stream, tool_calls }
    }

    pub const fn stream(self) -> bool {
        self.stream
    }

    pub const fn tool_calls(self) -> bool {
        self.tool_calls
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatRole {
    System,
    User,
    Assistant,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ChatMessage {
    role: ChatRole,
    content: String,
}

impl ChatMessage {
    pub fn new(
        role: ChatRole,
        content: impl Into<String>,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let content = content.into();
        if content.is_empty()
            || content.len() > MAX_MESSAGE_BYTES
            || content.chars().any(|character| character == '\0')
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "chat_message.content",
                reason: "must be non-empty, bounded, and free of control characters",
            });
        }
        Ok(Self { role, content })
    }

    pub const fn role(&self) -> ChatRole {
        self.role
    }

    pub const fn content_len(&self) -> usize {
        self.content.len()
    }

    pub fn content_digest(&self) -> Digest {
        digest_bytes(self.content.as_bytes())
    }

    pub(crate) fn content(&self) -> &str {
        &self.content
    }
}

impl fmt::Debug for ChatMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChatMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .field("content_digest", &self.content_digest())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum InferenceInput {
    Chat(Vec<ChatMessage>),
    Text(String),
}

impl InferenceInput {
    pub fn chat(messages: Vec<ChatMessage>) -> Result<Self, HuggingFaceInferenceError> {
        if messages.is_empty() {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "chat_messages",
                reason: "must contain at least one message",
            });
        }
        Ok(Self::Chat(messages))
    }

    pub fn text(input: impl Into<String>) -> Result<Self, HuggingFaceInferenceError> {
        let input = input.into();
        if input.is_empty()
            || input.len() > MAX_INPUT_BYTES
            || input.chars().any(|character| character == '\0')
        {
            return Err(HuggingFaceInferenceError::InvalidField {
                field: "text_input",
                reason: "must be non-empty, bounded, and free of control characters",
            });
        }
        Ok(Self::Text(input))
    }

    pub const fn kind(&self) -> InputKind {
        match self {
            Self::Chat(_) => InputKind::ChatMessages,
            Self::Text(_) => InputKind::Text,
        }
    }

    pub(crate) fn input_bytes(&self) -> usize {
        match self {
            Self::Chat(messages) => messages.iter().map(ChatMessage::content_len).sum(),
            Self::Text(input) => input.len(),
        }
    }

    pub(crate) fn item_count(&self) -> usize {
        match self {
            Self::Chat(messages) => messages.len(),
            Self::Text(_) => 1,
        }
    }

    pub(crate) fn text_input(&self) -> Option<&str> {
        match self {
            Self::Chat(_) => None,
            Self::Text(input) => Some(input),
        }
    }

    pub(crate) fn messages(&self) -> Option<&[ChatMessage]> {
        match self {
            Self::Chat(messages) => Some(messages),
            Self::Text(_) => None,
        }
    }
}

impl fmt::Debug for InferenceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chat(messages) => formatter
                .debug_struct("InferenceInput::Chat")
                .field("message_count", &messages.len())
                .field("input_bytes", &self.input_bytes())
                .finish(),
            Self::Text(input) => formatter
                .debug_struct("InferenceInput::Text")
                .field("input_bytes", &input.len())
                .field("input_digest", &digest_bytes(input.as_bytes()))
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationBudget {
    max_new_tokens: u32,
    temperature_milli: Option<u16>,
    top_p_milli: Option<u16>,
}

impl Eq for GenerationBudget {}

impl GenerationBudget {
    pub fn new(
        max_new_tokens: u32,
        temperature_milli: Option<u16>,
        top_p_milli: Option<u16>,
    ) -> Result<Self, HuggingFaceInferenceError> {
        if max_new_tokens == 0 || max_new_tokens > MAX_NEW_TOKENS {
            return Err(HuggingFaceInferenceError::GenerationBudgetExceeded);
        }
        if temperature_milli.is_some_and(|value| value > 2000)
            || top_p_milli.is_some_and(|value| value == 0 || value > 1000)
        {
            return Err(HuggingFaceInferenceError::GenerationBudgetExceeded);
        }
        Ok(Self {
            max_new_tokens,
            temperature_milli,
            top_p_milli,
        })
    }

    pub const fn max_new_tokens(self) -> u32 {
        self.max_new_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceRequest {
    task: InferenceTask,
    input: InferenceInput,
    generation: GenerationBudget,
    options: RequestOptions,
}

impl InferenceRequest {
    pub fn new(task: InferenceTask, input: InferenceInput, generation: GenerationBudget) -> Self {
        Self {
            task,
            input,
            generation,
            options: RequestOptions::bounded(),
        }
    }

    pub const fn with_options(mut self, options: RequestOptions) -> Self {
        self.options = options;
        self
    }

    pub const fn task(&self) -> InferenceTask {
        self.task
    }

    pub fn input(&self) -> &InferenceInput {
        &self.input
    }

    pub const fn generation(&self) -> GenerationBudget {
        self.generation
    }

    pub const fn options(&self) -> RequestOptions {
        self.options
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InferenceRequestFingerprint {
    pub request_digest: Digest,
    pub input_kind: InputKind,
    pub item_count: usize,
    pub input_bytes: usize,
    pub max_new_tokens: u32,
    pub options: RequestOptions,
}

impl InferenceRequestFingerprint {
    pub(crate) fn from_request(
        scope: &HuggingFaceInferenceScope,
        request: &InferenceRequest,
    ) -> Self {
        let canonical = CanonicalRequest::from_request(scope, request);
        Self {
            request_digest: digest_serializable(&canonical),
            input_kind: request.input.kind(),
            item_count: request.input.item_count(),
            input_bytes: request.input.input_bytes(),
            max_new_tokens: request.generation.max_new_tokens,
            options: request.options,
        }
    }
}

#[derive(Serialize)]
struct CanonicalRequest<'a> {
    task: InferenceTask,
    model: &'a ModelRevision,
    provider_route: &'a ProviderRoute,
    policy_digest: Digest,
    input: CanonicalInput<'a>,
    generation: GenerationBudget,
    options: RequestOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum CanonicalInput<'a> {
    Chat { messages: Vec<CanonicalMessage<'a>> },
    Text { input: &'a str },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalMessage<'a> {
    role: ChatRole,
    content: &'a str,
}

impl<'a> CanonicalRequest<'a> {
    fn from_request(scope: &'a HuggingFaceInferenceScope, request: &'a InferenceRequest) -> Self {
        let input = match &request.input {
            InferenceInput::Chat(messages) => CanonicalInput::Chat {
                messages: messages
                    .iter()
                    .map(|message| CanonicalMessage {
                        role: message.role,
                        content: message.content(),
                    })
                    .collect(),
            },
            InferenceInput::Text(input) => CanonicalInput::Text { input },
        };
        Self {
            task: request.task,
            model: &scope.model,
            provider_route: &scope.provider_route,
            policy_digest: scope.policy.digest(),
            input,
            generation: request.generation,
            options: request.options,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferenceResultProposal {
    pub proposal_version: String,
    pub service_id: String,
    pub task: InferenceTask,
    pub model: ModelRevision,
    pub provider_route: ProviderRoute,
    pub request: InferenceRequestFingerprint,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub model_digest: Digest,
    pub task_digest: Digest,
    pub proposal_digest: Digest,
}

impl InferenceResultProposal {
    pub(crate) fn new(
        scope: &HuggingFaceInferenceScope,
        registration: &PluginRegistration,
        request: &InferenceRequest,
    ) -> Self {
        let request = InferenceRequestFingerprint::from_request(scope, request);
        let mut proposal = Self {
            proposal_version: "hf-inference-proposal/v1".to_owned(),
            service_id: HUGGINGFACE_INFERENCE_SERVICE_ID.to_owned(),
            task: scope.task,
            model: scope.model.clone(),
            provider_route: scope.provider_route.clone(),
            request,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.digest(),
            provider_digest: scope.provider_digest(),
            model_digest: scope.model_digest(),
            task_digest: scope.task_digest(),
            proposal_digest: digest_bytes(b"uninitialized-proposal-digest"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serializable(&ProposalMaterial {
            proposal_version: &self.proposal_version,
            service_id: &self.service_id,
            task: self.task,
            model: &self.model,
            provider_route: &self.provider_route,
            request: &self.request,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            provider_digest: &self.provider_digest,
            model_digest: &self.model_digest,
            task_digest: &self.task_digest,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), HuggingFaceInferenceError> {
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(HuggingFaceInferenceError::ProposalTampered)
        }
    }
}

#[derive(Serialize)]
struct ProposalMaterial<'a> {
    proposal_version: &'a str,
    service_id: &'a str,
    task: InferenceTask,
    model: &'a ModelRevision,
    provider_route: &'a ProviderRoute,
    request: &'a InferenceRequestFingerprint,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    provider_digest: &'a Digest,
    model_digest: &'a Digest,
    task_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    EosToken,
    StopSequence,
}

impl FinishReason {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "stop" => Some(Self::Stop),
            "length" => Some(Self::Length),
            "eos_token" => Some(Self::EosToken),
            "stop_sequence" => Some(Self::StopSequence),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageProjection {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

impl UsageProjection {
    pub(crate) fn new(
        prompt_tokens: u64,
        completion_tokens: u64,
        total_tokens: u64,
    ) -> Result<Self, HuggingFaceInferenceError> {
        if prompt_tokens.saturating_add(completion_tokens) != total_tokens {
            return Err(HuggingFaceInferenceError::MalformedResponse(
                "usage totals do not add up",
            ));
        }
        Ok(Self {
            prompt_tokens,
            completion_tokens,
            total_tokens,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedContent {
    pub content_digest: Digest,
    pub byte_length: usize,
    pub preview: Option<String>,
    pub preview_truncated: bool,
}

impl RedactedContent {
    pub(crate) fn from_text(value: &str, policy: OutputRedactionPolicy) -> Self {
        let byte_length = value.len();
        let content_digest = digest_bytes(value.as_bytes());
        match policy.mode {
            OutputRedactionMode::DigestOnly => Self {
                content_digest,
                byte_length,
                preview: None,
                preview_truncated: false,
            },
            OutputRedactionMode::Prefix => {
                let preview: String = value.chars().take(policy.preview_chars).collect();
                let preview_truncated = preview.chars().count() < value.chars().count();
                Self {
                    content_digest,
                    byte_length,
                    preview: Some(preview),
                    preview_truncated,
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Fixture,
    Fake,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderMode {
    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthority {
    mode: ProviderMode,
    connected: bool,
    native: bool,
}

impl EvidenceAuthority {
    pub(crate) const fn for_mode(mode: ProviderMode) -> Self {
        Self {
            mode,
            connected: false,
            native: false,
        }
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    RecordedSuccess,
    RecordedProviderError,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorProjection {
    pub class: ProviderFailureClass,
    pub http_status: Option<u16>,
    pub retryable: bool,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferenceResultEvidence {
    pub evidence_version: String,
    pub recording_key: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub provider_digest: Digest,
    pub model_digest: Digest,
    pub task_digest: Digest,
    pub response_digest: Digest,
    pub content: Option<RedactedContent>,
    pub usage: Option<UsageProjection>,
    pub latency_ms: u64,
    pub finish_reason: Option<FinishReason>,
    pub disposition: EvidenceDisposition,
    pub provider_error: Option<ProviderErrorProjection>,
    pub authority: EvidenceAuthority,
    pub evidence_digest: Digest,
}

impl InferenceResultEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mode: ProviderMode,
        recording_key: Digest,
        proposal: &InferenceResultProposal,
        response_digest: Digest,
        content: Option<RedactedContent>,
        usage: Option<UsageProjection>,
        latency_ms: u64,
        finish_reason: Option<FinishReason>,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
    ) -> Self {
        let mut evidence = Self {
            evidence_version: "hf-inference-evidence/v1".to_owned(),
            recording_key,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            model_digest: proposal.model_digest.clone(),
            task_digest: proposal.task_digest.clone(),
            response_digest,
            content,
            usage,
            latency_ms,
            finish_reason,
            disposition,
            provider_error,
            authority: EvidenceAuthority::for_mode(mode),
            evidence_digest: digest_bytes(b"uninitialized-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serializable(&EvidenceMaterial {
            evidence_version: &self.evidence_version,
            recording_key: &self.recording_key,
            proposal_digest: &self.proposal_digest,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            provider_digest: &self.provider_digest,
            model_digest: &self.model_digest,
            task_digest: &self.task_digest,
            response_digest: &self.response_digest,
            content: self.content.as_ref(),
            usage: self.usage.as_ref(),
            latency_ms: self.latency_ms,
            finish_reason: self.finish_reason.as_ref(),
            disposition: self.disposition,
            provider_error: self.provider_error.as_ref(),
            authority: &self.authority,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), HuggingFaceInferenceError> {
        if self.authority.connected() || self.authority.native() {
            return Err(HuggingFaceInferenceError::EvidenceTampered);
        }
        if self.evidence_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(HuggingFaceInferenceError::EvidenceTampered)
        }
    }

    pub fn content_digest(&self) -> Option<&Digest> {
        self.content.as_ref().map(|content| &content.content_digest)
    }
}

#[derive(Serialize)]
struct EvidenceMaterial<'a> {
    evidence_version: &'a str,
    recording_key: &'a Digest,
    proposal_digest: &'a Digest,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    provider_digest: &'a Digest,
    model_digest: &'a Digest,
    task_digest: &'a Digest,
    response_digest: &'a Digest,
    content: Option<&'a RedactedContent>,
    usage: Option<&'a UsageProjection>,
    latency_ms: u64,
    finish_reason: Option<&'a FinishReason>,
    disposition: EvidenceDisposition,
    provider_error: Option<&'a ProviderErrorProjection>,
    authority: &'a EvidenceAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelDescription {
    model: ModelRevision,
    task: InferenceTask,
    provider_route: ProviderRoute,
    source: String,
    hub_read_back: bool,
    connected: bool,
    native: bool,
}

impl ModelDescription {
    pub(crate) fn from_scope(scope: &HuggingFaceInferenceScope) -> Self {
        Self {
            model: scope.model.clone(),
            task: scope.task,
            provider_route: scope.provider_route.clone(),
            source: "scoped_declaration_only".to_owned(),
            hub_read_back: false,
            connected: false,
            native: false,
        }
    }

    pub fn model(&self) -> &ModelRevision {
        &self.model
    }

    pub const fn task(&self) -> InferenceTask {
        self.task
    }

    pub fn provider_route(&self) -> &ProviderRoute {
        &self.provider_route
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub const fn hub_read_back(&self) -> bool {
        self.hub_read_back
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }
}

/// Compile-time assertion that the public provider identity remains the
/// provider-specific one and is not a generic catalog surface.
pub const fn provider_identity() -> &'static str {
    HUGGINGFACE_INFERENCE_PROVIDER_ID
}

/// Compile-time assertion used by callers that need the contract schema id.
pub const fn contract_schema_identity() -> &'static str {
    HUGGINGFACE_INFERENCE_SCHEMA_VERSION
}

/// Compile-time assertion used by callers that need the exact service seam.
pub const fn service_identity() -> &'static str {
    HUGGINGFACE_INFERENCE_SERVICE_ID
}
