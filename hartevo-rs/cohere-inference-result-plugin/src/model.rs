//! Typed, bounded, serializable contract models for the Cohere result seam.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    COHERE_INFERENCE_CONTRACT_JSON, COHERE_INFERENCE_CONTRACT_VERSION,
    COHERE_INFERENCE_PLUGIN_VERSION, COHERE_INFERENCE_PROVIDER_ID, COHERE_INFERENCE_SCHEMA_VERSION,
    COHERE_INFERENCE_SERVICE_ID, digest_bytes, digest_serializable,
};

pub const DEFAULT_COHERE_API_HOST: &str = "https://api.cohere.com";
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_MODEL_REVISION_BYTES: usize = 128;
pub const MAX_POLICY_REVISION_BYTES: usize = 128;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_ITEMS: usize = 64;
pub const MAX_ITEM_BYTES: usize = 256 * 1024;
pub const MAX_NEW_TOKENS: u32 = 4096;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EMBEDDING_DIMENSIONS: usize = 16_384;

/// Provider errors are bounded projections. They never contain provider body
/// text, authorization material, or a raw provider error message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    InvalidRequest,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
    TransportUnavailable,
    UnexpectedStatus,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CohereInferenceError {
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
    #[error("request revision mismatch")]
    RequestRevisionMismatch,
    #[error("result revision is stale or invalid")]
    ResultRevisionMismatch,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("consent binding drifted")]
    ConsentDrift,
    #[error("policy binding drifted")]
    PolicyDrift,
    #[error("input exceeds the configured byte bound")]
    InputTooLarge,
    #[error("input item count exceeds the configured bound")]
    ItemCountExceeded,
    #[error("input item exceeds the configured byte bound")]
    ItemTooLarge,
    #[error("generation budget exceeds the configured bound")]
    GenerationBudgetExceeded,
    #[error("tool calls are not allowed by the Layer-1 contract")]
    ToolCallsForbidden,
    #[error("streaming is not allowed by the Layer-1 contract")]
    StreamingForbidden,
    #[error("file and document authority are not allowed by the Layer-1 contract")]
    FileAuthorityForbidden,
    #[error("model or endpoint mutation is not allowed by the Layer-1 contract")]
    ModelMutationForbidden,
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

pub type Result<T> = std::result::Result<T, CohereInferenceError>;

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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecretKind {
    CohereApiKey,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CohereApiKey => "cohere_api_key",
        }
    }

    #[allow(non_upper_case_globals)]
    pub const ApiKey: Self = Self::CohereApiKey;
}

/// Opaque host-owned secret binding.
///
/// This type intentionally implements neither `Serialize` nor `Deserialize`.
/// The constructor hashes the opaque host handle and discards it; the API key
/// or handle can therefore never appear in a contract, proposal, evidence,
/// `Debug` output, or serialized scope snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: Digest,
    kind: SecretKind,
    revision: u64,
}

impl SecretReference {
    pub fn new(opaque_reference: impl AsRef<str>, kind: SecretKind, revision: u64) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(CohereInferenceError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }
        let mut material = b"hartevo:cohere-secret-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        material.extend_from_slice(kind.as_str().as_bytes());
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
            .field("kind", &self.kind.as_str())
            .field("revision", &self.revision)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferencePermission {
    CohereInference,
}

impl InferencePermission {
    #[allow(non_upper_case_globals)]
    pub const Inference: Self = Self::CohereInference;
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CohereApiHost(String);

impl CohereApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim_end_matches('/').to_owned();
        if value != DEFAULT_COHERE_API_HOST
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_whitespace)
        {
            return Err(CohereInferenceError::InvalidField {
                field: "api_endpoint",
                reason: "must be the HTTPS Cohere API host without query or fragment",
            });
        }
        Ok(Self(value))
    }

    pub fn api() -> Self {
        Self(DEFAULT_COHERE_API_HOST.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type CohereEndpoint = CohereApiHost;

impl fmt::Debug for CohereApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CohereApiHost")
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
    pub fn new(model_id: impl Into<String>, immutable_revision: impl Into<String>) -> Result<Self> {
        let model_id = model_id.into();
        let immutable_revision = immutable_revision.into();
        if model_id.trim().is_empty()
            || model_id.len() > MAX_IDENTIFIER_BYTES
            || model_id.chars().any(char::is_whitespace)
            || model_id.chars().any(char::is_control)
        {
            return Err(CohereInferenceError::InvalidField {
                field: "model_id",
                reason: "must be a bounded non-empty Cohere model identifier",
            });
        }
        if immutable_revision.trim().is_empty()
            || immutable_revision.len() > MAX_MODEL_REVISION_BYTES
            || immutable_revision.chars().any(char::is_whitespace)
            || immutable_revision.chars().any(char::is_control)
            || matches!(
                immutable_revision.as_str(),
                "latest" | "default" | "main" | "master"
            )
        {
            return Err(CohereInferenceError::InvalidField {
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

pub type CohereModelRevision = ModelRevision;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceTask {
    Chat,
    Generate,
    Embed,
}

impl InferenceTask {
    #[allow(non_upper_case_globals)]
    pub const ChatCompletion: Self = Self::Chat;
    #[allow(non_upper_case_globals)]
    pub const TextGeneration: Self = Self::Generate;
    #[allow(non_upper_case_globals)]
    pub const Embedding: Self = Self::Embed;

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Generate => "generate",
            Self::Embed => "embed",
        }
    }

    pub const fn endpoint_path(self) -> &'static str {
        match self {
            Self::Chat => "/v2/chat",
            Self::Generate => "/v1/generate",
            Self::Embed => "/v2/embed",
        }
    }

    pub fn digest(self) -> Digest {
        digest_serializable(&self)
    }
}

pub type CohereTask = InferenceTask;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRoute {
    provider_id: String,
    api_host: CohereApiHost,
}

impl ProviderRoute {
    pub fn new(api_host: CohereApiHost) -> Result<Self> {
        if api_host.as_str() != DEFAULT_COHERE_API_HOST {
            return Err(CohereInferenceError::InvalidField {
                field: "provider_route",
                reason: "only the explicit Cohere API route is allowlisted",
            });
        }
        Ok(Self {
            provider_id: COHERE_INFERENCE_PROVIDER_ID.to_owned(),
            api_host,
        })
    }

    pub fn cohere() -> Self {
        Self {
            provider_id: COHERE_INFERENCE_PROVIDER_ID.to_owned(),
            api_host: CohereApiHost::api(),
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn api_host(&self) -> &CohereApiHost {
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
            .field("api_endpoint", &self.api_host)
            .field("digest", &self.digest())
            .finish()
    }
}

pub type CohereProviderRoute = ProviderRoute;

/// Account details intentionally do not implement serialization because they
/// contain the opaque secret binding.
#[derive(Clone, Eq, PartialEq)]
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
        secret: SecretReference,
    ) -> Result<Self> {
        Self::with_organization(account_id, None::<String>, permission, secret)
    }

    pub fn with_organization(
        account_id: impl Into<String>,
        organization: Option<impl Into<String>>,
        permission: InferencePermission,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        let account_id = account_id.into();
        let organization = organization.map(Into::into);
        validate_identifier("account_id", &account_id, "account identifier")?;
        if organization.as_deref().is_some_and(|value| {
            value.trim().is_empty()
                || value.len() > MAX_IDENTIFIER_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(CohereInferenceError::InvalidField {
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
            account_id: &self.account_id,
            organization: self.organization.as_deref(),
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        scoped_id("work_product_id", id, revision)
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
pub struct ConsentScope {
    id: String,
    revision: u64,
}

impl ConsentScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
        scoped_id("consent_id", id, revision)
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

fn scoped_id<T>(field: &'static str, id: impl Into<String>, revision: u64) -> Result<T>
where
    T: From<ScopedId>,
{
    let id = id.into();
    validate_identifier(field, &id, "scope identifier")?;
    Ok(T::from(ScopedId { id, revision }))
}

fn validate_identifier(field: &'static str, value: &str, reason_name: &'static str) -> Result<()> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(CohereInferenceError::InvalidField {
            field,
            reason: match reason_name {
                "account identifier" => "must be a bounded non-empty account identifier",
                "scope identifier" => "must be a bounded non-empty scope identifier",
                _ => "must be a bounded non-empty identifier",
            },
        });
    }
    Ok(())
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

impl From<ScopedId> for ConsentScope {
    fn from(value: ScopedId) -> Self {
        Self {
            id: value.id,
            revision: value.revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferencePolicy {
    revision: String,
    max_input_bytes: usize,
    max_items: usize,
    max_item_bytes: usize,
    max_new_tokens: u32,
    max_response_bytes: usize,
    max_embedding_dimensions: usize,
}

impl InferencePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        revision: impl Into<String>,
        max_input_bytes: usize,
        max_items: usize,
        max_item_bytes: usize,
        max_new_tokens: u32,
        max_response_bytes: usize,
        max_embedding_dimensions: usize,
    ) -> Result<Self> {
        let revision = revision.into();
        if revision.trim().is_empty()
            || revision.len() > MAX_POLICY_REVISION_BYTES
            || revision.chars().any(char::is_whitespace)
            || revision.chars().any(char::is_control)
        {
            return Err(CohereInferenceError::InvalidField {
                field: "policy_revision",
                reason: "must be a bounded non-empty revision",
            });
        }
        if max_input_bytes == 0
            || max_input_bytes > MAX_INPUT_BYTES
            || max_items == 0
            || max_items > MAX_ITEMS
            || max_item_bytes == 0
            || max_item_bytes > MAX_ITEM_BYTES
            || max_new_tokens > MAX_NEW_TOKENS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_embedding_dimensions == 0
            || max_embedding_dimensions > MAX_EMBEDDING_DIMENSIONS
        {
            return Err(CohereInferenceError::InvalidField {
                field: "inference_policy",
                reason: "one or more bounds are outside the Layer-1 limits",
            });
        }
        Ok(Self {
            revision,
            max_input_bytes,
            max_items,
            max_item_bytes,
            max_new_tokens,
            max_response_bytes,
            max_embedding_dimensions,
        })
    }

    pub fn bounded(revision: impl Into<String>) -> Result<Self> {
        Self::new(
            revision,
            64 * 1024,
            16,
            16 * 1024,
            1024,
            MAX_RESPONSE_BYTES,
            4096,
        )
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub const fn max_items(&self) -> usize {
        self.max_items
    }

    pub const fn max_item_bytes(&self) -> usize {
        self.max_item_bytes
    }

    pub const fn max_new_tokens(&self) -> u32 {
        self.max_new_tokens
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn max_embedding_dimensions(&self) -> usize {
        self.max_embedding_dimensions
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

pub type CohereInferencePolicy = InferencePolicy;

#[derive(Clone, Eq, PartialEq)]
pub struct CohereInferenceScope {
    api_host: CohereApiHost,
    account: AccountScope,
    model: ModelRevision,
    task: InferenceTask,
    provider_route: ProviderRoute,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
    policy: InferencePolicy,
}

impl CohereInferenceScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_host: CohereApiHost,
        account: AccountScope,
        model: ModelRevision,
        task: InferenceTask,
        provider_route: ProviderRoute,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        consent: ConsentScope,
        policy: InferencePolicy,
    ) -> Result<Self> {
        if provider_route.api_host() != &api_host {
            return Err(CohereInferenceError::ScopeMismatch(
                "provider route host differs from the scoped API endpoint",
            ));
        }
        if provider_route.provider_id() != COHERE_INFERENCE_PROVIDER_ID {
            return Err(CohereInferenceError::ProviderRouteMismatch);
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
            consent,
            policy,
        })
    }

    pub fn api_host(&self) -> &CohereApiHost {
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

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
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

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn policy_digest(&self) -> Digest {
        self.policy.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&ScopeDigestMaterial {
            api_host: &self.api_host,
            account: AccountDigestMaterial::from(&self.account),
            model: &self.model,
            task: self.task,
            provider_route: &self.provider_route,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            consent: &self.consent,
            policy: &self.policy,
        })
    }
}

impl fmt::Debug for CohereInferenceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CohereInferenceScope")
            .field("api_endpoint", &self.api_host)
            .field("account", &self.account)
            .field("model", &self.model)
            .field("task", &self.task)
            .field("provider_route", &self.provider_route)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("consent", &self.consent)
            .field("policy_revision", &self.policy.revision)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

pub type CohereScope = CohereInferenceScope;

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    api_host: &'a CohereApiHost,
    account: AccountDigestMaterial<'a>,
    model: &'a ModelRevision,
    task: InferenceTask,
    provider_route: &'a ProviderRoute,
    project: &'a ProjectScope,
    mission: &'a MissionScope,
    work_product: &'a WorkProductScope,
    consent: &'a ConsentScope,
    policy: &'a InferencePolicy,
}

#[derive(Serialize)]
struct AccountDigestMaterial<'a> {
    account_id: &'a str,
    organization: Option<&'a str>,
    permission: InferencePermission,
    secret_reference_digest: &'a Digest,
}

impl<'a> From<&'a AccountScope> for AccountDigestMaterial<'a> {
    fn from(value: &'a AccountScope) -> Self {
        Self {
            account_id: &value.account_id,
            organization: value.organization.as_deref(),
            permission: value.permission,
            secret_reference_digest: value.secret_reference.reference_digest(),
        }
    }
}

#[derive(Serialize)]
struct PermissionBinding<'a> {
    account_id: &'a str,
    organization: Option<&'a str>,
    permission: InferencePermission,
    secret_reference_digest: &'a Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeDrift,
    PermissionDrift,
    ConsentDrift,
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
    consent_digest: Digest,
    policy_digest: Digest,
    registration_digest: Digest,
    revocation_revision: u64,
    status: RegistrationStatus,
}

impl PluginRegistration {
    pub(crate) fn new(scope: &CohereInferenceScope) -> Self {
        let version_digest = digest_serializable(&(
            COHERE_INFERENCE_PLUGIN_VERSION,
            COHERE_INFERENCE_CONTRACT_VERSION,
        ));
        let contract_digest = digest_bytes(COHERE_INFERENCE_CONTRACT_JSON.as_bytes());
        let provider_digest = scope.provider_digest();
        let model_digest = scope.model_digest();
        let task_digest = scope.task_digest();
        let scope_digest = scope.digest();
        let permission_digest = scope.permission_digest();
        let consent_digest = scope.consent_digest();
        let policy_digest = scope.policy_digest();
        let registration_digest = digest_serializable(&RegistrationMaterial {
            plugin_version: COHERE_INFERENCE_PLUGIN_VERSION,
            contract_version: COHERE_INFERENCE_CONTRACT_VERSION,
            version_digest: &version_digest,
            contract_digest: &contract_digest,
            provider_digest: &provider_digest,
            model_digest: &model_digest,
            task_digest: &task_digest,
            scope_digest: &scope_digest,
            permission_digest: &permission_digest,
            consent_digest: &consent_digest,
            policy_digest: &policy_digest,
        });
        Self {
            plugin_version: COHERE_INFERENCE_PLUGIN_VERSION.to_owned(),
            contract_version: COHERE_INFERENCE_CONTRACT_VERSION.to_owned(),
            version_digest,
            contract_digest,
            provider_digest,
            model_digest,
            task_digest,
            scope_digest,
            permission_digest,
            consent_digest,
            policy_digest,
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

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
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

    pub(crate) fn validate_against(&self, scope: &CohereInferenceScope) -> Result<()> {
        let expected_version =
            digest_serializable(&(self.plugin_version.as_str(), self.contract_version.as_str()));
        let expected_contract = digest_bytes(COHERE_INFERENCE_CONTRACT_JSON.as_bytes());
        let expected_registration = digest_serializable(&RegistrationMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            model_digest: &self.model_digest,
            task_digest: &self.task_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            policy_digest: &self.policy_digest,
        });
        if self.version_digest != expected_version
            || self.contract_digest != expected_contract
            || self.provider_digest != scope.provider_digest()
            || self.model_digest != scope.model_digest()
            || self.task_digest != scope.task_digest()
            || self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest()
            || self.consent_digest != scope.consent_digest()
            || self.policy_digest != scope.policy_digest()
            || self.registration_digest != expected_registration
        {
            return Err(CohereInferenceError::RegistrationTampered);
        }
        if !self.is_active() {
            return Err(CohereInferenceError::RegistrationRevoked);
        }
        Ok(())
    }

    pub(crate) fn revoke(&mut self, reason: RevocationReason) -> Result<Revocation> {
        if self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                CohereInferenceError::InvalidField {
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

    pub(crate) fn restore(&mut self) -> Result<()> {
        if !self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                CohereInferenceError::InvalidField {
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
    consent_digest: &'a Digest,
    policy_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    ChatMessages,
    SingleText,
    TextBatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestOptions {
    stream: bool,
    tool_calls: bool,
    file_inputs: bool,
}

impl RequestOptions {
    pub const fn bounded() -> Self {
        Self {
            stream: false,
            tool_calls: false,
            file_inputs: false,
        }
    }

    pub const fn new(stream: bool, tool_calls: bool, file_inputs: bool) -> Self {
        Self {
            stream,
            tool_calls,
            file_inputs,
        }
    }

    pub const fn stream(self) -> bool {
        self.stream
    }

    pub const fn tool_calls(self) -> bool {
        self.tool_calls
    }

    pub const fn file_inputs(self) -> bool {
        self.file_inputs
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
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
    pub fn new(role: ChatRole, content: impl Into<String>) -> Result<Self> {
        let content = content.into();
        if content.is_empty()
            || content.len() > MAX_ITEM_BYTES
            || content.chars().any(char::is_control)
        {
            return Err(CohereInferenceError::InvalidField {
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
    Texts(Vec<String>),
}

impl InferenceInput {
    pub fn chat(messages: Vec<ChatMessage>) -> Result<Self> {
        if messages.is_empty() || messages.len() > MAX_ITEMS {
            return Err(CohereInferenceError::ItemCountExceeded);
        }
        Ok(Self::Chat(messages))
    }

    pub fn text(input: impl Into<String>) -> Result<Self> {
        let input = input.into();
        validate_input_text(&input)?;
        Ok(Self::Text(input))
    }

    pub fn texts<I, S>(texts: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let texts = texts.into_iter().map(Into::into).collect::<Vec<_>>();
        if texts.is_empty() || texts.len() > MAX_ITEMS {
            return Err(CohereInferenceError::ItemCountExceeded);
        }
        for text in &texts {
            validate_input_text(text)?;
        }
        Ok(Self::Texts(texts))
    }

    pub fn generate(input: impl Into<String>) -> Result<Self> {
        Self::text(input)
    }

    pub fn embed<I, S>(texts: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::texts(texts)
    }

    pub const fn kind(&self) -> InputKind {
        match self {
            Self::Chat(_) => InputKind::ChatMessages,
            Self::Text(_) => InputKind::SingleText,
            Self::Texts(_) => InputKind::TextBatch,
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Chat(messages) => messages.len(),
            Self::Text(_) => 1,
            Self::Texts(texts) => texts.len(),
        }
    }

    pub fn input_bytes(&self) -> usize {
        match self {
            Self::Chat(messages) => messages.iter().map(ChatMessage::content_len).sum(),
            Self::Text(text) => text.len(),
            Self::Texts(texts) => texts.iter().map(String::len).sum(),
        }
    }

    pub(crate) fn messages(&self) -> Option<&[ChatMessage]> {
        match self {
            Self::Chat(messages) => Some(messages),
            Self::Text(_) | Self::Texts(_) => None,
        }
    }

    pub(crate) fn single_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Chat(_) | Self::Texts(_) => None,
        }
    }

    pub(crate) fn text_batch(&self) -> Option<&[String]> {
        match self {
            Self::Texts(texts) => Some(texts),
            Self::Chat(_) | Self::Text(_) => None,
        }
    }

    pub(crate) fn digest(&self) -> Digest {
        match self {
            Self::Chat(messages) => digest_serializable(
                &messages
                    .iter()
                    .map(|message| (message.role, message.content()))
                    .collect::<Vec<_>>(),
            ),
            Self::Text(text) => digest_bytes(text.as_bytes()),
            Self::Texts(texts) => digest_serializable(texts),
        }
    }
}

impl fmt::Debug for InferenceInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InferenceInput")
            .field("kind", &self.kind())
            .field("item_count", &self.item_count())
            .field("input_bytes", &self.input_bytes())
            .field("input_digest", &self.digest())
            .finish()
    }
}

fn validate_input_text(text: &str) -> Result<()> {
    if text.is_empty() || text.len() > MAX_ITEM_BYTES || text.chars().any(char::is_control) {
        return Err(CohereInferenceError::InvalidField {
            field: "input.text",
            reason: "must be non-empty, bounded, and free of control characters",
        });
    }
    Ok(())
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
    pub fn new(max_new_tokens: u32) -> Result<Self> {
        if max_new_tokens > MAX_NEW_TOKENS {
            return Err(CohereInferenceError::GenerationBudgetExceeded);
        }
        Ok(Self {
            max_new_tokens,
            temperature_milli: None,
            top_p_milli: None,
        })
    }

    pub const fn none() -> Self {
        Self {
            max_new_tokens: 0,
            temperature_milli: None,
            top_p_milli: None,
        }
    }

    pub fn with_sampling(
        mut self,
        temperature_milli: Option<u16>,
        top_p_milli: Option<u16>,
    ) -> Result<Self> {
        if temperature_milli.is_some_and(|value| value > 2000)
            || top_p_milli.is_some_and(|value| value == 0 || value > 1000)
        {
            return Err(CohereInferenceError::GenerationBudgetExceeded);
        }
        self.temperature_milli = temperature_milli;
        self.top_p_milli = top_p_milli;
        Ok(self)
    }

    pub const fn max_new_tokens(self) -> u32 {
        self.max_new_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InferenceRequest {
    request_revision: u64,
    task: InferenceTask,
    input: InferenceInput,
    generation: GenerationBudget,
    options: RequestOptions,
}

impl InferenceRequest {
    pub fn new(task: InferenceTask, input: InferenceInput, generation: GenerationBudget) -> Self {
        Self {
            request_revision: 1,
            task,
            input,
            generation,
            options: RequestOptions::bounded(),
        }
    }

    pub fn with_request_revision(mut self, request_revision: u64) -> Result<Self> {
        if request_revision == 0 {
            return Err(CohereInferenceError::InvalidField {
                field: "request_revision",
                reason: "must be non-zero",
            });
        }
        self.request_revision = request_revision;
        Ok(self)
    }

    pub fn with_revision(self, request_revision: u64) -> Result<Self> {
        self.with_request_revision(request_revision)
    }

    pub const fn with_options(mut self, options: RequestOptions) -> Self {
        self.options = options;
        self
    }

    pub const fn request_revision(&self) -> u64 {
        self.request_revision
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InferenceRequestFingerprint {
    pub request_revision: u64,
    pub request_digest: Digest,
    pub input_digest: Digest,
    pub input_kind: InputKind,
    pub item_count: usize,
    pub input_bytes: usize,
    pub max_new_tokens: u32,
    pub options: RequestOptions,
}

impl InferenceRequestFingerprint {
    pub(crate) fn from_request(scope: &CohereInferenceScope, request: &InferenceRequest) -> Self {
        let canonical = CanonicalRequest::from_request(scope, request);
        Self {
            request_revision: request.request_revision,
            request_digest: digest_serializable(&canonical),
            input_digest: request.input.digest(),
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
    request_revision: u64,
    task: InferenceTask,
    model: &'a ModelRevision,
    provider_route: &'a ProviderRoute,
    policy_digest: Digest,
    consent_digest: Digest,
    input: CanonicalInput<'a>,
    generation: GenerationBudget,
    options: RequestOptions,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
enum CanonicalInput<'a> {
    Chat { messages: Vec<CanonicalMessage<'a>> },
    Text { text: &'a str },
    Texts { texts: &'a [String] },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalMessage<'a> {
    role: ChatRole,
    content: &'a str,
}

impl<'a> CanonicalRequest<'a> {
    fn from_request(scope: &'a CohereInferenceScope, request: &'a InferenceRequest) -> Self {
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
            InferenceInput::Text(text) => CanonicalInput::Text { text },
            InferenceInput::Texts(texts) => CanonicalInput::Texts { texts },
        };
        Self {
            request_revision: request.request_revision,
            task: request.task,
            model: &scope.model,
            provider_route: &scope.provider_route,
            policy_digest: scope.policy.digest(),
            consent_digest: scope.consent.digest(),
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
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub policy_digest: Digest,
    pub proposal_digest: Digest,
}

pub type CohereInferenceResultProposal = InferenceResultProposal;

impl InferenceResultProposal {
    pub(crate) fn new(
        scope: &CohereInferenceScope,
        registration: &PluginRegistration,
        request: &InferenceRequest,
    ) -> Self {
        let request = InferenceRequestFingerprint::from_request(scope, request);
        let mut proposal = Self {
            proposal_version: "cohere-inference-result-proposal/v1".to_owned(),
            service_id: COHERE_INFERENCE_SERVICE_ID.to_owned(),
            task: scope.task,
            model: scope.model.clone(),
            provider_route: scope.provider_route.clone(),
            request,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.digest(),
            provider_digest: scope.provider_digest(),
            model_digest: scope.model_digest(),
            task_digest: scope.task_digest(),
            permission_digest: scope.permission_digest(),
            consent_digest: scope.consent_digest(),
            policy_digest: scope.policy_digest(),
            proposal_digest: digest_bytes(b"uninitialized-cohere-proposal-digest"),
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
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            policy_digest: &self.policy_digest,
        })
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(CohereInferenceError::ProposalTampered)
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
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    policy_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceResultState {
    Submitted,
    Queued,
    Running,
    Completed,
    Failed,
    Partial,
    Timeout,
    Expired,
    ProviderUnknown,
}

pub type ResultState = InferenceResultState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Other,
}

impl FinishReason {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        let value = value.to_ascii_lowercase();
        Some(match value.as_str() {
            "stop" | "complete" | "completed" | "end_turn" => Self::Stop,
            "length" | "max_tokens" | "max_tokens_reached" => Self::Length,
            "tool_calls" | "tool_call" | "function_call" | "tool_use" => Self::ToolCalls,
            "content_filter" | "safety" => Self::ContentFilter,
            "" => return None,
            _ => Self::Other,
        })
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
    ) -> Result<Self> {
        if prompt_tokens.saturating_add(completion_tokens) != total_tokens {
            return Err(CohereInferenceError::MalformedResponse(
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Chat,
    Generation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactedContent {
    pub content_digest: Digest,
    pub byte_length: usize,
    pub item_count: usize,
    pub kind: ContentKind,
}

impl RedactedContent {
    pub(crate) fn new(value: &[u8], item_count: usize, kind: ContentKind) -> Result<Self> {
        if item_count == 0 || item_count > MAX_ITEMS || value.len() > MAX_RESPONSE_BYTES {
            return Err(CohereInferenceError::MalformedResponse(
                "redacted content is outside the bounded projection",
            ));
        }
        Ok(Self {
            content_digest: digest_bytes(value),
            byte_length: value.len(),
            item_count,
            kind,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddingProjection {
    pub item_count: usize,
    pub dimensions: usize,
    pub embedding_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderMode {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderMode {
    pub const BLOCKED_ENV: Self = Self::BlockedEnv;

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Fake => "fake",
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
    first_party: bool,
}

impl EvidenceAuthority {
    pub(crate) const fn for_mode(mode: ProviderMode) -> Self {
        Self {
            mode,
            connected: false,
            native: false,
            first_party: false,
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

    pub const fn first_party(&self) -> bool {
        self.first_party
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    RecordedSuccess,
    RecordedPartial,
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
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub policy_digest: Digest,
    pub model_id: String,
    pub model_revision: String,
    pub request_revision: u64,
    pub result_revision: u64,
    pub response_digest: Digest,
    pub content: Option<RedactedContent>,
    pub embedding: Option<EmbeddingProjection>,
    pub usage: Option<UsageProjection>,
    pub latency_ms: u64,
    pub finish_reason: Option<FinishReason>,
    pub state: InferenceResultState,
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
        result_revision: u64,
        response_digest: Digest,
        content: Option<RedactedContent>,
        embedding: Option<EmbeddingProjection>,
        usage: Option<UsageProjection>,
        latency_ms: u64,
        finish_reason: Option<FinishReason>,
        state: InferenceResultState,
        disposition: EvidenceDisposition,
        provider_error: Option<ProviderErrorProjection>,
    ) -> Self {
        let mut evidence = Self {
            evidence_version: "cohere-inference-result-evidence/v1".to_owned(),
            recording_key,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            model_digest: proposal.model_digest.clone(),
            task_digest: proposal.task_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            policy_digest: proposal.policy_digest.clone(),
            model_id: proposal.model.model_id().to_owned(),
            model_revision: proposal.model.immutable_revision().to_owned(),
            request_revision: proposal.request.request_revision,
            result_revision,
            response_digest,
            content,
            embedding,
            usage,
            latency_ms,
            finish_reason,
            state,
            disposition,
            provider_error,
            authority: EvidenceAuthority::for_mode(mode),
            evidence_digest: digest_bytes(b"uninitialized-cohere-evidence-digest"),
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
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            policy_digest: &self.policy_digest,
            model_id: &self.model_id,
            model_revision: &self.model_revision,
            request_revision: self.request_revision,
            result_revision: self.result_revision,
            response_digest: &self.response_digest,
            content: self.content.as_ref(),
            embedding: self.embedding.as_ref(),
            usage: self.usage.as_ref(),
            latency_ms: self.latency_ms,
            finish_reason: self.finish_reason.as_ref(),
            state: &self.state,
            disposition: self.disposition,
            provider_error: self.provider_error.as_ref(),
            authority: &self.authority,
        })
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.authority.connected() || self.authority.native() || self.authority.first_party() {
            return Err(CohereInferenceError::EvidenceTampered);
        }
        if self.request_revision == 0
            || self.result_revision == 0
            || self.evidence_digest != self.compute_digest()
        {
            return Err(CohereInferenceError::EvidenceTampered);
        }
        Ok(())
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
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    policy_digest: &'a Digest,
    model_id: &'a str,
    model_revision: &'a str,
    request_revision: u64,
    result_revision: u64,
    response_digest: &'a Digest,
    content: Option<&'a RedactedContent>,
    embedding: Option<&'a EmbeddingProjection>,
    usage: Option<&'a UsageProjection>,
    latency_ms: u64,
    finish_reason: Option<&'a FinishReason>,
    state: &'a InferenceResultState,
    disposition: EvidenceDisposition,
    provider_error: Option<&'a ProviderErrorProjection>,
    authority: &'a EvidenceAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelDescription {
    model: ModelRevision,
    task: InferenceTask,
    provider_route: ProviderRoute,
    source: String,
    model_list_read_back: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl ModelDescription {
    pub(crate) fn from_scope(scope: &CohereInferenceScope) -> Self {
        Self {
            model: scope.model.clone(),
            task: scope.task,
            provider_route: scope.provider_route.clone(),
            source: "scoped_declaration_only".to_owned(),
            model_list_read_back: false,
            connected: false,
            native: false,
            first_party: false,
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

    pub const fn model_list_read_back(&self) -> bool {
        self.model_list_read_back
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }
}

pub const fn provider_identity() -> &'static str {
    COHERE_INFERENCE_PROVIDER_ID
}

pub const fn contract_schema_identity() -> &'static str {
    COHERE_INFERENCE_SCHEMA_VERSION
}

pub const fn service_identity() -> &'static str {
    COHERE_INFERENCE_SERVICE_ID
}
