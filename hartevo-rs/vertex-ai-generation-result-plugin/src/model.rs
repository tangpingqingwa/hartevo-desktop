//! Typed, bounded, and redacted contract models for the Vertex AI seam.

use std::{
    collections::BTreeSet,
    fmt,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::{
    VERTEX_AI_GENERATION_CONTRACT_JSON, VERTEX_AI_GENERATION_CONTRACT_VERSION,
    VERTEX_AI_GENERATION_PLUGIN_VERSION, VERTEX_AI_GENERATION_PROVIDER_ID,
    VERTEX_AI_GENERATION_SCHEMA_VERSION, VERTEX_AI_GENERATION_SERVICE_ID, digest_bytes,
    digest_serializable,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REVISION_BYTES: usize = 64;
pub const MAX_INPUT_PARTS: usize = 16;
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TEXT_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGE_REFERENCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DOCUMENT_REFERENCE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTPUT_TOKENS: u32 = 8192;
pub const MAX_CANDIDATES: usize = 8;
pub const MAX_SAFETY_RATINGS: usize = 16;
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_SCHEMA_NAME_BYTES: usize = 64;
pub const MAX_RESPONSE_ID_BYTES: usize = 256;

/// Provider errors are bounded projections. They never carry provider body
/// text, credential material, raw prompts, or raw output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    ServerError,
    Timeout,
    Cancelled,
    Expired,
    TransportUnavailable,
    MalformedResponse,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum VertexAiGenerationError {
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
    #[error("Google Cloud project mismatch")]
    ProjectMismatch,
    #[error("Vertex location mismatch")]
    LocationMismatch,
    #[error("publisher mismatch")]
    PublisherMismatch,
    #[error("model identity mismatch")]
    ModelMismatch,
    #[error("model snapshot drifted from the pinned immutable snapshot")]
    ModelSnapshotDrift,
    #[error("provider route mismatch; silent failover is refused")]
    ProviderRouteMismatch,
    #[error("permission binding drifted")]
    PermissionDrift,
    #[error("consent binding drifted")]
    ConsentDrift,
    #[error("Mission revision drifted")]
    MissionRevisionDrift,
    #[error("Project revision drifted")]
    ProjectRevisionDrift,
    #[error("Work Product revision drifted")]
    WorkProductRevisionDrift,
    #[error("input exceeds the configured byte bound")]
    InputTooLarge,
    #[error("input part exceeds the configured byte bound")]
    InputPartTooLarge,
    #[error("input modality is not allowlisted by the scope")]
    ModalityForbidden,
    #[error("input part count exceeds the configured bound")]
    InputPartCountExceeded,
    #[error("output byte bound exceeds the configured scope")]
    OutputTooLarge,
    #[error("candidate count exceeds the configured bound")]
    CandidateCountExceeded,
    #[error("output token budget exceeds the configured bound")]
    OutputTokenBudgetExceeded,
    #[error("tool calls are forbidden by the Layer-1 contract")]
    ToolCallsForbidden,
    #[error("grounding is forbidden by the Layer-1 contract")]
    GroundingForbidden,
    #[error("streaming is forbidden by the Layer-1 generateContent contract")]
    StreamingForbidden,
    #[error("output schema is not allowlisted by the scope")]
    SchemaMismatch,
    #[error("schema or response metadata exceeds the configured bound")]
    SchemaTooLarge,
    #[error("response is too large for the configured Layer-1 bound")]
    ResponseTooLarge,
    #[error("recorded response ingress binding is tampered")]
    ResponseIngressTampered,
    #[error("response has too many candidates")]
    ResponseCandidateCountExceeded,
    #[error("response candidate content exceeds the configured bound")]
    ResponseContentTooLarge,
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
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn sha256(bytes: impl AsRef<[u8]>) -> Self {
        digest_bytes(bytes.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, VertexAiGenerationError> {
        let value = value.into();
        if is_sha256(&value) {
            Ok(Self(value))
        } else {
            Err(VertexAiGenerationError::InvalidField {
                field: "digest",
                reason: "must be a lowercase SHA-256 hex digest",
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        is_sha256(&self.0)
    }

    pub(crate) fn from_hex(bytes: impl AsRef<[u8]>) -> Self {
        Self(crate::hex_encode(bytes))
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
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

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_token(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= max_bytes
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn valid_revision(value: &str) -> bool {
    valid_token(value, MAX_REVISION_BYTES)
        && !matches!(
            value,
            "latest" | "default" | "current" | "stable" | "preview"
        )
}

fn valid_scoped_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .chars()
            .all(|character| !character.is_control() && !character.is_whitespace())
}

fn validate_scoped_id(
    field: &'static str,
    value: String,
    revision: u64,
) -> Result<(String, u64), VertexAiGenerationError> {
    if !valid_scoped_id(&value) {
        return Err(VertexAiGenerationError::InvalidField {
            field,
            reason: "must be a bounded non-empty scope identifier",
        });
    }
    if revision == 0 {
        return Err(VertexAiGenerationError::InvalidField {
            field: "revision",
            reason: "must be non-zero",
        });
    }
    Ok((value, revision))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ServiceAccount,
}

/// Opaque host-owned credential binding.
///
/// The constructor hashes the host handle and discards it. This type
/// deliberately implements neither `Serialize` nor `Deserialize`; only its
/// digest, kind, and revision may cross the Layer-1 contract boundary.
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: u64,
    kind: SecretKind,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("credential_revision", &self.credential_revision)
            .field("kind", &self.kind)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        kind: SecretKind,
        credential_revision: u64,
    ) -> Result<Self, VertexAiGenerationError> {
        let opaque_reference = opaque_reference.as_ref();
        if !valid_token(opaque_reference, MAX_IDENTIFIER_BYTES) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }
        if credential_revision == 0 {
            return Err(VertexAiGenerationError::InvalidField {
                field: "credential_revision",
                reason: "must be non-zero",
            });
        }
        let reference_digest = digest_serializable(&(
            "hartevo:vertex-ai-secret-reference:v1",
            opaque_reference,
            kind,
            credential_revision,
        ));
        Ok(Self {
            reference_digest,
            credential_revision,
            kind,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleCloudProject {
    project_id: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GoogleCloudProjectWire {
    project_id: String,
    revision: u64,
}

impl<'de> Deserialize<'de> for GoogleCloudProject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = GoogleCloudProjectWire::deserialize(deserializer)?;
        Self::new(wire.project_id, wire.revision).map_err(serde::de::Error::custom)
    }
}

impl GoogleCloudProject {
    pub fn new(
        project_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, VertexAiGenerationError> {
        let project_id = project_id.into();
        let valid = project_id.len() >= 4
            && project_id.len() <= 30
            && project_id.bytes().enumerate().all(|(index, byte)| {
                (index == 0 && byte.is_ascii_lowercase())
                    || (index > 0
                        && (byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
            })
            && !project_id.ends_with('-');
        if !valid {
            return Err(VertexAiGenerationError::InvalidField {
                field: "google_cloud_project_id",
                reason: "must be a bounded lowercase Google Cloud project id",
            });
        }
        if revision == 0 {
            return Err(VertexAiGenerationError::InvalidField {
                field: "google_cloud_project_revision",
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            project_id,
            revision,
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct VertexLocation(String);

impl<'de> Deserialize<'de> for VertexLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl VertexLocation {
    pub fn new(value: impl Into<String>) -> Result<Self, VertexAiGenerationError> {
        let value = value.into().to_ascii_lowercase();
        let segments = value.split('-').collect::<Vec<_>>();
        let valid = value.len() <= MAX_IDENTIFIER_BYTES
            && value != "global"
            && segments.len() >= 2
            && segments.iter().all(|segment| !segment.is_empty())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_digit());
        if !valid {
            return Err(VertexAiGenerationError::InvalidField {
                field: "location",
                reason: "must be a bounded regional Vertex AI location, not global",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn regional_endpoint(&self) -> String {
        format!("{}-aiplatform.googleapis.com", self.0)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

impl fmt::Debug for VertexLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("VertexLocation")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VertexApiVersion {
    V1,
}

impl VertexApiVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VertexPublisher {
    Google,
}

impl VertexPublisher {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
        }
    }
}

fn allowlisted_model_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("gemini-") else {
        return false;
    };
    let mut parts = rest.splitn(2, '-');
    let Some(version) = parts.next() else {
        return false;
    };
    let Some(family) = parts.next() else {
        return false;
    };
    version.contains('.')
        && version
            .split('.')
            .all(|segment| !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()))
        && !family.is_empty()
        && family
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
        && !value.contains("preview")
        && !value.contains("experimental")
        && !value.contains("-exp")
        && !value.contains("tuning")
        && !value.ends_with("-latest")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelSnapshot {
    model_id: String,
    immutable_snapshot: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelSnapshotWire {
    model_id: String,
    immutable_snapshot: String,
}

impl<'de> Deserialize<'de> for ModelSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ModelSnapshotWire::deserialize(deserializer)?;
        Self::new(wire.model_id, wire.immutable_snapshot).map_err(serde::de::Error::custom)
    }
}

impl ModelSnapshot {
    pub fn new(
        model_id: impl Into<String>,
        immutable_snapshot: impl Into<String>,
    ) -> Result<Self, VertexAiGenerationError> {
        let model_id = model_id.into();
        let immutable_snapshot = immutable_snapshot.into();
        if !valid_token(&model_id, MAX_IDENTIFIER_BYTES) || !allowlisted_model_id(&model_id) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "model_id",
                reason: "must be an allowlisted stable Gemini model family",
            });
        }
        if !valid_revision(&immutable_snapshot) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "immutable_model_snapshot",
                reason: "must be a bounded immutable snapshot, not a floating alias",
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

    pub fn expected_model_version(&self) -> String {
        if self
            .model_id
            .ends_with(&format!("-{}", self.immutable_snapshot))
        {
            self.model_id.clone()
        } else {
            format!("{}-{}", self.model_id, self.immutable_snapshot)
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProjectScopeWire {
    id: String,
    revision: u64,
}

impl<'de> Deserialize<'de> for ProjectScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ProjectScopeWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.revision).map_err(serde::de::Error::custom)
    }
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, VertexAiGenerationError> {
        let (id, revision) = validate_scoped_id("project_id", id.into(), revision)?;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MissionScopeWire {
    id: String,
    revision: u64,
}

impl<'de> Deserialize<'de> for MissionScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = MissionScopeWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.revision).map_err(serde::de::Error::custom)
    }
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, VertexAiGenerationError> {
        let (id, revision) = validate_scoped_id("mission_id", id.into(), revision)?;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: String,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WorkProductScopeWire {
    id: String,
    revision: u64,
}

impl<'de> Deserialize<'de> for WorkProductScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WorkProductScopeWire::deserialize(deserializer)?;
        Self::new(wire.id, wire.revision).map_err(serde::de::Error::custom)
    }
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, VertexAiGenerationError> {
        let (id, revision) = validate_scoped_id("work_product_id", id.into(), revision)?;
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
#[serde(rename_all = "snake_case")]
pub enum VertexAiPermission {
    GenerateContent,
}

/// Permission and opaque credential binding. No credential bytes are held.
pub struct PermissionScope {
    permission: VertexAiPermission,
    secret_reference: SecretReference,
}

impl Clone for PermissionScope {
    fn clone(&self) -> Self {
        Self {
            permission: self.permission.clone(),
            secret_reference: self.secret_reference.clone(),
        }
    }
}

impl PartialEq for PermissionScope {
    fn eq(&self, other: &Self) -> bool {
        self.permission == other.permission && self.secret_reference == other.secret_reference
    }
}

impl Eq for PermissionScope {}

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

impl PermissionScope {
    pub fn new(
        permission: VertexAiPermission,
        secret_reference: SecretReference,
    ) -> Result<Self, VertexAiGenerationError> {
        Ok(Self {
            permission,
            secret_reference,
        })
    }

    pub fn generate_content(
        secret_reference: SecretReference,
    ) -> Result<Self, VertexAiGenerationError> {
        Self::new(VertexAiPermission::GenerateContent, secret_reference)
    }

    pub const fn permission(&self) -> &VertexAiPermission {
        &self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&PermissionDigestMaterial {
            permission: &self.permission,
            secret_reference_digest: self.secret_reference.reference_digest(),
            credential_revision: self.secret_reference.credential_revision(),
            kind: self.secret_reference.kind(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputModality {
    Text,
    ImageReference,
    DocumentReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputPolicy {
    revision: String,
    allowed_modalities: BTreeSet<InputModality>,
    max_input_bytes: usize,
    max_parts: usize,
    max_text_bytes: usize,
    max_image_bytes: usize,
    max_document_bytes: usize,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputPolicyWire {
    revision: String,
    allowed_modalities: BTreeSet<InputModality>,
    max_input_bytes: usize,
    max_parts: usize,
    max_text_bytes: usize,
    max_image_bytes: usize,
    max_document_bytes: usize,
}

impl<'de> Deserialize<'de> for InputPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = InputPolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.revision,
            wire.max_input_bytes,
            wire.max_parts,
            wire.max_text_bytes,
            wire.max_image_bytes,
            wire.max_document_bytes,
        )
        .and_then(|policy| policy.with_modalities(wire.allowed_modalities))
        .map_err(serde::de::Error::custom)
    }
}

impl InputPolicy {
    pub fn new(
        revision: impl Into<String>,
        max_input_bytes: usize,
        max_parts: usize,
        max_text_bytes: usize,
        max_image_bytes: usize,
        max_document_bytes: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        let revision = revision.into();
        if !valid_revision(&revision) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "input_policy_revision",
                reason: "must be a bounded non-floating revision",
            });
        }
        if max_input_bytes == 0
            || max_input_bytes > MAX_INPUT_BYTES
            || max_parts == 0
            || max_parts > MAX_INPUT_PARTS
            || max_text_bytes == 0
            || max_text_bytes > MAX_TEXT_INPUT_BYTES
            || max_text_bytes > max_input_bytes
            || max_image_bytes == 0
            || max_image_bytes > MAX_IMAGE_REFERENCE_BYTES
            || max_image_bytes > max_input_bytes
            || max_document_bytes == 0
            || max_document_bytes > MAX_DOCUMENT_REFERENCE_BYTES
            || max_document_bytes > max_input_bytes
        {
            return Err(VertexAiGenerationError::InvalidField {
                field: "input_policy_bounds",
                reason: "must be positive and within the Layer-1 multimodal ceilings",
            });
        }
        Ok(Self {
            revision,
            allowed_modalities: BTreeSet::from([
                InputModality::Text,
                InputModality::ImageReference,
                InputModality::DocumentReference,
            ]),
            max_input_bytes,
            max_parts,
            max_text_bytes,
            max_image_bytes,
            max_document_bytes,
        })
    }

    pub fn bounded() -> Self {
        Self::new(
            "vertex-input-policy/v1",
            MAX_INPUT_BYTES,
            MAX_INPUT_PARTS,
            MAX_TEXT_INPUT_BYTES,
            MAX_IMAGE_REFERENCE_BYTES,
            MAX_DOCUMENT_REFERENCE_BYTES,
        )
        .expect("Layer-1 input bounds are valid")
    }

    pub fn with_modalities(
        mut self,
        modalities: impl IntoIterator<Item = InputModality>,
    ) -> Result<Self, VertexAiGenerationError> {
        let allowed_modalities = modalities.into_iter().collect::<BTreeSet<_>>();
        if allowed_modalities.is_empty() {
            return Err(VertexAiGenerationError::InvalidField {
                field: "allowed_modalities",
                reason: "must retain at least one allowlisted modality",
            });
        }
        self.allowed_modalities = allowed_modalities;
        Ok(self)
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn allowed_modalities(&self) -> &BTreeSet<InputModality> {
        &self.allowed_modalities
    }

    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub const fn max_parts(&self) -> usize {
        self.max_parts
    }

    pub const fn max_text_bytes(&self) -> usize {
        self.max_text_bytes
    }

    pub const fn max_image_bytes(&self) -> usize {
        self.max_image_bytes
    }

    pub const fn max_document_bytes(&self) -> usize {
        self.max_document_bytes
    }

    pub fn allows(&self, modality: &InputModality) -> bool {
        self.allowed_modalities.contains(modality)
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

const ALLOWED_IMAGE_MEDIA_TYPES: &[&str] = &["image/jpeg", "image/png", "image/webp"];
const ALLOWED_DOCUMENT_MEDIA_TYPES: &[&str] = &[
    "application/json",
    "application/pdf",
    "text/markdown",
    "text/plain",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum InputPart {
    Text {
        content_digest: Digest,
        byte_length: usize,
    },
    ImageReference {
        reference_digest: Digest,
        media_type: String,
        byte_length: usize,
    },
    DocumentReference {
        reference_digest: Digest,
        media_type: String,
        byte_length: usize,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
enum InputPartWire {
    Text {
        content_digest: Digest,
        byte_length: usize,
    },
    ImageReference {
        reference_digest: Digest,
        media_type: String,
        byte_length: usize,
    },
    DocumentReference {
        reference_digest: Digest,
        media_type: String,
        byte_length: usize,
    },
}

impl<'de> Deserialize<'de> for InputPart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let part = match InputPartWire::deserialize(deserializer)? {
            InputPartWire::Text {
                content_digest,
                byte_length,
            } => Self::Text {
                content_digest,
                byte_length,
            },
            InputPartWire::ImageReference {
                reference_digest,
                media_type,
                byte_length,
            } => Self::ImageReference {
                reference_digest,
                media_type,
                byte_length,
            },
            InputPartWire::DocumentReference {
                reference_digest,
                media_type,
                byte_length,
            } => Self::DocumentReference {
                reference_digest,
                media_type,
                byte_length,
            },
        };
        part.validate_metadata().map_err(serde::de::Error::custom)?;
        Ok(part)
    }
}

impl InputPart {
    pub fn text(value: impl AsRef<str>) -> Result<Self, VertexAiGenerationError> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_TEXT_INPUT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(VertexAiGenerationError::InvalidField {
                field: "text_input",
                reason: "must be non-empty, bounded, and free of control characters",
            });
        }
        Ok(Self::Text {
            content_digest: digest_serializable(&("vertex-text-input/v1", value)),
            byte_length: value.len(),
        })
    }

    pub fn image_reference(
        reference: impl AsRef<str>,
        media_type: impl Into<String>,
        byte_length: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        let media_type = media_type.into().to_ascii_lowercase();
        validate_media_reference(
            "image_reference",
            reference.as_ref(),
            &media_type,
            byte_length,
            ALLOWED_IMAGE_MEDIA_TYPES,
            MAX_IMAGE_REFERENCE_BYTES,
        )?;
        Ok(Self::ImageReference {
            reference_digest: media_reference_digest("image", reference.as_ref(), &media_type),
            media_type,
            byte_length,
        })
    }

    pub fn document_reference(
        reference: impl AsRef<str>,
        media_type: impl Into<String>,
        byte_length: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        let media_type = media_type.into().to_ascii_lowercase();
        validate_media_reference(
            "document_reference",
            reference.as_ref(),
            &media_type,
            byte_length,
            ALLOWED_DOCUMENT_MEDIA_TYPES,
            MAX_DOCUMENT_REFERENCE_BYTES,
        )?;
        Ok(Self::DocumentReference {
            reference_digest: media_reference_digest("document", reference.as_ref(), &media_type),
            media_type,
            byte_length,
        })
    }

    pub const fn modality(&self) -> InputModality {
        match self {
            Self::Text { .. } => InputModality::Text,
            Self::ImageReference { .. } => InputModality::ImageReference,
            Self::DocumentReference { .. } => InputModality::DocumentReference,
        }
    }

    pub const fn byte_length(&self) -> usize {
        match self {
            Self::Text { byte_length, .. }
            | Self::ImageReference { byte_length, .. }
            | Self::DocumentReference { byte_length, .. } => *byte_length,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        match self {
            Self::Text {
                content_digest,
                byte_length,
            } => {
                if !content_digest.is_sha256() {
                    return Err(VertexAiGenerationError::InvalidField {
                        field: "text_content_digest",
                        reason: "must be a SHA-256 digest",
                    });
                }
                if *byte_length == 0 || *byte_length > MAX_TEXT_INPUT_BYTES {
                    return Err(VertexAiGenerationError::InputPartTooLarge);
                }
            }
            Self::ImageReference {
                reference_digest,
                media_type,
                byte_length,
            } => {
                if !reference_digest.is_sha256() {
                    return Err(VertexAiGenerationError::InvalidField {
                        field: "image_reference_digest",
                        reason: "must be a SHA-256 digest",
                    });
                }
                if !ALLOWED_IMAGE_MEDIA_TYPES.contains(&media_type.as_str()) {
                    return Err(VertexAiGenerationError::InvalidField {
                        field: "media_type",
                        reason: "must be an allowlisted image media type",
                    });
                }
                if *byte_length == 0 || *byte_length > MAX_IMAGE_REFERENCE_BYTES {
                    return Err(VertexAiGenerationError::InputPartTooLarge);
                }
            }
            Self::DocumentReference {
                reference_digest,
                media_type,
                byte_length,
            } => {
                if !reference_digest.is_sha256() {
                    return Err(VertexAiGenerationError::InvalidField {
                        field: "document_reference_digest",
                        reason: "must be a SHA-256 digest",
                    });
                }
                if !ALLOWED_DOCUMENT_MEDIA_TYPES.contains(&media_type.as_str()) {
                    return Err(VertexAiGenerationError::InvalidField {
                        field: "media_type",
                        reason: "must be an allowlisted document media type",
                    });
                }
                if *byte_length == 0 || *byte_length > MAX_DOCUMENT_REFERENCE_BYTES {
                    return Err(VertexAiGenerationError::InputPartTooLarge);
                }
            }
        }
        Ok(())
    }
}

fn validate_media_reference(
    field: &'static str,
    reference: &str,
    media_type: &str,
    byte_length: usize,
    allowed_media_types: &[&str],
    max_bytes: usize,
) -> Result<(), VertexAiGenerationError> {
    if !valid_token(reference, MAX_IDENTIFIER_BYTES) {
        return Err(VertexAiGenerationError::InvalidField {
            field,
            reason: "must be a bounded opaque reference, not file bytes",
        });
    }
    if !allowed_media_types.contains(&media_type) {
        return Err(VertexAiGenerationError::InvalidField {
            field: "media_type",
            reason: "must be an allowlisted image or document media type",
        });
    }
    if byte_length == 0 || byte_length > max_bytes {
        return Err(VertexAiGenerationError::InputPartTooLarge);
    }
    Ok(())
}

fn media_reference_digest(kind: &str, reference: &str, media_type: &str) -> Digest {
    digest_serializable(&("vertex-media-reference/v1", kind, reference, media_type))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationInput {
    parts: Vec<InputPart>,
    total_bytes: usize,
    input_digest: Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationInputWire {
    parts: Vec<InputPart>,
    total_bytes: usize,
    input_digest: Digest,
}

impl<'de> Deserialize<'de> for GenerationInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = GenerationInputWire::deserialize(deserializer)?;
        let input = Self {
            parts: wire.parts,
            total_bytes: wire.total_bytes,
            input_digest: wire.input_digest,
        };
        input.verify_integrity().map_err(serde::de::Error::custom)?;
        Ok(input)
    }
}

impl GenerationInput {
    pub fn new(parts: Vec<InputPart>) -> Result<Self, VertexAiGenerationError> {
        let total_bytes = validate_input_parts(&parts)?;
        let input_digest = digest_serializable(&("vertex-generation-input/v1", &parts));
        Ok(Self {
            parts,
            total_bytes,
            input_digest,
        })
    }

    pub fn text(value: impl AsRef<str>) -> Result<Self, VertexAiGenerationError> {
        Self::new(vec![InputPart::text(value)?])
    }

    pub fn image_reference(
        reference: impl AsRef<str>,
        media_type: impl Into<String>,
        byte_length: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        Self::new(vec![InputPart::image_reference(
            reference,
            media_type,
            byte_length,
        )?])
    }

    pub fn document_reference(
        reference: impl AsRef<str>,
        media_type: impl Into<String>,
        byte_length: usize,
    ) -> Result<Self, VertexAiGenerationError> {
        Self::new(vec![InputPart::document_reference(
            reference,
            media_type,
            byte_length,
        )?])
    }

    pub fn multimodal(parts: Vec<InputPart>) -> Result<Self, VertexAiGenerationError> {
        Self::new(parts)
    }

    pub fn parts(&self) -> &[InputPart] {
        &self.parts
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub fn modalities(&self) -> Vec<InputModality> {
        self.parts
            .iter()
            .map(InputPart::modality)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn verify_integrity(&self) -> Result<(), VertexAiGenerationError> {
        let expected_total_bytes = validate_input_parts(&self.parts)?;
        if expected_total_bytes != self.total_bytes {
            return Err(VertexAiGenerationError::ProposalTampered);
        }
        let expected = digest_serializable(&("vertex-generation-input/v1", &self.parts));
        if expected == self.input_digest {
            Ok(())
        } else {
            Err(VertexAiGenerationError::ProposalTampered)
        }
    }
}

fn validate_input_parts(parts: &[InputPart]) -> Result<usize, VertexAiGenerationError> {
    if parts.is_empty() {
        return Err(VertexAiGenerationError::InvalidField {
            field: "input_parts",
            reason: "must contain at least one text, image reference, or document reference",
        });
    }
    if parts.len() > MAX_INPUT_PARTS {
        return Err(VertexAiGenerationError::InputPartCountExceeded);
    }
    let mut total_bytes = 0_usize;
    for part in parts {
        part.validate_metadata()?;
        total_bytes = total_bytes
            .checked_add(part.byte_length())
            .ok_or(VertexAiGenerationError::InputTooLarge)?;
    }
    if total_bytes > MAX_INPUT_BYTES {
        return Err(VertexAiGenerationError::InputTooLarge);
    }
    Ok(total_bytes)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestOptions {
    streaming: bool,
    tool_calls: bool,
    grounding: bool,
}

impl RequestOptions {
    pub const fn bounded() -> Self {
        Self {
            streaming: false,
            tool_calls: false,
            grounding: false,
        }
    }

    pub const fn new(streaming: bool, tool_calls: bool, grounding: bool) -> Self {
        Self {
            streaming,
            tool_calls,
            grounding,
        }
    }

    pub const fn streaming(self) -> bool {
        self.streaming
    }

    pub const fn tool_calls(self) -> bool {
        self.tool_calls
    }

    pub const fn grounding(self) -> bool {
        self.grounding
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationRequest {
    input: GenerationInput,
    max_output_tokens: u32,
    candidate_count: usize,
    options: RequestOptions,
    output_schema: Option<OutputSchema>,
}

pub type VertexAiGenerationRequest = GenerationRequest;

impl GenerationRequest {
    pub fn new(input: GenerationInput) -> Self {
        Self {
            input,
            max_output_tokens: MAX_OUTPUT_TOKENS,
            candidate_count: 1,
            options: RequestOptions::bounded(),
            output_schema: None,
        }
    }

    pub fn with_max_output_tokens(mut self, max_output_tokens: u32) -> Self {
        self.max_output_tokens = max_output_tokens;
        self
    }

    pub fn with_candidate_count(mut self, candidate_count: usize) -> Self {
        self.candidate_count = candidate_count;
        self
    }

    pub const fn with_options(mut self, options: RequestOptions) -> Self {
        self.options = options;
        self
    }

    pub fn with_output_schema(mut self, output_schema: Option<OutputSchema>) -> Self {
        self.output_schema = output_schema;
        self
    }

    pub fn input(&self) -> &GenerationInput {
        &self.input
    }

    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    pub const fn options(&self) -> RequestOptions {
        self.options
    }

    pub fn output_schema(&self) -> Option<&OutputSchema> {
        self.output_schema.as_ref()
    }

    pub(crate) fn validate_bounds(&self) -> Result<(), VertexAiGenerationError> {
        if self.max_output_tokens == 0 || self.max_output_tokens > MAX_OUTPUT_TOKENS {
            return Err(VertexAiGenerationError::OutputTokenBudgetExceeded);
        }
        if self.candidate_count == 0 || self.candidate_count > MAX_CANDIDATES {
            return Err(VertexAiGenerationError::CandidateCountExceeded);
        }
        if let Some(schema) = &self.output_schema {
            schema.validate_metadata()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputSchema {
    name: String,
    schema_digest: Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutputSchemaWire {
    name: String,
    schema_digest: Digest,
}

impl<'de> Deserialize<'de> for OutputSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OutputSchemaWire::deserialize(deserializer)?;
        Self::from_digest(wire.name, wire.schema_digest).map_err(serde::de::Error::custom)
    }
}

impl OutputSchema {
    pub fn from_json_schema(
        name: impl Into<String>,
        schema: impl AsRef<[u8]>,
    ) -> Result<Self, VertexAiGenerationError> {
        let schema = schema.as_ref();
        if schema.is_empty() || schema.len() > MAX_SCHEMA_BYTES {
            return Err(VertexAiGenerationError::SchemaTooLarge);
        }
        let parsed_schema = serde_json::from_slice::<serde_json::Value>(schema).map_err(|_| {
            VertexAiGenerationError::InvalidField {
                field: "output_schema",
                reason: "must be valid JSON",
            }
        })?;
        if !parsed_schema.is_object() {
            return Err(VertexAiGenerationError::InvalidField {
                field: "output_schema",
                reason: "must be a JSON object schema",
            });
        }
        Self::from_digest(name, digest_bytes(schema))
    }

    pub fn from_digest(
        name: impl Into<String>,
        schema_digest: Digest,
    ) -> Result<Self, VertexAiGenerationError> {
        let name = name.into();
        if !valid_token(&name, MAX_SCHEMA_NAME_BYTES) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "output_schema_name",
                reason: "must be a bounded schema identifier",
            });
        }
        if !schema_digest.is_sha256() {
            return Err(VertexAiGenerationError::InvalidField {
                field: "output_schema_digest",
                reason: "must be a SHA-256 digest",
            });
        }
        Ok(Self {
            name,
            schema_digest,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        if !valid_token(&self.name, MAX_SCHEMA_NAME_BYTES) || !self.schema_digest.is_sha256() {
            return Err(VertexAiGenerationError::SchemaTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    DigestOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionPolicy {
    mode: RedactionMode,
    retain_raw_prompts: bool,
    retain_raw_outputs: bool,
    retain_hidden_reasoning: bool,
    retain_grounding_chunks: bool,
    retain_tool_arguments: bool,
    retain_file_bytes: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedactionPolicyWire {
    mode: RedactionMode,
    retain_raw_prompts: bool,
    retain_raw_outputs: bool,
    retain_hidden_reasoning: bool,
    retain_grounding_chunks: bool,
    retain_tool_arguments: bool,
    retain_file_bytes: bool,
}

impl<'de> Deserialize<'de> for RedactionPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RedactionPolicyWire::deserialize(deserializer)?;
        if wire.mode != RedactionMode::DigestOnly
            || wire.retain_raw_prompts
            || wire.retain_raw_outputs
            || wire.retain_hidden_reasoning
            || wire.retain_grounding_chunks
            || wire.retain_tool_arguments
            || wire.retain_file_bytes
        {
            return Err(serde::de::Error::custom(
                VertexAiGenerationError::InvalidField {
                    field: "redaction_policy",
                    reason: "Layer-1 redaction must be digest-only and retain no raw content",
                },
            ));
        }
        Ok(Self::digest_only())
    }
}

impl RedactionPolicy {
    pub const fn digest_only() -> Self {
        Self {
            mode: RedactionMode::DigestOnly,
            retain_raw_prompts: false,
            retain_raw_outputs: false,
            retain_hidden_reasoning: false,
            retain_grounding_chunks: false,
            retain_tool_arguments: false,
            retain_file_bytes: false,
        }
    }

    pub const fn mode(self) -> RedactionMode {
        self.mode
    }

    pub const fn retains_raw_prompts(self) -> bool {
        self.retain_raw_prompts
    }

    pub const fn retains_raw_outputs(self) -> bool {
        self.retain_raw_outputs
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseScope {
    revision: String,
    max_candidates: usize,
    max_output_bytes: usize,
    max_output_tokens: u32,
    output_schema: Option<OutputSchema>,
    redaction: RedactionPolicy,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResponseScopeWire {
    revision: String,
    max_candidates: usize,
    max_output_bytes: usize,
    max_output_tokens: u32,
    output_schema: Option<OutputSchema>,
    redaction: RedactionPolicy,
}

impl<'de> Deserialize<'de> for ResponseScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ResponseScopeWire::deserialize(deserializer)?;
        Self::new(
            wire.revision,
            wire.max_candidates,
            wire.max_output_bytes,
            wire.max_output_tokens,
            wire.output_schema,
            wire.redaction,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ResponseScope {
    pub fn new(
        revision: impl Into<String>,
        max_candidates: usize,
        max_output_bytes: usize,
        max_output_tokens: u32,
        output_schema: Option<OutputSchema>,
        redaction: RedactionPolicy,
    ) -> Result<Self, VertexAiGenerationError> {
        let revision = revision.into();
        if !valid_revision(&revision) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "response_policy_revision",
                reason: "must be a bounded non-floating revision",
            });
        }
        if max_candidates == 0
            || max_candidates > MAX_CANDIDATES
            || max_output_bytes == 0
            || max_output_bytes > MAX_OUTPUT_BYTES
            || max_output_tokens == 0
            || max_output_tokens > MAX_OUTPUT_TOKENS
        {
            return Err(VertexAiGenerationError::InvalidField {
                field: "response_policy_bounds",
                reason: "must be positive and within the Layer-1 response ceilings",
            });
        }
        Ok(Self {
            revision,
            max_candidates,
            max_output_bytes,
            max_output_tokens,
            output_schema,
            redaction,
        })
    }

    pub fn bounded() -> Self {
        Self::new(
            "vertex-response-policy/v1",
            MAX_CANDIDATES,
            MAX_OUTPUT_BYTES,
            MAX_OUTPUT_TOKENS,
            None,
            RedactionPolicy::digest_only(),
        )
        .expect("Layer-1 response bounds are valid")
    }

    pub fn with_output_schema(
        mut self,
        output_schema: OutputSchema,
    ) -> Result<Self, VertexAiGenerationError> {
        self.output_schema = Some(output_schema);
        Ok(self)
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn max_candidates(&self) -> usize {
        self.max_candidates
    }

    pub const fn max_output_bytes(&self) -> usize {
        self.max_output_bytes
    }

    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub fn output_schema(&self) -> Option<&OutputSchema> {
        self.output_schema.as_ref()
    }

    pub const fn redaction(&self) -> RedactionPolicy {
        self.redaction
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCategory {
    Harassment,
    HateSpeech,
    SexuallyExplicit,
    DangerousContent,
    CivicIntegrity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyThreshold {
    BlockLowAndAbove,
    BlockMediumAndAbove,
    BlockOnlyHigh,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetySetting {
    category: SafetyCategory,
    threshold: SafetyThreshold,
}

impl SafetySetting {
    pub const fn new(category: SafetyCategory, threshold: SafetyThreshold) -> Self {
        Self {
            category,
            threshold,
        }
    }

    pub const fn category(&self) -> SafetyCategory {
        self.category
    }

    pub const fn threshold(&self) -> SafetyThreshold {
        self.threshold
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyPolicy {
    revision: String,
    settings: Vec<SafetySetting>,
    block_on_unspecified: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SafetyPolicyWire {
    revision: String,
    settings: Vec<SafetySetting>,
    block_on_unspecified: bool,
}

impl<'de> Deserialize<'de> for SafetyPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SafetyPolicyWire::deserialize(deserializer)?;
        Self::new(wire.revision, wire.settings, wire.block_on_unspecified)
            .map_err(serde::de::Error::custom)
    }
}

impl SafetyPolicy {
    pub fn new(
        revision: impl Into<String>,
        settings: Vec<SafetySetting>,
        block_on_unspecified: bool,
    ) -> Result<Self, VertexAiGenerationError> {
        let revision = revision.into();
        if !valid_revision(&revision) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "safety_policy_revision",
                reason: "must be a bounded non-floating revision",
            });
        }
        if settings.len() > MAX_SAFETY_RATINGS {
            return Err(VertexAiGenerationError::InvalidField {
                field: "safety_settings",
                reason: "must be bounded",
            });
        }
        let mut categories = BTreeSet::new();
        if settings
            .iter()
            .any(|setting| !categories.insert(setting.category))
        {
            return Err(VertexAiGenerationError::InvalidField {
                field: "safety_settings",
                reason: "must not contain duplicate categories",
            });
        }
        Ok(Self {
            revision,
            settings,
            block_on_unspecified,
        })
    }

    pub fn strict(revision: impl Into<String>) -> Result<Self, VertexAiGenerationError> {
        Self::new(
            revision,
            vec![
                SafetySetting::new(
                    SafetyCategory::Harassment,
                    SafetyThreshold::BlockMediumAndAbove,
                ),
                SafetySetting::new(
                    SafetyCategory::HateSpeech,
                    SafetyThreshold::BlockMediumAndAbove,
                ),
                SafetySetting::new(
                    SafetyCategory::SexuallyExplicit,
                    SafetyThreshold::BlockMediumAndAbove,
                ),
                SafetySetting::new(
                    SafetyCategory::DangerousContent,
                    SafetyThreshold::BlockMediumAndAbove,
                ),
                SafetySetting::new(
                    SafetyCategory::CivicIntegrity,
                    SafetyThreshold::BlockMediumAndAbove,
                ),
            ],
            true,
        )
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub fn settings(&self) -> &[SafetySetting] {
        &self.settings
    }

    pub const fn block_on_unspecified(&self) -> bool {
        self.block_on_unspecified
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolGroundingPolicy {
    revision: String,
    allow_tool_calls: bool,
    allow_grounding: bool,
    allow_search_grounding: bool,
    allow_maps_grounding: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ToolGroundingPolicyWire {
    revision: String,
    allow_tool_calls: bool,
    allow_grounding: bool,
    allow_search_grounding: bool,
    allow_maps_grounding: bool,
}

impl<'de> Deserialize<'de> for ToolGroundingPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ToolGroundingPolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.revision,
            wire.allow_tool_calls,
            wire.allow_grounding,
            wire.allow_search_grounding,
            wire.allow_maps_grounding,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl ToolGroundingPolicy {
    pub fn new(
        revision: impl Into<String>,
        allow_tool_calls: bool,
        allow_grounding: bool,
        allow_search_grounding: bool,
        allow_maps_grounding: bool,
    ) -> Result<Self, VertexAiGenerationError> {
        let revision = revision.into();
        if !valid_revision(&revision) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "tool_grounding_policy_revision",
                reason: "must be a bounded non-floating revision",
            });
        }
        if allow_tool_calls || allow_grounding || allow_search_grounding || allow_maps_grounding {
            return Err(VertexAiGenerationError::ToolCallsForbidden);
        }
        Ok(Self {
            revision,
            allow_tool_calls: false,
            allow_grounding: false,
            allow_search_grounding: false,
            allow_maps_grounding: false,
        })
    }

    pub fn disabled(revision: impl Into<String>) -> Result<Self, VertexAiGenerationError> {
        Self::new(revision, false, false, false, false)
    }

    pub fn revision(&self) -> &str {
        &self.revision
    }

    pub const fn allow_tool_calls(&self) -> bool {
        self.allow_tool_calls
    }

    pub const fn allow_grounding(&self) -> bool {
        self.allow_grounding
    }

    pub const fn allow_search_grounding(&self) -> bool {
        self.allow_search_grounding
    }

    pub const fn allow_maps_grounding(&self) -> bool {
        self.allow_maps_grounding
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: u64,
    purpose: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConsentScopeWire {
    consent_digest: Digest,
    revision: u64,
    purpose: String,
}

impl<'de> Deserialize<'de> for ConsentScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConsentScopeWire::deserialize(deserializer)?;
        if wire.purpose != "vertex_ai_gemini_generation" {
            return Err(serde::de::Error::custom(
                VertexAiGenerationError::InvalidField {
                    field: "consent_purpose",
                    reason: "must be the Vertex AI Gemini generation purpose",
                },
            ));
        }
        Self::from_digest(wire.consent_digest, wire.revision).map_err(serde::de::Error::custom)
    }
}

impl ConsentScope {
    pub fn new(
        opaque_consent_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, VertexAiGenerationError> {
        let reference = opaque_consent_reference.as_ref();
        if !valid_token(reference, MAX_IDENTIFIER_BYTES) {
            return Err(VertexAiGenerationError::InvalidField {
                field: "consent_reference",
                reason: "must be a bounded non-empty consent handle",
            });
        }
        if revision == 0 {
            return Err(VertexAiGenerationError::InvalidField {
                field: "consent_revision",
                reason: "must be non-zero",
            });
        }
        Ok(Self {
            consent_digest: digest_serializable(&("vertex-consent/v1", reference, revision)),
            revision,
            purpose: "vertex_ai_gemini_generation".to_owned(),
        })
    }

    pub fn from_digest(
        consent_digest: Digest,
        revision: u64,
    ) -> Result<Self, VertexAiGenerationError> {
        if !consent_digest.is_sha256() || revision == 0 {
            return Err(VertexAiGenerationError::InvalidField {
                field: "consent_scope",
                reason: "must contain a SHA-256 digest and non-zero revision",
            });
        }
        Ok(Self {
            consent_digest,
            revision,
            purpose: "vertex_ai_gemini_generation".to_owned(),
        })
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug)]
pub struct VertexAiGenerationScope {
    google_cloud_project: GoogleCloudProject,
    location: VertexLocation,
    api_version: VertexApiVersion,
    publisher: VertexPublisher,
    model: ModelSnapshot,
    input_policy: InputPolicy,
    safety_policy: SafetyPolicy,
    tool_grounding_policy: ToolGroundingPolicy,
    response: ResponseScope,
    mission: MissionScope,
    project: ProjectScope,
    work_product: WorkProductScope,
    consent: ConsentScope,
    permission: PermissionScope,
}

impl VertexAiGenerationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        google_cloud_project: GoogleCloudProject,
        location: VertexLocation,
        publisher: VertexPublisher,
        model: ModelSnapshot,
        input_policy: InputPolicy,
        safety_policy: SafetyPolicy,
        tool_grounding_policy: ToolGroundingPolicy,
        response: ResponseScope,
        mission: MissionScope,
        project: ProjectScope,
        work_product: WorkProductScope,
        consent: ConsentScope,
        permission: PermissionScope,
    ) -> Result<Self, VertexAiGenerationError> {
        if tool_grounding_policy.allow_tool_calls()
            || tool_grounding_policy.allow_grounding()
            || tool_grounding_policy.allow_search_grounding()
            || tool_grounding_policy.allow_maps_grounding()
        {
            return Err(VertexAiGenerationError::GroundingForbidden);
        }
        Ok(Self {
            google_cloud_project,
            location,
            api_version: VertexApiVersion::V1,
            publisher,
            model,
            input_policy,
            safety_policy,
            tool_grounding_policy,
            response,
            mission,
            project,
            work_product,
            consent,
            permission,
        })
    }

    pub fn google_cloud_project(&self) -> &GoogleCloudProject {
        &self.google_cloud_project
    }

    pub fn location(&self) -> &VertexLocation {
        &self.location
    }

    pub const fn api_version(&self) -> VertexApiVersion {
        self.api_version
    }

    pub const fn publisher(&self) -> VertexPublisher {
        self.publisher
    }

    pub fn model(&self) -> &ModelSnapshot {
        &self.model
    }

    pub fn input_policy(&self) -> &InputPolicy {
        &self.input_policy
    }

    pub fn safety_policy(&self) -> &SafetyPolicy {
        &self.safety_policy
    }

    pub fn tool_grounding_policy(&self) -> &ToolGroundingPolicy {
        &self.tool_grounding_policy
    }

    pub fn response(&self) -> &ResponseScope {
        &self.response
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn model_digest(&self) -> Digest {
        self.model.digest()
    }

    pub fn provider_digest(&self) -> Digest {
        digest_serializable(&ProviderBinding {
            provider_id: VERTEX_AI_GENERATION_PROVIDER_ID,
            api_version: self.api_version,
            location: &self.location,
            publisher: self.publisher,
        })
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn input_policy_digest(&self) -> Digest {
        self.input_policy.digest()
    }

    pub fn safety_policy_digest(&self) -> Digest {
        self.safety_policy.digest()
    }

    pub fn tool_grounding_policy_digest(&self) -> Digest {
        self.tool_grounding_policy.digest()
    }

    pub fn response_digest(&self) -> Digest {
        self.response.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&ScopeDigestMaterial {
            google_cloud_project: &self.google_cloud_project,
            location: &self.location,
            api_version: self.api_version,
            publisher: self.publisher,
            model: &self.model,
            input_policy: &self.input_policy,
            safety_policy: &self.safety_policy,
            tool_grounding_policy: &self.tool_grounding_policy,
            response: &self.response,
            mission: &self.mission,
            project: &self.project,
            work_product: &self.work_product,
            consent: &self.consent,
            permission_digest: self.permission.digest(),
        })
    }
}

#[derive(Serialize)]
struct PermissionDigestMaterial<'a> {
    permission: &'a VertexAiPermission,
    secret_reference_digest: &'a Digest,
    credential_revision: u64,
    kind: SecretKind,
}

#[derive(Serialize)]
struct ProviderBinding<'a> {
    provider_id: &'static str,
    api_version: VertexApiVersion,
    location: &'a VertexLocation,
    publisher: VertexPublisher,
}

#[derive(Serialize)]
struct ScopeDigestMaterial<'a> {
    google_cloud_project: &'a GoogleCloudProject,
    location: &'a VertexLocation,
    api_version: VertexApiVersion,
    publisher: VertexPublisher,
    model: &'a ModelSnapshot,
    input_policy: &'a InputPolicy,
    safety_policy: &'a SafetyPolicy,
    tool_grounding_policy: &'a ToolGroundingPolicy,
    response: &'a ResponseScope,
    mission: &'a MissionScope,
    project: &'a ProjectScope,
    work_product: &'a WorkProductScope,
    consent: &'a ConsentScope,
    permission_digest: Digest,
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

    pub fn reason(&self) -> &RevocationReason {
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
    permission_digest: Digest,
    scope_digest: Digest,
    project_digest: Digest,
    location_digest: Digest,
    model_digest: Digest,
    input_policy_digest: Digest,
    safety_policy_digest: Digest,
    tool_grounding_policy_digest: Digest,
    response_digest: Digest,
    consent_digest: Digest,
    registration_digest: Digest,
    revocation_revision: u64,
    status: RegistrationStatus,
}

impl PluginRegistration {
    pub(crate) fn new(scope: &VertexAiGenerationScope) -> Self {
        let version_digest = digest_serializable(&(
            VERTEX_AI_GENERATION_PLUGIN_VERSION,
            VERTEX_AI_GENERATION_CONTRACT_VERSION,
        ));
        let contract_digest = digest_bytes(VERTEX_AI_GENERATION_CONTRACT_JSON.as_bytes());
        let provider_digest = scope.provider_digest();
        let permission_digest = scope.permission_digest();
        let scope_digest = scope.digest();
        let project_digest = scope.project().digest();
        let location_digest = scope.location().digest();
        let model_digest = scope.model_digest();
        let input_policy_digest = scope.input_policy_digest();
        let safety_policy_digest = scope.safety_policy_digest();
        let tool_grounding_policy_digest = scope.tool_grounding_policy_digest();
        let response_digest = scope.response_digest();
        let consent_digest = scope.consent().digest();
        let registration_digest = digest_serializable(&RegistrationMaterial {
            plugin_version: VERTEX_AI_GENERATION_PLUGIN_VERSION,
            contract_version: VERTEX_AI_GENERATION_CONTRACT_VERSION,
            version_digest: &version_digest,
            contract_digest: &contract_digest,
            provider_digest: &provider_digest,
            permission_digest: &permission_digest,
            scope_digest: &scope_digest,
            project_digest: &project_digest,
            location_digest: &location_digest,
            model_digest: &model_digest,
            input_policy_digest: &input_policy_digest,
            safety_policy_digest: &safety_policy_digest,
            tool_grounding_policy_digest: &tool_grounding_policy_digest,
            response_digest: &response_digest,
            consent_digest: &consent_digest,
        });
        Self {
            plugin_version: VERTEX_AI_GENERATION_PLUGIN_VERSION.to_owned(),
            contract_version: VERTEX_AI_GENERATION_CONTRACT_VERSION.to_owned(),
            version_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            project_digest,
            location_digest,
            model_digest,
            input_policy_digest,
            safety_policy_digest,
            tool_grounding_policy_digest,
            response_digest,
            consent_digest,
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

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn location_digest(&self) -> &Digest {
        &self.location_digest
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn input_policy_digest(&self) -> &Digest {
        &self.input_policy_digest
    }

    pub fn safety_policy_digest(&self) -> &Digest {
        &self.safety_policy_digest
    }

    pub fn tool_grounding_policy_digest(&self) -> &Digest {
        &self.tool_grounding_policy_digest
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
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
        scope: &VertexAiGenerationScope,
    ) -> Result<(), VertexAiGenerationError> {
        let expected_version_digest =
            digest_serializable(&(self.plugin_version.as_str(), self.contract_version.as_str()));
        let expected_contract_digest = digest_bytes(VERTEX_AI_GENERATION_CONTRACT_JSON.as_bytes());
        let expected_registration_digest = digest_serializable(&RegistrationMaterial {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            project_digest: &self.project_digest,
            location_digest: &self.location_digest,
            model_digest: &self.model_digest,
            input_policy_digest: &self.input_policy_digest,
            safety_policy_digest: &self.safety_policy_digest,
            tool_grounding_policy_digest: &self.tool_grounding_policy_digest,
            response_digest: &self.response_digest,
            consent_digest: &self.consent_digest,
        });
        if self.plugin_version != VERTEX_AI_GENERATION_PLUGIN_VERSION
            || self.contract_version != VERTEX_AI_GENERATION_CONTRACT_VERSION
            || self.version_digest != expected_version_digest
            || self.contract_digest != expected_contract_digest
            || self.provider_digest != scope.provider_digest()
            || self.permission_digest != scope.permission_digest()
            || self.scope_digest != scope.digest()
            || self.project_digest != scope.project().digest()
            || self.location_digest != scope.location().digest()
            || self.model_digest != scope.model_digest()
            || self.input_policy_digest != scope.input_policy_digest()
            || self.safety_policy_digest != scope.safety_policy_digest()
            || self.tool_grounding_policy_digest != scope.tool_grounding_policy_digest()
            || self.response_digest != scope.response_digest()
            || self.consent_digest != scope.consent().digest()
            || self.registration_digest != expected_registration_digest
        {
            return Err(VertexAiGenerationError::RegistrationTampered);
        }
        match &self.status {
            RegistrationStatus::Revoked { revision, .. }
                if *revision == 0 || *revision != self.revocation_revision =>
            {
                return Err(VertexAiGenerationError::RegistrationTampered);
            }
            RegistrationStatus::Active | RegistrationStatus::Revoked { .. } => {}
        }
        if !self.is_active() {
            return Err(VertexAiGenerationError::RegistrationRevoked);
        }
        Ok(())
    }

    pub(crate) fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, VertexAiGenerationError> {
        if self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                VertexAiGenerationError::InvalidField {
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

    pub(crate) fn restore(&mut self) -> Result<(), VertexAiGenerationError> {
        if !self.is_active() {
            self.revocation_revision = self.revocation_revision.checked_add(1).ok_or(
                VertexAiGenerationError::InvalidField {
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
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    project_digest: &'a Digest,
    location_digest: &'a Digest,
    model_digest: &'a Digest,
    input_policy_digest: &'a Digest,
    safety_policy_digest: &'a Digest,
    tool_grounding_policy_digest: &'a Digest,
    response_digest: &'a Digest,
    consent_digest: &'a Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestFingerprint {
    request_digest: Digest,
    input_digest: Digest,
    input_bytes: usize,
    modalities: Vec<InputModality>,
    max_output_tokens: u32,
    candidate_count: usize,
    options: RequestOptions,
    output_schema_digest: Option<Digest>,
    source_fence: Digest,
}

static REQUEST_SOURCE_KEY: OnceLock<Digest> = OnceLock::new();

fn request_source_key() -> &'static Digest {
    REQUEST_SOURCE_KEY.get_or_init(|| {
        let mut material = b"hartevo-vertex-ai-request-source-key/v1".to_vec();
        material.extend_from_slice(&std::process::id().to_be_bytes());
        if let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) {
            material.extend_from_slice(&elapsed.as_secs().to_be_bytes());
            material.extend_from_slice(&elapsed.subsec_nanos().to_be_bytes());
        }
        digest_bytes(&material)
    })
}

pub(crate) fn expected_request_source_fence(
    scope_digest: &Digest,
    request_digest: &Digest,
) -> Digest {
    let mut material = b"hartevo-vertex-ai-request-source-fence/v1".to_vec();
    material.extend_from_slice(request_source_key().as_str().as_bytes());
    material.extend_from_slice(scope_digest.as_str().as_bytes());
    material.extend_from_slice(request_digest.as_str().as_bytes());
    digest_bytes(&material)
}

impl RequestFingerprint {
    pub(crate) fn from_request(
        scope: &VertexAiGenerationScope,
        request: &GenerationRequest,
    ) -> Self {
        let scope_digest = scope.digest();
        let request_material = RequestDigestMaterial {
            scope_digest: scope_digest.clone(),
            input: &request.input,
            max_output_tokens: request.max_output_tokens,
            candidate_count: request.candidate_count,
            options: request.options,
            output_schema: request.output_schema.as_ref(),
        };
        let request_digest = digest_serializable(&request_material);
        Self {
            source_fence: expected_request_source_fence(&scope_digest, &request_digest),
            request_digest,
            input_digest: request.input.input_digest().clone(),
            input_bytes: request.input.total_bytes(),
            modalities: request.input.modalities(),
            max_output_tokens: request.max_output_tokens,
            candidate_count: request.candidate_count,
            options: request.options,
            output_schema_digest: request.output_schema.as_ref().map(|schema| schema.digest()),
        }
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }

    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub fn modalities(&self) -> &[InputModality] {
        &self.modalities
    }

    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }

    pub const fn candidate_count(&self) -> usize {
        self.candidate_count
    }

    pub const fn options(&self) -> RequestOptions {
        self.options
    }

    pub fn output_schema_digest(&self) -> Option<&Digest> {
        self.output_schema_digest.as_ref()
    }

    pub fn source_fence(&self) -> &Digest {
        &self.source_fence
    }

    fn validate_bounds(&self) -> Result<(), VertexAiGenerationError> {
        if self.input_bytes == 0 || self.input_bytes > MAX_INPUT_BYTES {
            return Err(VertexAiGenerationError::InputTooLarge);
        }
        if self.modalities.is_empty() || self.modalities.len() > 3 {
            return Err(VertexAiGenerationError::ModalityForbidden);
        }
        let unique_modalities = self.modalities.iter().collect::<BTreeSet<_>>();
        if unique_modalities.len() != self.modalities.len() {
            return Err(VertexAiGenerationError::ModalityForbidden);
        }
        if self.max_output_tokens == 0 || self.max_output_tokens > MAX_OUTPUT_TOKENS {
            return Err(VertexAiGenerationError::OutputTokenBudgetExceeded);
        }
        if self.candidate_count == 0 || self.candidate_count > MAX_CANDIDATES {
            return Err(VertexAiGenerationError::CandidateCountExceeded);
        }
        if let Some(schema_digest) = &self.output_schema_digest
            && !schema_digest.is_sha256()
        {
            return Err(VertexAiGenerationError::SchemaMismatch);
        }
        if !self.request_digest.is_sha256()
            || !self.input_digest.is_sha256()
            || !self.source_fence.is_sha256()
        {
            return Err(VertexAiGenerationError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct RequestDigestMaterial<'a> {
    scope_digest: Digest,
    input: &'a GenerationInput,
    max_output_tokens: u32,
    candidate_count: usize,
    options: RequestOptions,
    output_schema: Option<&'a OutputSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerationResultProposal {
    pub(crate) proposal_version: String,
    pub(crate) service_id: String,
    pub(crate) google_cloud_project: GoogleCloudProject,
    pub(crate) location: VertexLocation,
    pub(crate) api_version: VertexApiVersion,
    pub(crate) publisher: VertexPublisher,
    pub(crate) model: ModelSnapshot,
    pub(crate) request: RequestFingerprint,
    pub(crate) contract_digest: Digest,
    pub(crate) provider_digest: Digest,
    pub(crate) permission_digest: Digest,
    pub(crate) scope_digest: Digest,
    pub(crate) project_digest: Digest,
    pub(crate) mission_digest: Digest,
    pub(crate) work_product_digest: Digest,
    pub(crate) consent_digest: Digest,
    pub(crate) input_policy_digest: Digest,
    pub(crate) safety_policy_digest: Digest,
    pub(crate) tool_grounding_policy_digest: Digest,
    pub(crate) response_digest: Digest,
    pub(crate) registration_digest: Digest,
    pub(crate) proposal_digest: Digest,
}

impl GenerationResultProposal {
    pub(crate) fn new(
        scope: &VertexAiGenerationScope,
        registration: &PluginRegistration,
        request: &GenerationRequest,
    ) -> Self {
        let mut proposal = Self {
            proposal_version: "vertex-ai-generation-result-proposal/v1".to_owned(),
            service_id: VERTEX_AI_GENERATION_SERVICE_ID.to_owned(),
            google_cloud_project: scope.google_cloud_project.clone(),
            location: scope.location.clone(),
            api_version: scope.api_version,
            publisher: scope.publisher,
            model: scope.model.clone(),
            request: RequestFingerprint::from_request(scope, request),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: scope.provider_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.digest(),
            project_digest: scope.project().digest(),
            mission_digest: scope.mission().digest(),
            work_product_digest: scope.work_product().digest(),
            consent_digest: scope.consent().digest(),
            input_policy_digest: scope.input_policy_digest(),
            safety_policy_digest: scope.safety_policy_digest(),
            tool_grounding_policy_digest: scope.tool_grounding_policy_digest(),
            response_digest: scope.response_digest(),
            registration_digest: registration.registration_digest.clone(),
            proposal_digest: digest_bytes(b"uninitialized-vertex-proposal-digest"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub(crate) fn compute_digest(&self) -> Digest {
        digest_serializable(&ProposalMaterial {
            proposal_version: &self.proposal_version,
            service_id: &self.service_id,
            google_cloud_project: &self.google_cloud_project,
            location: &self.location,
            api_version: self.api_version,
            publisher: self.publisher,
            model: &self.model,
            request: &self.request,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            project_digest: &self.project_digest,
            mission_digest: &self.mission_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            input_policy_digest: &self.input_policy_digest,
            safety_policy_digest: &self.safety_policy_digest,
            tool_grounding_policy_digest: &self.tool_grounding_policy_digest,
            response_digest: &self.response_digest,
            registration_digest: &self.registration_digest,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), VertexAiGenerationError> {
        self.request.validate_bounds()?;
        if self.request.source_fence
            != expected_request_source_fence(&self.scope_digest, &self.request.request_digest)
        {
            return Err(VertexAiGenerationError::ProposalTampered);
        }
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(VertexAiGenerationError::ProposalTampered)
        }
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub fn request(&self) -> &RequestFingerprint {
        &self.request
    }
}

#[derive(Serialize)]
struct ProposalMaterial<'a> {
    proposal_version: &'a str,
    service_id: &'a str,
    google_cloud_project: &'a GoogleCloudProject,
    location: &'a VertexLocation,
    api_version: VertexApiVersion,
    publisher: VertexPublisher,
    model: &'a ModelSnapshot,
    request: &'a RequestFingerprint,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    project_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    input_policy_digest: &'a Digest,
    safety_policy_digest: &'a Digest,
    tool_grounding_policy_digest: &'a Digest,
    response_digest: &'a Digest,
    registration_digest: &'a Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    MaxTokens,
    Safety,
    Recitation,
    Other,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyProbability {
    Negligible,
    Low,
    Medium,
    High,
    Unspecified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetySeverity {
    Negligible,
    Low,
    Medium,
    High,
    Unspecified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyRating {
    pub category: SafetyCategory,
    pub probability: SafetyProbability,
    pub severity: SafetySeverity,
    pub blocked: bool,
}

impl SafetyRating {
    pub const fn new(
        category: SafetyCategory,
        probability: SafetyProbability,
        severity: SafetySeverity,
        blocked: bool,
    ) -> Self {
        Self {
            category,
            probability,
            severity,
            blocked,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyBlockReason {
    Safety,
    ProhibitedContent,
    Spii,
    Blocklist,
    Unspecified,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromptFeedback {
    pub block_reason: Option<SafetyBlockReason>,
    pub safety_ratings: Vec<SafetyRating>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PromptFeedbackWire {
    block_reason: Option<SafetyBlockReason>,
    safety_ratings: Vec<SafetyRating>,
}

impl<'de> Deserialize<'de> for PromptFeedback {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = PromptFeedbackWire::deserialize(deserializer)?;
        Self::new(wire.block_reason, wire.safety_ratings).map_err(serde::de::Error::custom)
    }
}

impl PromptFeedback {
    pub fn new(
        block_reason: Option<SafetyBlockReason>,
        safety_ratings: Vec<SafetyRating>,
    ) -> Result<Self, VertexAiGenerationError> {
        if safety_ratings.len() > MAX_SAFETY_RATINGS {
            return Err(VertexAiGenerationError::MalformedResponse(
                "too many prompt safety ratings",
            ));
        }
        Ok(Self {
            block_reason,
            safety_ratings,
        })
    }

    pub fn is_blocked(&self) -> bool {
        self.block_reason.is_some() || self.safety_ratings.iter().any(|rating| rating.blocked)
    }

    pub(crate) fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        if self.safety_ratings.len() > MAX_SAFETY_RATINGS {
            return Err(VertexAiGenerationError::MalformedResponse(
                "too many prompt safety ratings",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageMetadata {
    pub prompt_token_count: u64,
    pub candidates_token_count: u64,
    pub total_token_count: u64,
    pub cached_content_token_count: Option<u64>,
    pub thoughts_token_count: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UsageMetadataWire {
    prompt_token_count: u64,
    candidates_token_count: u64,
    total_token_count: u64,
    cached_content_token_count: Option<u64>,
    thoughts_token_count: Option<u64>,
}

impl<'de> Deserialize<'de> for UsageMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = UsageMetadataWire::deserialize(deserializer)?;
        Self::new(
            wire.prompt_token_count,
            wire.candidates_token_count,
            wire.total_token_count,
            wire.cached_content_token_count,
            wire.thoughts_token_count,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl UsageMetadata {
    pub fn new(
        prompt_token_count: u64,
        candidates_token_count: u64,
        total_token_count: u64,
        cached_content_token_count: Option<u64>,
        thoughts_token_count: Option<u64>,
    ) -> Result<Self, VertexAiGenerationError> {
        if prompt_token_count
            .checked_add(candidates_token_count)
            .is_none_or(|sum| sum > total_token_count)
        {
            return Err(VertexAiGenerationError::MalformedResponse(
                "usage total is smaller than prompt plus candidates tokens",
            ));
        }
        Ok(Self {
            prompt_token_count,
            candidates_token_count,
            total_token_count,
            cached_content_token_count,
            thoughts_token_count,
        })
    }

    pub(crate) fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        if self
            .prompt_token_count
            .checked_add(self.candidates_token_count)
            .is_none_or(|sum| sum > self.total_token_count)
        {
            return Err(VertexAiGenerationError::MalformedResponse(
                "usage total is smaller than prompt plus candidates tokens",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VertexAiCandidate {
    pub index: u32,
    pub content_digest: Digest,
    pub content_byte_length: usize,
    pub finish_reason: FinishReason,
    pub safety_ratings: Vec<SafetyRating>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VertexAiCandidateWire {
    index: u32,
    content_digest: Digest,
    content_byte_length: usize,
    finish_reason: FinishReason,
    safety_ratings: Vec<SafetyRating>,
}

impl<'de> Deserialize<'de> for VertexAiCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = VertexAiCandidateWire::deserialize(deserializer)?;
        Self::new(
            wire.index,
            wire.content_digest,
            wire.content_byte_length,
            wire.finish_reason,
            wire.safety_ratings,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl VertexAiCandidate {
    pub fn new(
        index: u32,
        content_digest: Digest,
        content_byte_length: usize,
        finish_reason: FinishReason,
        safety_ratings: Vec<SafetyRating>,
    ) -> Result<Self, VertexAiGenerationError> {
        if !content_digest.is_sha256()
            || content_byte_length == 0
            || content_byte_length > MAX_OUTPUT_BYTES
            || safety_ratings.len() > MAX_SAFETY_RATINGS
        {
            return Err(VertexAiGenerationError::MalformedResponse(
                "candidate metadata is malformed",
            ));
        }
        Ok(Self {
            index,
            content_digest,
            content_byte_length,
            finish_reason,
            safety_ratings,
        })
    }

    pub fn from_text(
        index: u32,
        content: impl AsRef<str>,
        finish_reason: FinishReason,
        safety_ratings: Vec<SafetyRating>,
    ) -> Result<Self, VertexAiGenerationError> {
        let content = content.as_ref();
        if content.is_empty() || content.chars().any(char::is_control) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "candidate content is empty or contains control characters",
            ));
        }
        Self::new(
            index,
            digest_bytes(content.as_bytes()),
            content.len(),
            finish_reason,
            safety_ratings,
        )
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub(crate) fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        Self::new(
            self.index,
            self.content_digest.clone(),
            self.content_byte_length,
            self.finish_reason,
            self.safety_ratings.clone(),
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VertexAiResponse {
    pub response_id: String,
    pub model_version: String,
    pub candidates: Vec<VertexAiCandidate>,
    pub prompt_feedback: Option<PromptFeedback>,
    pub usage_metadata: Option<UsageMetadata>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VertexAiResponseWire {
    response_id: String,
    model_version: String,
    candidates: Vec<VertexAiCandidate>,
    prompt_feedback: Option<PromptFeedback>,
    usage_metadata: Option<UsageMetadata>,
}

impl<'de> Deserialize<'de> for VertexAiResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = VertexAiResponseWire::deserialize(deserializer)?;
        Self::new(
            wire.response_id,
            wire.model_version,
            wire.candidates,
            wire.prompt_feedback,
            wire.usage_metadata,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl VertexAiResponse {
    pub fn new(
        response_id: impl Into<String>,
        model_version: impl Into<String>,
        candidates: Vec<VertexAiCandidate>,
        prompt_feedback: Option<PromptFeedback>,
        usage_metadata: Option<UsageMetadata>,
    ) -> Result<Self, VertexAiGenerationError> {
        let response_id = response_id.into();
        let model_version = model_version.into();
        if !valid_token(&response_id, MAX_RESPONSE_ID_BYTES) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "response id is missing or invalid",
            ));
        }
        if !valid_token(&model_version, MAX_IDENTIFIER_BYTES) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "model version is missing or invalid",
            ));
        }
        let response = Self {
            response_id,
            model_version,
            candidates,
            prompt_feedback,
            usage_metadata,
        };
        response.validate_metadata()?;
        Ok(response)
    }

    pub fn state(&self) -> ResponseState {
        if self
            .prompt_feedback
            .as_ref()
            .is_some_and(PromptFeedback::is_blocked)
            || self
                .candidates
                .iter()
                .any(|candidate| candidate.safety_ratings.iter().any(|rating| rating.blocked))
            || self
                .candidates
                .iter()
                .any(|candidate| candidate.finish_reason == FinishReason::Safety)
        {
            ResponseState::Blocked
        } else if self.candidates.is_empty()
            || self.candidates.iter().any(|candidate| {
                matches!(
                    candidate.finish_reason,
                    FinishReason::MaxTokens | FinishReason::Other | FinishReason::Unspecified
                )
            })
        {
            ResponseState::Partial
        } else {
            ResponseState::Complete
        }
    }

    pub fn output_digest(&self) -> Option<Digest> {
        if self.candidates.is_empty() {
            None
        } else {
            Some(digest_serializable(&self.candidates))
        }
    }

    pub fn response_digest(&self) -> Digest {
        digest_serializable(self)
    }

    pub(crate) fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        if !valid_token(&self.response_id, MAX_RESPONSE_ID_BYTES) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "response id is missing or invalid",
            ));
        }
        if !valid_token(&self.model_version, MAX_IDENTIFIER_BYTES) {
            return Err(VertexAiGenerationError::MalformedResponse(
                "model version is missing or invalid",
            ));
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(VertexAiGenerationError::ResponseCandidateCountExceeded);
        }
        let mut output_bytes = 0_usize;
        for candidate in &self.candidates {
            candidate.validate_metadata()?;
            output_bytes = output_bytes
                .checked_add(candidate.content_byte_length)
                .ok_or(VertexAiGenerationError::ResponseContentTooLarge)?;
        }
        if output_bytes > MAX_OUTPUT_BYTES {
            return Err(VertexAiGenerationError::ResponseContentTooLarge);
        }
        if let Some(feedback) = &self.prompt_feedback {
            feedback.validate_metadata()?;
        }
        if let Some(usage) = &self.usage_metadata {
            usage.validate_metadata()?;
        }
        if self.candidates.is_empty()
            && self
                .prompt_feedback
                .as_ref()
                .is_none_or(|feedback| !feedback.is_blocked())
        {
            return Err(VertexAiGenerationError::MalformedResponse(
                "response has neither candidates nor a safety block",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseState {
    Complete,
    Partial,
    Blocked,
    Failed,
    Cancelled,
    Expired,
    RateLimited,
    AccessLost,
    ProviderUnknown,
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAuthority {
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_outcome_adoption: bool,
}

impl EvidenceAuthority {
    pub const fn for_mode(_mode: ProviderMode) -> Self {
        Self {
            connected: false,
            native: false,
            durable_receipt: false,
            independent_read_back: false,
            kernel_outcome_adoption: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateSummary {
    pub index: u32,
    pub content_digest: Digest,
    pub content_byte_length: usize,
    pub finish_reason: FinishReason,
    pub safety_ratings: Vec<SafetyRating>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CandidateSummaryWire {
    index: u32,
    content_digest: Digest,
    content_byte_length: usize,
    finish_reason: FinishReason,
    safety_ratings: Vec<SafetyRating>,
}

impl<'de> Deserialize<'de> for CandidateSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = CandidateSummaryWire::deserialize(deserializer)?;
        VertexAiCandidate::new(
            wire.index,
            wire.content_digest,
            wire.content_byte_length,
            wire.finish_reason,
            wire.safety_ratings,
        )
        .map(|candidate| Self::from(&candidate))
        .map_err(serde::de::Error::custom)
    }
}

impl From<&VertexAiCandidate> for CandidateSummary {
    fn from(candidate: &VertexAiCandidate) -> Self {
        Self {
            index: candidate.index,
            content_digest: candidate.content_digest.clone(),
            content_byte_length: candidate.content_byte_length,
            finish_reason: candidate.finish_reason,
            safety_ratings: candidate.safety_ratings.clone(),
        }
    }
}

impl CandidateSummary {
    fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        VertexAiCandidate::new(
            self.index,
            self.content_digest.clone(),
            self.content_byte_length,
            self.finish_reason,
            self.safety_ratings.clone(),
        )
        .map(|_| ())
    }
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
pub struct GenerationResultEvidence {
    pub evidence_version: String,
    pub proposal_digest: Digest,
    pub request_digest: Digest,
    pub request_source_fence: Digest,
    pub contract_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub consent_digest: Digest,
    pub google_cloud_project: GoogleCloudProject,
    pub location: VertexLocation,
    pub publisher: VertexPublisher,
    pub model: ModelSnapshot,
    pub response_id: Option<String>,
    pub model_version: Option<String>,
    pub response_digest: Digest,
    pub output_digest: Option<Digest>,
    pub candidates: Vec<CandidateSummary>,
    pub prompt_feedback: Option<PromptFeedback>,
    pub usage_metadata: Option<UsageMetadata>,
    pub state: ResponseState,
    pub provider_error: Option<ProviderErrorProjection>,
    pub redaction: RedactionPolicy,
    pub provenance: ProviderMode,
    pub authority: EvidenceAuthority,
    pub evidence_digest: Digest,
}

impl GenerationResultEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        mode: ProviderMode,
        proposal: &GenerationResultProposal,
        response_id: Option<String>,
        model_version: Option<String>,
        response_digest: Digest,
        output_digest: Option<Digest>,
        candidates: Vec<CandidateSummary>,
        prompt_feedback: Option<PromptFeedback>,
        usage_metadata: Option<UsageMetadata>,
        state: ResponseState,
        provider_error: Option<ProviderErrorProjection>,
        redaction: RedactionPolicy,
    ) -> Self {
        let authority = EvidenceAuthority::for_mode(mode);
        let mut evidence = Self {
            evidence_version: "vertex-ai-generation-result-evidence/v1".to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            request_digest: proposal.request.request_digest.clone(),
            request_source_fence: proposal.request.source_fence.clone(),
            contract_digest: proposal.contract_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            permission_digest: proposal.permission_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project_digest: proposal.project_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            consent_digest: proposal.consent_digest.clone(),
            google_cloud_project: proposal.google_cloud_project.clone(),
            location: proposal.location.clone(),
            publisher: proposal.publisher,
            model: proposal.model.clone(),
            response_id,
            model_version,
            response_digest,
            output_digest,
            candidates,
            prompt_feedback,
            usage_metadata,
            state,
            provider_error,
            redaction,
            provenance: mode,
            authority,
            evidence_digest: digest_bytes(b"uninitialized-vertex-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        digest_serializable(&EvidenceMaterial {
            evidence_version: &self.evidence_version,
            proposal_digest: &self.proposal_digest,
            request_digest: &self.request_digest,
            request_source_fence: &self.request_source_fence,
            contract_digest: &self.contract_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            project_digest: &self.project_digest,
            mission_digest: &self.mission_digest,
            work_product_digest: &self.work_product_digest,
            consent_digest: &self.consent_digest,
            google_cloud_project: &self.google_cloud_project,
            location: &self.location,
            publisher: self.publisher,
            model: &self.model,
            response_id: self.response_id.as_deref(),
            model_version: self.model_version.as_deref(),
            response_digest: &self.response_digest,
            output_digest: self.output_digest.as_ref(),
            candidates: &self.candidates,
            prompt_feedback: self.prompt_feedback.as_ref(),
            usage_metadata: self.usage_metadata.as_ref(),
            state: self.state,
            provider_error: self.provider_error.as_ref(),
            redaction: self.redaction,
            provenance: self.provenance,
            authority: self.authority,
        })
    }

    pub fn verify_integrity(&self) -> Result<(), VertexAiGenerationError> {
        if self.validate_metadata().is_err()
            || self.authority.connected
            || self.authority.native
            || self.authority.durable_receipt
            || self.authority.independent_read_back
            || self.authority.kernel_outcome_adoption
            || self.redaction.retains_raw_prompts()
            || self.redaction.retains_raw_outputs()
            || self.evidence_digest != self.compute_digest()
        {
            Err(VertexAiGenerationError::EvidenceTampered)
        } else {
            Ok(())
        }
    }

    fn validate_metadata(&self) -> Result<(), VertexAiGenerationError> {
        if self.evidence_version != "vertex-ai-generation-result-evidence/v1"
            || !self.proposal_digest.is_sha256()
            || !self.request_digest.is_sha256()
            || !self.request_source_fence.is_sha256()
            || !self.contract_digest.is_sha256()
            || !self.registration_digest.is_sha256()
            || !self.provider_digest.is_sha256()
            || !self.permission_digest.is_sha256()
            || !self.scope_digest.is_sha256()
            || !self.project_digest.is_sha256()
            || !self.mission_digest.is_sha256()
            || !self.work_product_digest.is_sha256()
            || !self.consent_digest.is_sha256()
            || !self.response_digest.is_sha256()
            || self
                .output_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_sha256())
        {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        if self.request_source_fence
            != expected_request_source_fence(&self.scope_digest, &self.request_digest)
        {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        if self
            .response_id
            .as_deref()
            .is_some_and(|value| !valid_token(value, MAX_RESPONSE_ID_BYTES))
            || self
                .model_version
                .as_deref()
                .is_some_and(|value| !valid_token(value, MAX_IDENTIFIER_BYTES))
        {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        let mut output_bytes = 0_usize;
        for candidate in &self.candidates {
            candidate.validate_metadata()?;
            output_bytes = output_bytes
                .checked_add(candidate.content_byte_length)
                .ok_or(VertexAiGenerationError::EvidenceTampered)?;
        }
        if output_bytes > MAX_OUTPUT_BYTES {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        if let Some(feedback) = &self.prompt_feedback {
            feedback.validate_metadata()?;
        }
        if let Some(usage) = &self.usage_metadata {
            usage.validate_metadata()?;
        }
        if let Some(error) = &self.provider_error
            && !error.error_digest.is_sha256()
        {
            return Err(VertexAiGenerationError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn content_digest(&self) -> Option<&Digest> {
        self.output_digest.as_ref()
    }
}

#[derive(Serialize)]
struct EvidenceMaterial<'a> {
    evidence_version: &'a str,
    proposal_digest: &'a Digest,
    request_digest: &'a Digest,
    request_source_fence: &'a Digest,
    contract_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    project_digest: &'a Digest,
    mission_digest: &'a Digest,
    work_product_digest: &'a Digest,
    consent_digest: &'a Digest,
    google_cloud_project: &'a GoogleCloudProject,
    location: &'a VertexLocation,
    publisher: VertexPublisher,
    model: &'a ModelSnapshot,
    response_id: Option<&'a str>,
    model_version: Option<&'a str>,
    response_digest: &'a Digest,
    output_digest: Option<&'a Digest>,
    candidates: &'a [CandidateSummary],
    prompt_feedback: Option<&'a PromptFeedback>,
    usage_metadata: Option<&'a UsageMetadata>,
    state: ResponseState,
    provider_error: Option<&'a ProviderErrorProjection>,
    redaction: RedactionPolicy,
    provenance: ProviderMode,
    authority: EvidenceAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelDescription {
    pub google_cloud_project: GoogleCloudProject,
    pub location: VertexLocation,
    pub api_version: VertexApiVersion,
    pub publisher: VertexPublisher,
    pub model: ModelSnapshot,
    pub input_policy_digest: Digest,
    pub safety_policy_digest: Digest,
    pub tool_grounding_policy_digest: Digest,
    pub response_digest: Digest,
    pub source: String,
    pub connected: bool,
    pub native: bool,
    pub independent_read_back: bool,
}

impl ModelDescription {
    pub(crate) fn from_scope(scope: &VertexAiGenerationScope) -> Self {
        Self {
            google_cloud_project: scope.google_cloud_project.clone(),
            location: scope.location.clone(),
            api_version: scope.api_version,
            publisher: scope.publisher,
            model: scope.model.clone(),
            input_policy_digest: scope.input_policy_digest(),
            safety_policy_digest: scope.safety_policy_digest(),
            tool_grounding_policy_digest: scope.tool_grounding_policy_digest(),
            response_digest: scope.response_digest(),
            source: "scoped_declaration_only".to_owned(),
            connected: false,
            native: false,
            independent_read_back: false,
        }
    }
}

pub const fn provider_identity() -> &'static str {
    VERTEX_AI_GENERATION_PROVIDER_ID
}

pub const fn contract_schema_identity() -> &'static str {
    VERTEX_AI_GENERATION_SCHEMA_VERSION
}

pub const fn service_identity() -> &'static str {
    VERTEX_AI_GENERATION_SERVICE_ID
}
