//! Bounded, serializable-safe `OpenAI` Moderation contract values.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::{
    OPENAI_MODERATION_API_HOST, OPENAI_MODERATION_API_PATH, OPENAI_MODERATION_RESULT_CONTRACT_JSON,
    OPENAI_MODERATION_RESULT_PLUGIN_VERSION, OPENAI_MODERATION_RESULT_PROVIDER_ID, digest_bytes,
    digest_serializable,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REFERENCE_BYTES: usize = 256;
pub const MAX_MODEL_BYTES: usize = 128;
pub const MAX_POLICY_REVISION_BYTES: usize = 128;
pub const MAX_INPUT_BYTES: usize = 512 * 1024;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_INPUT_ITEMS: usize = 8;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_CATEGORIES: usize = 32;
pub const MAX_RECORDING_ID_BYTES: usize = 128;
pub const MAX_DIAGNOSTIC_BYTES: usize = 256;

/// Every error is a safe projection and never contains provider bodies,
/// supplied text, image references, URLs, credentials, or PII.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpenAiModerationError {
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
    #[error("evidence digest does not match its immutable contents")]
    EvidenceTampered,
    #[error("model snapshot drifted")]
    ModelDrift,
    #[error("moderation policy drifted")]
    PolicyDrift,
    #[error("category allowlist drifted")]
    CategoryAllowlistDrift,
    #[error("project revision drifted")]
    ProjectRevisionDrift,
    #[error("Mission revision drifted")]
    MissionRevisionDrift,
    #[error("Work Product revision drifted")]
    WorkProductRevisionDrift,
    #[error("moderation input does not match the proposal")]
    InputMismatch,
    #[error("moderation input type is not allowed")]
    InputTypeForbidden,
    #[error("moderation input exceeds the configured byte bound")]
    InputTooLarge,
    #[error("text input exceeds the configured byte bound")]
    TextTooLarge,
    #[error("image input exceeds the configured byte bound")]
    ImageTooLarge,
    #[error("moderation input item count exceeds the configured bound")]
    ItemCountExceeded,
    #[error("image media type is not allowlisted")]
    ImageTypeForbidden,
    #[error("category is not in the policy allowlist")]
    CategoryNotAllowlisted,
    #[error("provider response exceeds the configured byte bound")]
    ResponseTooLarge,
    #[error("provider response is truncated")]
    ResponseTruncated,
    #[error("provider response is malformed")]
    MalformedProviderResponse,
    #[error("provider response is partial")]
    PartialProviderResponse,
    #[error("provider identity does not match the proposal")]
    ProviderIdentityMismatch,
    #[error("provider returned HTTP status {0}")]
    UnsupportedHttpStatus(u16),
    #[error("provider rejected the credential")]
    Unauthorized,
    #[error("provider permission was denied")]
    Forbidden,
    #[error("provider rejected the bounded payload")]
    PayloadTooLarge,
    #[error("provider rate limit is fail-closed")]
    RateLimited,
    #[error("provider timed out")]
    ProviderTimeout,
    #[error("provider state is unknown")]
    ProviderUnknown,
    #[error("provider is unavailable in BLOCKED_ENV: {0}")]
    BlockedEnvironment(&'static str),
    #[error("a proposal or evidence fingerprint was replayed")]
    ReplayDetected,
    #[error("native moderation execution is a Layer-2 gap")]
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
    OAuth,
}

/// Opaque host-owned API-key or OAuth reference.
///
/// The supplied handle is hashed at construction and is never retained,
/// serialized, or displayed. Layer 1 has no way to resolve it.
#[derive(Clone, Eq, PartialEq)]
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
    ) -> Result<Self, OpenAiModerationError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "opaque_secret_reference",
                reason: "must be a bounded non-empty host handle",
            });
        }
        if revision == 0 {
            return Err(OpenAiModerationError::InvalidField {
                field: "secret_reference_revision",
                reason: "must be non-zero",
            });
        }
        let mut material = b"hartevo:openai-moderation-secret-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        material.push(match kind {
            SecretKind::ApiKey => 0,
            SecretKind::OAuth => 1,
        });
        Ok(Self {
            reference_digest: digest_bytes(&material),
            kind,
            revision,
        })
    }

    pub fn api_key(
        opaque_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(opaque_reference, SecretKind::ApiKey, revision)
    }

    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        revision: u64,
    ) -> Result<Self, OpenAiModerationError> {
        Self::new(opaque_reference, SecretKind::OAuth, revision)
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
pub enum OpenAiModerationPermission {
    ModerationsCreate,
}

/// Permission plus the digest-only host credential binding.
#[derive(Clone, Eq, PartialEq)]
pub struct PermissionScope {
    permission: OpenAiModerationPermission,
    secret_reference: SecretReference,
}

impl PermissionScope {
    pub fn new(permission: OpenAiModerationPermission, secret_reference: SecretReference) -> Self {
        Self {
            permission,
            secret_reference,
        }
    }

    pub const fn permission(&self) -> OpenAiModerationPermission {
        self.permission
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.permission,
            self.secret_reference.reference_digest(),
            self.secret_reference.kind(),
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

impl Serialize for PermissionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PermissionScope", 4)?;
        state.serialize_field("permission", &self.permission)?;
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("secretKind", &self.secret_reference.kind())?;
        state.serialize_field("secretRevision", &self.secret_reference.revision())?;
        state.end()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: String,
    revision: u64,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAiModerationError> {
        Ok(Self {
            id: bounded_scope_id("project_id", id.into())?,
            revision: nonzero_revision("project_revision", revision)?,
        })
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAiModerationError> {
        Ok(Self {
            id: bounded_scope_id("mission_id", id.into())?,
            revision: nonzero_revision("mission_revision", revision)?,
        })
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
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, OpenAiModerationError> {
        Ok(Self {
            id: bounded_scope_id("work_product_id", id.into())?,
            revision: nonzero_revision("work_product_revision", revision)?,
        })
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

fn bounded_scope_id(field: &'static str, id: String) -> Result<String, OpenAiModerationError> {
    if id.trim().is_empty() || id.len() > MAX_IDENTIFIER_BYTES || id.chars().any(char::is_control) {
        return Err(OpenAiModerationError::InvalidField {
            field,
            reason: "must be a bounded non-empty scope identifier",
        });
    }
    Ok(id)
}

fn nonzero_revision(field: &'static str, revision: u64) -> Result<u64, OpenAiModerationError> {
    if revision == 0 {
        return Err(OpenAiModerationError::InvalidField {
            field,
            reason: "must be non-zero",
        });
    }
    Ok(revision)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiModerationProviderScope {
    provider_id: String,
    api_host: String,
    api_path: String,
}

impl OpenAiModerationProviderScope {
    pub fn new(
        provider_id: impl Into<String>,
        api_host: impl Into<String>,
        api_path: impl Into<String>,
    ) -> Result<Self, OpenAiModerationError> {
        let provider_id = provider_id.into();
        let api_host = api_host.into().trim_end_matches('/').to_owned();
        let api_path = api_path.into();
        if provider_id != OPENAI_MODERATION_RESULT_PROVIDER_ID {
            return Err(OpenAiModerationError::InvalidField {
                field: "provider_id",
                reason: "must be the explicit OpenAI Moderation provider",
            });
        }
        if api_host != OPENAI_MODERATION_API_HOST
            || api_host.contains('?')
            || api_host.contains('#')
            || api_host.chars().any(char::is_whitespace)
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "api_host",
                reason: "must be the fixed HTTPS OpenAI API host",
            });
        }
        if api_path != OPENAI_MODERATION_API_PATH {
            return Err(OpenAiModerationError::InvalidField {
                field: "api_path",
                reason: "must be the direct Moderations endpoint",
            });
        }
        Ok(Self {
            provider_id,
            api_host,
            api_path,
        })
    }

    pub fn openai() -> Self {
        Self {
            provider_id: OPENAI_MODERATION_RESULT_PROVIDER_ID.to_owned(),
            api_host: OPENAI_MODERATION_API_HOST.to_owned(),
            api_path: OPENAI_MODERATION_API_PATH.to_owned(),
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn api_host(&self) -> &str {
        &self.api_host
    }

    pub fn api_path(&self) -> &str {
        &self.api_path
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
    ) -> Result<Self, OpenAiModerationError> {
        let model_id = model_id.into();
        let immutable_snapshot = immutable_snapshot.into();
        validate_model_part("model_id", &model_id)?;
        validate_model_part("immutable_model_snapshot", &immutable_snapshot)?;
        if matches!(
            immutable_snapshot.as_str(),
            "latest" | "default" | "auto" | "main" | "master"
        ) {
            return Err(OpenAiModerationError::InvalidField {
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

    pub(crate) fn matches_provider_model(&self, value: &str) -> bool {
        value == self.model_id || value == self.immutable_snapshot
    }
}

fn validate_model_part(field: &'static str, value: &str) -> Result<(), OpenAiModerationError> {
    if value.trim().is_empty()
        || value.len() > MAX_MODEL_BYTES
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(OpenAiModerationError::InvalidField {
            field,
            reason: "must be a bounded non-empty model value without whitespace",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ModerationCategory {
    #[serde(rename = "harassment")]
    Harassment,
    #[serde(rename = "harassment/threatening")]
    HarassmentThreatening,
    #[serde(rename = "hate")]
    Hate,
    #[serde(rename = "hate/threatening")]
    HateThreatening,
    #[serde(rename = "illicit")]
    Illicit,
    #[serde(rename = "illicit/violent")]
    IllicitViolent,
    #[serde(rename = "self-harm")]
    SelfHarm,
    #[serde(rename = "self-harm/intent")]
    SelfHarmIntent,
    #[serde(rename = "self-harm/instructions")]
    SelfHarmInstructions,
    #[serde(rename = "sexual")]
    Sexual,
    #[serde(rename = "sexual/minors")]
    SexualMinors,
    #[serde(rename = "violence")]
    Violence,
    #[serde(rename = "violence/graphic")]
    ViolenceGraphic,
}

impl ModerationCategory {
    pub const ALL: [Self; 13] = [
        Self::Harassment,
        Self::HarassmentThreatening,
        Self::Hate,
        Self::HateThreatening,
        Self::Illicit,
        Self::IllicitViolent,
        Self::SelfHarm,
        Self::SelfHarmIntent,
        Self::SelfHarmInstructions,
        Self::Sexual,
        Self::SexualMinors,
        Self::Violence,
        Self::ViolenceGraphic,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Harassment => "harassment",
            Self::HarassmentThreatening => "harassment/threatening",
            Self::Hate => "hate",
            Self::HateThreatening => "hate/threatening",
            Self::Illicit => "illicit",
            Self::IllicitViolent => "illicit/violent",
            Self::SelfHarm => "self-harm",
            Self::SelfHarmIntent => "self-harm/intent",
            Self::SelfHarmInstructions => "self-harm/instructions",
            Self::Sexual => "sexual",
            Self::SexualMinors => "sexual/minors",
            Self::Violence => "violence",
            Self::ViolenceGraphic => "violence/graphic",
        }
    }

    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|category| category.as_str() == value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryAllowlist {
    categories: BTreeSet<ModerationCategory>,
}

impl CategoryAllowlist {
    pub fn new(
        categories: impl IntoIterator<Item = ModerationCategory>,
    ) -> Result<Self, OpenAiModerationError> {
        let categories: BTreeSet<_> = categories.into_iter().collect();
        if categories.is_empty() || categories.len() > MAX_CATEGORIES {
            return Err(OpenAiModerationError::InvalidField {
                field: "category_allowlist",
                reason: "must contain a bounded non-empty category set",
            });
        }
        Ok(Self { categories })
    }

    pub fn all() -> Self {
        Self {
            categories: ModerationCategory::ALL.into_iter().collect(),
        }
    }

    pub fn contains(&self, category: ModerationCategory) -> bool {
        self.categories.contains(&category)
    }

    pub fn categories(&self) -> &BTreeSet<ModerationCategory> {
        &self.categories
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoreRetention {
    None,
    BasisPoints,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionPolicy {
    retain_flags: bool,
    score_retention: ScoreRetention,
}

impl RedactionPolicy {
    pub const fn flags_and_scores() -> Self {
        Self {
            retain_flags: true,
            score_retention: ScoreRetention::BasisPoints,
        }
    }

    pub const fn flags_only() -> Self {
        Self {
            retain_flags: true,
            score_retention: ScoreRetention::None,
        }
    }

    pub const fn retain_flags(self) -> bool {
        self.retain_flags
    }

    pub const fn score_retention(self) -> ScoreRetention {
        self.score_retention
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModerationPolicy {
    revision: String,
    max_input_bytes: usize,
    max_text_bytes: usize,
    max_image_bytes: usize,
    max_items: usize,
    max_response_bytes: usize,
    allow_text: bool,
    allow_image: bool,
    categories: CategoryAllowlist,
    redaction: RedactionPolicy,
}

impl ModerationPolicy {
    pub fn new(
        revision: impl Into<String>,
        categories: CategoryAllowlist,
    ) -> Result<Self, OpenAiModerationError> {
        let policy = Self {
            revision: validate_policy_revision(revision.into())?,
            max_input_bytes: MAX_INPUT_BYTES,
            max_text_bytes: MAX_TEXT_BYTES,
            max_image_bytes: MAX_IMAGE_BYTES,
            max_items: MAX_INPUT_ITEMS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            allow_text: true,
            allow_image: true,
            categories,
            redaction: RedactionPolicy::flags_and_scores(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn conservative(revision: impl Into<String>) -> Result<Self, OpenAiModerationError> {
        Self::new(revision, CategoryAllowlist::all())?.with_limits(
            256 * 1024,
            128 * 1024,
            2 * 1024 * 1024,
            4,
            512 * 1024,
        )
    }

    pub fn with_limits(
        mut self,
        max_input_bytes: usize,
        max_text_bytes: usize,
        max_image_bytes: usize,
        max_items: usize,
        max_response_bytes: usize,
    ) -> Result<Self, OpenAiModerationError> {
        self.max_input_bytes = max_input_bytes;
        self.max_text_bytes = max_text_bytes;
        self.max_image_bytes = max_image_bytes;
        self.max_items = max_items;
        self.max_response_bytes = max_response_bytes;
        self.validate()?;
        Ok(self)
    }

    pub fn with_allowed_types(
        mut self,
        allow_text: bool,
        allow_image: bool,
    ) -> Result<Self, OpenAiModerationError> {
        if !allow_text && !allow_image {
            return Err(OpenAiModerationError::InvalidField {
                field: "input_type_allowlist",
                reason: "at least one input type must be allowed",
            });
        }
        self.allow_text = allow_text;
        self.allow_image = allow_image;
        self.validate()?;
        Ok(self)
    }

    #[must_use]
    pub fn with_redaction(mut self, redaction: RedactionPolicy) -> Self {
        self.redaction = redaction;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), OpenAiModerationError> {
        if validate_policy_revision(self.revision.clone()).is_err()
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_INPUT_BYTES
            || self.max_text_bytes == 0
            || self.max_text_bytes > self.max_input_bytes
            || self.max_text_bytes > MAX_TEXT_BYTES
            || self.max_image_bytes == 0
            || self.max_image_bytes > MAX_IMAGE_BYTES
            || self.max_items == 0
            || self.max_items > MAX_INPUT_ITEMS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || (!self.allow_text && !self.allow_image)
            || self.categories.categories.is_empty()
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "moderation_policy",
                reason: "one or more values exceed the Layer-1 bounds",
            });
        }
        Ok(())
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

    pub const fn max_image_bytes(&self) -> usize {
        self.max_image_bytes
    }

    pub const fn max_items(&self) -> usize {
        self.max_items
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    pub const fn allows_text(&self) -> bool {
        self.allow_text
    }

    pub const fn allows_image(&self) -> bool {
        self.allow_image
    }

    pub fn categories(&self) -> &CategoryAllowlist {
        &self.categories
    }

    pub const fn redaction(&self) -> RedactionPolicy {
        self.redaction
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

fn validate_policy_revision(revision: String) -> Result<String, OpenAiModerationError> {
    if revision.trim().is_empty()
        || revision.len() > MAX_POLICY_REVISION_BYTES
        || revision
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(OpenAiModerationError::InvalidField {
            field: "policy_revision",
            reason: "must be a bounded non-empty revision",
        });
    }
    Ok(revision)
}

pub type InputPolicy = ModerationPolicy;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiModerationScope {
    provider: OpenAiModerationProviderScope,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
    model: ModelSnapshot,
    policy: ModerationPolicy,
    permission: PermissionScope,
}

impl OpenAiModerationScope {
    pub fn new(
        provider: OpenAiModerationProviderScope,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        model: ModelSnapshot,
        policy: ModerationPolicy,
        permission: PermissionScope,
    ) -> Result<Self, OpenAiModerationError> {
        policy.validate()?;
        Ok(Self {
            provider,
            project,
            mission,
            work_product,
            model,
            policy,
            permission,
        })
    }

    pub fn provider(&self) -> &OpenAiModerationProviderScope {
        &self.provider
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

    pub fn model(&self) -> &ModelSnapshot {
        &self.model
    }

    pub fn policy(&self) -> &ModerationPolicy {
        &self.policy
    }

    pub fn permission(&self) -> &PermissionScope {
        &self.permission
    }

    pub fn provider_digest(&self) -> Digest {
        self.provider.digest()
    }

    pub fn project_digest(&self) -> Digest {
        self.project.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }

    pub fn model_digest(&self) -> Digest {
        self.model.digest()
    }

    pub fn policy_digest(&self) -> Digest {
        self.policy.digest()
    }

    pub fn category_allowlist_digest(&self) -> Digest {
        self.policy.categories().digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.provider.digest(),
            self.project.digest(),
            self.mission.digest(),
            self.work_product.digest(),
            self.model.digest(),
            self.policy.digest(),
            self.permission.digest(),
        ))
    }
}

pub type ModerationScope = OpenAiModerationScope;
pub type OpenAiProjectScope = ProjectScope;
pub type OpenAiMissionScope = MissionScope;
pub type OpenAiWorkProductScope = WorkProductScope;
pub type OpenAiModelSnapshot = ModelSnapshot;
pub type OpenAiProviderScope = OpenAiModerationProviderScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageMediaType {
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/webp")]
    Webp,
}

impl ImageMediaType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jpeg => "image/jpeg",
            Self::Png => "image/png",
            Self::Webp => "image/webp",
        }
    }

    pub fn parse(value: &str) -> Result<Self, OpenAiModerationError> {
        match value {
            "image/jpeg" => Ok(Self::Jpeg),
            "image/png" => Ok(Self::Png),
            "image/webp" => Ok(Self::Webp),
            _ => Err(OpenAiModerationError::ImageTypeForbidden),
        }
    }
}

/// Digest-only reference to an image owned by the host. Raw bytes and URLs
/// never enter this type.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ImageReference {
    reference_digest: Digest,
    byte_len: usize,
    media_type: ImageMediaType,
}

impl ImageReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        byte_len: usize,
        media_type: impl AsRef<str>,
    ) -> Result<Self, OpenAiModerationError> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_REFERENCE_BYTES
            || opaque_reference.chars().any(char::is_control)
            || opaque_reference.contains("://")
        {
            return Err(OpenAiModerationError::InvalidField {
                field: "opaque_image_reference",
                reason: "must be a bounded non-URL host handle",
            });
        }
        if byte_len == 0 || byte_len > MAX_IMAGE_BYTES {
            return Err(OpenAiModerationError::ImageTooLarge);
        }
        let media_type = ImageMediaType::parse(media_type.as_ref())?;
        let reference_digest = digest_serializable(&(
            "hartevo:openai-moderation-image-reference:v1",
            opaque_reference,
            byte_len,
            media_type,
        ));
        Ok(Self {
            reference_digest,
            byte_len,
            media_type,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub const fn media_type(&self) -> ImageMediaType {
        self.media_type
    }
}

impl fmt::Debug for ImageReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImageReference")
            .field("reference_digest", &self.reference_digest)
            .field("byte_len", &self.byte_len)
            .field("media_type", &self.media_type)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationInputKind {
    Text,
    Image,
    Mixed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModerationInputItem {
    kind: ModerationInputKind,
    content_digest: Digest,
    byte_len: usize,
    media_type: Option<ImageMediaType>,
}

impl ModerationInputItem {
    pub fn text(value: impl AsRef<str>) -> Result<Self, OpenAiModerationError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(OpenAiModerationError::InvalidField {
                field: "moderation_text",
                reason: "must be non-empty",
            });
        }
        if value.len() > MAX_TEXT_BYTES {
            return Err(OpenAiModerationError::TextTooLarge);
        }
        Ok(Self {
            kind: ModerationInputKind::Text,
            content_digest: digest_bytes(value.as_bytes()),
            byte_len: value.len(),
            media_type: None,
        })
    }

    pub fn image(reference: ImageReference) -> Self {
        let ImageReference {
            reference_digest,
            byte_len,
            media_type,
        } = reference;
        Self {
            kind: ModerationInputKind::Image,
            content_digest: reference_digest,
            byte_len,
            media_type: Some(media_type),
        }
    }

    pub const fn kind(&self) -> ModerationInputKind {
        self.kind
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub const fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub const fn media_type(&self) -> Option<ImageMediaType> {
        self.media_type
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ModerationInput {
    Text(ModerationInputItem),
    Image(ModerationInputItem),
    Items(Vec<ModerationInputItem>),
}

impl ModerationInput {
    pub fn text(value: impl AsRef<str>) -> Result<Self, OpenAiModerationError> {
        Ok(Self::Text(ModerationInputItem::text(value)?))
    }

    pub fn image(reference: ImageReference) -> Self {
        Self::Image(ModerationInputItem::image(reference))
    }

    pub fn image_reference(
        opaque_reference: impl AsRef<str>,
        byte_len: usize,
        media_type: impl AsRef<str>,
    ) -> Result<Self, OpenAiModerationError> {
        Ok(Self::image(ImageReference::new(
            opaque_reference,
            byte_len,
            media_type,
        )?))
    }

    pub fn items(items: Vec<ModerationInputItem>) -> Result<Self, OpenAiModerationError> {
        if items.is_empty() || items.len() > MAX_INPUT_ITEMS {
            return Err(OpenAiModerationError::ItemCountExceeded);
        }
        Ok(Self::Items(items))
    }

    pub fn kind(&self) -> ModerationInputKind {
        match self {
            Self::Text(_) => ModerationInputKind::Text,
            Self::Image(_) => ModerationInputKind::Image,
            Self::Items(items) => {
                if items
                    .iter()
                    .all(|item| item.kind() == ModerationInputKind::Text)
                {
                    ModerationInputKind::Text
                } else if items
                    .iter()
                    .all(|item| item.kind() == ModerationInputKind::Image)
                {
                    ModerationInputKind::Image
                } else {
                    ModerationInputKind::Mixed
                }
            }
        }
    }

    pub fn item_count(&self) -> usize {
        match self {
            Self::Text(_) | Self::Image(_) => 1,
            Self::Items(items) => items.len(),
        }
    }

    pub fn parts(&self) -> Vec<&ModerationInputItem> {
        match self {
            Self::Text(item) | Self::Image(item) => vec![item],
            Self::Items(items) => items.iter().collect(),
        }
    }

    pub fn input_bytes(&self) -> usize {
        self.parts()
            .into_iter()
            .map(ModerationInputItem::byte_len)
            .sum()
    }

    pub fn input_digest(&self) -> Digest {
        let safe_items: Vec<_> = self
            .parts()
            .into_iter()
            .map(|item| {
                (
                    item.kind(),
                    item.content_digest(),
                    item.byte_len(),
                    item.media_type(),
                )
            })
            .collect();
        digest_serializable(&("hartevo:openai-moderation-input:v1", safe_items))
    }

    pub fn validate(&self, policy: &ModerationPolicy) -> Result<(), OpenAiModerationError> {
        if self.item_count() > policy.max_items() {
            return Err(OpenAiModerationError::ItemCountExceeded);
        }
        if self.input_bytes() > policy.max_input_bytes() {
            return Err(OpenAiModerationError::InputTooLarge);
        }
        for item in self.parts() {
            match item.kind() {
                ModerationInputKind::Text if !policy.allows_text() => {
                    return Err(OpenAiModerationError::InputTypeForbidden);
                }
                ModerationInputKind::Text if item.byte_len() > policy.max_text_bytes() => {
                    return Err(OpenAiModerationError::TextTooLarge);
                }
                ModerationInputKind::Image if !policy.allows_image() => {
                    return Err(OpenAiModerationError::InputTypeForbidden);
                }
                ModerationInputKind::Image if item.byte_len() > policy.max_image_bytes() => {
                    return Err(OpenAiModerationError::ImageTooLarge);
                }
                ModerationInputKind::Mixed => {
                    return Err(OpenAiModerationError::InputTypeForbidden);
                }
                ModerationInputKind::Text | ModerationInputKind::Image => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, OpenAiModerationError> {
        let value = value.into();
        bounded_identifier("request_id", value).map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResponseId(String);

impl ResponseId {
    pub fn new(value: impl Into<String>) -> Result<Self, OpenAiModerationError> {
        let value = value.into();
        bounded_identifier("response_id", value).map(Self)
    }

    pub fn digest(&self) -> Digest {
        digest_bytes(self.0.as_bytes())
    }
}

fn bounded_identifier(field: &'static str, value: String) -> Result<String, OpenAiModerationError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(OpenAiModerationError::InvalidField {
            field,
            reason: "must be a bounded non-empty identifier",
        });
    }
    Ok(value)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenAiModerationRequest {
    request_id: RequestId,
    input: ModerationInput,
}

impl OpenAiModerationRequest {
    pub fn new(request_id: RequestId, input: ModerationInput) -> Self {
        Self { request_id, input }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn input(&self) -> &ModerationInput {
        &self.input
    }

    pub fn input_digest(&self) -> Digest {
        self.input.input_digest()
    }
}

pub type ModerationRequest = OpenAiModerationRequest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScoreProjection(u16);

impl ScoreProjection {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn from_probability(value: f64) -> Result<Self, OpenAiModerationError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(OpenAiModerationError::MalformedProviderResponse);
        }
        let basis_points = (value * 10_000.0).round() as u16;
        Ok(Self(basis_points.min(10_000)))
    }

    pub const fn from_basis_points(value: u16) -> Result<Self, OpenAiModerationError> {
        if value > 10_000 {
            return Err(OpenAiModerationError::InvalidField {
                field: "score_basis_points",
                reason: "must be between zero and ten thousand",
            });
        }
        Ok(Self(value))
    }

    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CategoryOutcome {
    category: ModerationCategory,
    flagged: bool,
    score: Option<ScoreProjection>,
}

impl CategoryOutcome {
    pub const fn new(
        category: ModerationCategory,
        flagged: bool,
        score: Option<ScoreProjection>,
    ) -> Self {
        Self {
            category,
            flagged,
            score,
        }
    }

    pub const fn category(&self) -> ModerationCategory {
        self.category
    }

    pub const fn flagged(&self) -> bool {
        self.flagged
    }

    pub const fn score(&self) -> Option<ScoreProjection> {
        self.score
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputDescriptor {
    kind: ModerationInputKind,
    item_count: usize,
    input_bytes: usize,
    input_digest: Digest,
}

impl InputDescriptor {
    pub(crate) fn from_input(input: &ModerationInput) -> Self {
        Self {
            kind: input.kind(),
            item_count: input.item_count(),
            input_bytes: input.input_bytes(),
            input_digest: input.input_digest(),
        }
    }

    pub const fn kind(&self) -> ModerationInputKind {
        self.kind
    }

    pub const fn item_count(&self) -> usize {
        self.item_count
    }

    pub const fn input_bytes(&self) -> usize {
        self.input_bytes
    }

    pub fn input_digest(&self) -> &Digest {
        &self.input_digest
    }
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
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockedEnvCode {
    NativeTransportDisabled,
    CredentialsUnavailable,
    EnvironmentUnavailable,
}

impl BlockedEnvCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeTransportDisabled => "NATIVE_TRANSPORT_DISABLED",
            Self::CredentialsUnavailable => "CREDENTIALS_UNAVAILABLE",
            Self::EnvironmentUnavailable => "ENVIRONMENT_UNAVAILABLE",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationStatus {
    Completed,
    Malformed,
    Partial,
    Unauthorized,
    Forbidden,
    PayloadTooLarge,
    RateLimited,
    ServerError,
    Timeout,
    ProviderUnknown,
    BlockedEnv,
}

impl ModerationStatus {
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Completed)
    }

    pub const fn fail_closed(self) -> bool {
        !self.is_success()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureKind {
    Malformed,
    Partial,
    Unauthorized,
    Forbidden,
    PayloadTooLarge,
    RateLimited,
    ServerError,
    Timeout,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFailureProjection {
    kind: ProviderFailureKind,
    http_status: Option<u16>,
}

impl ProviderFailureProjection {
    pub const fn new(kind: ProviderFailureKind, http_status: Option<u16>) -> Self {
        Self { kind, http_status }
    }

    pub const fn kind(self) -> ProviderFailureKind {
        self.kind
    }

    pub const fn http_status(self) -> Option<u16> {
        self.http_status
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionMetadata {
    raw_content_retained: bool,
    raw_provider_json_retained: bool,
    hidden_reasoning_retained: bool,
    user_pii_retained: bool,
    category_outcomes_retained: bool,
    scores_retained_as_basis_points: bool,
}

impl RedactionMetadata {
    pub const fn for_policy(policy: RedactionPolicy) -> Self {
        Self {
            raw_content_retained: false,
            raw_provider_json_retained: false,
            hidden_reasoning_retained: false,
            user_pii_retained: false,
            category_outcomes_retained: true,
            scores_retained_as_basis_points: matches!(
                policy.score_retention(),
                ScoreRetention::BasisPoints
            ),
        }
    }

    pub const fn raw_content_retained(self) -> bool {
        self.raw_content_retained
    }

    pub const fn raw_provider_json_retained(self) -> bool {
        self.raw_provider_json_retained
    }

    pub const fn hidden_reasoning_retained(self) -> bool {
        self.hidden_reasoning_retained
    }

    pub const fn user_pii_retained(self) -> bool {
        self.user_pii_retained
    }

    pub const fn scores_retained_as_basis_points(self) -> bool {
        self.scores_retained_as_basis_points
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityClaims {
    connected: bool,
    native: bool,
    first_party: bool,
    external_writes: bool,
    automatic_blocking: bool,
    automatic_deletion: bool,
    notification: bool,
    kernel_authority: bool,
}

impl AuthorityClaims {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
            automatic_blocking: false,
            automatic_deletion: false,
            notification: false,
            kernel_authority: false,
        }
    }

    pub const fn connected(self) -> bool {
        self.connected
    }

    pub const fn native(self) -> bool {
        self.native
    }

    pub const fn first_party(self) -> bool {
        self.first_party
    }

    pub const fn external_writes(self) -> bool {
        self.external_writes
    }

    pub const fn automatic_blocking(self) -> bool {
        self.automatic_blocking
    }

    pub const fn automatic_deletion(self) -> bool {
        self.automatic_deletion
    }

    pub const fn notification(self) -> bool {
        self.notification
    }

    pub const fn kernel_authority(self) -> bool {
        self.kernel_authority
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiModerationProposal {
    request_id: RequestId,
    registration_digest: Digest,
    provider_digest: Digest,
    project_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    model_digest: Digest,
    policy_digest: Digest,
    category_allowlist_digest: Digest,
    input: InputDescriptor,
    request_fingerprint: Digest,
    proposal_digest: Digest,
}

impl OpenAiModerationProposal {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: RequestId,
        registration_digest: Digest,
        provider_digest: Digest,
        project_digest: Digest,
        mission_digest: Digest,
        work_product_digest: Digest,
        model_digest: Digest,
        policy_digest: Digest,
        category_allowlist_digest: Digest,
        input: InputDescriptor,
        request_fingerprint: Digest,
    ) -> Self {
        let proposal_digest = Self::compute_digest(
            &request_id,
            &registration_digest,
            &provider_digest,
            &project_digest,
            &mission_digest,
            &work_product_digest,
            &model_digest,
            &policy_digest,
            &category_allowlist_digest,
            &input,
            &request_fingerprint,
        );
        Self {
            request_id,
            registration_digest,
            provider_digest,
            project_digest,
            mission_digest,
            work_product_digest,
            model_digest,
            policy_digest,
            category_allowlist_digest,
            input,
            request_fingerprint,
            proposal_digest,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        request_id: &RequestId,
        registration_digest: &Digest,
        provider_digest: &Digest,
        project_digest: &Digest,
        mission_digest: &Digest,
        work_product_digest: &Digest,
        model_digest: &Digest,
        policy_digest: &Digest,
        category_allowlist_digest: &Digest,
        input: &InputDescriptor,
        request_fingerprint: &Digest,
    ) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-proposal:v1",
            request_id,
            registration_digest,
            provider_digest,
            project_digest,
            mission_digest,
            work_product_digest,
            model_digest,
            policy_digest,
            category_allowlist_digest,
            input,
            request_fingerprint,
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), OpenAiModerationError> {
        let expected = Self::compute_digest(
            &self.request_id,
            &self.registration_digest,
            &self.provider_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
            &self.model_digest,
            &self.policy_digest,
            &self.category_allowlist_digest,
            &self.input,
            &self.request_fingerprint,
        );
        if expected == self.proposal_digest {
            Ok(())
        } else {
            Err(OpenAiModerationError::ProposalTampered)
        }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn category_allowlist_digest(&self) -> &Digest {
        &self.category_allowlist_digest
    }

    pub fn input(&self) -> &InputDescriptor {
        &self.input
    }

    pub fn input_digest(&self) -> &Digest {
        self.input.input_digest()
    }

    pub fn request_fingerprint(&self) -> &Digest {
        &self.request_fingerprint
    }

    pub fn idempotency_key(&self) -> &Digest {
        &self.request_fingerprint
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

pub type ModerationProposal = OpenAiModerationProposal;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeChanged,
    CredentialRotated,
    ProviderChanged,
    EvidenceTampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    registration_digest: Digest,
    revision: u64,
    reason: RevocationReason,
    revocation_digest: Digest,
}

impl RegistrationRevocation {
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn reason(&self) -> RevocationReason {
        self.reason
    }

    pub fn revocation_digest(&self) -> &Digest {
        &self.revocation_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiModerationRegistration {
    plugin_version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    evidence_digest: Digest,
    scope_digest: Digest,
    project_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    model_digest: Digest,
    policy_digest: Digest,
    category_allowlist_digest: Digest,
    permission_digest: Digest,
    registration_digest: Digest,
    revocation_revision: u64,
    status: RegistrationStatus,
    revocation: Option<RegistrationRevocation>,
}

impl OpenAiModerationRegistration {
    pub(crate) fn bind(
        scope: &OpenAiModerationScope,
        provider_digest: Digest,
        evidence_digest: Digest,
    ) -> Self {
        let plugin_version_digest =
            digest_bytes(OPENAI_MODERATION_RESULT_PLUGIN_VERSION.as_bytes());
        let contract_digest = digest_bytes(OPENAI_MODERATION_RESULT_CONTRACT_JSON.as_bytes());
        let scope_digest = scope.digest();
        let project_digest = scope.project_digest();
        let mission_digest = scope.mission_digest();
        let work_product_digest = scope.work_product_digest();
        let model_digest = scope.model_digest();
        let policy_digest = scope.policy_digest();
        let category_allowlist_digest = scope.category_allowlist_digest();
        let permission_digest = scope.permission_digest();
        let registration_digest = Self::compute_digest(
            &plugin_version_digest,
            &contract_digest,
            &provider_digest,
            &evidence_digest,
            &scope_digest,
            &project_digest,
            &mission_digest,
            &work_product_digest,
            &model_digest,
            &policy_digest,
            &category_allowlist_digest,
            &permission_digest,
        );
        Self {
            plugin_version_digest,
            contract_digest,
            provider_digest,
            evidence_digest,
            scope_digest,
            project_digest,
            mission_digest,
            work_product_digest,
            model_digest,
            policy_digest,
            category_allowlist_digest,
            permission_digest,
            registration_digest,
            revocation_revision: 0,
            status: RegistrationStatus::Active,
            revocation: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        plugin_version_digest: &Digest,
        contract_digest: &Digest,
        provider_digest: &Digest,
        evidence_digest: &Digest,
        scope_digest: &Digest,
        project_digest: &Digest,
        mission_digest: &Digest,
        work_product_digest: &Digest,
        model_digest: &Digest,
        policy_digest: &Digest,
        category_allowlist_digest: &Digest,
        permission_digest: &Digest,
    ) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-registration:v1",
            plugin_version_digest,
            contract_digest,
            provider_digest,
            evidence_digest,
            scope_digest,
            project_digest,
            mission_digest,
            work_product_digest,
            model_digest,
            policy_digest,
            category_allowlist_digest,
            permission_digest,
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), OpenAiModerationError> {
        let expected = Self::compute_digest(
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.evidence_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.work_product_digest,
            &self.model_digest,
            &self.policy_digest,
            &self.category_allowlist_digest,
            &self.permission_digest,
        );
        if expected == self.registration_digest {
            Ok(())
        } else {
            Err(OpenAiModerationError::RegistrationTampered)
        }
    }

    pub(crate) fn validate_against(
        &self,
        scope: &OpenAiModerationScope,
        provider_digest: &Digest,
        evidence_digest: &Digest,
    ) -> Result<(), OpenAiModerationError> {
        self.verify_integrity()?;
        if self.status != RegistrationStatus::Active {
            return Err(OpenAiModerationError::RegistrationRevoked);
        }
        if &self.provider_digest != provider_digest
            || &self.evidence_digest != evidence_digest
            || self.scope_digest != scope.digest()
            || self.project_digest != scope.project_digest()
            || self.mission_digest != scope.mission_digest()
            || self.work_product_digest != scope.work_product_digest()
            || self.model_digest != scope.model_digest()
            || self.policy_digest != scope.policy_digest()
            || self.category_allowlist_digest != scope.category_allowlist_digest()
            || self.permission_digest != scope.permission_digest()
        {
            return Err(OpenAiModerationError::RegistrationTampered);
        }
        Ok(())
    }

    pub(crate) fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<RegistrationRevocation, OpenAiModerationError> {
        self.verify_integrity()?;
        if self.status == RegistrationStatus::Revoked {
            return Err(OpenAiModerationError::RegistrationRevoked);
        }
        self.revocation_revision = self.revocation_revision.saturating_add(1);
        let revocation_digest = digest_serializable(&(
            "hartevo:openai-moderation-revocation:v1",
            &self.registration_digest,
            self.revocation_revision,
            reason,
        ));
        let revocation = RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            revision: self.revocation_revision,
            reason,
            revocation_digest,
        };
        self.status = RegistrationStatus::Revoked;
        self.revocation = Some(revocation.clone());
        Ok(revocation)
    }

    pub(crate) fn restore(&mut self) -> Result<(), OpenAiModerationError> {
        self.verify_integrity()?;
        self.status = RegistrationStatus::Active;
        self.revocation = None;
        self.revocation_revision = self.revocation_revision.saturating_add(1);
        Ok(())
    }

    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn category_allowlist_digest(&self) -> &Digest {
        &self.category_allowlist_digest
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

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn revocation(&self) -> Option<&RegistrationRevocation> {
        self.revocation.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenAiModerationEvidence {
    request_id: RequestId,
    registration_digest: Digest,
    provider_digest: Digest,
    evidence_mode: ProviderMode,
    project_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    model_digest: Digest,
    policy_digest: Digest,
    category_allowlist_digest: Digest,
    input: InputDescriptor,
    request_fingerprint: Digest,
    status: ModerationStatus,
    flagged: Option<bool>,
    categories: Vec<CategoryOutcome>,
    frame_digest: Digest,
    response_id_digest: Option<Digest>,
    failure: Option<ProviderFailureProjection>,
    latency_ms: u64,
    recorded: bool,
    redaction: RedactionMetadata,
    authority: AuthorityClaims,
    evidence_digest: Digest,
}

impl OpenAiModerationEvidence {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        proposal: &OpenAiModerationProposal,
        evidence_mode: ProviderMode,
        status: ModerationStatus,
        flagged: Option<bool>,
        categories: Vec<CategoryOutcome>,
        frame_digest: Digest,
        response_id_digest: Option<Digest>,
        failure: Option<ProviderFailureProjection>,
        latency_ms: u64,
        recorded: bool,
        redaction: RedactionMetadata,
    ) -> Self {
        let mut evidence = Self {
            request_id: proposal.request_id.clone(),
            registration_digest: proposal.registration_digest.clone(),
            provider_digest: proposal.provider_digest.clone(),
            evidence_mode,
            project_digest: proposal.project_digest.clone(),
            mission_digest: proposal.mission_digest.clone(),
            work_product_digest: proposal.work_product_digest.clone(),
            model_digest: proposal.model_digest.clone(),
            policy_digest: proposal.policy_digest.clone(),
            category_allowlist_digest: proposal.category_allowlist_digest.clone(),
            input: proposal.input.clone(),
            request_fingerprint: proposal.request_fingerprint.clone(),
            status,
            flagged,
            categories,
            frame_digest,
            response_id_digest,
            failure,
            latency_ms,
            recorded,
            redaction,
            authority: AuthorityClaims::layer_one(),
            evidence_digest: Digest::sha256([]),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        digest_serializable(&(
            "hartevo:openai-moderation-evidence:v1",
            (
                &self.request_id,
                &self.registration_digest,
                &self.provider_digest,
                self.evidence_mode,
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
                &self.model_digest,
                &self.policy_digest,
                &self.category_allowlist_digest,
            ),
            (
                &self.input,
                &self.request_fingerprint,
                self.status,
                self.flagged,
                &self.categories,
                &self.frame_digest,
                &self.response_id_digest,
                &self.failure,
            ),
            (
                self.latency_ms,
                self.recorded,
                self.redaction,
                self.authority,
            ),
        ))
    }

    pub fn verify_integrity(&self) -> Result<(), OpenAiModerationError> {
        if self.compute_digest() == self.evidence_digest {
            Ok(())
        } else {
            Err(OpenAiModerationError::EvidenceTampered)
        }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.evidence_mode
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn category_allowlist_digest(&self) -> &Digest {
        &self.category_allowlist_digest
    }

    pub fn input(&self) -> &InputDescriptor {
        &self.input
    }

    pub fn input_digest(&self) -> &Digest {
        self.input.input_digest()
    }

    pub fn request_fingerprint(&self) -> &Digest {
        &self.request_fingerprint
    }

    pub const fn status(&self) -> ModerationStatus {
        self.status
    }

    pub const fn flagged(&self) -> Option<bool> {
        self.flagged
    }

    pub fn categories(&self) -> &[CategoryOutcome] {
        &self.categories
    }

    pub fn category(&self, category: ModerationCategory) -> Option<&CategoryOutcome> {
        self.categories
            .iter()
            .find(|outcome| outcome.category() == category)
    }

    pub fn response_id_digest(&self) -> Option<&Digest> {
        self.response_id_digest.as_ref()
    }

    pub fn frame_digest(&self) -> &Digest {
        &self.frame_digest
    }

    pub const fn failure(&self) -> Option<ProviderFailureProjection> {
        self.failure
    }

    pub const fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    pub const fn recorded(&self) -> bool {
        self.recorded
    }

    pub const fn redaction(&self) -> RedactionMetadata {
        self.redaction
    }

    pub const fn authority(&self) -> AuthorityClaims {
        self.authority
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

pub type ModerationEvidence = OpenAiModerationEvidence;

// Stable aliases keep the contract ergonomic for callers that use the API's
// all-caps spelling while the issue-facing public types remain OpenAi*.
pub type OpenAIModerationServiceError = OpenAiModerationError;
pub type OpenAIModerationScope = OpenAiModerationScope;
pub type OpenAIModerationRegistration = OpenAiModerationRegistration;
pub type OpenAiModerationPolicy = ModerationPolicy;
pub type OpenAiModerationInput = ModerationInput;
pub type OpenAiModerationCategory = ModerationCategory;
pub type OpenAiModerationCategoryAllowlist = CategoryAllowlist;
pub type OpenAiModerationResultError = OpenAiModerationError;
