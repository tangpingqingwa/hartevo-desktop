use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as ShaDigest, Sha256};

use crate::error::{AnthropicMessageResultError, Result};

pub const DEFAULT_API_HOST: &str = "https://api.anthropic.com";
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";
pub const ANTHROPIC_MESSAGES_METHOD: &str = "POST";
pub const ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";
pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_REQUEST_CONTENT_BYTES: usize = 256 * 1024;
pub const MAX_MESSAGES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_MAX_TOKENS: u32 = 8192;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CONTENT_BLOCKS: usize = 64;
pub const MAX_CITATIONS: usize = 32;
pub const MAX_CITATION_METADATA_BYTES: usize = 2048;
pub const MAX_STOP_SEQUENCE_BYTES: usize = 256;
pub const MAX_LATENCY_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_TOKEN_COUNT: u64 = 1_000_000_000;

/// Lowercase SHA-256 used for every sensitive or externally meaningful fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AnthropicMessageResultError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex_encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<str>) -> Self {
        Self::from_bytes(value.as_ref().as_bytes())
    }

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract values serialize");
        Self::from_bytes(bytes)
    }

    pub fn pending() -> Self {
        Self::from_text("pending-anthropic-message-result-digest")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Digest {
    type Err = AnthropicMessageResultError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::new(value)
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

macro_rules! bounded_identifier {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $kind)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AnthropicMessageResultError;

            fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

fn validate_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value.bytes().any(|byte| matches!(byte, b'?' | b'#' | b'%'))
    {
        Err(AnthropicMessageResultError::InvalidIdentifier { kind })
    } else {
        Ok(())
    }
}

bounded_identifier!(AccountId, "account");
bounded_identifier!(WorkspaceId, "workspace");
bounded_identifier!(ProjectId, "Project");
bounded_identifier!(MissionId, "Mission");
bounded_identifier!(WorkProductId, "Work Product");
bounded_identifier!(RequestId, "request");

impl RequestId {
    pub fn new_request(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() > MAX_REQUEST_ID_BYTES {
            return Err(AnthropicMessageResultError::RequestIdInvalid);
        }
        Self::new(value).map_err(|_| AnthropicMessageResultError::RequestIdInvalid)
    }
}

/// Anthropic's API host is exact-scoped. An alternate host is accepted only
/// when it is an HTTPS host explicitly supplied by the host application.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ApiHost(String);

impl ApiHost {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().trim_end_matches('/').to_owned();
        let authority = value.strip_prefix("https://").unwrap_or_default();
        if value.is_empty()
            || value.len() > MAX_IDENTIFIER_BYTES
            || authority.is_empty()
            || authority.contains('/')
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_whitespace)
        {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "api_host",
                reason: "must be a bounded HTTPS host without query or fragment",
            });
        }
        Ok(Self(value))
    }

    pub fn anthropic() -> Self {
        Self(DEFAULT_API_HOST.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        let authority = self.0.strip_prefix("https://").unwrap_or_default();
        if self.0.is_empty()
            || self.0.len() > MAX_IDENTIFIER_BYTES
            || authority.is_empty()
            || authority.contains('/')
            || self.0.contains('?')
            || self.0.contains('#')
            || self.0.chars().any(char::is_whitespace)
        {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "api_host",
                reason: "must be a bounded HTTPS host without query or fragment",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for ApiHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ApiHost").field(&self.0).finish()
    }
}

/// The model id and immutable version are fenced separately. A floating alias
/// cannot be used as a model version.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelVersion {
    pub model_id: String,
    pub immutable_version: String,
}

impl ModelVersion {
    pub fn new(model_id: impl Into<String>, immutable_version: impl Into<String>) -> Result<Self> {
        let model_id = model_id.into();
        let immutable_version = immutable_version.into();
        validate_bounded_text(&model_id, "model_id", MAX_IDENTIFIER_BYTES)?;
        validate_bounded_text(
            &immutable_version,
            "immutable_model_version",
            MAX_IDENTIFIER_BYTES,
        )?;
        if immutable_version.chars().any(char::is_whitespace)
            || matches!(
                immutable_version.as_str(),
                "latest" | "default" | "main" | "master"
            )
        {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "immutable_model_version",
                reason: "must be a pinned model version, not a floating alias",
            });
        }
        Ok(Self {
            model_id,
            immutable_version,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.model_id.clone(), self.immutable_version.clone()).map(|_| ())
    }
}

impl fmt::Debug for ModelVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelVersion")
            .field("model_id", &self.model_id)
            .field("immutable_version", &self.immutable_version)
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
}

/// Opaque host-owned reference. Only a digest, kind, and revision survive.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    pub reference_digest: Digest,
    pub kind: SecretKind,
    pub revision: u64,
}

impl SecretReference {
    pub fn new(opaque_reference: impl AsRef<str>, revision: u64) -> Result<Self> {
        let opaque_reference = opaque_reference.as_ref();
        if opaque_reference.trim().is_empty()
            || opaque_reference.len() > MAX_IDENTIFIER_BYTES
            || opaque_reference.chars().any(char::is_control)
        {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "opaque_api_key_secret_reference",
                reason: "must be a bounded non-empty opaque host handle",
            });
        }
        let mut material = b"hartevo:anthropic-api-key-reference:v1:".to_vec();
        material.extend_from_slice(opaque_reference.as_bytes());
        material.extend_from_slice(&revision.to_be_bytes());
        Ok(Self {
            reference_digest: Digest::from_bytes(material),
            kind: SecretKind::ApiKey,
            revision,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn validate(&self) -> Result<()> {
        if !self.reference_digest.is_sha256() || !matches!(self.kind, SecretKind::ApiKey) {
            return Err(AnthropicMessageResultError::SecretReferenceMismatch);
        }
        Ok(())
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
pub enum AnthropicPermission {
    MessagesCreate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    pub permissions: Vec<AnthropicPermission>,
    pub revision: u64,
    pub snapshot_digest: Digest,
}

impl PermissionSnapshot {
    pub fn messages_create(revision: u64) -> Self {
        let mut value = Self {
            permissions: vec![AnthropicPermission::MessagesCreate],
            revision,
            snapshot_digest: Digest::pending(),
        };
        value.snapshot_digest = value.computed_digest();
        value
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.snapshot_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn digest(&self) -> &Digest {
        &self.snapshot_digest
    }

    pub fn validate(&self) -> Result<()> {
        if self.permissions != [AnthropicPermission::MessagesCreate]
            || self.snapshot_digest != self.computed_digest()
        {
            return Err(AnthropicMessageResultError::PermissionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    pub project_id: ProjectId,
    pub revision: u64,
}

impl ProjectScope {
    pub fn new(project_id: ProjectId, revision: u64) -> Self {
        Self {
            project_id,
            revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub revision: u64,
}

impl MissionScope {
    pub fn new(mission_id: MissionId, revision: u64) -> Self {
        Self {
            mission_id,
            revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    pub work_product_id: WorkProductId,
    pub revision: u64,
}

impl WorkProductScope {
    pub fn new(work_product_id: WorkProductId, revision: u64) -> Self {
        Self {
            work_product_id,
            revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRedactionPolicy {
    #[default]
    ContentDigestsOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MessagePolicy {
    pub policy_revision: String,
    pub max_request_content_bytes: usize,
    pub max_messages: usize,
    pub max_message_bytes: usize,
    pub max_max_tokens: u32,
    pub max_response_bytes: usize,
    pub max_content_blocks: usize,
    pub max_citations: usize,
    pub output_redaction: OutputRedactionPolicy,
}

impl Default for MessagePolicy {
    fn default() -> Self {
        Self {
            policy_revision: "anthropic-message-result-policy-r1".to_owned(),
            max_request_content_bytes: MAX_REQUEST_CONTENT_BYTES,
            max_messages: MAX_MESSAGES,
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_max_tokens: MAX_MAX_TOKENS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_content_blocks: MAX_CONTENT_BLOCKS,
            max_citations: MAX_CITATIONS,
            output_redaction: OutputRedactionPolicy::ContentDigestsOnly,
        }
    }
}

impl MessagePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.policy_revision.trim().is_empty()
            || self.policy_revision.len() > MAX_IDENTIFIER_BYTES
            || self.policy_revision.chars().any(char::is_control)
            || self.max_request_content_bytes == 0
            || self.max_request_content_bytes > MAX_REQUEST_CONTENT_BYTES
            || self.max_messages == 0
            || self.max_messages > MAX_MESSAGES
            || self.max_message_bytes == 0
            || self.max_message_bytes > MAX_MESSAGE_BYTES
            || self.max_max_tokens == 0
            || self.max_max_tokens > MAX_MAX_TOKENS
            || self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_content_blocks == 0
            || self.max_content_blocks > MAX_CONTENT_BLOCKS
            || self.max_citations > MAX_CITATIONS
        {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "message_policy",
                reason: "policy values must stay within Layer-1 bounds",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Exact account/workspace/API/model/project/Mission/Work Product binding.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicScope {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub api_host: ApiHost,
    pub api_version: String,
    pub secret_reference: SecretReference,
    pub permission_snapshot: PermissionSnapshot,
    pub model: ModelVersion,
    pub provider_revision: String,
    pub project: ProjectScope,
    pub mission: MissionScope,
    pub work_product: WorkProductScope,
    pub policy: MessagePolicy,
}

impl AnthropicScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        workspace_id: WorkspaceId,
        api_host: ApiHost,
        api_version: impl Into<String>,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        model: ModelVersion,
        provider_revision: impl Into<String>,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
        policy: MessagePolicy,
    ) -> Result<Self> {
        let scope = Self {
            account_id,
            workspace_id,
            api_host,
            api_version: api_version.into(),
            secret_reference,
            permission_snapshot,
            model,
            provider_revision: provider_revision.into(),
            project,
            mission,
            work_product,
            policy,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn fixture() -> Self {
        let account = AccountId::new("account-fixture").expect("fixture account");
        let workspace = WorkspaceId::new("workspace-fixture").expect("fixture workspace");
        let model =
            ModelVersion::new("claude-3-5-sonnet-20241022", "2024-10-22").expect("fixture model");
        Self::new(
            account,
            workspace,
            ApiHost::anthropic(),
            ANTHROPIC_API_VERSION,
            SecretReference::new("fixture-api-key", 1).expect("fixture secret"),
            PermissionSnapshot::messages_create(1),
            model,
            "anthropic-messages-r1",
            ProjectScope::new(ProjectId::new("project-fixture").expect("project"), 1),
            MissionScope::new(MissionId::new("mission-fixture").expect("mission"), 1),
            WorkProductScope::new(
                WorkProductId::new("work-product-fixture").expect("work product"),
                1,
            ),
            MessagePolicy::default(),
        )
        .expect("fixture scope")
    }

    pub fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.workspace_id.validate()?;
        self.secret_reference.validate()?;
        self.permission_snapshot.validate()?;
        self.model.validate()?;
        self.api_host.validate()?;
        validate_bounded_text(&self.api_version, "api_version", MAX_IDENTIFIER_BYTES)?;
        if self.api_version != ANTHROPIC_API_VERSION {
            return Err(AnthropicMessageResultError::ApiVersionDrift);
        }
        validate_bounded_text(
            &self.provider_revision,
            "provider_revision",
            MAX_IDENTIFIER_BYTES,
        )?;
        if self.provider_revision.chars().any(char::is_whitespace) {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "provider_revision",
                reason: "must not contain whitespace",
            });
        }
        self.policy.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission.mission_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product.work_product_id
    }
}

impl fmt::Debug for AnthropicScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicScope")
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("api_host", &self.api_host)
            .field("api_version", &self.api_version)
            .field("secret_reference", &self.secret_reference)
            .field("permission_digest", &self.permission_snapshot.digest())
            .field("model", &self.model)
            .field("provider_revision", &self.provider_revision)
            .field("project", &self.project)
            .field("mission", &self.mission)
            .field("work_product", &self.work_product)
            .field("policy_revision", &self.policy.policy_revision)
            .field("scope_digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Fake,
    Recording,
    Loopback,
    BlockedEnv,
}

pub type ProviderMode = ProviderProvenance;

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub revision_digest: Digest,
}

impl ProviderDefinition {
    pub fn for_scope(scope: &AnthropicScope) -> Self {
        let provider_id = crate::PROVIDER_ID.to_owned();
        let provider_version = crate::PLUGIN_VERSION.to_owned();
        let api_version = scope.api_version.clone();
        let provider_revision = scope.provider_revision.clone();
        let api_digest = Digest::from_serializable(&(&scope.api_host, &api_version));
        let revision_digest = Digest::from_text(&provider_revision);
        let provider_digest = Digest::from_serializable(&(
            &provider_id,
            &provider_version,
            &api_version,
            &provider_revision,
        ));
        Self {
            provider_id,
            provider_version,
            api_version,
            provider_revision,
            provider_digest,
            api_digest,
            revision_digest,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub secret_reference_digest: Digest,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl AnthropicRegistration {
    pub fn new(scope: &AnthropicScope, provider: &ProviderDefinition) -> Result<Self> {
        scope.validate()?;
        let mut registration = Self {
            plugin_version: crate::PLUGIN_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            model_digest: scope.model.digest(),
            permission_digest: scope.permission_snapshot.digest().clone(),
            scope_digest: scope.digest(),
            revision_digest: provider.revision_digest.clone(),
            secret_reference_digest: scope.secret_reference.reference_digest.clone(),
            state: RegistrationState::Active,
            registration_digest: Digest::pending(),
        };
        registration.registration_digest = registration.computed_digest();
        Ok(registration)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn validate_against(
        &self,
        scope: &AnthropicScope,
        provider: &ProviderDefinition,
    ) -> Result<()> {
        if self.plugin_version != crate::PLUGIN_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.model_digest != scope.model.digest()
            || self.permission_digest != *scope.permission_snapshot.digest()
            || self.scope_digest != scope.digest()
            || self.revision_digest != provider.revision_digest
            || self.secret_reference_digest != scope.secret_reference.reference_digest
            || self.registration_digest != self.computed_digest()
        {
            return Err(AnthropicMessageResultError::RegistrationDigestMismatch);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state == RegistrationState::Active
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation> {
        if !self.is_active() {
            return Err(AnthropicMessageResultError::RegistrationRevoked);
        }
        let previous_digest = self.registration_digest.clone();
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.computed_digest();
        Ok(RegistrationRevocation {
            previous_digest,
            revoked_digest: self.registration_digest.clone(),
        })
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.is_active() {
            return Ok(());
        }
        self.state = RegistrationState::Active;
        self.registration_digest = self.computed_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocation {
    pub previous_digest: Digest,
    pub revoked_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    User,
    Assistant,
}

/// Caller-owned message input. The custom Debug implementation exposes only
/// role, length, and a content digest; the service never stores this value.
#[derive(Clone, Eq, PartialEq)]
pub struct AnthropicMessage {
    role: MessageRole,
    content: String,
}

impl AnthropicMessage {
    pub fn new(role: MessageRole, content: impl Into<String>) -> Result<Self> {
        let content = content.into();
        validate_content(&content, "message_content", MAX_MESSAGE_BYTES)?;
        Ok(Self { role, content })
    }

    pub fn role(&self) -> MessageRole {
        self.role
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn content_bytes(&self) -> usize {
        self.content.len()
    }

    pub fn content_digest(&self) -> Digest {
        Digest::from_bytes(self.content.as_bytes())
    }
}

impl fmt::Debug for AnthropicMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicMessage")
            .field("role", &self.role)
            .field("content_bytes", &self.content.len())
            .field("content_digest", &self.content_digest())
            .finish()
    }
}

/// Caller-owned Messages request. It is consumed only transiently by the
/// proposal compiler or transport seam; proposals retain metadata and digests,
/// never its prompt text.
#[derive(Clone, Eq, PartialEq)]
pub struct AnthropicMessageRequest {
    request_id: RequestId,
    model: ModelVersion,
    max_tokens: u32,
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
    stop_sequences: Vec<String>,
    stream: bool,
    tools_requested: bool,
}

impl AnthropicMessageRequest {
    pub fn new(
        request_id: RequestId,
        model: ModelVersion,
        max_tokens: u32,
        messages: Vec<AnthropicMessage>,
    ) -> Result<Self> {
        if max_tokens == 0 || max_tokens > MAX_MAX_TOKENS {
            return Err(AnthropicMessageResultError::MaxTokensExceeded);
        }
        if messages.is_empty() {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "messages",
                reason: "at least one message is required",
            });
        }
        request_id.validate()?;
        model.validate()?;
        Ok(Self {
            request_id,
            model,
            max_tokens,
            system: None,
            messages,
            stop_sequences: Vec::new(),
            stream: false,
            tools_requested: false,
        })
    }

    pub fn with_system(mut self, system: impl Into<String>) -> Result<Self> {
        let system = system.into();
        validate_content(&system, "system_prompt", MAX_MESSAGE_BYTES)?;
        self.system = Some(system);
        Ok(self)
    }

    pub fn with_stop_sequences(mut self, stop_sequences: Vec<String>) -> Result<Self> {
        if stop_sequences.iter().any(|value| {
            value.is_empty()
                || value.len() > MAX_STOP_SEQUENCE_BYTES
                || value.chars().any(char::is_control)
        }) {
            return Err(AnthropicMessageResultError::InvalidInput {
                field: "stop_sequences",
                reason: "stop sequences must be bounded and non-empty",
            });
        }
        self.stop_sequences = stop_sequences;
        Ok(self)
    }

    #[must_use]
    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = stream;
        self
    }

    #[must_use]
    pub fn with_tools_requested(mut self, requested: bool) -> Self {
        self.tools_requested = requested;
        self
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn model(&self) -> &ModelVersion {
        &self.model
    }

    pub const fn max_tokens(&self) -> u32 {
        self.max_tokens
    }

    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    pub fn messages(&self) -> &[AnthropicMessage] {
        &self.messages
    }

    pub fn stream(&self) -> bool {
        self.stream
    }

    pub fn tools_requested(&self) -> bool {
        self.tools_requested
    }

    pub fn content_bytes(&self) -> usize {
        self.system.as_ref().map_or(0, String::len)
            + self
                .messages
                .iter()
                .map(AnthropicMessage::content_bytes)
                .sum::<usize>()
            + self.stop_sequences.iter().map(String::len).sum::<usize>()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(&self.digest_material())
    }

    pub fn validate_for(&self, scope: &AnthropicScope) -> Result<()> {
        scope.validate()?;
        self.request_id.validate()?;
        if self.model != scope.model {
            return Err(AnthropicMessageResultError::ModelVersionDrift);
        }
        if self.messages.len() > scope.policy.max_messages {
            return Err(AnthropicMessageResultError::MessageCountExceeded);
        }
        if self
            .messages
            .iter()
            .any(|message| message.content_bytes() > scope.policy.max_message_bytes)
            || self
                .system
                .as_ref()
                .is_some_and(|system| system.len() > scope.policy.max_message_bytes)
        {
            return Err(AnthropicMessageResultError::MessageContentTooLarge);
        }
        if self.content_bytes() > scope.policy.max_request_content_bytes {
            return Err(AnthropicMessageResultError::RequestContentTooLarge);
        }
        if self.max_tokens == 0 || self.max_tokens > scope.policy.max_max_tokens {
            return Err(AnthropicMessageResultError::MaxTokensExceeded);
        }
        if self.stream {
            return Err(AnthropicMessageResultError::StreamingForbidden);
        }
        if self.tools_requested {
            return Err(AnthropicMessageResultError::ToolExecutionForbidden);
        }
        Ok(())
    }

    pub(crate) fn wire_body(&self) -> Vec<u8> {
        let messages = self
            .messages
            .iter()
            .map(|message| {
                json!({
                    "role": match message.role { MessageRole::User => "user", MessageRole::Assistant => "assistant" },
                    "content": message.content,
                })
            })
            .collect::<Vec<_>>();
        let mut body = json!({
            "model": self.model.model_id,
            "max_tokens": self.max_tokens,
            "messages": messages,
        });
        if let Some(system) = &self.system {
            body["system"] = Value::String(system.clone());
        }
        if !self.stop_sequences.is_empty() {
            body["stop_sequences"] = json!(self.stop_sequences);
        }
        serde_json::to_vec(&body).expect("Anthropic request body serializes")
    }

    fn digest_material(&self) -> RequestDigestMaterial {
        RequestDigestMaterial {
            request_id: self.request_id.as_str().to_owned(),
            model: self.model.clone(),
            max_tokens: self.max_tokens,
            system: self.system.clone(),
            messages: self
                .messages
                .iter()
                .map(|message| DigestMessage {
                    role: message.role,
                    content: message.content.clone(),
                })
                .collect(),
            stop_sequences: self.stop_sequences.clone(),
            stream: self.stream,
            tools_requested: self.tools_requested,
        }
    }
}

impl fmt::Debug for AnthropicMessageRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicMessageRequest")
            .field("request_id", &self.request_id)
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("system_bytes", &self.system.as_ref().map_or(0, String::len))
            .field("message_count", &self.messages.len())
            .field("content_bytes", &self.content_bytes())
            .field("stop_sequence_count", &self.stop_sequences.len())
            .field("request_digest", &self.digest())
            .field("stream", &self.stream)
            .field("tools_requested", &self.tools_requested)
            .finish()
    }
}

#[derive(Serialize)]
struct RequestDigestMaterial {
    request_id: String,
    model: ModelVersion,
    max_tokens: u32,
    system: Option<String>,
    messages: Vec<DigestMessage>,
    stop_sequences: Vec<String>,
    stream: bool,
    tools_requested: bool,
}

#[derive(Serialize)]
struct DigestMessage {
    role: MessageRole,
    content: String,
}

fn validate_bounded_text(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(AnthropicMessageResultError::InvalidInput {
            field,
            reason: "must be bounded, non-empty, and free of control characters",
        })
    } else {
        Ok(())
    }
}

fn validate_content(value: &str, field: &'static str, max: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        Err(AnthropicMessageResultError::InvalidInput {
            field,
            reason: "must be bounded and contain no unsupported control characters",
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicMessageResultProposal {
    pub request_id: RequestId,
    pub request_digest: Digest,
    pub model: ModelVersion,
    pub max_tokens: u32,
    pub message_count: usize,
    pub request_content_bytes: usize,
    pub system_content_digest: Option<Digest>,
    pub scope: AnthropicScope,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
}

impl AnthropicMessageResultProposal {
    pub(crate) fn compile(
        scope: &AnthropicScope,
        registration: &AnthropicRegistration,
        request: &AnthropicMessageRequest,
        provider: &ProviderDefinition,
    ) -> Result<Self> {
        request.validate_for(scope)?;
        let mut proposal = Self {
            request_id: request.request_id.clone(),
            request_digest: request.digest(),
            model: request.model.clone(),
            max_tokens: request.max_tokens,
            message_count: request.messages.len(),
            request_content_bytes: request.content_bytes(),
            system_content_digest: request
                .system
                .as_ref()
                .map(|system| Digest::from_bytes(system.as_bytes())),
            scope: scope.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            model_digest: scope.model.digest(),
            permission_digest: scope.permission_snapshot.digest().clone(),
            scope_digest: scope.digest(),
            revision_digest: provider.revision_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            proposal_digest: Digest::pending(),
        };
        proposal.proposal_digest = proposal.computed_digest();
        Ok(proposal)
    }

    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.proposal_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.proposal_digest != self.computed_digest() {
            return Err(AnthropicMessageResultError::ProposalDigestMismatch);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        scope: &AnthropicScope,
        registration: &AnthropicRegistration,
        provider: &ProviderDefinition,
    ) -> Result<()> {
        self.verify_integrity()?;
        if self.scope != *scope
            || self.scope_digest != scope.digest()
            || self.provider_digest != provider.provider_digest
            || self.api_digest != provider.api_digest
            || self.model_digest != scope.model.digest()
            || self.permission_digest != *scope.permission_snapshot.digest()
            || self.revision_digest != provider.revision_digest
            || self.registration_digest != registration.registration_digest
            || self.model != scope.model
        {
            return Err(AnthropicMessageResultError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    EndTurn,
    MaxTokens,
    ToolUse,
    StopSequence,
    Refusal,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Complete,
    ToolUse,
    Refused,
    Partial,
    ProviderError,
    ProviderUnknown,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ServerError,
    TransportUnavailable,
    BlockedEnv,
    MalformedResponse,
    PartialResponse,
    ProviderUnknown,
    ResponseTooLarge,
}

pub type ProviderFailureClass = ProviderErrorClass;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorProjection {
    pub class: ProviderErrorClass,
    pub http_status: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub response_body_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCategory {
    Safety,
    Policy,
    Provider,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RefusalProjection {
    pub category: RefusalCategory,
    pub reason_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentBlockKind {
    Text,
    ToolUse,
    ThinkingRedacted,
    Refusal,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentBlockProjection {
    pub kind: ContentBlockKind,
    pub content_digest: Digest,
    pub content_bytes: usize,
    pub citation_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitationMetadata {
    pub source_type: String,
    pub source_digest: Digest,
    pub title_digest: Option<Digest>,
    pub url_digest: Option<Digest>,
    pub cited_text_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl CitationMetadata {
    pub(crate) fn from_json(value: &Value) -> Result<Self> {
        let object = value
            .as_object()
            .ok_or(AnthropicMessageResultError::MalformedResponse(
                "citation block is not an object",
            ))?;
        let source_type = object
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("provider_unknown");
        validate_bounded_text(source_type, "citation_type", 64)?;
        let source_material = object
            .get("url")
            .and_then(Value::as_str)
            .or_else(|| {
                object
                    .get("document_index")
                    .and_then(Value::as_i64)
                    .map(|_| "document")
            })
            .unwrap_or("provider_unknown");
        let title_digest = object
            .get("title")
            .and_then(Value::as_str)
            .map(Digest::from_text);
        let url_digest = object
            .get("url")
            .and_then(Value::as_str)
            .map(Digest::from_text);
        let cited_text_digest = object
            .get("cited_text")
            .or_else(|| object.get("text"))
            .and_then(Value::as_str)
            .map(Digest::from_text);
        let metadata_bytes = serde_json::to_vec(value)
            .map_err(|_| AnthropicMessageResultError::MalformedResponse("citation metadata"))?;
        if metadata_bytes.len() > MAX_CITATION_METADATA_BYTES {
            return Err(AnthropicMessageResultError::MalformedResponse(
                "citation metadata exceeds bound",
            ));
        }
        Ok(Self {
            source_type: source_type.to_owned(),
            source_digest: Digest::from_text(source_material),
            title_digest,
            url_digest,
            cited_text_digest,
            metadata_digest: Digest::from_bytes(metadata_bytes),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UsageProjection {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cache_creation_input_tokens: Option<u64>,
    pub cache_read_input_tokens: Option<u64>,
}

impl UsageProjection {
    pub fn new(
        input_tokens: u64,
        output_tokens: u64,
        cache_creation_input_tokens: Option<u64>,
        cache_read_input_tokens: Option<u64>,
    ) -> Result<Self> {
        let total_tokens = input_tokens
            .checked_add(output_tokens)
            .ok_or(AnthropicMessageResultError::UsageInconsistent)?;
        if [
            input_tokens,
            output_tokens,
            cache_creation_input_tokens.unwrap_or(0),
            cache_read_input_tokens.unwrap_or(0),
        ]
        .into_iter()
        .any(|value| value > MAX_TOKEN_COUNT)
        {
            return Err(AnthropicMessageResultError::UsageInconsistent);
        }
        Ok(Self {
            input_tokens,
            output_tokens,
            total_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.total_tokens != self.input_tokens.saturating_add(self.output_tokens)
            || self.input_tokens > MAX_TOKEN_COUNT
            || self.output_tokens > MAX_TOKEN_COUNT
        {
            return Err(AnthropicMessageResultError::UsageInconsistent);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Layer1Authority {
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub durable_provider_receipt: bool,
    pub independent_output_read_back: bool,
    pub kernel_truth: bool,
    pub kernel_effect: bool,
    pub kernel_receipt: bool,
    pub kernel_verification: bool,
    pub kernel_outcome: bool,
    pub work_product_adoption: bool,
}

impl Layer1Authority {
    pub const fn layer_one() -> Self {
        Self {
            connected: false,
            native: false,
            external_writes: false,
            durable_provider_receipt: false,
            independent_output_read_back: false,
            kernel_truth: false,
            kernel_effect: false,
            kernel_receipt: false,
            kernel_verification: false,
            kernel_outcome: false,
            work_product_adoption: false,
        }
    }

    pub const fn is_non_authoritative(self) -> bool {
        !self.connected
            && !self.native
            && !self.external_writes
            && !self.durable_provider_receipt
            && !self.independent_output_read_back
            && !self.kernel_truth
            && !self.kernel_effect
            && !self.kernel_receipt
            && !self.kernel_verification
            && !self.kernel_outcome
            && !self.work_product_adoption
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicMessageResultEvidence {
    pub request_id: RequestId,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub scope: AnthropicScope,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub model_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub recording_id_digest: Digest,
    pub response_id_digest: Option<Digest>,
    pub response_digest: Digest,
    pub response_bytes: usize,
    pub response_model: Option<ModelVersion>,
    pub status: ResultStatus,
    pub stop_reason: Option<StopReason>,
    pub usage: Option<UsageProjection>,
    pub latency_ms: u64,
    pub refusal: Option<RefusalProjection>,
    pub citations: Vec<CitationMetadata>,
    pub content_blocks: Vec<ContentBlockProjection>,
    pub content_digest: Digest,
    pub provider_error: Option<ProviderErrorProjection>,
    pub provenance: ProviderProvenance,
    pub authority: Layer1Authority,
    pub evidence_digest: Digest,
}

impl AnthropicMessageResultEvidence {
    pub fn computed_digest(&self) -> Digest {
        let mut value = self.clone();
        value.evidence_digest = Digest::pending();
        Digest::from_serializable(&value)
    }

    pub fn verify_integrity(&self) -> Result<()> {
        if self.evidence_digest != self.computed_digest() {
            return Err(AnthropicMessageResultError::EvidenceDigestMismatch);
        }
        if let Some(usage) = &self.usage {
            usage.validate()?;
        }
        if !self.authority.is_non_authoritative() {
            return Err(AnthropicMessageResultError::MutationForbidden(
                "Layer-1 evidence authority flags",
            ));
        }
        Ok(())
    }

    pub const fn is_adoptable(&self) -> bool {
        false
    }

    pub fn result_fingerprint(&self) -> Digest {
        Digest::from_serializable(&(
            &self.request_digest,
            &self.response_digest,
            &self.content_digest,
            &self.status,
            &self.stop_reason,
            &self.usage,
        ))
    }
}

pub type MessageResultEvidence = AnthropicMessageResultEvidence;

pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serializable(value)
}
