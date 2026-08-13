//! Mission-scoped MCP tool provider and consumer seam.
//!
//! This module is a protocol boundary over the plugin runtime.  It does not
//! spawn a process, resolve a command, read a credential, or grant an effect
//! authority.  A host supplies a typed stdio adapter; the module binds every
//! request to the mounted plugin receipt, MCP server identity, Project/Mission
//! scope, session, and generation before a model-visible value is returned.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use super::{
    CompatibilityPolicy, ConsumerKind, Digest, PluginDefinition, PluginDefinitionHandle,
    PluginError, PluginId, PluginLifecycle, PluginRuntime, PluginScope, PluginVersion,
    ProviderCardinality, RegistrationReceipt, ServiceAccess, ServiceDefinition, ServiceId,
    UnmountReceipt,
};

pub const MCP_TOOL_SERVICE_ID: &str = "mcp.tool.service";
pub const MCP_TOOL_SERVICE_SCHEMA: &str = "hartevo.mcp-tool-service/v1";
pub const MCP_PROTOCOL_SCHEMA: &str = "hartevo.mcp-json-rpc/v1";
pub const MCP_SESSION_SCHEMA: &str = "hartevo.mcp-session/v1";
pub const MCP_RESULT_SCHEMA: &str = "hartevo.mcp-tool-result/v1";
pub const MCP_RECEIPT_SCHEMA: &str = "hartevo.mcp-invocation-receipt/v1";
pub const MCP_AUDIT_SCHEMA: &str = "hartevo.mcp-audit/v1";
pub const MCP_POLICY_SCHEMA: &str = "hartevo.mcp-tool-policy/v1";
pub const MAX_MCP_VALUE_BYTES: usize = 512 * 1024;
const MAX_MCP_TEXT_BYTES: usize = 512;

fn digest_serialized<T: Serialize + ?Sized>(value: &T) -> Digest {
    Digest::from_serialized(value)
}

fn validate_digest(value: &Digest) -> Result<(), McpError> {
    value.validate().map_err(McpError::from)
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), McpError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(McpError::InvalidText);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpErrorCode {
    InvalidText,
    InvalidDigest,
    InvalidJson,
    InvalidSchema,
    InvalidIdentity,
    InvalidLaunchSpec,
    PolicyDenied,
    Plugin,
    ScopeMismatch,
    GenerationMismatch,
    MountMissing,
    PluginRevoked,
    PluginUnmounted,
    SessionClosed,
    SessionNotReady,
    SessionAlreadyInitialized,
    ServerIdentityMismatch,
    CapabilityMismatch,
    UnknownMethod,
    DuplicateRequestId,
    UnknownRequestId,
    LateResponse,
    DuplicateTool,
    DuplicateResource,
    UnknownTool,
    UnknownResource,
    SchemaDrift,
    InvalidToolInput,
    InvalidToolResult,
    RemoteError,
    Transport,
    ServerCrashed,
    Timeout,
    CancellationFailed,
    AuditCommitFailed,
    EffectProposalInvalid,
    ReceiptInvalid,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpError {
    #[error("MCP text is invalid")]
    InvalidText,
    #[error("MCP digest is invalid")]
    InvalidDigest,
    #[error("MCP JSON value is invalid or too large")]
    InvalidJson,
    #[error("MCP schema is invalid")]
    InvalidSchema,
    #[error("MCP server identity is invalid")]
    InvalidIdentity,
    #[error("MCP stdio launch specification is invalid")]
    InvalidLaunchSpec,
    #[error("MCP capability is not allowed by the bound Mission policy")]
    PolicyDenied,
    #[error("plugin runtime rejected the MCP mount")]
    Plugin(PluginError),
    #[error("MCP Project/Mission scope does not match the mounted plugin")]
    ScopeMismatch,
    #[error("MCP generation does not match the mounted plugin")]
    GenerationMismatch,
    #[error("MCP plugin mount is missing or no longer active")]
    MountMissing,
    #[error("MCP plugin was revoked")]
    PluginRevoked,
    #[error("MCP plugin was unmounted")]
    PluginUnmounted,
    #[error("MCP session is closed")]
    SessionClosed,
    #[error("MCP session is not ready for this operation")]
    SessionNotReady,
    #[error("MCP session was already initialized")]
    SessionAlreadyInitialized,
    #[error("MCP server identity does not match the exact provider binding")]
    ServerIdentityMismatch,
    #[error("MCP server capabilities do not match the exact provider binding")]
    CapabilityMismatch,
    #[error("MCP method is unknown or not allowed")]
    UnknownMethod,
    #[error("MCP request id was already used")]
    DuplicateRequestId,
    #[error("MCP request id is not pending")]
    UnknownRequestId,
    #[error("MCP response id is late or does not match the request")]
    LateResponse,
    #[error("MCP server returned a duplicate tool")]
    DuplicateTool,
    #[error("MCP server returned a duplicate resource")]
    DuplicateResource,
    #[error("MCP tool is not discovered in this exact session")]
    UnknownTool,
    #[error("MCP resource is not discovered in this exact session")]
    UnknownResource,
    #[error("MCP tool or server schema drifted")]
    SchemaDrift,
    #[error("MCP tool input does not match the discovered schema")]
    InvalidToolInput,
    #[error("MCP tool result is invalid")]
    InvalidToolResult,
    #[error("MCP server returned a typed error")]
    RemoteError,
    #[error("MCP stdio transport failed")]
    Transport,
    #[error("MCP server crashed")]
    ServerCrashed,
    #[error("MCP request timed out")]
    Timeout,
    #[error("MCP cancellation failed")]
    CancellationFailed,
    #[error("MCP durable audit log commit failed")]
    AuditCommitFailed,
    #[error("MCP effect proposal is invalid")]
    EffectProposalInvalid,
    #[error("MCP invocation receipt is invalid")]
    ReceiptInvalid,
}

impl From<PluginError> for McpError {
    fn from(error: PluginError) -> Self {
        Self::Plugin(error)
    }
}

impl McpError {
    pub const fn code(self) -> McpErrorCode {
        match self {
            Self::InvalidText => McpErrorCode::InvalidText,
            Self::InvalidDigest => McpErrorCode::InvalidDigest,
            Self::InvalidJson => McpErrorCode::InvalidJson,
            Self::InvalidSchema => McpErrorCode::InvalidSchema,
            Self::InvalidIdentity => McpErrorCode::InvalidIdentity,
            Self::InvalidLaunchSpec => McpErrorCode::InvalidLaunchSpec,
            Self::PolicyDenied => McpErrorCode::PolicyDenied,
            Self::Plugin(_) => McpErrorCode::Plugin,
            Self::ScopeMismatch => McpErrorCode::ScopeMismatch,
            Self::GenerationMismatch => McpErrorCode::GenerationMismatch,
            Self::MountMissing => McpErrorCode::MountMissing,
            Self::PluginRevoked => McpErrorCode::PluginRevoked,
            Self::PluginUnmounted => McpErrorCode::PluginUnmounted,
            Self::SessionClosed => McpErrorCode::SessionClosed,
            Self::SessionNotReady => McpErrorCode::SessionNotReady,
            Self::SessionAlreadyInitialized => McpErrorCode::SessionAlreadyInitialized,
            Self::ServerIdentityMismatch => McpErrorCode::ServerIdentityMismatch,
            Self::CapabilityMismatch => McpErrorCode::CapabilityMismatch,
            Self::UnknownMethod => McpErrorCode::UnknownMethod,
            Self::DuplicateRequestId => McpErrorCode::DuplicateRequestId,
            Self::UnknownRequestId => McpErrorCode::UnknownRequestId,
            Self::LateResponse => McpErrorCode::LateResponse,
            Self::DuplicateTool => McpErrorCode::DuplicateTool,
            Self::DuplicateResource => McpErrorCode::DuplicateResource,
            Self::UnknownTool => McpErrorCode::UnknownTool,
            Self::UnknownResource => McpErrorCode::UnknownResource,
            Self::SchemaDrift => McpErrorCode::SchemaDrift,
            Self::InvalidToolInput => McpErrorCode::InvalidToolInput,
            Self::InvalidToolResult => McpErrorCode::InvalidToolResult,
            Self::RemoteError => McpErrorCode::RemoteError,
            Self::Transport => McpErrorCode::Transport,
            Self::ServerCrashed => McpErrorCode::ServerCrashed,
            Self::Timeout => McpErrorCode::Timeout,
            Self::CancellationFailed => McpErrorCode::CancellationFailed,
            Self::AuditCommitFailed => McpErrorCode::AuditCommitFailed,
            Self::EffectProposalInvalid => McpErrorCode::EffectProposalInvalid,
            Self::ReceiptInvalid => McpErrorCode::ReceiptInvalid,
        }
    }
}

impl From<super::PluginErrorCode> for McpErrorCode {
    fn from(error: super::PluginErrorCode) -> Self {
        let _ = error;
        Self::Plugin
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct McpText(String);

impl McpText {
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        validate_text(&value, MAX_MCP_TEXT_BYTES)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpText")
            .field("digest", &digest_serialized(&self.0))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct McpServerId(String);

impl McpServerId {
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        if super::valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(McpError::InvalidText)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpServerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpServerId")
            .field("digest", &digest_serialized(&self.0))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct McpToolName(String);

impl McpToolName {
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        if super::valid_identifier(&value) {
            Ok(Self(value))
        } else {
            Err(McpError::InvalidText)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpToolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolName")
            .field("digest", &digest_serialized(&self.0))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct McpResourceUri(String);

impl McpResourceUri {
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        validate_text(&value, MAX_MCP_TEXT_BYTES * 4)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpResourceUri")
            .field("digest", &digest_serialized(&self.0))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct McpProtocolVersion(String);

impl McpProtocolVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        validate_text(&value, 64)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpProtocolVersion")
            .field("digest", &digest_serialized(&self.0))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct McpJson(Value);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpJsonKind {
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

impl McpJson {
    pub fn from_value(value: Value) -> Result<Self, McpError> {
        let encoded = serde_json::to_vec(&value).map_err(|_| McpError::InvalidJson)?;
        if encoded.len() > MAX_MCP_VALUE_BYTES {
            return Err(McpError::InvalidJson);
        }
        Ok(Self(value))
    }

    pub fn parse_str(value: &str) -> Result<Self, McpError> {
        let value = serde_json::from_str(value).map_err(|_| McpError::InvalidJson)?;
        Self::from_value(value)
    }

    pub fn value(&self) -> &Value {
        &self.0
    }

    pub fn into_value(self) -> Value {
        self.0
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(&self.0)
    }

    pub fn kind(&self) -> McpJsonKind {
        match self.0 {
            Value::Null => McpJsonKind::Null,
            Value::Bool(_) => McpJsonKind::Boolean,
            Value::Number(_) => McpJsonKind::Number,
            Value::String(_) => McpJsonKind::String,
            Value::Array(_) => McpJsonKind::Array,
            Value::Object(_) => McpJsonKind::Object,
        }
    }
}

impl fmt::Debug for McpJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpJson")
            .field("digest", &self.digest())
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpTimeout {
    milliseconds: u64,
}

impl McpTimeout {
    pub fn new(milliseconds: u64) -> Result<Self, McpError> {
        if milliseconds == 0 {
            return Err(McpError::InvalidText);
        }
        Ok(Self { milliseconds })
    }

    pub const fn milliseconds(self) -> u64 {
        self.milliseconds
    }
}

impl Default for McpTimeout {
    fn default() -> Self {
        Self {
            milliseconds: 5_000,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct McpSecretReference {
    reference_digest: Digest,
}

impl McpSecretReference {
    pub fn new(reference_digest: Digest) -> Result<Self, McpError> {
        validate_digest(&reference_digest)?;
        Ok(Self { reference_digest })
    }

    pub fn digest(&self) -> &Digest {
        &self.reference_digest
    }
}

impl fmt::Debug for McpSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpSecretReference")
            .field("reference_digest", &self.reference_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpStdioLaunchSpec {
    command_digest: Digest,
    argument_digests: Vec<Digest>,
    environment_digests: Vec<Digest>,
    secret_references: Vec<McpSecretReference>,
}

impl McpStdioLaunchSpec {
    pub fn new(
        command_digest: Digest,
        argument_digests: Vec<Digest>,
        environment_digests: Vec<Digest>,
        secret_references: Vec<McpSecretReference>,
    ) -> Result<Self, McpError> {
        let spec = Self {
            command_digest,
            argument_digests,
            environment_digests,
            secret_references,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn command_digest(&self) -> &Digest {
        &self.command_digest
    }

    pub fn argument_digests(&self) -> &[Digest] {
        &self.argument_digests
    }

    pub fn environment_digests(&self) -> &[Digest] {
        &self.environment_digests
    }

    pub fn secret_references(&self) -> &[McpSecretReference] {
        &self.secret_references
    }

    fn validate(&self) -> Result<(), McpError> {
        validate_digest(&self.command_digest)?;
        for digest in self
            .argument_digests
            .iter()
            .chain(self.environment_digests.iter())
        {
            validate_digest(digest)?;
        }
        for reference in &self.secret_references {
            validate_digest(reference.digest())?;
        }
        Ok(())
    }
}

impl fmt::Debug for McpStdioLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpStdioLaunchSpec")
            .field("command_digest", &self.command_digest)
            .field("argument_count", &self.argument_digests.len())
            .field("environment_count", &self.environment_digests.len())
            .field("secret_reference_count", &self.secret_references.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpToolEffectClass {
    ReadOnly,
    ExternalEffect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub cancellation: bool,
}

impl McpCapabilities {
    pub const fn new(tools: bool, resources: bool, cancellation: bool) -> Self {
        Self {
            tools,
            resources,
            cancellation,
        }
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

/// The allowlist is supplied by the Mission policy before the server is
/// contacted.  Names/URIs are retained only as typed matching keys; durable
/// records bind the resulting policy digest rather than exposing them.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolPolicy {
    policy_digest: Digest,
    allowed_tool_names: BTreeSet<McpToolName>,
    allowed_tool_definition_digests: BTreeSet<Digest>,
    allowed_resource_uris: BTreeSet<McpResourceUri>,
    allow_external_effect_proposals: bool,
}

impl McpToolPolicy {
    pub fn new(
        allowed_tool_names: BTreeSet<McpToolName>,
        allowed_tool_definition_digests: BTreeSet<Digest>,
        allowed_resource_uris: BTreeSet<McpResourceUri>,
        allow_external_effect_proposals: bool,
    ) -> Result<Self, McpError> {
        let policy_digest = digest_serialized(&(
            MCP_POLICY_SCHEMA,
            &allowed_tool_names,
            &allowed_tool_definition_digests,
            &allowed_resource_uris,
            allow_external_effect_proposals,
        ));
        Self::with_digest(
            policy_digest,
            allowed_tool_names,
            allowed_tool_definition_digests,
            allowed_resource_uris,
            allow_external_effect_proposals,
        )
    }

    pub fn with_digest(
        policy_digest: Digest,
        allowed_tool_names: BTreeSet<McpToolName>,
        allowed_tool_definition_digests: BTreeSet<Digest>,
        allowed_resource_uris: BTreeSet<McpResourceUri>,
        allow_external_effect_proposals: bool,
    ) -> Result<Self, McpError> {
        validate_digest(&policy_digest)?;
        for digest in &allowed_tool_definition_digests {
            validate_digest(digest)?;
        }
        let policy = Self {
            policy_digest,
            allowed_tool_names,
            allowed_tool_definition_digests,
            allowed_resource_uris,
            allow_external_effect_proposals,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn allowed_tool_names(&self) -> &BTreeSet<McpToolName> {
        &self.allowed_tool_names
    }

    pub fn allowed_tool_definition_digests(&self) -> &BTreeSet<Digest> {
        &self.allowed_tool_definition_digests
    }

    pub fn allowed_resource_uris(&self) -> &BTreeSet<McpResourceUri> {
        &self.allowed_resource_uris
    }

    pub const fn allow_external_effect_proposals(&self) -> bool {
        self.allow_external_effect_proposals
    }

    fn allows_tool(&self, definition: &McpToolDefinition) -> bool {
        self.allowed_tool_names.contains(definition.name())
            && (self.allowed_tool_definition_digests.is_empty()
                || self
                    .allowed_tool_definition_digests
                    .contains(definition.definition_digest()))
            && (definition.effect_class() == McpToolEffectClass::ReadOnly
                || self.allow_external_effect_proposals)
    }

    fn allows_resource(&self, definition: &McpResourceDefinition) -> bool {
        self.allowed_resource_uris.contains(definition.uri())
    }

    fn validate(&self) -> Result<(), McpError> {
        let expected = digest_serialized(&(
            MCP_POLICY_SCHEMA,
            &self.allowed_tool_names,
            &self.allowed_tool_definition_digests,
            &self.allowed_resource_uris,
            self.allow_external_effect_proposals,
        ));
        if self.policy_digest != expected {
            return Err(McpError::InvalidSchema);
        }
        for name in &self.allowed_tool_names {
            if !super::valid_identifier(name.as_str()) {
                return Err(McpError::InvalidText);
            }
        }
        for uri in &self.allowed_resource_uris {
            validate_text(uri.as_str(), MAX_MCP_TEXT_BYTES * 4)?;
        }
        Ok(())
    }
}

impl fmt::Debug for McpToolPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolPolicy")
            .field("policy_digest", &self.policy_digest)
            .field(
                "allowed_tool_name_set_digest",
                &digest_serialized(&self.allowed_tool_names),
            )
            .field(
                "allowed_tool_definition_set_digest",
                &digest_serialized(&self.allowed_tool_definition_digests),
            )
            .field(
                "allowed_resource_uri_set_digest",
                &digest_serialized(&self.allowed_resource_uris),
            )
            .field(
                "allow_external_effect_proposals",
                &self.allow_external_effect_proposals,
            )
            .finish_non_exhaustive()
    }
}

/// The single typed service seam used by MCP plugin contributions.  Registry
/// state remains owned by `PluginRuntime`; this marker only builds the
/// existing runtime service descriptor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct McpToolService;

impl McpToolService {
    pub const ID: &'static str = MCP_TOOL_SERVICE_ID;

    pub fn definition() -> Result<ServiceDefinition, McpError> {
        ServiceDefinition::read_only(
            ServiceId::new(Self::ID)?,
            PluginVersion::new(1, 0, 0),
            Digest::from_text(MCP_TOOL_SERVICE_SCHEMA),
            ProviderCardinality::Many,
            CompatibilityPolicy::SameMajor,
        )
        .map_err(McpError::from)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerIdentity {
    server_id: McpServerId,
    version: PluginVersion,
    protocol_version: McpProtocolVersion,
    server_digest: Digest,
    schema_digest: Digest,
}

impl McpServerIdentity {
    pub fn new(
        server_id: McpServerId,
        version: PluginVersion,
        protocol_version: McpProtocolVersion,
        schema_digest: Digest,
    ) -> Result<Self, McpError> {
        validate_digest(&schema_digest)?;
        let server_digest =
            digest_serialized(&(MCP_PROTOCOL_SCHEMA, &server_id, version, &protocol_version));
        let identity = Self {
            server_id,
            version,
            protocol_version,
            server_digest,
            schema_digest,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn server_id(&self) -> &McpServerId {
        &self.server_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn protocol_version(&self) -> &McpProtocolVersion {
        &self.protocol_version
    }

    pub fn server_digest(&self) -> &Digest {
        &self.server_digest
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    fn validate(&self) -> Result<(), McpError> {
        if !super::valid_identifier(self.server_id.as_str()) {
            return Err(McpError::InvalidIdentity);
        }
        validate_digest(&self.server_digest)?;
        validate_digest(&self.schema_digest)?;
        let expected = digest_serialized(&(
            MCP_PROTOCOL_SCHEMA,
            &self.server_id,
            self.version,
            &self.protocol_version,
        ));
        if expected != self.server_digest {
            return Err(McpError::InvalidIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for McpServerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpServerIdentity")
            .field("server_digest", &self.server_digest)
            .field("server_id_digest", &digest_serialized(&self.server_id.0))
            .field("version", &self.version)
            .field("protocol_version", &self.protocol_version)
            .field("schema_digest", &self.schema_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerBinding {
    identity: McpServerIdentity,
    launch: McpStdioLaunchSpec,
    capabilities: McpCapabilities,
    provider_digest: Digest,
}

impl McpServerBinding {
    pub fn new(
        identity: McpServerIdentity,
        launch: McpStdioLaunchSpec,
        capabilities: McpCapabilities,
    ) -> Result<Self, McpError> {
        if identity.schema_digest() != &capabilities.digest() {
            return Err(McpError::CapabilityMismatch);
        }
        let provider_digest =
            digest_serialized(&(MCP_SESSION_SCHEMA, &identity, &launch, capabilities));
        let binding = Self {
            identity,
            launch,
            capabilities,
            provider_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn identity(&self) -> &McpServerIdentity {
        &self.identity
    }

    pub fn launch(&self) -> &McpStdioLaunchSpec {
        &self.launch
    }

    pub const fn capabilities(&self) -> McpCapabilities {
        self.capabilities
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    fn validate(&self) -> Result<(), McpError> {
        self.identity.validate()?;
        self.launch.validate()?;
        if self.identity.schema_digest() != &self.capabilities.digest() {
            return Err(McpError::CapabilityMismatch);
        }
        let expected = digest_serialized(&(
            MCP_SESSION_SCHEMA,
            &self.identity,
            &self.launch,
            self.capabilities,
        ));
        if expected != self.provider_digest {
            return Err(McpError::InvalidIdentity);
        }
        Ok(())
    }
}

impl fmt::Debug for McpServerBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpServerBinding")
            .field("provider_digest", &self.provider_digest)
            .field("identity", &self.identity)
            .field("launch", &self.launch)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpToolPlugin {
    definition: PluginDefinition,
    binding: McpServerBinding,
    service_id: ServiceId,
    provider_id: super::ProviderId,
    consumer_id: super::ConsumerId,
}

impl McpToolPlugin {
    pub fn new(
        plugin_id: PluginId,
        plugin_version: PluginVersion,
        scope: PluginScope,
        binding: McpServerBinding,
    ) -> Result<Self, McpError> {
        let service = McpToolService::definition()?;
        let service_id = service.id().clone();
        let provider_id = super::ProviderId::new(format!(
            "mcp.tool.provider.{}",
            binding.identity().server_id().as_str()
        ))?;
        let consumer_id = super::ConsumerId::new(format!(
            "mcp.tool.consumer.{}",
            binding.identity().server_id().as_str()
        ))?;
        let provider = super::ProviderDefinition::new(
            provider_id.clone(),
            service_id.clone(),
            binding.identity().version(),
            binding.provider_digest().clone(),
        )?;
        let consumer = super::ConsumerDefinition::tool(
            consumer_id.clone(),
            service_id.clone(),
            PluginVersion::new(1, 0, 0),
            digest_serialized(&(
                MCP_SESSION_SCHEMA,
                binding.provider_digest(),
                binding.identity().schema_digest(),
            )),
        )?;
        let definition = PluginDefinition::new(
            plugin_id,
            plugin_version,
            scope,
            super::PluginContributions {
                services: vec![service],
                providers: vec![provider],
                consumers: vec![consumer],
                ..super::PluginContributions::default()
            },
        )?;
        Ok(Self {
            definition,
            binding,
            service_id,
            provider_id,
            consumer_id,
        })
    }

    pub fn definition(&self) -> &PluginDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &PluginScope {
        self.definition.scope()
    }

    pub fn plugin_digest(&self) -> &Digest {
        self.definition.digest()
    }

    pub fn binding(&self) -> &McpServerBinding {
        &self.binding
    }

    pub fn define(&self, runtime: &mut PluginRuntime) -> Result<PluginDefinitionHandle, McpError> {
        runtime
            .define(self.definition.clone())
            .map_err(McpError::from)
    }

    pub fn mount(&self, runtime: &mut PluginRuntime) -> Result<McpToolMount, McpError> {
        let handle = self.define(runtime)?;
        let receipt = runtime.mount(&handle)?;
        let mount = McpToolMount {
            plugin: self.clone(),
            handle,
            receipt,
        };
        mount.validate_runtime(runtime)?;
        Ok(mount)
    }
}

impl fmt::Debug for McpToolPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolPlugin")
            .field("plugin_digest", &self.plugin_digest())
            .field("scope_digest", &self.scope().digest())
            .field("server", &self.binding.identity)
            .field("service_id_digest", &digest_serialized(&self.service_id))
            .field("provider_id_digest", &digest_serialized(&self.provider_id))
            .field("consumer_id_digest", &digest_serialized(&self.consumer_id))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct McpToolMount {
    plugin: McpToolPlugin,
    handle: PluginDefinitionHandle,
    receipt: RegistrationReceipt,
}

impl McpToolMount {
    pub fn plugin(&self) -> &McpToolPlugin {
        &self.plugin
    }

    pub fn handle(&self) -> &PluginDefinitionHandle {
        &self.handle
    }

    pub fn receipt(&self) -> &RegistrationReceipt {
        &self.receipt
    }

    pub fn plugin_digest(&self) -> &Digest {
        self.plugin.plugin_digest()
    }

    pub fn validate_runtime(&self, runtime: &PluginRuntime) -> Result<(), McpError> {
        let lifecycle = runtime.lifecycle(&self.handle)?;
        match lifecycle.lifecycle {
            PluginLifecycle::Mounted => {}
            PluginLifecycle::Revoked => return Err(McpError::PluginRevoked),
            PluginLifecycle::Stopped => return Err(McpError::PluginUnmounted),
            _ => return Err(McpError::MountMissing),
        }
        if lifecycle.plugin_digest != *self.plugin_digest()
            || lifecycle.scope_digest != self.plugin.scope().digest()
            || lifecycle.receipt_digest.as_ref() != Some(self.receipt.digest())
        {
            return Err(McpError::MountMissing);
        }
        let inspection = runtime.inspect(self.plugin.scope());
        if inspection.scope_digest != self.plugin.scope().digest()
            || inspection.generation != self.plugin.scope().generation()
            || !inspection.plugins.iter().any(|plugin| {
                plugin.plugin_digest == *self.plugin_digest()
                    && plugin.receipt_digest == *self.receipt.digest()
                    && plugin.version == self.plugin.definition.version()
            })
        {
            return Err(McpError::MountMissing);
        }
        self.validate_contributions(&inspection)
    }

    pub fn unmount(&self, runtime: &mut PluginRuntime) -> Result<UnmountReceipt, McpError> {
        self.validate_runtime(runtime)?;
        runtime.unmount(&self.receipt).map_err(McpError::from)
    }

    pub fn revoke(
        &self,
        runtime: &mut PluginRuntime,
    ) -> Result<super::RevocationReceipt, McpError> {
        self.validate_runtime(runtime)?;
        runtime.revoke(&self.handle).map_err(McpError::from)
    }

    fn validate_contributions(
        &self,
        inspection: &super::RuntimeInspection,
    ) -> Result<(), McpError> {
        let definition = self.plugin.definition();
        let service = definition
            .contributions()
            .services
            .first()
            .ok_or(McpError::MountMissing)?;
        let provider = definition
            .contributions()
            .providers
            .first()
            .ok_or(McpError::MountMissing)?;
        let consumer = definition
            .contributions()
            .consumers
            .first()
            .ok_or(McpError::MountMissing)?;
        let service_ok = inspection.services.iter().any(|candidate| {
            candidate.service_id_digest == Digest::from_text(service.id().as_str())
                && candidate.owner_plugin_digest == *self.plugin_digest()
                && candidate.version == service.version()
                && candidate.access == ServiceAccess::ReadOnly
                && candidate.contract_digest == *service.contract_digest()
        });
        let provider_ok = inspection.providers.iter().any(|candidate| {
            candidate.provider_id_digest == Digest::from_text(provider.id().as_str())
                && candidate.service_id_digest == Digest::from_text(provider.service_id().as_str())
                && candidate.owner_plugin_digest == *self.plugin_digest()
                && candidate.version == provider.version()
                && candidate.implementation_digest == *provider.implementation_digest()
        });
        let consumer_ok = inspection.consumers.iter().any(|candidate| {
            candidate.consumer_id_digest == Digest::from_text(consumer.id().as_str())
                && candidate.service_id_digest == Digest::from_text(consumer.service_id().as_str())
                && candidate.owner_plugin_digest == *self.plugin_digest()
                && candidate.kind == ConsumerKind::Tool
                && candidate.required_version == consumer.required_version()
                && candidate.descriptor_digest == *consumer.descriptor_digest()
        });
        if service_ok && provider_ok && consumer_ok {
            Ok(())
        } else {
            Err(McpError::MountMissing)
        }
    }
}

impl fmt::Debug for McpToolMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolMount")
            .field("plugin_digest", &self.plugin_digest())
            .field("scope_digest", &self.plugin.scope().digest())
            .field("receipt_digest", &self.receipt.digest())
            .field("generation", &self.plugin.scope().generation())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpSessionBinding {
    session_digest: Digest,
    plugin_digest: Digest,
    receipt_digest: Digest,
    policy_digest: Digest,
    server_digest: Digest,
    server_version: PluginVersion,
    protocol_version: McpProtocolVersion,
    schema_digest: Digest,
    project_digest: Digest,
    mission_digest: Digest,
    scope_digest: Digest,
    generation: u64,
}

impl McpSessionBinding {
    fn new(
        mount: &McpToolMount,
        session_nonce: Digest,
        policy_digest: Digest,
    ) -> Result<Self, McpError> {
        validate_digest(&session_nonce)?;
        validate_digest(&policy_digest)?;
        let scope = mount.plugin.scope();
        let identity = mount.plugin.binding.identity();
        let session_digest = digest_serialized(&(
            MCP_SESSION_SCHEMA,
            mount.plugin_digest(),
            mount.receipt.digest(),
            &policy_digest,
            &scope.digest(),
            scope.generation(),
            session_nonce,
        ));
        let binding = Self {
            session_digest,
            plugin_digest: mount.plugin_digest().clone(),
            receipt_digest: mount.receipt.digest().clone(),
            policy_digest,
            server_digest: identity.server_digest().clone(),
            server_version: identity.version(),
            protocol_version: identity.protocol_version().clone(),
            schema_digest: identity.schema_digest().clone(),
            project_digest: digest_serialized(scope.project_id()),
            mission_digest: digest_serialized(scope.mission_id()),
            scope_digest: scope.digest(),
            generation: scope.generation(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn session_digest(&self) -> &Digest {
        &self.session_digest
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn receipt_digest(&self) -> &Digest {
        &self.receipt_digest
    }

    pub fn policy_digest(&self) -> &Digest {
        &self.policy_digest
    }

    pub fn server_digest(&self) -> &Digest {
        &self.server_digest
    }

    pub const fn server_version(&self) -> PluginVersion {
        self.server_version
    }

    pub fn protocol_version(&self) -> &McpProtocolVersion {
        &self.protocol_version
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub fn project_digest(&self) -> &Digest {
        &self.project_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn validate(&self) -> Result<(), McpError> {
        for digest in [
            &self.session_digest,
            &self.plugin_digest,
            &self.receipt_digest,
            &self.policy_digest,
            &self.server_digest,
            &self.schema_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.scope_digest,
        ] {
            validate_digest(digest)?;
        }
        if self.generation == 0 {
            return Err(McpError::GenerationMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for McpSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpSessionBinding")
            .field("session_digest", &self.session_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("receipt_digest", &self.receipt_digest)
            .field("policy_digest", &self.policy_digest)
            .field("server_digest", &self.server_digest)
            .field("server_version", &self.server_version)
            .field("protocol_version", &self.protocol_version)
            .field("schema_digest", &self.schema_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpMissionContext {
    scope: PluginScope,
}

impl McpMissionContext {
    pub fn new(scope: PluginScope) -> Result<Self, McpError> {
        scope.validate().map_err(McpError::from)?;
        Ok(Self { scope })
    }

    pub fn scope(&self) -> &PluginScope {
        &self.scope
    }

    pub fn digest(&self) -> Digest {
        self.scope.digest()
    }
}

impl fmt::Debug for McpMissionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpMissionContext")
            .field("scope_digest", &self.scope.digest())
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(untagged)]
pub enum McpRequestId {
    Number(u64),
    Text(String),
}

impl McpRequestId {
    pub const fn number(value: u64) -> Self {
        Self::Number(value)
    }

    pub fn text(value: impl Into<String>) -> Result<Self, McpError> {
        let value = value.into();
        validate_text(&value, 128)?;
        Ok(Self::Text(value))
    }

    fn validate(&self) -> Result<(), McpError> {
        if matches!(self, Self::Number(0)) {
            return Err(McpError::InvalidText);
        }
        if let Self::Text(value) = self {
            validate_text(value, 128)?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(self)
    }
}

impl fmt::Debug for McpRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRequestId")
            .field("digest", &self.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMethod {
    Initialize,
    Initialized,
    ToolsList,
    ResourcesList,
    ToolsCall,
    Cancel,
}

impl McpMethod {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::Initialized => "notifications/initialized",
            Self::ToolsList => "tools/list",
            Self::ResourcesList => "resources/list",
            Self::ToolsCall => "tools/call",
            Self::Cancel => "notifications/cancelled",
        }
    }

    fn parse(value: &str) -> Result<Self, McpError> {
        match value {
            "initialize" => Ok(Self::Initialize),
            "notifications/initialized" => Ok(Self::Initialized),
            "tools/list" => Ok(Self::ToolsList),
            "resources/list" => Ok(Self::ResourcesList),
            "tools/call" => Ok(Self::ToolsCall),
            "notifications/cancelled" => Ok(Self::Cancel),
            _ => Err(McpError::UnknownMethod),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportErrorCode {
    Io,
    MalformedFrame,
    Closed,
    ServerCrashed,
    Timeout,
    UnknownMethod,
    LateResponse,
    DuplicateResponse,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpTransportError {
    #[error("MCP stdio I/O failed")]
    Io,
    #[error("MCP stdio frame is malformed")]
    MalformedFrame,
    #[error("MCP stdio channel is closed")]
    Closed,
    #[error("MCP server crashed")]
    ServerCrashed,
    #[error("MCP stdio request timed out")]
    Timeout,
    #[error("MCP server sent an unknown method")]
    UnknownMethod,
    #[error("MCP response arrived for a different request")]
    LateResponse,
    #[error("MCP server sent a duplicate response")]
    DuplicateResponse,
}

impl McpTransportError {
    pub const fn code(self) -> McpTransportErrorCode {
        match self {
            Self::Io => McpTransportErrorCode::Io,
            Self::MalformedFrame => McpTransportErrorCode::MalformedFrame,
            Self::Closed => McpTransportErrorCode::Closed,
            Self::ServerCrashed => McpTransportErrorCode::ServerCrashed,
            Self::Timeout => McpTransportErrorCode::Timeout,
            Self::UnknownMethod => McpTransportErrorCode::UnknownMethod,
            Self::LateResponse => McpTransportErrorCode::LateResponse,
            Self::DuplicateResponse => McpTransportErrorCode::DuplicateResponse,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpJsonRpcRequest {
    jsonrpc: String,
    id: McpRequestId,
    method: McpMethod,
    params: McpJson,
}

impl McpJsonRpcRequest {
    fn new(id: McpRequestId, method: McpMethod, params: McpJson) -> Result<Self, McpError> {
        id.validate()?;
        let request = Self {
            jsonrpc: "2.0".into(),
            id,
            method,
            params,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn initialize(
        id: McpRequestId,
        protocol_version: &McpProtocolVersion,
        client_name: &McpText,
        client_version: PluginVersion,
    ) -> Result<Self, McpError> {
        Self::new(
            id,
            McpMethod::Initialize,
            McpJson::from_value(json!({
                "protocolVersion": protocol_version.as_str(),
                "capabilities": {},
                "clientInfo": {
                    "name": client_name.as_str(),
                    "version": format!("{}.{}.{}", client_version.major(), client_version.minor(), client_version.patch()),
                }
            }))?,
        )
    }

    pub fn tools_list(id: McpRequestId) -> Result<Self, McpError> {
        Self::new(id, McpMethod::ToolsList, McpJson::from_value(json!({}))?)
    }

    pub fn resources_list(id: McpRequestId) -> Result<Self, McpError> {
        Self::new(
            id,
            McpMethod::ResourcesList,
            McpJson::from_value(json!({}))?,
        )
    }

    pub fn tools_call(
        id: McpRequestId,
        tool: &McpToolName,
        arguments: &McpJson,
    ) -> Result<Self, McpError> {
        if arguments.kind() != McpJsonKind::Object {
            return Err(McpError::InvalidToolInput);
        }
        Self::new(
            id,
            McpMethod::ToolsCall,
            McpJson::from_value(json!({
                "name": tool.as_str(),
                "arguments": arguments.value(),
            }))?,
        )
    }

    pub fn id(&self) -> &McpRequestId {
        &self.id
    }

    pub const fn method(&self) -> McpMethod {
        self.method
    }

    pub fn params(&self) -> &McpJson {
        &self.params
    }

    fn validate(&self) -> Result<(), McpError> {
        if self.jsonrpc != "2.0" {
            return Err(McpError::InvalidSchema);
        }
        self.id.validate()
    }

    fn to_wire(&self) -> Value {
        json!({
            "jsonrpc": self.jsonrpc,
            "id": self.id,
            "method": self.method.wire_name(),
            "params": self.params.value(),
        })
    }
}

impl fmt::Debug for McpJsonRpcRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpJsonRpcRequest")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params_digest", &self.params.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpJsonRpcNotification {
    jsonrpc: String,
    method: McpMethod,
    params: McpJson,
}

impl fmt::Debug for McpJsonRpcNotification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpJsonRpcNotification")
            .field("method", &self.method)
            .field("params_digest", &self.params.digest())
            .finish_non_exhaustive()
    }
}

impl McpJsonRpcNotification {
    fn cancelled(request_id: &McpRequestId) -> Result<Self, McpError> {
        Ok(Self {
            jsonrpc: "2.0".into(),
            method: McpMethod::Cancel,
            params: McpJson::from_value(json!({
                "requestId": request_id,
                "reason": "mission-cancellation",
            }))?,
        })
    }

    fn to_wire(&self) -> Value {
        json!({
            "jsonrpc": self.jsonrpc,
            "method": self.method.wire_name(),
            "params": self.params.value(),
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpRemoteError {
    pub code: i64,
    pub message_digest: Digest,
    pub data_digest: Option<Digest>,
}

impl McpRemoteError {
    fn from_wire(value: &Value) -> Result<Self, McpError> {
        let object = value.as_object().ok_or(McpError::InvalidSchema)?;
        let code = object
            .get("code")
            .and_then(Value::as_i64)
            .ok_or(McpError::InvalidSchema)?;
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .ok_or(McpError::InvalidSchema)?;
        let message_digest = digest_serialized(&message);
        let data_digest = object.get("data").map(digest_serialized);
        Ok(Self {
            code,
            message_digest,
            data_digest,
        })
    }

    fn validate(&self) -> Result<(), McpError> {
        validate_digest(&self.message_digest)?;
        if let Some(data_digest) = &self.data_digest {
            validate_digest(data_digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for McpRemoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRemoteError")
            .field("code", &self.code)
            .field("message_digest", &self.message_digest)
            .field("data_digest", &self.data_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpJsonRpcResponse {
    jsonrpc: String,
    id: McpRequestId,
    result: Option<McpJson>,
    error: Option<McpRemoteError>,
}

impl McpJsonRpcResponse {
    pub fn success(id: McpRequestId, result: McpJson) -> Result<Self, McpError> {
        id.validate()?;
        Ok(Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        })
    }

    pub fn id(&self) -> &McpRequestId {
        &self.id
    }

    pub fn result(&self) -> Result<&McpJson, McpError> {
        if let Some(error) = &self.error {
            error.validate()?;
            return Err(McpError::RemoteError);
        }
        self.result.as_ref().ok_or(McpError::InvalidSchema)
    }

    fn from_wire(value: &Value) -> Result<Self, McpError> {
        let object = value.as_object().ok_or(McpError::InvalidSchema)?;
        if object.contains_key("method") {
            let method = object
                .get("method")
                .and_then(Value::as_str)
                .ok_or(McpError::InvalidSchema)?;
            McpMethod::parse(method)?;
            return Err(McpError::LateResponse);
        }
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(McpError::InvalidSchema);
        }
        let id_value = object.get("id").ok_or(McpError::InvalidSchema)?.clone();
        let id: McpRequestId =
            serde_json::from_value(id_value).map_err(|_| McpError::InvalidSchema)?;
        id.validate()?;
        let result = object
            .get("result")
            .cloned()
            .map(McpJson::from_value)
            .transpose()?;
        let error = object
            .get("error")
            .map(McpRemoteError::from_wire)
            .transpose()?;
        if result.is_some() == error.is_some() {
            return Err(McpError::InvalidSchema);
        }
        Ok(Self {
            jsonrpc: "2.0".into(),
            id,
            result,
            error,
        })
    }
}

impl fmt::Debug for McpJsonRpcResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpJsonRpcResponse")
            .field("id", &self.id)
            .field("result_digest", &self.result.as_ref().map(McpJson::digest))
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

pub trait McpStdioChannel {
    fn write_frame(&mut self, frame: &str) -> Result<(), McpTransportError>;
    fn read_frame(&mut self, timeout: McpTimeout) -> Result<String, McpTransportError>;
}

pub trait McpStdioHostAdapter {
    fn exchange(
        &mut self,
        request: &McpJsonRpcRequest,
        timeout: McpTimeout,
    ) -> Result<McpJsonRpcResponse, McpTransportError>;

    fn notify(
        &mut self,
        notification: &McpJsonRpcNotification,
        timeout: McpTimeout,
    ) -> Result<(), McpTransportError>;
}

pub struct McpStdioJsonRpcHostAdapter<C> {
    channel: C,
}

impl<C> fmt::Debug for McpStdioJsonRpcHostAdapter<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpStdioJsonRpcHostAdapter")
            .field("channel_type", &std::any::type_name::<C>())
            .finish_non_exhaustive()
    }
}

impl<C> McpStdioJsonRpcHostAdapter<C> {
    pub const fn new(channel: C) -> Self {
        Self { channel }
    }

    pub fn channel(&self) -> &C {
        &self.channel
    }

    pub fn channel_mut(&mut self) -> &mut C {
        &mut self.channel
    }

    pub fn into_channel(self) -> C {
        self.channel
    }
}

impl<C: McpStdioChannel> McpStdioHostAdapter for McpStdioJsonRpcHostAdapter<C> {
    fn exchange(
        &mut self,
        request: &McpJsonRpcRequest,
        timeout: McpTimeout,
    ) -> Result<McpJsonRpcResponse, McpTransportError> {
        let frame = serde_json::to_string(&request.to_wire())
            .map_err(|_| McpTransportError::MalformedFrame)?;
        self.channel.write_frame(&frame)?;
        let response = self.channel.read_frame(timeout)?;
        let value: Value =
            serde_json::from_str(&response).map_err(|_| McpTransportError::MalformedFrame)?;
        let response = McpJsonRpcResponse::from_wire(&value).map_err(|error| match error {
            McpError::UnknownMethod => McpTransportError::UnknownMethod,
            McpError::LateResponse => McpTransportError::LateResponse,
            _ => McpTransportError::MalformedFrame,
        })?;
        if response.id() != request.id() {
            return Err(McpTransportError::LateResponse);
        }
        Ok(response)
    }

    fn notify(
        &mut self,
        notification: &McpJsonRpcNotification,
        _timeout: McpTimeout,
    ) -> Result<(), McpTransportError> {
        let frame = serde_json::to_string(&notification.to_wire())
            .map_err(|_| McpTransportError::MalformedFrame)?;
        self.channel.write_frame(&frame)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolDefinition {
    server_digest: Digest,
    server_version: PluginVersion,
    name: McpToolName,
    version: PluginVersion,
    schema_digest: Digest,
    input_schema: McpJson,
    description: Option<McpText>,
    effect_class: McpToolEffectClass,
    definition_digest: Digest,
}

impl McpToolDefinition {
    pub fn new(
        binding: &McpServerBinding,
        name: McpToolName,
        input_schema: McpJson,
        description: Option<McpText>,
        effect_class: McpToolEffectClass,
    ) -> Result<Self, McpError> {
        if input_schema.kind() != McpJsonKind::Object {
            return Err(McpError::InvalidSchema);
        }
        let schema_digest = input_schema.digest();
        let mut definition = Self {
            server_digest: binding.identity().server_digest().clone(),
            server_version: binding.identity().version(),
            name,
            version: binding.identity().version(),
            schema_digest,
            input_schema,
            description,
            effect_class,
            definition_digest: Digest::from_text("pending-mcp-tool-definition"),
        };
        definition.definition_digest = definition.computed_digest();
        definition.validate(binding)?;
        Ok(definition)
    }

    pub fn name(&self) -> &McpToolName {
        &self.name
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    pub fn input_schema(&self) -> &McpJson {
        &self.input_schema
    }

    pub fn description(&self) -> Option<&McpText> {
        self.description.as_ref()
    }

    pub const fn effect_class(&self) -> McpToolEffectClass {
        self.effect_class
    }

    pub fn definition_digest(&self) -> &Digest {
        &self.definition_digest
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            MCP_PROTOCOL_SCHEMA,
            &self.server_digest,
            self.server_version,
            &self.name,
            self.version,
            &self.schema_digest,
            &self.description.as_ref().map(McpText::as_str),
            self.effect_class,
        ))
    }

    fn validate(&self, binding: &McpServerBinding) -> Result<(), McpError> {
        if self.server_digest != *binding.identity().server_digest()
            || self.server_version != binding.identity().version()
            || self.version != binding.identity().version()
            || self.schema_digest != self.input_schema.digest()
            || self.input_schema.kind() != McpJsonKind::Object
            || self.definition_digest != self.computed_digest()
        {
            return Err(McpError::SchemaDrift);
        }
        validate_digest(&self.server_digest)?;
        validate_digest(&self.schema_digest)
    }
}

impl fmt::Debug for McpToolDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolDefinition")
            .field("definition_digest", &self.definition_digest)
            .field("server_digest", &self.server_digest)
            .field("server_version", &self.server_version)
            .field("name_digest", &digest_serialized(&self.name))
            .field("version", &self.version)
            .field("schema_digest", &self.schema_digest)
            .field(
                "description_digest",
                &self
                    .description
                    .as_ref()
                    .map(|v| digest_serialized(v.as_str())),
            )
            .field("effect_class", &self.effect_class)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolInput {
    definition_digest: Digest,
    schema_digest: Digest,
    value: McpJson,
}

impl McpToolInput {
    pub fn for_definition(
        definition: &McpToolDefinition,
        value: McpJson,
    ) -> Result<Self, McpError> {
        if value.kind() != McpJsonKind::Object {
            return Err(McpError::InvalidToolInput);
        }
        let input = Self {
            definition_digest: definition.definition_digest().clone(),
            schema_digest: definition.schema_digest().clone(),
            value,
        };
        input.validate(definition)?;
        Ok(input)
    }

    pub fn value(&self) -> &McpJson {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        digest_serialized(&(&self.definition_digest, &self.schema_digest, &self.value))
    }

    pub fn definition_digest(&self) -> &Digest {
        &self.definition_digest
    }

    fn validate(&self, definition: &McpToolDefinition) -> Result<(), McpError> {
        if self.definition_digest != *definition.definition_digest()
            || self.schema_digest != *definition.schema_digest()
            || self.value.kind() != McpJsonKind::Object
        {
            return Err(McpError::InvalidToolInput);
        }
        Ok(())
    }
}

impl fmt::Debug for McpToolInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolInput")
            .field("definition_digest", &self.definition_digest)
            .field("schema_digest", &self.schema_digest)
            .field("input_digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpResourceDefinition {
    server_digest: Digest,
    server_version: PluginVersion,
    uri: McpResourceUri,
    name: McpText,
    mime_type: Option<McpText>,
    version: PluginVersion,
    schema_digest: Digest,
    definition_digest: Digest,
}

impl McpResourceDefinition {
    pub fn new(
        binding: &McpServerBinding,
        uri: McpResourceUri,
        name: McpText,
        mime_type: Option<McpText>,
    ) -> Result<Self, McpError> {
        let schema_digest = digest_serialized(&(&uri, &name, &mime_type));
        let mut definition = Self {
            server_digest: binding.identity().server_digest().clone(),
            server_version: binding.identity().version(),
            uri,
            name,
            mime_type,
            version: binding.identity().version(),
            schema_digest,
            definition_digest: Digest::from_text("pending-mcp-resource-definition"),
        };
        definition.definition_digest = definition.computed_digest();
        definition.validate(binding)?;
        Ok(definition)
    }

    pub fn uri(&self) -> &McpResourceUri {
        &self.uri
    }

    pub fn name(&self) -> &McpText {
        &self.name
    }

    pub fn definition_digest(&self) -> &Digest {
        &self.definition_digest
    }

    pub fn schema_digest(&self) -> &Digest {
        &self.schema_digest
    }

    fn computed_digest(&self) -> Digest {
        digest_serialized(&(
            MCP_PROTOCOL_SCHEMA,
            &self.server_digest,
            self.server_version,
            &self.uri,
            &self.name,
            &self.mime_type.as_ref().map(McpText::as_str),
            self.version,
            &self.schema_digest,
        ))
    }

    fn validate(&self, binding: &McpServerBinding) -> Result<(), McpError> {
        if self.server_digest != *binding.identity().server_digest()
            || self.server_version != binding.identity().version()
            || self.version != binding.identity().version()
            || self.schema_digest != digest_serialized(&(&self.uri, &self.name, &self.mime_type))
            || self.definition_digest != self.computed_digest()
        {
            return Err(McpError::SchemaDrift);
        }
        validate_digest(&self.definition_digest)
    }
}

impl fmt::Debug for McpResourceDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpResourceDefinition")
            .field("definition_digest", &self.definition_digest)
            .field("server_digest", &self.server_digest)
            .field("server_version", &self.server_version)
            .field("uri_digest", &digest_serialized(&self.uri))
            .field("name_digest", &digest_serialized(&self.name))
            .field("version", &self.version)
            .field("schema_digest", &self.schema_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpEffectProposal {
    schema: String,
    proposal_digest: Digest,
    session_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    tool_definition_digest: Digest,
    input_digest: Digest,
    result_digest: Digest,
}

impl McpEffectProposal {
    fn new(
        binding: &McpSessionBinding,
        tool_definition_digest: &Digest,
        input_digest: Digest,
        result_digest: Digest,
    ) -> Result<Self, McpError> {
        let mut proposal = Self {
            schema: MCP_RESULT_SCHEMA.into(),
            proposal_digest: Digest::from_text("pending-mcp-effect-proposal"),
            session_digest: binding.session_digest().clone(),
            scope_digest: binding.scope_digest().clone(),
            generation: binding.generation(),
            tool_definition_digest: tool_definition_digest.clone(),
            input_digest,
            result_digest,
        };
        proposal.proposal_digest = digest_serialized(&(
            &proposal.schema,
            &proposal.session_digest,
            &proposal.scope_digest,
            proposal.generation,
            &proposal.tool_definition_digest,
            &proposal.input_digest,
            &proposal.result_digest,
        ));
        proposal.validate()?;
        Ok(proposal)
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    fn validate(&self) -> Result<(), McpError> {
        if self.schema != MCP_RESULT_SCHEMA || self.generation == 0 {
            return Err(McpError::EffectProposalInvalid);
        }
        for digest in [
            &self.proposal_digest,
            &self.session_digest,
            &self.scope_digest,
            &self.tool_definition_digest,
            &self.input_digest,
            &self.result_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

impl fmt::Debug for McpEffectProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpEffectProposal")
            .field("schema", &self.schema)
            .field("proposal_digest", &self.proposal_digest)
            .field("session_digest", &self.session_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("tool_definition_digest", &self.tool_definition_digest)
            .field("input_digest", &self.input_digest)
            .field("result_digest", &self.result_digest)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpToolResult {
    schema: String,
    session_digest: Digest,
    policy_digest: Digest,
    server_digest: Digest,
    server_version: PluginVersion,
    scope_digest: Digest,
    generation: u64,
    tool_definition_digest: Digest,
    tool_name_digest: Digest,
    request_id_digest: Digest,
    input_digest: Digest,
    result_digest: Digest,
    output: McpJson,
    is_error: bool,
    effect_proposal: Option<McpEffectProposal>,
}

impl McpToolResult {
    fn from_response(
        binding: &McpSessionBinding,
        definition: &McpToolDefinition,
        request_id: &McpRequestId,
        input: &McpToolInput,
        output: McpJson,
        is_error: bool,
    ) -> Result<Self, McpError> {
        let input_digest = input.digest();
        let result_digest = digest_serialized(&(MCP_RESULT_SCHEMA, &output, is_error));
        let effect_proposal = match definition.effect_class() {
            McpToolEffectClass::ReadOnly => None,
            McpToolEffectClass::ExternalEffect => Some(McpEffectProposal::new(
                binding,
                definition.definition_digest(),
                input_digest.clone(),
                result_digest.clone(),
            )?),
        };
        let result = Self {
            schema: MCP_RESULT_SCHEMA.into(),
            session_digest: binding.session_digest().clone(),
            policy_digest: binding.policy_digest().clone(),
            server_digest: binding.server_digest().clone(),
            server_version: binding.server_version(),
            scope_digest: binding.scope_digest().clone(),
            generation: binding.generation(),
            tool_definition_digest: definition.definition_digest().clone(),
            tool_name_digest: digest_serialized(definition.name()),
            request_id_digest: request_id.digest(),
            input_digest,
            result_digest,
            output,
            is_error,
            effect_proposal,
        };
        result.validate(binding, definition)
    }

    pub fn output(&self) -> &McpJson {
        &self.output
    }

    pub fn result_digest(&self) -> &Digest {
        &self.result_digest
    }

    pub fn effect_proposal(&self) -> Option<&McpEffectProposal> {
        self.effect_proposal.as_ref()
    }

    fn validate(
        &self,
        binding: &McpSessionBinding,
        definition: &McpToolDefinition,
    ) -> Result<Self, McpError> {
        if self.schema != MCP_RESULT_SCHEMA
            || self.session_digest != *binding.session_digest()
            || self.policy_digest != *binding.policy_digest()
            || self.server_digest != *binding.server_digest()
            || self.server_version != binding.server_version()
            || self.scope_digest != *binding.scope_digest()
            || self.generation != binding.generation()
            || self.tool_definition_digest != *definition.definition_digest()
            || self.tool_name_digest != digest_serialized(definition.name())
            || self.result_digest
                != digest_serialized(&(MCP_RESULT_SCHEMA, &self.output, self.is_error))
        {
            return Err(McpError::InvalidToolResult);
        }
        if let Some(proposal) = &self.effect_proposal {
            proposal.validate()?;
        }
        match definition.effect_class() {
            McpToolEffectClass::ReadOnly if self.effect_proposal.is_some() => {
                Err(McpError::EffectProposalInvalid)
            }
            McpToolEffectClass::ExternalEffect if self.effect_proposal.is_none() => {
                Err(McpError::EffectProposalInvalid)
            }
            _ => Ok(self.clone()),
        }
    }
}

impl fmt::Debug for McpToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolResult")
            .field("result_digest", &self.result_digest)
            .field("session_digest", &self.session_digest)
            .field("policy_digest", &self.policy_digest)
            .field("server_digest", &self.server_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("tool_definition_digest", &self.tool_definition_digest)
            .field("tool_name_digest", &self.tool_name_digest)
            .field("request_id_digest", &self.request_id_digest)
            .field("input_digest", &self.input_digest)
            .field("is_error", &self.is_error)
            .field("effect_proposal", &self.effect_proposal)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpInvocationStatus {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInvocationReceipt {
    schema: String,
    status: McpInvocationStatus,
    session_digest: Digest,
    policy_digest: Digest,
    server_digest: Digest,
    server_version: PluginVersion,
    project_digest: Digest,
    mission_digest: Digest,
    scope_digest: Digest,
    generation: u64,
    request_id_digest: Digest,
    invocation_digest: Digest,
    tool_definition_digest: Digest,
    input_digest: Digest,
    result_digest: Option<Digest>,
    audit_event_digest: Digest,
    effect_proposal_digest: Option<Digest>,
}

impl McpInvocationReceipt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        binding: &McpSessionBinding,
        status: McpInvocationStatus,
        request_id: &McpRequestId,
        tool_definition_digest: Digest,
        input_digest: Digest,
        result_digest: Option<Digest>,
        audit_event_digest: Digest,
        effect_proposal_digest: Option<Digest>,
    ) -> Result<Self, McpError> {
        let invocation_digest = digest_serialized(&(
            MCP_RECEIPT_SCHEMA,
            status,
            binding.session_digest(),
            binding.policy_digest(),
            binding.server_digest(),
            binding.server_version(),
            binding.project_digest(),
            binding.mission_digest(),
            binding.scope_digest(),
            binding.generation(),
            request_id.digest(),
            &tool_definition_digest,
            &input_digest,
            &result_digest,
            &audit_event_digest,
            &effect_proposal_digest,
        ));
        let receipt = Self {
            schema: MCP_RECEIPT_SCHEMA.into(),
            status,
            session_digest: binding.session_digest().clone(),
            policy_digest: binding.policy_digest().clone(),
            server_digest: binding.server_digest().clone(),
            server_version: binding.server_version(),
            project_digest: binding.project_digest().clone(),
            mission_digest: binding.mission_digest().clone(),
            scope_digest: binding.scope_digest().clone(),
            generation: binding.generation(),
            request_id_digest: request_id.digest(),
            invocation_digest,
            tool_definition_digest,
            input_digest,
            result_digest,
            audit_event_digest,
            effect_proposal_digest,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn invocation_digest(&self) -> &Digest {
        &self.invocation_digest
    }

    pub fn result_digest(&self) -> Option<&Digest> {
        self.result_digest.as_ref()
    }

    pub fn status(&self) -> McpInvocationStatus {
        self.status
    }

    pub fn validate(&self) -> Result<(), McpError> {
        if self.schema != MCP_RECEIPT_SCHEMA || self.generation == 0 {
            return Err(McpError::ReceiptInvalid);
        }
        for digest in [
            &self.session_digest,
            &self.policy_digest,
            &self.server_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.scope_digest,
            &self.request_id_digest,
            &self.invocation_digest,
            &self.tool_definition_digest,
            &self.input_digest,
            &self.audit_event_digest,
        ]
        .into_iter()
        .chain(self.result_digest.iter())
        .chain(self.effect_proposal_digest.iter())
        {
            validate_digest(digest)?;
        }
        if self.invocation_digest
            != digest_serialized(&(
                MCP_RECEIPT_SCHEMA,
                self.status,
                &self.session_digest,
                &self.policy_digest,
                &self.server_digest,
                self.server_version,
                &self.project_digest,
                &self.mission_digest,
                &self.scope_digest,
                self.generation,
                &self.request_id_digest,
                &self.tool_definition_digest,
                &self.input_digest,
                &self.result_digest,
                &self.audit_event_digest,
                &self.effect_proposal_digest,
            ))
        {
            return Err(McpError::ReceiptInvalid);
        }
        Ok(())
    }
}

impl fmt::Debug for McpInvocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpInvocationReceipt")
            .field("schema", &self.schema)
            .field("invocation_digest", &self.invocation_digest)
            .field("status", &self.status)
            .field("session_digest", &self.session_digest)
            .field("policy_digest", &self.policy_digest)
            .field("server_digest", &self.server_digest)
            .field("server_version", &self.server_version)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("request_id_digest", &self.request_id_digest)
            .field("tool_definition_digest", &self.tool_definition_digest)
            .field("input_digest", &self.input_digest)
            .field("result_digest", &self.result_digest)
            .field("audit_event_digest", &self.audit_event_digest)
            .field("effect_proposal_digest", &self.effect_proposal_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpInvocationOutcome {
    pub result: McpToolResult,
    pub receipt: McpInvocationReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpCancellationReceipt {
    pub schema: String,
    pub session_digest: Digest,
    pub policy_digest: Digest,
    pub request_id_digest: Digest,
    pub audit_event_digest: Digest,
}

impl McpCancellationReceipt {
    pub fn validate(&self) -> Result<(), McpError> {
        if self.schema != MCP_RECEIPT_SCHEMA {
            return Err(McpError::ReceiptInvalid);
        }
        for digest in [
            &self.session_digest,
            &self.policy_digest,
            &self.request_id_digest,
            &self.audit_event_digest,
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpAuditEventKind {
    SessionBound,
    Initialized,
    CapabilitiesDiscovered,
    ToolDefinitionVisible,
    ResourceDefinitionVisible,
    InvocationStarted,
    InvocationCompleted,
    InvocationFailed,
    CancellationRequested,
    Revoked,
    Unmounted,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpAuditLogError {
    #[error("MCP audit log is unavailable")]
    Unavailable,
    #[error("MCP audit log rejected an event")]
    Rejected,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpAuditEntry {
    pub schema: String,
    pub event_digest: Digest,
    pub kind: McpAuditEventKind,
    pub session_digest: Digest,
    pub plugin_digest: Digest,
    pub receipt_digest: Digest,
    pub policy_digest: Digest,
    pub server_digest: Digest,
    pub server_version: PluginVersion,
    pub protocol_digest: Digest,
    pub schema_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub scope_digest: Digest,
    pub generation: u64,
    pub request_id_digest: Option<Digest>,
    pub method: McpMethod,
    pub tool_definition_digest: Option<Digest>,
    pub tool_name_digest: Option<Digest>,
    pub resource_definition_digest: Option<Digest>,
    pub resource_uri_digest: Option<Digest>,
    pub input_digest: Option<Digest>,
    pub result_digest: Option<Digest>,
    pub effect_proposal_digest: Option<Digest>,
    pub error_code: Option<McpErrorCode>,
    pub model_visible: bool,
    pub observed_at: u64,
}

impl McpAuditEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        binding: &McpSessionBinding,
        kind: McpAuditEventKind,
        request_id: Option<&McpRequestId>,
        method: McpMethod,
        tool_definition_digest: Option<Digest>,
        tool_name_digest: Option<Digest>,
        resource_definition_digest: Option<Digest>,
        resource_uri_digest: Option<Digest>,
        input_digest: Option<Digest>,
        result_digest: Option<Digest>,
        effect_proposal_digest: Option<Digest>,
        error_code: Option<McpErrorCode>,
        model_visible: bool,
        observed_at: u64,
    ) -> Result<Self, McpError> {
        let mut entry = Self {
            schema: MCP_AUDIT_SCHEMA.into(),
            event_digest: Digest::from_text("pending-mcp-audit-event"),
            kind,
            session_digest: binding.session_digest().clone(),
            plugin_digest: binding.plugin_digest().clone(),
            receipt_digest: binding.receipt_digest().clone(),
            policy_digest: binding.policy_digest().clone(),
            server_digest: binding.server_digest().clone(),
            server_version: binding.server_version(),
            protocol_digest: digest_serialized(binding.protocol_version()),
            schema_digest: binding.schema_digest().clone(),
            project_digest: binding.project_digest().clone(),
            mission_digest: binding.mission_digest().clone(),
            scope_digest: binding.scope_digest().clone(),
            generation: binding.generation(),
            request_id_digest: request_id.map(McpRequestId::digest),
            method,
            tool_definition_digest,
            tool_name_digest,
            resource_definition_digest,
            resource_uri_digest,
            input_digest,
            result_digest,
            effect_proposal_digest,
            error_code,
            model_visible,
            observed_at,
        };
        entry.validate_without_event_digest()?;
        entry.event_digest = entry.canonical_digest();
        Ok(entry)
    }

    fn canonical_digest(&self) -> Digest {
        digest_serialized(&(
            (
                &self.schema,
                self.kind,
                &self.session_digest,
                &self.plugin_digest,
                &self.receipt_digest,
                &self.policy_digest,
                &self.server_digest,
                self.server_version,
                &self.protocol_digest,
            ),
            (
                &self.schema_digest,
                &self.project_digest,
                &self.mission_digest,
                &self.scope_digest,
                self.generation,
                &self.request_id_digest,
                self.method,
                &self.tool_definition_digest,
            ),
            (
                &self.tool_name_digest,
                &self.resource_definition_digest,
                &self.resource_uri_digest,
                &self.input_digest,
                &self.result_digest,
                &self.effect_proposal_digest,
                &self.error_code,
                self.model_visible,
                self.observed_at,
            ),
        ))
    }

    fn validate_without_event_digest(&self) -> Result<(), McpError> {
        if self.schema != MCP_AUDIT_SCHEMA || self.generation == 0 {
            return Err(McpError::InvalidSchema);
        }
        for digest in [
            &self.session_digest,
            &self.plugin_digest,
            &self.receipt_digest,
            &self.policy_digest,
            &self.server_digest,
            &self.protocol_digest,
            &self.schema_digest,
            &self.project_digest,
            &self.mission_digest,
            &self.scope_digest,
        ]
        .into_iter()
        .chain(self.request_id_digest.iter())
        .chain(self.tool_definition_digest.iter())
        .chain(self.tool_name_digest.iter())
        .chain(self.resource_definition_digest.iter())
        .chain(self.resource_uri_digest.iter())
        .chain(self.input_digest.iter())
        .chain(self.result_digest.iter())
        .chain(self.effect_proposal_digest.iter())
        {
            validate_digest(digest)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), McpError> {
        self.validate_without_event_digest()?;
        if self.event_digest != self.canonical_digest() {
            return Err(McpError::InvalidSchema);
        }
        Ok(())
    }
}

impl fmt::Debug for McpAuditEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpAuditEntry")
            .field("event_digest", &self.event_digest)
            .field("kind", &self.kind)
            .field("session_digest", &self.session_digest)
            .field("plugin_digest", &self.plugin_digest)
            .field("receipt_digest", &self.receipt_digest)
            .field("policy_digest", &self.policy_digest)
            .field("server_digest", &self.server_digest)
            .field("server_version", &self.server_version)
            .field("protocol_digest", &self.protocol_digest)
            .field("schema_digest", &self.schema_digest)
            .field("project_digest", &self.project_digest)
            .field("mission_digest", &self.mission_digest)
            .field("scope_digest", &self.scope_digest)
            .field("generation", &self.generation)
            .field("request_id_digest", &self.request_id_digest)
            .field("method", &self.method)
            .field("tool_definition_digest", &self.tool_definition_digest)
            .field("tool_name_digest", &self.tool_name_digest)
            .field(
                "resource_definition_digest",
                &self.resource_definition_digest,
            )
            .field("resource_uri_digest", &self.resource_uri_digest)
            .field("input_digest", &self.input_digest)
            .field("result_digest", &self.result_digest)
            .field("effect_proposal_digest", &self.effect_proposal_digest)
            .field("error_code", &self.error_code)
            .field("model_visible", &self.model_visible)
            .field("observed_at", &self.observed_at)
            .finish_non_exhaustive()
    }
}

pub trait McpAuditLog {
    fn append(&mut self, entry: McpAuditEntry) -> Result<(), McpAuditLogError>;
}

#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryMcpAuditLog {
    entries: Vec<McpAuditEntry>,
}

impl MemoryMcpAuditLog {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[McpAuditEntry] {
        &self.entries
    }
}

impl fmt::Debug for MemoryMcpAuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryMcpAuditLog")
            .field("event_count", &self.entries.len())
            .field(
                "event_set_digest",
                &digest_serialized(
                    &self
                        .entries
                        .iter()
                        .map(|entry| &entry.event_digest)
                        .collect::<Vec<_>>(),
                ),
            )
            .finish_non_exhaustive()
    }
}

impl McpAuditLog for MemoryMcpAuditLog {
    fn append(&mut self, entry: McpAuditEntry) -> Result<(), McpAuditLogError> {
        entry.validate().map_err(|_| McpAuditLogError::Rejected)?;
        if self
            .entries
            .iter()
            .any(|existing| existing.event_digest == entry.event_digest)
        {
            return Err(McpAuditLogError::Rejected);
        }
        self.entries.push(entry);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSessionStatus {
    New,
    Initializing,
    Ready,
    Failed,
    TimedOut,
    Crashed,
    Revoked,
    Unmounted,
}

pub struct McpToolProvider<T> {
    mount: McpToolMount,
    binding: McpSessionBinding,
    policy: McpToolPolicy,
    transport: T,
    status: McpSessionStatus,
    capabilities: Option<McpCapabilities>,
    tools: BTreeMap<McpToolName, McpToolDefinition>,
    resources: BTreeMap<McpResourceUri, McpResourceDefinition>,
    used_request_ids: BTreeSet<McpRequestId>,
    pending_request_ids: BTreeSet<McpRequestId>,
    next_request_id: u64,
}

impl<T> McpToolProvider<T> {
    pub fn new(
        mount: McpToolMount,
        session_nonce: Digest,
        policy: McpToolPolicy,
        transport: T,
    ) -> Result<Self, McpError> {
        policy.validate()?;
        let binding =
            McpSessionBinding::new(&mount, session_nonce, policy.policy_digest().clone())?;
        Ok(Self {
            mount,
            binding,
            policy,
            transport,
            status: McpSessionStatus::New,
            capabilities: None,
            tools: BTreeMap::new(),
            resources: BTreeMap::new(),
            used_request_ids: BTreeSet::new(),
            pending_request_ids: BTreeSet::new(),
            next_request_id: 1,
        })
    }

    pub fn mount(&self) -> &McpToolMount {
        &self.mount
    }

    pub fn binding(&self) -> &McpSessionBinding {
        &self.binding
    }

    pub fn policy(&self) -> &McpToolPolicy {
        &self.policy
    }

    pub const fn status(&self) -> McpSessionStatus {
        self.status
    }

    pub fn capabilities(&self) -> Option<McpCapabilities> {
        self.capabilities
    }

    pub fn tools(&self) -> Vec<McpToolDefinition> {
        self.tools.values().cloned().collect()
    }

    pub fn resources(&self) -> Vec<McpResourceDefinition> {
        self.resources.values().cloned().collect()
    }

    pub fn validate_scope(&self, context: &McpMissionContext) -> Result<(), McpError> {
        if context.scope() != self.mount.plugin.scope()
            || context.scope().generation() != self.binding.generation()
        {
            return Err(McpError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn reserve_request_id(
        &mut self,
        context: &McpMissionContext,
    ) -> Result<McpRequestId, McpError> {
        self.validate_scope(context)?;
        if self.status != McpSessionStatus::Ready {
            return Err(McpError::SessionNotReady);
        }
        let id = McpRequestId::number(self.next_request_id);
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(McpError::DuplicateRequestId)?;
        self.used_request_ids.insert(id.clone());
        self.pending_request_ids.insert(id.clone());
        Ok(id)
    }

    fn ensure_ready(&mut self, runtime: &PluginRuntime) -> Result<(), McpError> {
        if let Err(error) = self.mount.validate_runtime(runtime) {
            self.status = match error {
                McpError::PluginRevoked => McpSessionStatus::Revoked,
                McpError::PluginUnmounted => McpSessionStatus::Unmounted,
                _ => McpSessionStatus::Failed,
            };
            return Err(error);
        }
        if self.status != McpSessionStatus::Ready {
            return Err(McpError::SessionNotReady);
        }
        Ok(())
    }

    fn ensure_new(&mut self, runtime: &PluginRuntime) -> Result<(), McpError> {
        if let Err(error) = self.mount.validate_runtime(runtime) {
            self.status = match error {
                McpError::PluginRevoked => McpSessionStatus::Revoked,
                McpError::PluginUnmounted => McpSessionStatus::Unmounted,
                _ => McpSessionStatus::Failed,
            };
            return Err(error);
        }
        match self.status {
            McpSessionStatus::New => Ok(()),
            McpSessionStatus::Initializing => Err(McpError::SessionNotReady),
            McpSessionStatus::Ready => Err(McpError::SessionAlreadyInitialized),
            McpSessionStatus::Revoked => Err(McpError::PluginRevoked),
            McpSessionStatus::Unmounted => Err(McpError::PluginUnmounted),
            McpSessionStatus::TimedOut | McpSessionStatus::Crashed | McpSessionStatus::Failed => {
                Err(McpError::SessionClosed)
            }
        }
    }

    fn fail<U>(&mut self, error: McpError) -> Result<U, McpError> {
        self.capabilities = None;
        self.tools.clear();
        self.resources.clear();
        self.pending_request_ids.clear();
        self.status = match error {
            McpError::Timeout => McpSessionStatus::TimedOut,
            McpError::ServerCrashed => McpSessionStatus::Crashed,
            McpError::PluginRevoked => McpSessionStatus::Revoked,
            McpError::PluginUnmounted => McpSessionStatus::Unmounted,
            _ => McpSessionStatus::Failed,
        };
        Err(error)
    }

    fn reserve_explicit(&mut self, id: &McpRequestId) -> Result<(), McpError> {
        id.validate()?;
        if self.used_request_ids.contains(id) {
            return Err(McpError::DuplicateRequestId);
        }
        self.used_request_ids.insert(id.clone());
        self.pending_request_ids.insert(id.clone());
        Ok(())
    }

    fn send_reserved(
        &mut self,
        request: &McpJsonRpcRequest,
        timeout: McpTimeout,
    ) -> Result<McpJson, McpError>
    where
        T: McpStdioHostAdapter,
    {
        let id = request.id().clone();
        if !self.pending_request_ids.contains(&id) {
            return self.fail(McpError::DuplicateRequestId);
        }
        let response = match self.transport.exchange(request, timeout) {
            Ok(response) => response,
            Err(error) => {
                self.pending_request_ids.remove(&id);
                return self.fail(map_transport_error(error));
            }
        };
        self.pending_request_ids.remove(&id);
        if response.id() != &id {
            return self.fail(McpError::LateResponse);
        }
        match response.result() {
            Ok(result) => Ok(result.clone()),
            Err(error) => self.fail(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn append_audit<L>(
        &mut self,
        log: &mut L,
        kind: McpAuditEventKind,
        request_id: Option<&McpRequestId>,
        method: McpMethod,
        tool_definition_digest: Option<Digest>,
        tool_name_digest: Option<Digest>,
        resource_definition_digest: Option<Digest>,
        resource_uri_digest: Option<Digest>,
        input_digest: Option<Digest>,
        result_digest: Option<Digest>,
        effect_proposal_digest: Option<Digest>,
        error_code: Option<McpErrorCode>,
        model_visible: bool,
        observed_at: u64,
    ) -> Result<Digest, McpError>
    where
        L: McpAuditLog,
    {
        let entry = McpAuditEntry::new(
            &self.binding,
            kind,
            request_id,
            method,
            tool_definition_digest,
            tool_name_digest,
            resource_definition_digest,
            resource_uri_digest,
            input_digest,
            result_digest,
            effect_proposal_digest,
            error_code,
            model_visible,
            observed_at,
        )?;
        let digest = entry.event_digest.clone();
        if log.append(entry).is_err() {
            self.status = McpSessionStatus::Failed;
            return Err(McpError::AuditCommitFailed);
        }
        Ok(digest)
    }

    #[allow(clippy::too_many_lines)]
    pub fn initialize<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpCapabilities, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.ensure_new(runtime)?;
        self.status = McpSessionStatus::Initializing;
        self.append_audit(
            log,
            McpAuditEventKind::SessionBound,
            None,
            McpMethod::Initialize,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            observed_at,
        )?;
        let request_id = self.next_generated_id()?;
        let request = McpJsonRpcRequest::initialize(
            request_id.clone(),
            self.mount.plugin.binding.identity().protocol_version(),
            &McpText::new("hartevo-plugin-runtime")?,
            PluginVersion::new(1, 0, 0),
        )?;
        let result = match self.send_reserved(&request, timeout) {
            Ok(result) => result,
            Err(error) => {
                let _ = self.append_audit(
                    log,
                    McpAuditEventKind::InvocationFailed,
                    Some(&request_id),
                    McpMethod::Initialize,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(error.code()),
                    false,
                    observed_at,
                );
                return Err(error);
            }
        };
        let capabilities = match parse_initialize_result(&result, self.mount.plugin.binding()) {
            Ok(capabilities) => capabilities,
            Err(error) => {
                let _ = self.append_audit(
                    log,
                    McpAuditEventKind::InvocationFailed,
                    Some(&request_id),
                    McpMethod::Initialize,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(error.code()),
                    false,
                    observed_at,
                );
                return self.fail(error);
            }
        };
        self.transport
            .notify(
                &McpJsonRpcNotification {
                    jsonrpc: "2.0".into(),
                    method: McpMethod::Initialized,
                    params: McpJson::from_value(json!({}))?,
                },
                timeout,
            )
            .map_err(map_transport_error)
            .or_else(|error| self.fail(error))?;
        self.capabilities = Some(capabilities);
        self.status = McpSessionStatus::Ready;
        self.append_audit(
            log,
            McpAuditEventKind::Initialized,
            Some(&request_id),
            McpMethod::Initialize,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            observed_at,
        )?;
        self.append_audit(
            log,
            McpAuditEventKind::CapabilitiesDiscovered,
            Some(&request_id),
            McpMethod::Initialized,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            observed_at,
        )?;
        Ok(capabilities)
    }

    pub fn list_tools<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<Vec<McpToolDefinition>, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.ensure_ready(runtime)?;
        if !self.capabilities.ok_or(McpError::SessionNotReady)?.tools {
            return Err(McpError::CapabilityMismatch);
        }
        let request_id = self.next_generated_id()?;
        let request = McpJsonRpcRequest::tools_list(request_id.clone())?;
        let result = self.send_with_failure_audit(
            &request,
            McpMethod::ToolsList,
            log,
            observed_at,
            timeout,
        )?;
        let definitions = match parse_tool_list(&result, self.mount.plugin.binding()) {
            Ok(definitions) => definitions,
            Err(error) => return self.fail(error),
        };
        let definitions: Vec<_> = definitions
            .into_iter()
            .filter(|definition| self.policy.allows_tool(definition))
            .collect();
        for definition in &definitions {
            if let Some(previous) = self.tools.get(definition.name())
                && previous != definition
            {
                return self.fail(McpError::SchemaDrift);
            }
        }
        for definition in &definitions {
            self.append_audit(
                log,
                McpAuditEventKind::ToolDefinitionVisible,
                Some(&request_id),
                McpMethod::ToolsList,
                Some(definition.definition_digest().clone()),
                Some(digest_serialized(definition.name())),
                None,
                None,
                Some(definition.schema_digest().clone()),
                None,
                None,
                None,
                true,
                observed_at,
            )?;
        }
        for definition in &definitions {
            self.tools
                .insert(definition.name().clone(), definition.clone());
        }
        Ok(definitions)
    }

    pub fn list_resources<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<Vec<McpResourceDefinition>, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.ensure_ready(runtime)?;
        if !self
            .capabilities
            .ok_or(McpError::SessionNotReady)?
            .resources
        {
            return Err(McpError::CapabilityMismatch);
        }
        let request_id = self.next_generated_id()?;
        let request = McpJsonRpcRequest::resources_list(request_id.clone())?;
        let result = self.send_with_failure_audit(
            &request,
            McpMethod::ResourcesList,
            log,
            observed_at,
            timeout,
        )?;
        let definitions = match parse_resource_list(&result, self.mount.plugin.binding()) {
            Ok(definitions) => definitions,
            Err(error) => return self.fail(error),
        };
        let definitions: Vec<_> = definitions
            .into_iter()
            .filter(|definition| self.policy.allows_resource(definition))
            .collect();
        for definition in &definitions {
            if let Some(previous) = self.resources.get(definition.uri())
                && previous != definition
            {
                return self.fail(McpError::SchemaDrift);
            }
        }
        for definition in &definitions {
            self.append_audit(
                log,
                McpAuditEventKind::ResourceDefinitionVisible,
                Some(&request_id),
                McpMethod::ResourcesList,
                None,
                None,
                Some(definition.definition_digest().clone()),
                Some(digest_serialized(definition.uri())),
                Some(definition.schema_digest().clone()),
                None,
                None,
                None,
                true,
                observed_at,
            )?;
        }
        for definition in &definitions {
            self.resources
                .insert(definition.uri().clone(), definition.clone());
        }
        Ok(definitions)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_tool<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        tool: &McpToolName,
        input: &McpToolInput,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpInvocationOutcome, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        let request_id = self.reserve_request_id(context)?;
        self.call_tool_with_id(
            context,
            runtime,
            &request_id,
            tool,
            input,
            log,
            observed_at,
            timeout,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_tool_with_id<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        request_id: &McpRequestId,
        tool: &McpToolName,
        input: &McpToolInput,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpInvocationOutcome, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.ensure_ready(runtime)?;
        if !self.pending_request_ids.contains(request_id) {
            return Err(if self.used_request_ids.contains(request_id) {
                McpError::DuplicateRequestId
            } else {
                McpError::UnknownRequestId
            });
        }
        let definition = self.tools.get(tool).ok_or(McpError::UnknownTool)?.clone();
        input.validate(&definition)?;
        let request = McpJsonRpcRequest::tools_call(request_id.clone(), tool, input.value())?;
        self.append_audit(
            log,
            McpAuditEventKind::InvocationStarted,
            Some(request_id),
            McpMethod::ToolsCall,
            Some(definition.definition_digest().clone()),
            Some(digest_serialized(tool)),
            None,
            None,
            Some(input.digest()),
            None,
            None,
            None,
            true,
            observed_at,
        )?;
        let raw_result = match self.send_reserved(&request, timeout) {
            Ok(result) => result,
            Err(error) => {
                let _ = self.append_audit(
                    log,
                    McpAuditEventKind::InvocationFailed,
                    Some(request_id),
                    McpMethod::ToolsCall,
                    Some(definition.definition_digest().clone()),
                    Some(digest_serialized(tool)),
                    None,
                    None,
                    Some(input.digest()),
                    None,
                    None,
                    Some(error.code()),
                    true,
                    observed_at,
                );
                return Err(error);
            }
        };
        let is_error = raw_result
            .value()
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let result = match McpToolResult::from_response(
            &self.binding,
            &definition,
            request_id,
            input,
            raw_result,
            is_error,
        ) {
            Ok(result) => result,
            Err(error) => return self.fail(error),
        };
        let event_digest = self.append_audit(
            log,
            McpAuditEventKind::InvocationCompleted,
            Some(request_id),
            McpMethod::ToolsCall,
            Some(definition.definition_digest().clone()),
            Some(digest_serialized(tool)),
            None,
            None,
            Some(input.digest()),
            Some(result.result_digest().clone()),
            result
                .effect_proposal()
                .map(|proposal| proposal.digest().clone()),
            None,
            true,
            observed_at,
        )?;
        let receipt = McpInvocationReceipt::new(
            &self.binding,
            McpInvocationStatus::Completed,
            request_id,
            definition.definition_digest().clone(),
            input.digest(),
            Some(result.result_digest().clone()),
            event_digest,
            result
                .effect_proposal()
                .map(|proposal| proposal.digest().clone()),
        )?;
        Ok(McpInvocationOutcome { result, receipt })
    }

    pub fn cancel<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &PluginRuntime,
        request_id: &McpRequestId,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpCancellationReceipt, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.ensure_ready(runtime)?;
        if !self.pending_request_ids.contains(request_id) {
            return Err(McpError::UnknownRequestId);
        }
        if !self
            .capabilities
            .ok_or(McpError::SessionNotReady)?
            .cancellation
        {
            return Err(McpError::CapabilityMismatch);
        }
        let event_digest = self.append_audit(
            log,
            McpAuditEventKind::CancellationRequested,
            Some(request_id),
            McpMethod::Cancel,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            true,
            observed_at,
        )?;
        let notification = McpJsonRpcNotification::cancelled(request_id)?;
        if let Err(error) = self.transport.notify(&notification, timeout) {
            self.pending_request_ids.remove(request_id);
            return self.fail(map_transport_error(error));
        }
        self.pending_request_ids.remove(request_id);
        let receipt = McpCancellationReceipt {
            schema: MCP_RECEIPT_SCHEMA.into(),
            session_digest: self.binding.session_digest().clone(),
            policy_digest: self.binding.policy_digest().clone(),
            request_id_digest: request_id.digest(),
            audit_event_digest: event_digest,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn revoke<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<super::RevocationReceipt, McpError>
    where
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.mount.validate_runtime(runtime)?;
        let receipt = self.mount.revoke(runtime)?;
        self.status = McpSessionStatus::Revoked;
        self.capabilities = None;
        self.tools.clear();
        self.resources.clear();
        self.pending_request_ids.clear();
        self.append_audit(
            log,
            McpAuditEventKind::Revoked,
            None,
            McpMethod::Cancel,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            observed_at,
        )?;
        Ok(receipt)
    }

    pub fn unmount<L>(
        &mut self,
        context: &McpMissionContext,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<UnmountReceipt, McpError>
    where
        L: McpAuditLog,
    {
        self.validate_scope(context)?;
        self.mount.validate_runtime(runtime)?;
        let receipt = self.mount.unmount(runtime)?;
        self.status = McpSessionStatus::Unmounted;
        self.capabilities = None;
        self.tools.clear();
        self.resources.clear();
        self.pending_request_ids.clear();
        self.append_audit(
            log,
            McpAuditEventKind::Unmounted,
            None,
            McpMethod::Cancel,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            observed_at,
        )?;
        Ok(receipt)
    }

    fn next_generated_id(&mut self) -> Result<McpRequestId, McpError> {
        let id = McpRequestId::number(self.next_request_id);
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(McpError::DuplicateRequestId)?;
        self.reserve_explicit(&id)?;
        Ok(id)
    }

    fn send_with_failure_audit<L>(
        &mut self,
        request: &McpJsonRpcRequest,
        method: McpMethod,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpJson, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        match self.send_reserved(request, timeout) {
            Ok(result) => Ok(result),
            Err(error) => {
                let _ = self.append_audit(
                    log,
                    McpAuditEventKind::InvocationFailed,
                    Some(request.id()),
                    method,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(error.code()),
                    false,
                    observed_at,
                );
                Err(error)
            }
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for McpToolProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolProvider")
            .field("binding", &self.binding)
            .field("policy", &self.policy)
            .field("status", &self.status)
            .field("capabilities", &self.capabilities)
            .field("tool_count", &self.tools.len())
            .field("resource_count", &self.resources.len())
            .field("used_request_count", &self.used_request_ids.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct McpToolConsumer;

impl McpToolConsumer {
    pub const fn new() -> Self {
        Self
    }

    pub fn initialize<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpCapabilities, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.initialize(context, runtime, log, observed_at, timeout)
    }

    pub fn list_tools<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<Vec<McpToolDefinition>, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.list_tools(context, runtime, log, observed_at, timeout)
    }

    pub fn list_resources<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &PluginRuntime,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<Vec<McpResourceDefinition>, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.list_resources(context, runtime, log, observed_at, timeout)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call_tool<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &PluginRuntime,
        tool: &McpToolName,
        input: &McpToolInput,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpInvocationOutcome, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.call_tool(context, runtime, tool, input, log, observed_at, timeout)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cancel<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &PluginRuntime,
        request_id: &McpRequestId,
        log: &mut L,
        observed_at: u64,
        timeout: McpTimeout,
    ) -> Result<McpCancellationReceipt, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.cancel(context, runtime, request_id, log, observed_at, timeout)
    }

    pub fn revoke<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<super::RevocationReceipt, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.revoke(context, runtime, log, observed_at)
    }

    pub fn unmount<T, L>(
        &self,
        context: &McpMissionContext,
        provider: &mut McpToolProvider<T>,
        runtime: &mut PluginRuntime,
        log: &mut L,
        observed_at: u64,
    ) -> Result<UnmountReceipt, McpError>
    where
        T: McpStdioHostAdapter,
        L: McpAuditLog,
    {
        provider.unmount(context, runtime, log, observed_at)
    }
}

fn map_transport_error(error: McpTransportError) -> McpError {
    match error {
        McpTransportError::Timeout => McpError::Timeout,
        McpTransportError::ServerCrashed => McpError::ServerCrashed,
        McpTransportError::LateResponse => McpError::LateResponse,
        McpTransportError::UnknownMethod => McpError::UnknownMethod,
        McpTransportError::Io
        | McpTransportError::MalformedFrame
        | McpTransportError::Closed
        | McpTransportError::DuplicateResponse => McpError::Transport,
    }
}

fn parse_initialize_result(
    result: &McpJson,
    binding: &McpServerBinding,
) -> Result<McpCapabilities, McpError> {
    let object = result.value().as_object().ok_or(McpError::InvalidSchema)?;
    let protocol = object
        .get("protocolVersion")
        .and_then(Value::as_str)
        .ok_or(McpError::InvalidSchema)?;
    if protocol != binding.identity().protocol_version().as_str() {
        return Err(McpError::ServerIdentityMismatch);
    }
    let server_info = object
        .get("serverInfo")
        .and_then(Value::as_object)
        .ok_or(McpError::InvalidSchema)?;
    let server_id = server_info
        .get("name")
        .and_then(Value::as_str)
        .ok_or(McpError::InvalidSchema)?;
    let server_version = server_info
        .get("version")
        .and_then(Value::as_str)
        .ok_or(McpError::InvalidSchema)?;
    if server_id != binding.identity().server_id().as_str()
        || server_version
            != format!(
                "{}.{}.{}",
                binding.identity().version().major(),
                binding.identity().version().minor(),
                binding.identity().version().patch()
            )
    {
        return Err(McpError::ServerIdentityMismatch);
    }
    let capabilities =
        parse_capabilities(object.get("capabilities").ok_or(McpError::InvalidSchema)?)?;
    if capabilities != binding.capabilities()
        || capabilities.digest() != *binding.identity().schema_digest()
    {
        return Err(McpError::CapabilityMismatch);
    }
    Ok(capabilities)
}

fn parse_capabilities(value: &Value) -> Result<McpCapabilities, McpError> {
    let object = value.as_object().ok_or(McpError::InvalidSchema)?;
    let tools = parse_capability_flag(object.get("tools"))?;
    let resources = parse_capability_flag(object.get("resources"))?;
    let cancellation = parse_capability_flag(object.get("cancellation"))?;
    Ok(McpCapabilities::new(tools, resources, cancellation))
}

fn parse_capability_flag(value: Option<&Value>) -> Result<bool, McpError> {
    match value {
        None => Ok(false),
        Some(Value::Bool(enabled)) => Ok(*enabled),
        Some(Value::Object(_)) => Ok(true),
        Some(_) => Err(McpError::InvalidSchema),
    }
}

fn parse_tool_list(
    result: &McpJson,
    binding: &McpServerBinding,
) -> Result<Vec<McpToolDefinition>, McpError> {
    let object = result.value().as_object().ok_or(McpError::InvalidSchema)?;
    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(McpError::InvalidSchema)?;
    let mut names = BTreeSet::new();
    let mut definitions = Vec::with_capacity(tools.len());
    for tool in tools {
        let object = tool.as_object().ok_or(McpError::InvalidSchema)?;
        let name = McpToolName::new(
            object
                .get("name")
                .and_then(Value::as_str)
                .ok_or(McpError::InvalidSchema)?,
        )?;
        if !names.insert(name.clone()) {
            return Err(McpError::DuplicateTool);
        }
        let input_schema = McpJson::from_value(
            object
                .get("inputSchema")
                .cloned()
                .ok_or(McpError::InvalidSchema)?,
        )?;
        let description = object
            .get("description")
            .and_then(Value::as_str)
            .map(McpText::new)
            .transpose()?;
        let effect_class = parse_effect_class(object)?;
        definitions.push(McpToolDefinition::new(
            binding,
            name,
            input_schema,
            description,
            effect_class,
        )?);
    }
    Ok(definitions)
}

fn parse_effect_class(
    object: &serde_json::Map<String, Value>,
) -> Result<McpToolEffectClass, McpError> {
    let value = object.get("effectClass").or_else(|| {
        object
            .get("annotations")
            .and_then(|v| v.get("hartevoEffectClass"))
    });
    match value.and_then(Value::as_str) {
        None | Some("read_only") => Ok(McpToolEffectClass::ReadOnly),
        Some("external_effect") => Ok(McpToolEffectClass::ExternalEffect),
        Some(_) => Err(McpError::InvalidSchema),
    }
}

fn parse_resource_list(
    result: &McpJson,
    binding: &McpServerBinding,
) -> Result<Vec<McpResourceDefinition>, McpError> {
    let object = result.value().as_object().ok_or(McpError::InvalidSchema)?;
    let resources = object
        .get("resources")
        .and_then(Value::as_array)
        .ok_or(McpError::InvalidSchema)?;
    let mut uris = BTreeSet::new();
    let mut definitions = Vec::with_capacity(resources.len());
    for resource in resources {
        let object = resource.as_object().ok_or(McpError::InvalidSchema)?;
        let uri = McpResourceUri::new(
            object
                .get("uri")
                .and_then(Value::as_str)
                .ok_or(McpError::InvalidSchema)?,
        )?;
        if !uris.insert(uri.clone()) {
            return Err(McpError::DuplicateResource);
        }
        let name = McpText::new(
            object
                .get("name")
                .and_then(Value::as_str)
                .ok_or(McpError::InvalidSchema)?,
        )?;
        let mime_type = object
            .get("mimeType")
            .and_then(Value::as_str)
            .map(McpText::new)
            .transpose()?;
        definitions.push(McpResourceDefinition::new(binding, uri, name, mime_type)?);
    }
    Ok(definitions)
}
